//! The engine's UDP. Datagrams need no stack, only a table of flows: each
//! device/destination pair is one flow, alive while datagrams keep coming in
//! either direction.

use std::{
    collections::{HashMap, hash_map::Entry},
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{self, error::TrySendError},
    time::{Instant, Sleep},
};

use crate::{
    dispatch::SourceKey,
    flow::{ClientSide, Refusal},
    packet::{self, Tuple},
};

/// Flows kept at most, and per device, so no device can take every slot.
const MAX_FLOWS: usize = 4096;
const MAX_FLOWS_PER_DEVICE: usize = 256;
/// What all the addresses no listed device holds share, made-up ones among
/// them: room for a new device's first flows, which open before the device
/// list has it, and too little to crowd out the listed devices.
const MAX_UNLISTED_FLOWS: usize = 64;
/// Name lookups past those caps, in a reserve of their own, so neither a full
/// table nor a device's other flows stop its lookups.
const DNS_RESERVE: usize = 512;
const DNS_RESERVE_PER_DEVICE: usize = 16;
pub(crate) const DNS_PORT: u16 = 53;
/// What may wait for a flow's relay; more is dropped, as on a congested link.
/// The relay of a flow runs once the reader has handed over the batch of
/// packets it took from the device, so a whole batch for one flow fits
/// (a device's VPN or video call sends many at once). A relay that keeps up
/// empties its queue at once; one that falls behind holds little.
const FLOW_QUEUE: usize = crate::engine::READ_BATCH;
const FLOW_QUEUE_BYTES: usize = 96 * 1024;
/// What may wait in the queues of one budget's flows together, and in every
/// queue: 4608 flows of full queues would otherwise hold 432 MiB.
const BUDGET_QUEUE_BYTES: usize = 4 * 1024 * 1024;
const ALL_QUEUES_BYTES: usize = 32 * 1024 * 1024;
/// A flow quiet this long in both directions is over. DNS lookups are one
/// question and one answer (and a retry within a few seconds), so theirs end
/// sooner and give their slot back.
const IDLE: Duration = Duration::from_secs(60);
const DNS_IDLE: Duration = Duration::from_secs(5);

/// The flows of every device, by device and destination.
#[derive(Debug)]
pub(crate) struct UdpTable {
    flows: HashMap<Tuple, Flow>,
    /// Each budget's flows, kept as flows come and go, so checking a cap
    /// never looks at the other flows.
    counts: HashMap<SourceKey, FlowCount>,
    /// Flows in the name lookups' reserve, over every budget.
    reserved: usize,
    /// Bytes waiting in every flow's queue.
    queued: Arc<AtomicUsize>,
    /// Datagrams dropped because their flow's relay had fallen behind, since
    /// the last report.
    dropped: u64,
    /// Where the flows' packets for devices go, to be written to the device.
    replies: mpsc::Sender<Vec<u8>>,
    mtu: usize,
}

/// A flow in the table: its relay's queue, and the budget it draws on.
#[derive(Debug)]
struct Flow {
    datagrams: mpsc::Sender<Vec<u8>>,
    waiting: Arc<Waiting>,
    key: SourceKey,
    /// It holds a slot of the name lookups' reserve, not of the table.
    reserved: bool,
}

/// A budget's flows: in the table, and in the name lookups' reserve; and the
/// bytes waiting in their queues.
#[derive(Debug, Default)]
struct FlowCount {
    flows: usize,
    reserved: usize,
    queued: Arc<AtomicUsize>,
}

/// Bytes waiting in a flow's queue, in the queues of its budget's flows, and
/// in every queue. The table adds a datagram as it queues it; the flow's
/// relay takes it off as it reads it.
///
/// A flow's queue counts against the budget it opened with for its whole
/// life, also once it moves to its device's own budget: its relay holds the
/// count, and queues are empty unless a relay falls behind.
#[derive(Debug)]
struct Waiting {
    flow: AtomicUsize,
    budget: Arc<AtomicUsize>,
    all: Arc<AtomicUsize>,
}

impl Waiting {
    fn new(budget: Arc<AtomicUsize>, all: Arc<AtomicUsize>) -> Self {
        Self { flow: AtomicUsize::new(0), budget, all }
    }

    /// Whether `bytes` more may wait. Only the table adds, so there is no
    /// less room by the time it does.
    fn has_room(&self, bytes: usize) -> bool {
        self.flow.load(Ordering::Relaxed) + bytes <= FLOW_QUEUE_BYTES
            && self.budget.load(Ordering::Relaxed) + bytes <= BUDGET_QUEUE_BYTES
            && self.all.load(Ordering::Relaxed) + bytes <= ALL_QUEUES_BYTES
    }

    fn add(&self, bytes: usize) {
        for count in [&self.flow, &*self.budget, &*self.all] {
            count.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn take(&self, bytes: usize) {
        for count in [&self.flow, &*self.budget, &*self.all] {
            count.fetch_sub(bytes, Ordering::Relaxed);
        }
    }

    /// The flow's relay is gone, and with it what it left in its queue.
    fn clear(&self) {
        self.take(self.flow.load(Ordering::Relaxed));
    }
}

/// A budget's cap on flows in the table.
fn cap(key: SourceKey) -> usize {
    match key {
        SourceKey::Unlisted => MAX_UNLISTED_FLOWS,
        SourceKey::Device(_) | SourceKey::Address(_) => MAX_FLOWS_PER_DEVICE,
    }
}

impl UdpTable {
    pub(crate) fn new(replies: mpsc::Sender<Vec<u8>>, mtu: usize) -> Self {
        Self {
            flows: HashMap::new(),
            counts: HashMap::new(),
            reserved: 0,
            queued: Arc::default(),
            dropped: 0,
            replies,
            mtu,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.flows.len()
    }

    /// Datagrams dropped because their flow's relay had fallen behind, since
    /// this was last asked.
    pub(crate) fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }

    /// Takes one datagram from a device. The first datagram of a flow comes
    /// back as a connection for the engine to serve. `key` gives the budget a
    /// new flow draws on; it is asked only when a flow may open.
    pub(crate) fn receive(&mut self, tuple: Tuple, payload: &[u8], key: impl FnOnce() -> SourceKey) -> Option<UdpConnection> {
        if let Some(flow) = self.flows.get(&tuple) {
            if !flow.datagrams.is_closed() {
                // Its relay has fallen behind: dropped, as on a congested link.
                if !flow.waiting.has_room(payload.len()) {
                    self.dropped += 1;
                    return None;
                }
                flow.waiting.add(payload.len());
                match flow.datagrams.try_send(payload.to_vec()) {
                    Ok(()) => return None,
                    Err(TrySendError::Full(_)) => {
                        flow.waiting.take(payload.len());
                        self.dropped += 1;
                        return None;
                    }
                    Err(TrySendError::Closed(_)) => flow.waiting.take(payload.len()),
                }
            }
            // The flow ended (it went quiet): this datagram starts a new one.
            if let Some(flow) = self.flows.remove(&tuple) {
                count_out(&mut self.counts, &mut self.reserved, &flow);
                flow.waiting.clear();
            }
        }
        let table_full = self.flows.len().saturating_sub(self.reserved) >= MAX_FLOWS;
        let no_reserve = tuple.1.port() != DNS_PORT || self.reserved >= DNS_RESERVE;
        // No room, whoever sent it.
        if table_full && no_reserve {
            return None;
        }
        let key = key();
        let (flows, in_reserve, budget) = self.counts.get(&key).map_or((0, 0, None), |count| {
            (count.flows, count.reserved, Some(count.queued.clone()))
        });
        let reserved = if !table_full && flows < cap(key) {
            false
        } else if !no_reserve && in_reserve < DNS_RESERVE_PER_DEVICE {
            true
        } else {
            return None;
        };
        let waiting = Arc::new(Waiting::new(budget.unwrap_or_default(), self.queued.clone()));
        // Nor is a flow opened while its budget's relays, or all of them,
        // have fallen behind.
        if !waiting.has_room(payload.len()) {
            self.dropped += 1;
            return None;
        }
        let count = self.counts.entry(key).or_insert_with(|| FlowCount { queued: waiting.budget.clone(), ..FlowCount::default() });
        if reserved {
            count.reserved += 1;
            self.reserved += 1;
        } else {
            count.flows += 1;
        }
        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        waiting.add(payload.len());
        let _ = tx.try_send(payload.to_vec());
        self.flows.insert(tuple, Flow { datagrams: tx, waiting: waiting.clone(), key, reserved });
        Some(UdpConnection::new(tuple, rx, waiting, self.replies.clone(), self.mtu))
    }

    /// Forgets the flows that ended, and moves those counted as unlisted to
    /// their device's own budget once `key` says the device is listed, so the
    /// first flows of a new device stop holding the pool every unlisted
    /// address shares. Lookups in the reserve end within seconds; they stay.
    pub(crate) fn sweep(&mut self, mut key: impl FnMut(IpAddr) -> SourceKey) {
        let Self { flows, counts, reserved, .. } = self;
        flows.retain(|tuple, flow| {
            if flow.datagrams.is_closed() {
                count_out(counts, reserved, flow);
                flow.waiting.clear();
                return false;
            }
            if flow.key == SourceKey::Unlisted && !flow.reserved {
                let listed = key(tuple.0.ip());
                if listed != SourceKey::Unlisted && counts.get(&listed).is_none_or(|count| count.flows < cap(listed)) {
                    count_out(counts, reserved, flow);
                    flow.key = listed;
                    counts.entry(listed).or_default().flows += 1;
                }
            }
            true
        });
    }
}

/// Takes a flow out of its budget's count, as it leaves the table or moves to
/// another budget.
fn count_out(counts: &mut HashMap<SourceKey, FlowCount>, reserved: &mut usize, flow: &Flow) {
    if flow.reserved {
        *reserved = reserved.saturating_sub(1);
    }
    let Entry::Occupied(mut entry) = counts.entry(flow.key) else { return };
    let count = entry.get_mut();
    if flow.reserved {
        count.reserved = count.reserved.saturating_sub(1);
    } else {
        count.flows = count.flows.saturating_sub(1);
    }
    if count.flows == 0 && count.reserved == 0 {
        entry.remove();
    }
}

/// A device's UDP flow, for its relay task: each read yields one datagram from
/// the device, each write sends one back. Reads end (return nothing) once the
/// flow has been quiet for its idle time.
pub(crate) struct UdpConnection {
    tuple: Tuple,
    datagrams: mpsc::Receiver<Vec<u8>>,
    waiting: Arc<Waiting>,
    replies: mpsc::Sender<Vec<u8>>,
    mtu: usize,
    idle: Duration,
    last_active: Instant,
    timer: Pin<Box<Sleep>>,
    refused: Option<Refusal>,
    next_ident: u16,
}

impl std::fmt::Debug for UdpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpConnection").field("tuple", &self.tuple).finish_non_exhaustive()
    }
}

impl UdpConnection {
    fn new(
        tuple: Tuple,
        datagrams: mpsc::Receiver<Vec<u8>>,
        waiting: Arc<Waiting>,
        replies: mpsc::Sender<Vec<u8>>,
        mtu: usize,
    ) -> Self {
        let idle = if tuple.1.port() == DNS_PORT { DNS_IDLE } else { IDLE };
        let now = Instant::now();
        Self {
            tuple,
            datagrams,
            waiting,
            replies,
            mtu,
            idle,
            last_active: now,
            timer: Box::pin(tokio::time::sleep_until(now + idle)),
            refused: None,
            next_ident: rand::random(),
        }
    }

    pub(crate) fn tuple(&self) -> Tuple {
        self.tuple
    }
}

impl AsyncRead for UdpConnection {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match this.datagrams.poll_recv(cx) {
                Poll::Ready(Some(datagram)) => {
                    this.waiting.take(datagram.len());
                    this.last_active = Instant::now();
                    match this.refused {
                        // An empty datagram would read as the end of the flow.
                        None if datagram.is_empty() => {}
                        None => {
                            let n = datagram.len().min(buf.remaining());
                            buf.put_slice(&datagram[..n]);
                            return Poll::Ready(Ok(()));
                        }
                        Some(Refusal::Silent) => {}
                        Some(Refusal::Reset) => {
                            if let Some(refusal) = packet::port_unreachable(this.tuple, &datagram) {
                                let _ = this.replies.try_send(refusal);
                            }
                        }
                    }
                }
                // The engine stopped.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => break,
            }
        }
        // Quiet for its idle time in both directions: the flow is over.
        let deadline = this.last_active + this.idle;
        if this.timer.deadline() != deadline {
            this.timer.as_mut().reset(deadline);
        }
        match this.timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UdpConnection {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.last_active = Instant::now();
        let ident = this.next_ident;
        this.next_ident = this.next_ident.wrapping_add(1);
        for packet in packet::udp_datagram(this.tuple.1, this.tuple.0, data, ident, this.mtu) {
            // A full queue drops the datagram, as a congested link would.
            let _ = this.replies.try_send(packet);
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl ClientSide for UdpConnection {
    fn refuse(&mut self, how: Refusal) {
        self.refused = Some(how);
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, net::SocketAddr};

    use captun_core::MacAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::packet::Packet;

    fn tuple() -> Tuple {
        ("10.0.0.5:5000".parse().unwrap(), "1.1.1.1:443".parse().unwrap())
    }

    /// The budget of [`tuple`]'s device: its address, as by default.
    fn mine() -> SourceKey {
        SourceKey::Address(tuple().0.ip())
    }

    /// A listed device's budget.
    fn device(n: u8) -> SourceKey {
        SourceKey::Device(MacAddr::new([0x02, 0, 0, 0, 0, n]))
    }

    /// Flow `n` from 10.0.0.`host` to `port`.
    fn flow(host: u8, n: usize, port: u16) -> Tuple {
        let source = 10_000 + u16::try_from(n).unwrap();
        (SocketAddr::from(([10, 0, 0, host], source)), SocketAddr::from(([203, 0, 113, 7], port)))
    }

    /// A table whose replies go nowhere.
    fn table() -> UdpTable {
        UdpTable::new(mpsc::channel(8).0, 1500)
    }

    /// Opens flows from `host` to `port` drawing on `key` until the table
    /// refuses one; returns those it opened.
    fn fill(table: &mut UdpTable, host: u8, port: u16, key: SourceKey) -> Vec<UdpConnection> {
        let mut open = Vec::new();
        while let Some(conn) = table.receive(flow(host, open.len(), port), b"x", || key) {
            open.push(conn);
        }
        open
    }

    /// A budget's flows in the table and in the reserve.
    fn counted(table: &UdpTable, key: SourceKey) -> (usize, usize) {
        table.counts.get(&key).map_or((0, 0), |count| (count.flows, count.reserved))
    }

    #[tokio::test]
    async fn the_first_datagram_opens_a_flow_and_later_ones_join_it() {
        let (replies, mut out) = mpsc::channel(8);
        let mut table = UdpTable::new(replies, 1500);
        let mut conn = table.receive(tuple(), b"one", mine).expect("a new flow");
        assert!(table.receive(tuple(), b"two", mine).is_none());

        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"one");
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"two");

        conn.write_all(b"back").await.unwrap();
        let reply = out.recv().await.unwrap();
        assert_eq!(packet::parse(&reply), Packet::Udp { tuple: (tuple().1, tuple().0), payload: b"back" });

        // Once the flow is gone, the next datagram starts another.
        drop(conn);
        assert!(table.receive(tuple(), b"three", mine).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_flow_ends() {
        let (replies, _out) = mpsc::channel(8);
        let mut table = UdpTable::new(replies, 1500);
        let mut conn = table.receive(tuple(), b"x", mine).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(conn.read(&mut buf).await.unwrap(), 1);
        let started = Instant::now();
        assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
        assert!(started.elapsed() >= IDLE);
        drop(conn);
        table.sweep(SourceKey::Address);
        assert_eq!(table.len(), 0);
        assert!(table.counts.is_empty());
    }

    #[tokio::test]
    async fn a_refused_flow_answers_with_port_unreachable() {
        let (replies, mut out) = mpsc::channel(8);
        let mut table = UdpTable::new(replies, 1500);
        let mut conn = table.receive(tuple(), b"hello", mine).unwrap();
        conn.refuse(Refusal::Reset);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 8];
            conn.read(&mut buf).await
        });
        let refusal = out.recv().await.unwrap();
        assert_eq!(refusal[9], 1, "an ICMP packet");
        reader.abort();
    }

    #[tokio::test]
    async fn a_device_has_256_flows_at_most_whichever_addresses_it_uses() {
        let mut table = table();
        let mut open = Vec::new();
        for n in 0..MAX_FLOWS_PER_DEVICE {
            // Two addresses of one device share its budget.
            let host = if n % 2 == 0 { 1 } else { 2 };
            open.push(table.receive(flow(host, n, 443), b"x", || device(1)).expect("room for the flow"));
        }
        assert!(table.receive(flow(3, 0, 443), b"x", || device(1)).is_none(), "a 257th flow");
        assert!(table.receive(flow(4, 0, 443), b"x", || device(2)).is_some(), "another device is held back");
    }

    #[tokio::test]
    async fn unlisted_addresses_share_64_flows() {
        let mut table = table();
        let open = fill(&mut table, 100, 443, SourceKey::Unlisted);
        assert_eq!(open.len(), MAX_UNLISTED_FLOWS);
        assert!(table.receive(flow(101, 0, 443), b"x", || SourceKey::Unlisted).is_none(), "another unlisted address");
        assert!(table.receive(flow(5, 0, 443), b"x", || device(1)).is_some(), "a listed device is held back");
    }

    #[tokio::test]
    async fn name_lookups_have_a_reserve_past_the_caps() {
        let mut table = table();
        // A device's lookups take its slots in the table first, then the
        // reserve, when its own flows have taken every slot.
        let first = fill(&mut table, 1, DNS_PORT, device(1));
        assert_eq!(first.len(), MAX_FLOWS_PER_DEVICE + DNS_RESERVE_PER_DEVICE);
        assert_eq!(counted(&table, device(1)), (MAX_FLOWS_PER_DEVICE, DNS_RESERVE_PER_DEVICE));
        drop(first);
        table.sweep(SourceKey::Address);

        // Sixteen devices fill the table.
        let full: Vec<UdpConnection> = (1..=16).flat_map(|n| fill(&mut table, n, 443, device(n))).collect();
        assert_eq!(full.len(), MAX_FLOWS);
        assert!(table.receive(flow(17, 0, 443), b"x", || device(17)).is_none(), "the table is full");
        // Lookups still go through, a few per device at once, up to the
        // reserve's own size.
        let mut reserve = Vec::new();
        for n in 17..=48 {
            let lookups = fill(&mut table, n, DNS_PORT, device(n));
            assert_eq!(lookups.len(), DNS_RESERVE_PER_DEVICE);
            reserve.extend(lookups);
        }
        assert_eq!(reserve.len(), DNS_RESERVE);
        assert!(table.receive(flow(49, 0, DNS_PORT), b"x", || device(49)).is_none(), "past the reserve");

        // A lookup that ends gives its slot of the reserve back.
        drop(reserve.pop());
        table.sweep(SourceKey::Address);
        assert!(table.receive(flow(49, 0, DNS_PORT), b"x", || device(49)).is_some());
    }

    #[tokio::test]
    async fn counts_follow_the_flows_that_end() {
        let mut table = table();
        let mut open = fill(&mut table, 1, 443, device(1));
        assert_eq!(open.len(), MAX_FLOWS_PER_DEVICE);

        // A flow that ended, found by its next datagram, which starts another.
        let ended = open.pop().unwrap();
        let tuple = ended.tuple();
        drop(ended);
        open.push(table.receive(tuple, b"again", || device(1)).expect("the ended flow's slot"));
        assert!(table.receive(flow(1, 1000, 443), b"x", || device(1)).is_none(), "the ended flow was counted out twice");

        // Flows a sweep clears away.
        open.clear();
        table.sweep(SourceKey::Address);
        assert_eq!(table.len(), 0);
        assert!(table.counts.is_empty());
        assert_eq!(table.reserved, 0);
        assert_eq!(fill(&mut table, 1, 443, device(1)).len(), MAX_FLOWS_PER_DEVICE);
    }

    #[tokio::test]
    async fn the_budget_is_asked_only_when_a_flow_may_open() {
        let mut table = table();
        let asked = Cell::new(0);
        let ask = || {
            asked.set(asked.get() + 1);
            device(1)
        };
        let _flow = table.receive(tuple(), b"one", ask).unwrap();
        assert!(table.receive(tuple(), b"two", ask).is_none());
        assert_eq!(asked.get(), 1, "asked for a flow already open");

        // Nor when there is no room, whoever sent it: only lookups have some.
        let _full: Vec<UdpConnection> = (2..=17).flat_map(|n| fill(&mut table, n, 443, device(n))).collect();
        assert!(table.receive(flow(18, 0, 443), b"x", ask).is_none());
        assert_eq!(asked.get(), 1, "asked with the table full");
        assert!(table.receive(flow(18, 0, DNS_PORT), b"x", ask).is_some());
        assert_eq!(asked.get(), 2);
    }

    /// Bytes waiting in a budget's queues, and in all of them.
    fn queued(table: &UdpTable, key: SourceKey) -> (usize, usize) {
        let budget = table.counts.get(&key).map_or(0, |count| count.queued.load(Ordering::Relaxed));
        (budget, table.queued.load(Ordering::Relaxed))
    }

    /// Reads every datagram waiting for `conn`'s relay.
    async fn drain(conn: &mut UdpConnection) -> usize {
        let mut buf = [0u8; 4096];
        let mut read = 0;
        while tokio::time::timeout(Duration::from_millis(1), conn.read(&mut buf)).await.is_ok() {
            read += 1;
        }
        read
    }

    #[tokio::test]
    async fn a_flows_queue_holds_a_batch_of_packets_and_no_more() {
        let mut table = table();
        // A whole batch of the reader's, 1 500 B datagrams of a VPN or a
        // video call, waits for the relay to run.
        let batch = crate::engine::READ_BATCH;
        let mut conn = table.receive(tuple(), &[0; 1_500], mine).unwrap();
        for _ in 1..batch {
            assert!(table.receive(tuple(), &[0; 1_500], mine).is_none());
        }
        assert_eq!(table.take_dropped(), 0, "part of a batch was dropped");
        assert_eq!(drain(&mut conn).await, batch);

        // Datagrams of 1 000 B: the count is reached first.
        for _ in 0..FLOW_QUEUE + 10 {
            assert!(table.receive(tuple(), &[0; 1_000], mine).is_none());
        }
        assert_eq!(table.take_dropped(), 10);
        assert_eq!(queued(&table, mine()), (FLOW_QUEUE * 1_000, FLOW_QUEUE * 1_000));
        // Read, they leave room again.
        assert_eq!(drain(&mut conn).await, FLOW_QUEUE);
        assert_eq!(queued(&table, mine()), (0, 0));

        // Datagrams of 9 000 B (jumbo frames): the bytes are reached first.
        let fit = FLOW_QUEUE_BYTES / 9_000;
        for _ in 0..fit + 3 {
            assert!(table.receive(tuple(), &[0; 9_000], mine).is_none());
        }
        assert_eq!(table.take_dropped(), 3);
        assert_eq!(drain(&mut conn).await, fit);
        assert_eq!(table.take_dropped(), 0);
    }

    /// Opens flows of `key` from `host`, each with `size` byte datagrams
    /// until its queue is full, until the table opens no more; returns them.
    fn fill_queues(table: &mut UdpTable, host: u8, key: SourceKey, size: usize) -> Vec<UdpConnection> {
        let mut open = Vec::new();
        while let Some(conn) = table.receive(flow(host, open.len(), 443), &vec![0; size], || key) {
            for _ in 1..FLOW_QUEUE_BYTES / size {
                table.receive(flow(host, open.len(), 443), &vec![0; size], || key);
            }
            open.push(conn);
        }
        open
    }

    #[tokio::test]
    async fn a_budgets_queues_hold_4_mib_together() {
        let mut table = table();
        // 2 KiB datagrams, 48 to a full queue: 42 full queues and 32
        // datagrams in another fill the budget.
        let mut open = fill_queues(&mut table, 1, device(1), 2_048);
        assert_eq!(open.len(), 43);
        assert_eq!(queued(&table, device(1)).0, BUDGET_QUEUE_BYTES);
        // Its relays have fallen behind: no more for any of its flows, those
        // with room in their own queue and new ones; another device's are
        // not held back.
        table.take_dropped();
        assert!(table.receive(flow(1, 42, 443), &[0; 2_048], || device(1)).is_none(), "an open flow");
        assert!(table.receive(flow(1, 1000, 443), &[0; 2_048], || device(1)).is_none(), "a new flow");
        assert_eq!(table.take_dropped(), 2);
        assert_eq!(counted(&table, device(1)).0, open.len(), "a flow opened without its datagram");
        assert!(table.receive(flow(2, 0, 443), &[0; 2_048], || device(2)).is_some());

        // One relay catches up: room again.
        assert_eq!(drain(&mut open[0]).await, FLOW_QUEUE_BYTES / 2_048);
        assert!(table.receive(flow(1, 1000, 443), &[0; 2_048], || device(1)).is_some());
    }

    #[tokio::test]
    async fn all_the_queues_together_hold_32_mib() {
        let mut table = table();
        // Eight devices fill their budgets with 32 KiB datagrams.
        let mut open = Vec::new();
        for d in 1..=8 {
            let theirs = fill_queues(&mut table, d, device(d), 32 * 1024);
            assert_eq!(queued(&table, device(d)).0, BUDGET_QUEUE_BYTES);
            open.push(theirs);
        }
        assert_eq!(table.queued.load(Ordering::Relaxed), ALL_QUEUES_BYTES);
        // Nothing more waits anywhere, a name lookup's either.
        assert!(table.receive(flow(9, 0, 443), &[0; 100], || device(9)).is_none());
        assert!(table.receive(flow(9, 0, DNS_PORT), &[0; 100], || device(9)).is_none());

        // Until a relay catches up.
        drain(&mut open[0][0]).await;
        assert!(table.receive(flow(9, 0, DNS_PORT), &[0; 100], || device(9)).is_some());
    }

    #[tokio::test]
    async fn what_an_ended_flow_left_queued_is_given_back() {
        let mut table = table();
        let conn = table.receive(tuple(), &[0; 1_000], mine).unwrap();
        table.receive(tuple(), &[0; 1_000], mine);
        let other = table.receive(flow(5, 0, 443), &[0; 1_000], mine).unwrap();
        table.receive(flow(5, 0, 443), &[0; 1_000], mine);
        assert_eq!(queued(&table, mine()), (4_000, 4_000));

        // One ends unread, found by its next datagram, which opens another.
        drop(conn);
        let _again = table.receive(tuple(), &[0; 1_000], mine).unwrap();
        assert_eq!(queued(&table, mine()), (3_000, 3_000));
        // One a sweep clears away.
        drop(other);
        table.sweep(SourceKey::Address);
        assert_eq!(queued(&table, mine()), (1_000, 1_000));
    }

    #[tokio::test]
    async fn unlisted_flows_move_to_their_device_once_it_is_listed() {
        let mut table = table();
        let open = fill(&mut table, 1, 443, SourceKey::Unlisted);
        assert_eq!(open.len(), MAX_UNLISTED_FLOWS);
        let _lookup = table.receive(flow(1, 0, DNS_PORT), b"x", || SourceKey::Unlisted).expect("room in the reserve");

        // 10.0.0.1 turns out to be a listed device. Its lookup in the
        // reserve stays where it is: it ends within seconds anyway.
        let listed = IpAddr::from([10, 0, 0, 1]);
        table.sweep(|ip| if ip == listed { device(1) } else { SourceKey::Unlisted });
        assert_eq!(counted(&table, SourceKey::Unlisted), (0, 1));
        assert_eq!(counted(&table, device(1)), (MAX_UNLISTED_FLOWS, 0));

        // The pool has room again, and the device's budget counts what moved.
        let more = fill(&mut table, 2, 443, SourceKey::Unlisted);
        assert_eq!(more.len(), MAX_UNLISTED_FLOWS);
        let rest = fill(&mut table, 1, 8443, device(1));
        assert_eq!(rest.len(), MAX_FLOWS_PER_DEVICE - MAX_UNLISTED_FLOWS);

        // What moved gives its slots back to the device when it ends.
        drop(open);
        table.sweep(|_| SourceKey::Unlisted);
        assert_eq!(counted(&table, device(1)), (MAX_FLOWS_PER_DEVICE - MAX_UNLISTED_FLOWS, 0));
        assert_eq!(counted(&table, SourceKey::Unlisted), (MAX_UNLISTED_FLOWS, 1));
    }
}
