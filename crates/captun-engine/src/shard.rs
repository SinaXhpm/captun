//! The engine's TCP stacks, side by side. Each connection belongs to one
//! stack, picked by a hash of its two ends, so every packet of it goes there
//! and every packet the stack sends for it comes from there. Each stack runs
//! in a task of its own and has its own lock, so the stacks share the work
//! over the processors and no one lock is shared by every connection.

use std::{
    collections::HashMap,
    hash::{BuildHasher, RandomState},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket};
use tokio::{
    sync::mpsc,
    time::{Instant, MissedTickBehavior},
};
use tracing::info;

use crate::{
    dispatch::SourceKey,
    engine::{Flows, SWEEP_EVERY, Tally, count},
    packet::Tuple,
    tcp::{self, TcpConnection},
};

/// Packets a stack takes in before it runs.
const BATCH: usize = 64;
/// Bounds on the wait between runs of a stack: its timers are in
/// milliseconds, and with no timer set it still looks in now and then.
const MIN_WAIT: Duration = Duration::from_millis(1);
const MAX_WAIT: Duration = Duration::from_secs(1);

/// Spreads connections over the stacks by a hash of their two ends, the same
/// for every packet of a connection. The hash is keyed afresh for each
/// engine, so devices cannot aim their connections at one stack.
#[derive(Debug)]
pub(crate) struct Picker {
    keys: RandomState,
    stacks: usize,
}

impl Picker {
    pub(crate) fn new(stacks: usize) -> Self {
        Self { keys: RandomState::new(), stacks: stacks.max(1) }
    }

    /// The stack a connection's packets go to.
    pub(crate) fn pick(&self, tuple: Tuple) -> usize {
        (self.keys.hash_one(tuple) % self.stacks as u64) as usize
    }
}

/// A TCP packet from a device, on its way to its connection's stack.
#[derive(Debug)]
pub(crate) struct Segment {
    pub(crate) packet: Vec<u8>,
    pub(crate) tuple: Tuple,
    /// Set for a SYN without ACK (the device is opening a connection): the
    /// budget the connection draws on.
    pub(crate) opening: Option<SourceKey>,
}

/// Resets the stack's connections when its task ends, so relay tasks do not
/// wait on a stack nobody drives.
struct CloseOnDrop(Arc<tcp::Shared>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Runs one TCP stack: takes in its connections' packets, runs the
/// connections that need it, gives the packets they send to the writer and
/// the connections that finish their handshake to relay tasks. Ends only
/// when the engine stops.
pub(crate) async fn serve(
    tcp: Arc<tcp::Shared>,
    mut segments: mpsc::Receiver<Segment>,
    out: mpsc::Sender<Vec<Vec<u8>>>,
    flows: Flows,
    tally: Arc<Tally>,
    budget: Arc<TraceBudget>,
) {
    let _close = CloseOnDrop(tcp.clone());
    let mut resends = Resends::default();
    let mut trace = Trace::new(budget);
    let mut batch = Vec::with_capacity(BATCH);
    let mut sweep = tokio::time::interval(SWEEP_EVERY);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let wait = tokio::time::sleep(MIN_WAIT);
    tokio::pin!(wait);

    loop {
        // Let the stack run: retransmit, acknowledge, send what relay tasks
        // wrote, and hand over connections that finished their handshake.
        let polled = tcp.lock().poll();
        count(&tally.tcp_opened, polled.opened.len() as u64);
        for (id, tuple) in polled.opened {
            flows.serve_tcp(TcpConnection::new(tcp.clone(), id, tuple));
        }
        if !polled.packets.is_empty() {
            let (mut resent, mut large) = (0, 0);
            for packet in &polled.packets {
                resent += u64::from(resends.is_resent(packet, true));
                large += u64::from(packet.len() > 1400);
                trace.note(packet, true);
            }
            count(&tally.resent_to_devices, resent);
            count(&tally.large_out, large);
            // The writer is gone only once the engine stops.
            if out.send(polled.packets).await.is_err() {
                return;
            }
        }
        wait.as_mut().reset(Instant::now() + polled.delay.unwrap_or(MAX_WAIT).clamp(MIN_WAIT, MAX_WAIT));

        tokio::select! {
            taken = segments.recv_many(&mut batch, BATCH) => {
                // So is the reader.
                if taken == 0 {
                    return;
                }
                let mut resent = 0;
                for segment in &batch {
                    resent += u64::from(resends.is_resent(&segment.packet, false));
                    trace.note(&segment.packet, false);
                }
                count(&tally.resent_by_devices, resent);
                let mut stack = tcp.lock();
                for Segment { packet, tuple, opening } in batch.drain(..) {
                    stack.receive(packet, tuple, opening);
                }
            }
            () = tcp.woken() => {}
            () = &mut wait => {}
            _ = sweep.tick() => {
                let unlisted = tcp.lock().sweep();
                move_listed(&tcp, &flows, unlisted);
            }
        }
    }
}

/// Moves connections opened before their device was on the device list to
/// the device's own budget once it is, so they stop holding the small pool
/// every unlisted address shares. The dispatcher is asked without the stack's
/// lock held.
fn move_listed(tcp: &tcp::Shared, flows: &Flows, unlisted: Vec<(u64, IpAddr)>) {
    let listed: Vec<(u64, SourceKey)> = unlisted
        .into_iter()
        .filter_map(|(id, ip)| match flows.source_key(ip) {
            SourceKey::Unlisted => None,
            key => Some((id, key)),
        })
        .collect();
    if listed.is_empty() {
        return;
    }
    let mut stack = tcp.lock();
    for (id, key) in listed {
        stack.move_to(id, key);
    }
}

/// The furthest sequence number seen in each direction of each connection,
/// to tell a segment sent again from a new one.
#[derive(Debug, Default)]
struct Resends {
    to_devices: HashMap<Tuple, u32>,
    by_devices: HashMap<Tuple, u32>,
}

/// Connections remembered at most, per stack; past that the books start over.
const RESEND_BOOKS: usize = 8192;

impl Resends {
    /// Whether a packet to (`to_device`) or from a device repeats sequence
    /// space already seen on its connection.
    fn is_resent(&mut self, packet: &[u8], to_device: bool) -> bool {
        let Some((tuple, seq, len)) = tcp_span(packet, to_device) else { return false };
        if len == 0 {
            return false;
        }
        let books = if to_device { &mut self.to_devices } else { &mut self.by_devices };
        if books.len() >= RESEND_BOOKS {
            books.clear();
        }
        let end = seq.wrapping_add(len);
        match books.get_mut(&tuple) {
            Some(furthest) => {
                // Wrapping comparisons, as TCP's own.
                let resent = (seq.wrapping_sub(*furthest) as i32) < 0;
                if (end.wrapping_sub(*furthest) as i32) > 0 {
                    *furthest = end;
                }
                resent
            }
            None => {
                books.insert(tuple, end);
                false
            }
        }
    }
}

const TRACE_CONNECTIONS: usize = 3;
const TRACE_PACKETS: u32 = 20;
const TRACE_RESETS: usize = 20;

/// What the trace may still tell, shared by the stacks, so it covers the
/// engine's first connections and resets wherever they land.
#[derive(Debug, Default)]
pub(crate) struct TraceBudget {
    connections: AtomicUsize,
    resets: AtomicUsize,
}

/// Takes one from a budget, unless `limit` are taken already.
fn take(counter: &AtomicUsize, limit: usize) -> bool {
    counter.load(Ordering::Relaxed) < limit && counter.fetch_add(1, Ordering::Relaxed) < limit
}

/// A packet-by-packet account of the first few connections, and of every
/// reset a device sends, for when connections fail in the field. The TTL
/// tells who wrote a packet: Android and Linux start at 64, Windows at 128.
#[derive(Debug)]
struct Trace {
    /// Packets told so far, per traced connection of this stack.
    traced: HashMap<Tuple, u32>,
    budget: Arc<TraceBudget>,
}

impl Trace {
    fn new(budget: Arc<TraceBudget>) -> Self {
        Self { traced: HashMap::new(), budget }
    }

    fn note(&mut self, packet: &[u8], to_device: bool) {
        let Ok(ip) = Ipv4Packet::new_checked(packet) else { return };
        if ip.next_header() != IpProtocol::Tcp {
            return;
        }
        let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else { return };
        let src = SocketAddr::from((ip.src_addr(), tcp.src_port()));
        let dst = SocketAddr::from((ip.dst_addr(), tcp.dst_port()));
        let tuple = if to_device { (dst, src) } else { (src, dst) };
        if !to_device
            && tcp.syn()
            && !tcp.ack()
            && !self.traced.contains_key(&tuple)
            && take(&self.budget.connections, TRACE_CONNECTIONS)
        {
            self.traced.insert(tuple, 0);
        }
        let traced = match self.traced.get_mut(&tuple) {
            Some(told) if *told < TRACE_PACKETS => {
                *told += 1;
                true
            }
            _ => false,
        };
        let reset = !to_device && tcp.rst() && take(&self.budget.resets, TRACE_RESETS);
        if !traced && !reset {
            return;
        }
        let flags: String = [(tcp.syn(), 'S'), (tcp.ack(), 'A'), (tcp.psh(), 'P'), (tcp.fin(), 'F'), (tcp.rst(), 'R')]
            .iter()
            .filter_map(|&(on, c)| on.then_some(c))
            .collect();
        info!(
            "packet {} {src} > {dst} [{flags}] seq={} ack={} win={} len={} ttl={} id={} df={}",
            if to_device { "to device" } else { "from device" },
            tcp.seq_number().0 as u32,
            tcp.ack_number().0 as u32,
            tcp.window_len(),
            tcp.payload().len(),
            ip.hop_limit(),
            ip.ident(),
            ip.dont_frag(),
        );
    }
}

/// A TCP packet's connection as (device, server), its first sequence number
/// and how much sequence space it takes (payload, SYN, FIN).
fn tcp_span(packet: &[u8], to_device: bool) -> Option<(Tuple, u32, u32)> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    let src = SocketAddr::from((ip.src_addr(), tcp.src_port()));
    let dst = SocketAddr::from((ip.dst_addr(), tcp.dst_port()));
    let tuple = if to_device { (dst, src) } else { (src, dst) };
    let len = u32::try_from(tcp.payload().len()).unwrap_or(u32::MAX) + u32::from(tcp.syn()) + u32::from(tcp.fin());
    Some((tuple, tcp.seq_number().0 as u32, len))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::SocketAddr};

    use super::*;

    fn tuple(device: u16, server: u16) -> Tuple {
        (SocketAddr::from(([10, 0, 0, 5], device)), SocketAddr::from(([203, 0, 113, 7], server)))
    }

    #[test]
    fn every_packet_of_a_connection_goes_to_the_same_stack() {
        let picker = Picker::new(4);
        for port in 1000..1200 {
            let first = picker.pick(tuple(port, 443));
            assert!(first < 4);
            for _ in 0..10 {
                assert_eq!(picker.pick(tuple(port, 443)), first);
            }
        }
        // And connections spread over all of them.
        let used: HashSet<usize> = (1000..1200).map(|port| picker.pick(tuple(port, 443))).collect();
        assert_eq!(used.len(), 4);
    }

    #[test]
    fn one_stack_takes_everything() {
        let picker = Picker::new(1);
        assert!((1000..1100).all(|port| picker.pick(tuple(port, 80)) == 0));
    }

    #[test]
    fn the_trace_budget_is_shared() {
        let budget = TraceBudget::default();
        let taken = (0..10).filter(|_| take(&budget.connections, TRACE_CONNECTIONS)).count();
        assert_eq!(taken, TRACE_CONNECTIONS);
    }
}
