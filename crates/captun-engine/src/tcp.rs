//! The engine's TCP: a userspace TCP stack (smoltcp) that answers every
//! connection a device opens, whatever address it is for, and hands each one
//! to a relay task as a byte stream.
//!
//! smoltcp does the TCP itself: retransmission on timers, fast retransmit,
//! congestion control, window scaling, resets for connections it does not
//! know. This module keeps the books around it: a listening socket made for
//! each connection just before the stack sees its SYN, a stream per connection
//! for the relay, and removal of sockets once the device and the relay are
//! both done with them.
//!
//! Each connection's socket sits in a socket set of its own. smoltcp looks at
//! every socket of a set for each packet it takes in or sends, so with one set
//! for all, the cost of a packet grew with the number of connections. With a
//! set each, a packet, a relay task's wake or a timer runs only the connection
//! it is for, and the stack keeps the connections' timers itself.

use std::{
    collections::{BTreeSet, HashMap, VecDeque, hash_map::Entry},
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use smoltcp::{
    iface::{Config, Interface, PollResult, SocketHandle, SocketSet},
    phy::{self, Checksum, ChecksumCapabilities, DeviceCapabilities, Medium},
    socket::tcp::{self, CongestionControl, State},
    time::Instant as NetInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address, Ipv6Address},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
    time::Instant,
};
use tracing::info;

use crate::{
    dispatch::SourceKey,
    flow::{ClientSide, Refusal},
    packet::Tuple,
};

/// Whether a connection's end is described in the log: about one in sixteen,
/// chosen by the device's port so the relay's line names the same ones.
pub(crate) fn described(tuple: Tuple) -> bool {
    tuple.0.port().is_multiple_of(16)
}

/// Connection ends described so far; a hundred tell the story.
static DESCRIBED: AtomicU64 = AtomicU64::new(0);
const DESCRIBE_AT_MOST: u64 = 100;

/// What a relay task did with its connection, told when it lets go.
#[derive(Clone, Copy, Debug)]
struct Ended {
    from_device: u64,
    to_device: u64,
    age: Duration,
}

/// A connection's buffers: in, what a device may send before the relay reads
/// it; out, data in flight to the device and data waiting for its window.
/// Both are allocated when the device's SYN arrives, so they bound memory.
/// Small ones keep a link busy at a few milliseconds' delay. A busy Wi-Fi
/// link takes tens of milliseconds, where 64 KiB in flight holds a download
/// to about 20 Mbit/s, so a device's first connections at once get big ones,
/// 256 KiB out and 64 KiB in, while their budget lasts.
const RX_BUFFER: usize = 32 * 1024;
const TX_BUFFER: usize = 64 * 1024;
const BIG_RX_BUFFER: usize = 64 * 1024;
const BIG_TX_BUFFER: usize = 256 * 1024;
/// Connections with big buffers at most, over the engine and per device.
/// The pool of unlisted addresses never gets them, so made-up addresses
/// cannot take them from the listed devices.
const MAX_BIG: usize = 1024;
const MAX_BIG_PER_DEVICE: usize = 32;
/// Connections kept at most, connections per device, and handshakes in
/// progress per device, counted over all the engine's stacks, so no device
/// can take every slot from the others or exhaust memory with connection
/// attempts. A full engine holds at most about 608 MiB of connection
/// buffers: 1024 connections with big ones (320 KiB each) and 3072 with
/// small ones (96 KiB). Their relays read 16 KiB at a time each way, 128 MiB
/// more; UDP flows' queues and buffers are counted in `udp.rs` and `flow.rs`.
const MAX_CONNECTIONS: usize = 4096;
const MAX_CONNECTIONS_PER_DEVICE: usize = 256;
const MAX_OPENING_PER_DEVICE: usize = 64;
/// What all the addresses no listed device holds share, made-up ones among
/// them: room for a new device's first connections, which open before the
/// device list has it, and too little to crowd out the listed devices.
const MAX_UNLISTED_CONNECTIONS: usize = 64;
pub(crate) const MAX_UNLISTED_OPENING: usize = 32;
/// Handshakes in progress over every device, so half-open connections never
/// take the room of finished ones, and their buffers stay under 320 MiB.
const MAX_OPENING: usize = 1024;
/// How long a connection may take to finish its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// An idle connection is checked on this often. Push channels (notifications,
/// chat, MQTT) sit quiet for minutes at a time; the device's answer keeps
/// them open.
const KEEP_ALIVE: Duration = Duration::from_secs(60);
/// A device that answers nothing (data or keep-alive) this long has gone
/// away; its connection is reset.
const DEAD_PEER_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the packets of a silently refused connection keep being ignored
/// after the last one arrived.
const SILENCE_LINGER: Duration = Duration::from_secs(60);
/// The least wait before a connection runs on a timer: smoltcp's timers are
/// in milliseconds.
const MIN_TIMER: Duration = Duration::from_millis(1);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Connection slots, counted over all the engine's stacks, so the caps hold
/// however a device's connections are spread among them.
#[derive(Debug, Default)]
pub(crate) struct Slots(Mutex<SlotBooks>);

#[derive(Debug, Default)]
struct SlotBooks {
    /// Connections open, of them those still in their handshake, and those
    /// with big buffers, over every budget.
    total: usize,
    opening: usize,
    big: usize,
    devices: HashMap<SourceKey, DeviceSlots>,
}

/// A budget's connections, how many of them are still in their handshake,
/// and how many have big buffers.
#[derive(Clone, Copy, Debug, Default)]
struct DeviceSlots {
    open: usize,
    opening: usize,
    big: usize,
}

/// A budget's caps: connections, handshakes in progress, and connections
/// with big buffers.
fn caps(key: SourceKey) -> (usize, usize, usize) {
    match key {
        SourceKey::Unlisted => (MAX_UNLISTED_CONNECTIONS, MAX_UNLISTED_OPENING, 0),
        SourceKey::Device(_) | SourceKey::Address(_) => {
            (MAX_CONNECTIONS_PER_DEVICE, MAX_OPENING_PER_DEVICE, MAX_BIG_PER_DEVICE)
        }
    }
}

/// The buffers a connection was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Size {
    Small,
    Big,
}

impl Size {
    /// Its buffers' lengths, in and out.
    fn buffers(self) -> (usize, usize) {
        match self {
            Self::Small => (RX_BUFFER, TX_BUFFER),
            Self::Big => (BIG_RX_BUFFER, BIG_TX_BUFFER),
        }
    }
}

impl Slots {
    /// Takes a slot for a new connection drawing on `key`, unless that would
    /// pass a cap, and says which buffers it gets: big ones while both the
    /// engine's and the budget's last.
    fn take(&self, key: SourceKey) -> Option<Size> {
        let mut books = lock(&self.0);
        let books = &mut *books;
        if books.total >= MAX_CONNECTIONS || books.opening >= MAX_OPENING {
            return None;
        }
        let (max_open, max_opening, max_big) = caps(key);
        let slots = books.devices.entry(key).or_default();
        if slots.open >= max_open || slots.opening >= max_opening {
            return None;
        }
        slots.open += 1;
        slots.opening += 1;
        books.total += 1;
        books.opening += 1;
        if slots.big < max_big && books.big < MAX_BIG {
            slots.big += 1;
            books.big += 1;
            return Some(Size::Big);
        }
        Some(Size::Small)
    }

    /// One of `key`'s connections is out of its handshake, done or failed.
    fn handshake_over(&self, key: SourceKey) {
        let mut books = lock(&self.0);
        let books = &mut *books;
        if let Some(slots) = books.devices.get_mut(&key)
            && slots.opening > 0
        {
            slots.opening -= 1;
            books.opening = books.opening.saturating_sub(1);
        }
    }

    /// Gives back the slot of one of `key`'s connections; `opening` when it
    /// was still in its handshake, and its big buffers' slot if it had them.
    fn give_back(&self, key: SourceKey, opening: bool, size: Size) {
        let mut books = lock(&self.0);
        let books = &mut *books;
        let Entry::Occupied(mut entry) = books.devices.entry(key) else { return };
        let slots = entry.get_mut();
        slots.open = slots.open.saturating_sub(1);
        books.total = books.total.saturating_sub(1);
        if opening && slots.opening > 0 {
            slots.opening -= 1;
            books.opening = books.opening.saturating_sub(1);
        }
        if size == Size::Big && slots.big > 0 {
            slots.big -= 1;
            books.big = books.big.saturating_sub(1);
        }
        if slots.open == 0 {
            entry.remove();
        }
    }

    /// Moves the slot of one of `from`'s connections that is past its
    /// handshake to `to`, if `to` has room for it. Only unlisted connections
    /// move, and they never have big buffers.
    fn move_slot(&self, from: SourceKey, to: SourceKey) -> bool {
        let mut books = lock(&self.0);
        let books = &mut *books;
        if from == to || books.devices.get(&to).is_some_and(|slots| slots.open >= caps(to).0) {
            return false;
        }
        let Entry::Occupied(mut entry) = books.devices.entry(from) else { return false };
        let slots = entry.get_mut();
        if slots.open <= slots.opening {
            return false;
        }
        slots.open -= 1;
        if slots.open == 0 {
            entry.remove();
        }
        books.devices.entry(to).or_default().open += 1;
        true
    }

    /// Connections open over all the stacks.
    pub(crate) fn total(&self) -> usize {
        lock(&self.0).total
    }

    /// A budget's connections, and of them those still in their handshake.
    #[cfg(test)]
    fn held(&self, key: SourceKey) -> (usize, usize) {
        lock(&self.0).devices.get(&key).map_or((0, 0), |slots| (slots.open, slots.opening))
    }

    /// Connections with big buffers: a budget's, and over every budget.
    #[cfg(test)]
    fn big(&self, key: SourceKey) -> (usize, usize) {
        let books = lock(&self.0);
        (books.devices.get(&key).map_or(0, |slots| slots.big), books.big)
    }
}

/// The stack's packet queues: packets from devices waiting to be processed,
/// and the stack's own packets waiting to be written to the device.
#[derive(Debug)]
pub(crate) struct Queues {
    pub(crate) rx: VecDeque<Vec<u8>>,
    pub(crate) tx: Vec<Vec<u8>>,
    mtu: usize,
}

impl Queues {
    pub(crate) fn new(mtu: usize) -> Self {
        Self { rx: VecDeque::new(), tx: Vec::new(), mtu }
    }
}

impl phy::Device for Queues {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _now: NetInstant) -> Option<(RxToken, TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((RxToken(packet), TxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _now: NetInstant) -> Option<TxToken<'_>> {
        Some(TxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // Checksums are written on the way out. On the way in the link the
        // packets crossed has checked them already.
        let mut checksum = ChecksumCapabilities::default();
        checksum.ipv4 = Checksum::Tx;
        checksum.tcp = Checksum::Tx;
        checksum.udp = Checksum::Tx;
        checksum.icmpv4 = Checksum::Tx;
        checksum.icmpv6 = Checksum::Tx;
        caps.checksum = checksum;
        caps
    }
}

#[derive(Debug)]
pub(crate) struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

#[derive(Debug)]
pub(crate) struct TxToken<'a>(&'a mut Vec<Vec<u8>>);

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.0.push(packet);
        result
    }
}

/// smoltcp's clock: time since the stack started, on tokio's clock.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Clock(Instant);

impl Clock {
    pub(crate) fn start() -> Self {
        Self(Instant::now())
    }

    pub(crate) fn now(&self) -> NetInstant {
        NetInstant::from_micros(i64::try_from(self.0.elapsed().as_micros()).unwrap_or(i64::MAX))
    }
}

/// One connection, from its SYN until its socket is removed.
struct Conn {
    /// Its socket, alone in a set of its own, so running it never looks at
    /// another connection's socket.
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    tuple: Tuple,
    /// The budget its slot was taken from, and is given back to.
    key: SourceKey,
    /// Its buffers, and with big ones the slot of those it gives back.
    size: Size,
    stage: Stage,
    /// Still counted among its budget's handshakes in progress.
    opening: bool,
    /// Waiting in the stack's list of connections to run.
    due: bool,
    /// When its timers next need it, as filed in the stack's timers.
    timer: Option<NetInstant>,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").field("tuple", &self.tuple).field("stage", &self.stage).finish_non_exhaustive()
    }
}

impl Conn {
    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.handle)
    }

    fn state(&self) -> State {
        self.sockets.get::<tcp::Socket>(self.handle).state()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// The handshake has not finished yet.
    Opening { since: Instant },
    /// A relay task has it.
    Serving,
    /// The relay task is done; the socket finishes closing on its own.
    Released,
}

/// What a run of the stack produced.
#[derive(Debug, Default)]
pub(crate) struct Polled {
    /// Packets to write to the device.
    pub(crate) packets: Vec<Vec<u8>>,
    /// Connections whose handshake finished, for relay tasks to serve.
    pub(crate) opened: Vec<(u64, Tuple)>,
    /// When the stack next needs to run, if no packet arrives before.
    pub(crate) delay: Option<Duration>,
}

pub(crate) struct Stack {
    iface: Interface,
    queues: Queues,
    conns: HashMap<u64, Conn>,
    by_tuple: HashMap<Tuple, u64>,
    /// An empty socket set, for packets of no connection: the stack answers
    /// them with a reset.
    strangers: SocketSet<'static>,
    /// Connections to run at the next poll: a packet came for them, their
    /// relay task did something, or a timer is due.
    due: Vec<u64>,
    /// When connections' timers next need them, soonest first.
    timers: BTreeSet<(NetInstant, u64)>,
    /// Silently refused connections and when their last packet came.
    silenced: HashMap<Tuple, Instant>,
    slots: Arc<Slots>,
    next_id: u64,
    clock: Clock,
}

impl std::fmt::Debug for Stack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stack").field("connections", &self.conns.len()).finish_non_exhaustive()
    }
}

impl Stack {
    fn new(mtu: usize, slots: Arc<Slots>) -> Self {
        let clock = Clock::start();
        let mut queues = Queues::new(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        // Seeds the initial sequence numbers, which must not be guessable.
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut queues, clock.now());
        // Answer for every address: each connection's socket listens on the
        // address the device dialed.
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0));
            let _ = addrs.push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1));
        let _ = iface.routes_mut().add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1));
        Self {
            iface,
            queues,
            conns: HashMap::new(),
            by_tuple: HashMap::new(),
            strangers: SocketSet::new(Vec::new()),
            due: Vec::new(),
            timers: BTreeSet::new(),
            silenced: HashMap::new(),
            slots,
            next_id: 1,
            clock,
        }
    }

    /// Takes one TCP packet from a device. `opening` is set for a SYN, with the
    /// budget a new connection draws on; a listening socket is made for it
    /// first if the connection is new.
    pub(crate) fn receive(&mut self, packet: Vec<u8>, tuple: Tuple, opening: Option<SourceKey>) {
        if let Some(last) = self.silenced.get_mut(&tuple) {
            *last = Instant::now();
            return;
        }
        if let Some(key) = opening {
            match self.by_tuple.get(&tuple).copied() {
                // A repeated SYN, or one crossing the handshake: the socket
                // already there answers it.
                Some(id) if self.state(id).is_some_and(|s| !matches!(s, State::Closed | State::TimeWait | State::Listen)) => {}
                previous => {
                    // An old connection on the same ports is over; make room.
                    if let Some(id) = previous {
                        self.forget(id);
                    }
                    // Unless a cap is reached; then no socket takes the SYN
                    // and the stack resets it.
                    self.open(tuple, key);
                }
            }
        }
        let id = self.by_tuple.get(&tuple).copied();
        let sockets = match id.and_then(|id| self.conns.get_mut(&id)) {
            Some(conn) => &mut conn.sockets,
            None => &mut self.strangers,
        };
        self.queues.rx.push_back(packet);
        let _ = self.iface.poll_ingress_single(self.clock.now(), &mut self.queues, sockets);
        let Some(id) = id else { return };
        match self.state(id) {
            // A listener that did not take its SYN, or one a reset sent back
            // to listening mid-handshake, serves nothing.
            Some(State::Listen) => self.forget(id),
            Some(_) => self.stir(id),
            None => {}
        }
    }

    /// Runs the connections that need it: those a packet came for, those
    /// their relay task stirred, and those whose timers are due. They
    /// acknowledge, send what relay tasks queued, retransmit and close.
    pub(crate) fn poll(&mut self) -> Polled {
        let now = self.clock.now();
        while let Some(&(at, id)) = self.timers.first()
            && at <= now
        {
            self.timers.pop_first();
            if let Some(conn) = self.conns.get_mut(&id) {
                conn.timer = None;
            }
            self.stir(id);
        }

        let mut opened = Vec::new();
        for id in std::mem::take(&mut self.due) {
            let Some(conn) = self.conns.get_mut(&id) else { continue };
            conn.due = false;
            // One segment per round, until it has nothing more to send.
            while self.iface.poll_egress(now, &mut self.queues, &mut conn.sockets) == PollResult::SocketStateChanged {}
            if conn.opening {
                match conn.state() {
                    State::SynReceived => {}
                    // A reset during the handshake puts the socket back to
                    // listening, where it must not stay.
                    State::Listen => {
                        self.forget(id);
                        continue;
                    }
                    // Removed by the next sweep, once its reset is out.
                    State::Closed => {
                        conn.opening = false;
                        self.slots.handshake_over(conn.key);
                    }
                    _ => {
                        conn.opening = false;
                        self.slots.handshake_over(conn.key);
                        conn.stage = Stage::Serving;
                        opened.push((id, conn.tuple));
                    }
                }
            }
            let next = self.iface.poll_at(now, &conn.sockets).map(|at| at.max(now + MIN_TIMER.into()));
            self.schedule(id, next);
        }

        let delay = self.timers.first().map(|&(at, _)| Duration::from(at - now));
        Polled { packets: std::mem::take(&mut self.queues.tx), opened, delay }
    }

    /// Removes what is finished: closed sockets whose relay is done, stalled
    /// handshakes, and silenced connections that went quiet. Run after
    /// [`poll`](Self::poll), so a reset queued before has been sent. Returns
    /// the open connections still counted as unlisted, with their device's
    /// address, to be moved to the device's own budget once it is listed.
    pub(crate) fn sweep(&mut self) -> Vec<(u64, IpAddr)> {
        let now = Instant::now();
        let (mut done, mut stalled, mut unlisted) = (Vec::new(), Vec::new(), Vec::new());
        for (&id, conn) in &mut self.conns {
            let socket = conn.sockets.get_mut::<tcp::Socket>(conn.handle);
            // Closed with nothing left to send, not even a reset.
            let finished = socket.state() == State::Closed && socket.local_endpoint().is_none();
            match conn.stage {
                Stage::Opening { since } => {
                    if finished {
                        done.push(id);
                    } else if now.duration_since(since) > HANDSHAKE_TIMEOUT {
                        socket.abort();
                        stalled.push(id);
                    }
                }
                Stage::Serving => {
                    if conn.key == SourceKey::Unlisted {
                        unlisted.push((id, conn.tuple.0.ip()));
                    }
                }
                Stage::Released => {
                    if finished || socket.state() == State::TimeWait {
                        done.push(id);
                    }
                }
            }
        }
        for id in done {
            self.forget(id);
        }
        // Their resets go out at the next poll.
        for id in stalled {
            self.stir(id);
        }
        self.silenced.retain(|_, last| now.duration_since(*last) < SILENCE_LINGER);
        unlisted
    }

    /// Moves a connection counted as unlisted to `key`, its device's own
    /// budget now that the device is listed, if that has room. Its first
    /// connections, opened before the device list had it, then stop holding
    /// the small pool every unlisted address shares.
    pub(crate) fn move_to(&mut self, id: u64, key: SourceKey) {
        if let Some(conn) = self.conns.get_mut(&id)
            && conn.key == SourceKey::Unlisted
            && !conn.opening
            && conn.size == Size::Small
            && self.slots.move_slot(conn.key, key)
        {
            conn.key = key;
        }
    }

    /// Makes a listening socket for a new connection drawing on `key`, if the
    /// caps allow, with the buffers its slot comes with.
    fn open(&mut self, tuple: Tuple, key: SourceKey) {
        let Some(size) = self.slots.take(key) else { return };
        let (rx, tx) = size.buffers();
        let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; rx]), tcp::SocketBuffer::new(vec![0u8; tx]));
        socket.set_congestion_control(CongestionControl::Cubic);
        // Relayed data is sent as it comes; the relay already writes in large chunks.
        socket.set_nagle_enabled(false);
        // smoltcp's timeout counts from the device's last segment, so without
        // keep-alives every connection quiet for two minutes would be reset.
        socket.set_keep_alive(Some(KEEP_ALIVE.into()));
        socket.set_timeout(Some(DEAD_PEER_TIMEOUT.into()));
        if socket.listen(IpListenEndpoint::from(tuple.1)).is_err() {
            self.slots.give_back(key, true, size);
            return;
        }
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(socket);
        let id = self.next_id;
        self.next_id += 1;
        let stage = Stage::Opening { since: Instant::now() };
        let conn = Conn { sockets, handle, tuple, key, size, stage, opening: true, due: false, timer: None };
        self.conns.insert(id, conn);
        self.by_tuple.insert(tuple, id);
    }

    /// Removes a connection at once, without a word to the device.
    fn forget(&mut self, id: u64) {
        let Some(conn) = self.conns.remove(&id) else { return };
        if self.by_tuple.get(&conn.tuple) == Some(&id) {
            self.by_tuple.remove(&conn.tuple);
        }
        if let Some(at) = conn.timer {
            self.timers.remove(&(at, id));
        }
        self.slots.give_back(conn.key, conn.opening, conn.size);
    }

    /// Has a connection run at the next poll.
    fn stir(&mut self, id: u64) {
        if let Some(conn) = self.conns.get_mut(&id)
            && !conn.due
        {
            conn.due = true;
            self.due.push(id);
        }
    }

    /// Files when a connection next needs to run, if nothing comes for it
    /// before; `None` when only a packet or its relay task can move it.
    fn schedule(&mut self, id: u64, at: Option<NetInstant>) {
        let Some(conn) = self.conns.get_mut(&id) else { return };
        if conn.timer == at {
            return;
        }
        if let Some(old) = conn.timer {
            self.timers.remove(&(old, id));
        }
        conn.timer = at;
        if let Some(at) = at {
            self.timers.insert((at, id));
        }
    }

    fn state(&self, id: u64) -> Option<State> {
        Some(self.conns.get(&id)?.state())
    }

    fn socket(&mut self, id: u64) -> Option<&mut tcp::Socket<'static>> {
        Some(self.conns.get_mut(&id)?.socket())
    }

    fn release(&mut self, id: u64, ended: Ended) {
        let Some(conn) = self.conns.get_mut(&id) else { return };
        conn.stage = Stage::Released;
        let socket = conn.sockets.get_mut::<tcp::Socket>(conn.handle);
        if described(conn.tuple) && DESCRIBED.fetch_add(1, Ordering::Relaxed) < DESCRIBE_AT_MOST {
            // Data still waiting for the device's acknowledgement at the end
            // means the device was not getting the engine's packets.
            info!(
                device = %conn.tuple.0,
                server = %conn.tuple.1,
                state = ?socket.state(),
                from_device = ended.from_device,
                to_device = ended.to_device,
                not_acknowledged = socket.send_queue(),
                "tcp connection let go after {} ms",
                ended.age.as_millis()
            );
        }
        // Nobody reads or writes it any more. Unless both sides have closed it
        // already, a reset tells the device rather than leaving it waiting.
        if socket.may_send() || socket.may_recv() {
            socket.abort();
        }
    }

    fn silence(&mut self, id: u64) {
        if let Some(conn) = self.conns.get(&id) {
            self.silenced.insert(conn.tuple, Instant::now());
        }
        self.forget(id);
    }

    /// Resets every connection, waking the relay tasks so they end.
    fn abort_all(&mut self) {
        for conn in self.conns.values_mut() {
            conn.socket().abort();
        }
    }
}

/// The stack, shared by the task that drives it and the relay tasks that
/// read and write through it.
pub(crate) struct Shared {
    stack: Mutex<Stack>,
    /// Asks the stack's task to run it: a relay task queued data, read some
    /// (opening the window), or closed.
    wake: Notify,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

impl Shared {
    /// A stack of its own, taking its connections' slots from `slots`,
    /// which all the engine's stacks share.
    pub(crate) fn new(mtu: usize, slots: Arc<Slots>) -> Arc<Self> {
        Arc::new(Self { stack: Mutex::new(Stack::new(mtu, slots)), wake: Notify::new() })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Stack> {
        lock(&self.stack)
    }

    /// Resolves when a relay task asked for the stack to run.
    pub(crate) async fn woken(&self) {
        self.wake.notified().await;
    }

    /// Ends every connection. For when the engine stops: nothing drives the
    /// stack any more, so relay tasks must not wait on it.
    pub(crate) fn close(&self) {
        self.lock().abort_all();
    }
}

/// A device's TCP connection, as a byte stream for its relay task.
pub(crate) struct TcpConnection {
    shared: Arc<Shared>,
    id: u64,
    tuple: Tuple,
    /// The device sent its FIN: once the data is read, the stream has ended
    /// rather than been reset.
    peer_finished: bool,
    /// Bytes read from the device and written toward it, and since when.
    from_device: u64,
    to_device: u64,
    opened: Instant,
}

impl std::fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConnection").field("tuple", &self.tuple).finish_non_exhaustive()
    }
}

/// The states a socket reaches only after the device's FIN.
fn fin_received(state: State) -> bool {
    matches!(state, State::CloseWait | State::LastAck | State::Closing | State::TimeWait)
}

fn reset() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "the device reset the connection")
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "the connection was closed by the engine")
}

impl TcpConnection {
    pub(crate) fn new(shared: Arc<Shared>, id: u64, tuple: Tuple) -> Self {
        Self { shared, id, tuple, peer_finished: false, from_device: 0, to_device: 0, opened: Instant::now() }
    }

    pub(crate) fn tuple(&self) -> Tuple {
        self.tuple
    }

    /// Has the stack run this connection soon, for what was just done to its
    /// socket: data queued, room made in the window, a close or a reset.
    fn stir(&self, mut stack: MutexGuard<'_, Stack>) {
        stack.stir(self.id);
        drop(stack);
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let mut stack = this.shared.lock();
        let Some(socket) = stack.socket(this.id) else { return Poll::Ready(Err(gone())) };
        this.peer_finished |= fin_received(socket.state());
        if socket.can_recv() {
            let n = socket.recv_slice(buf.initialize_unfilled()).unwrap_or(0);
            buf.advance(n);
            this.from_device += n as u64;
            // Room freed in the window: the stack may need to tell the device.
            this.stir(stack);
            return Poll::Ready(Ok(()));
        }
        if socket.may_recv() {
            socket.register_recv_waker(cx.waker());
            return Poll::Pending;
        }
        Poll::Ready(if this.peer_finished { Ok(()) } else { Err(reset()) })
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let mut stack = this.shared.lock();
        let Some(socket) = stack.socket(this.id) else { return Poll::Ready(Err(gone())) };
        this.peer_finished |= fin_received(socket.state());
        if !socket.may_send() {
            return Poll::Ready(Err(match socket.state() {
                State::Closed => reset(),
                _ => io::ErrorKind::BrokenPipe.into(),
            }));
        }
        match socket.send_slice(data) {
            Ok(0) if !data.is_empty() => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            Ok(n) => {
                this.to_device += n as u64;
                this.stir(stack);
                Poll::Ready(Ok(n))
            }
            Err(_) => Poll::Ready(Err(reset())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Sends a FIN once the data written so far is out.
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let mut stack = this.shared.lock();
        if let Some(socket) = stack.socket(this.id) {
            this.peer_finished |= fin_received(socket.state());
            socket.close();
        }
        this.stir(stack);
        Poll::Ready(Ok(()))
    }
}

impl ClientSide for TcpConnection {
    fn described(&self) -> bool {
        described(self.tuple)
    }

    fn refuse(&mut self, how: Refusal) {
        let mut stack = self.shared.lock();
        match how {
            Refusal::Reset => {
                if let Some(socket) = stack.socket(self.id) {
                    socket.abort();
                }
            }
            Refusal::Silent => stack.silence(self.id),
        }
        self.stir(stack);
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        let ended = Ended { from_device: self.from_device, to_device: self.to_device, age: self.opened.elapsed() };
        let mut stack = self.shared.lock();
        stack.release(self.id, ended);
        self.stir(stack);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use captun_core::MacAddr;
    use smoltcp::wire::{Ipv4Packet, TcpControl, TcpPacket};

    use super::*;
    use crate::engine_tests::raw_tcp;

    /// A listed device's budget.
    fn device(n: u8) -> SourceKey {
        SourceKey::Device(MacAddr::new([0x02, 0, 0, 0, 0, n]))
    }

    /// An address's own budget, which every address gets by default.
    fn address(n: u8) -> SourceKey {
        SourceKey::Address(IpAddr::from([10, 0, 0, n]))
    }

    /// Takes a slot for `key` whose handshake then finishes.
    fn open(slots: &Slots, key: SourceKey) -> bool {
        let taken = slots.take(key).is_some();
        if taken {
            slots.handshake_over(key);
        }
        taken
    }

    #[test]
    fn a_device_has_64_handshakes_and_256_connections_at_most() {
        for key in [device(1), address(1)] {
            let slots = Slots::default();
            for _ in 0..MAX_OPENING_PER_DEVICE {
                assert!(slots.take(key).is_some());
            }
            assert!(slots.take(key).is_none(), "a 65th handshake at once");
            assert!(slots.take(device(2)).is_some(), "another device is held back");

            for _ in 0..MAX_OPENING_PER_DEVICE {
                slots.handshake_over(key);
            }
            while open(&slots, key) {}
            assert_eq!(slots.total(), MAX_CONNECTIONS_PER_DEVICE + 1);

            // A connection that ends gives its slot back.
            slots.give_back(key, false, Size::Small);
            assert!(open(&slots, key));
            assert!(!open(&slots, key));
        }
    }

    #[test]
    fn the_engine_has_4096_connections_at_most() {
        let slots = Slots::default();
        let mut n = 1;
        while slots.total() < MAX_CONNECTIONS {
            if !open(&slots, device(n)) {
                n += 1;
            }
        }
        assert!(slots.take(device(n + 1)).is_none(), "a new device passed the engine's cap");
        slots.give_back(device(1), false, Size::Small);
        assert!(slots.take(device(n + 1)).is_some());
    }

    #[test]
    fn a_handshake_given_up_counts_out_of_both() {
        let slots = Slots::default();
        for _ in 0..MAX_OPENING_PER_DEVICE {
            assert!(slots.take(device(1)).is_some());
        }
        slots.give_back(device(1), true, Size::Small);
        assert!(slots.take(device(1)).is_some());
        assert_eq!(slots.total(), MAX_OPENING_PER_DEVICE);
        assert_eq!(slots.held(device(1)), (MAX_OPENING_PER_DEVICE, MAX_OPENING_PER_DEVICE));
    }

    #[test]
    fn unlisted_addresses_share_32_handshakes_and_64_connections() {
        let slots = Slots::default();
        for _ in 0..MAX_UNLISTED_OPENING {
            assert!(slots.take(SourceKey::Unlisted).is_some());
        }
        assert!(slots.take(SourceKey::Unlisted).is_none(), "a 33rd handshake at once");
        assert!(slots.take(device(1)).is_some(), "a listed device is held back");

        for _ in 0..MAX_UNLISTED_OPENING {
            slots.handshake_over(SourceKey::Unlisted);
        }
        while open(&slots, SourceKey::Unlisted) {}
        assert_eq!(slots.held(SourceKey::Unlisted), (MAX_UNLISTED_CONNECTIONS, 0));
        assert!(open(&slots, device(2)), "a listed device is held back");
    }

    #[test]
    fn handshakes_in_progress_are_capped_over_every_device() {
        let slots = Slots::default();
        let devices = u8::try_from(MAX_OPENING / MAX_OPENING_PER_DEVICE).unwrap();
        for n in 0..devices {
            for _ in 0..MAX_OPENING_PER_DEVICE {
                assert!(slots.take(device(n)).is_some());
            }
        }
        assert!(slots.take(device(devices)).is_none(), "more handshakes at once than the engine takes");
        assert!(slots.take(SourceKey::Unlisted).is_none());

        // A finished handshake makes room for another; open connections do
        // not count.
        slots.handshake_over(device(0));
        assert!(slots.take(device(devices)).is_some());
        assert!(slots.take(device(devices + 1)).is_none());
        // So does a handshake given up.
        slots.give_back(device(1), true, Size::Small);
        assert!(slots.take(device(devices + 1)).is_some());
    }

    #[test]
    fn an_unlisted_slot_moves_only_past_its_handshake_and_into_room() {
        let slots = Slots::default();
        assert!(slots.take(SourceKey::Unlisted).is_some());
        assert!(!slots.move_slot(SourceKey::Unlisted, device(1)), "a handshake in progress moved");
        slots.handshake_over(SourceKey::Unlisted);
        assert!(slots.move_slot(SourceKey::Unlisted, device(1)));
        assert_eq!(slots.held(SourceKey::Unlisted), (0, 0));
        assert_eq!(slots.held(device(1)), (1, 0));
        assert_eq!(slots.total(), 1);
        slots.give_back(device(1), false, Size::Small);
        assert_eq!((slots.held(device(1)), slots.total()), ((0, 0), 0));

        // A device with no room left takes none of the pool's connections.
        while open(&slots, device(2)) {}
        assert!(open(&slots, SourceKey::Unlisted));
        assert!(!slots.move_slot(SourceKey::Unlisted, device(2)));
        assert_eq!(slots.held(SourceKey::Unlisted), (1, 0));
        assert_eq!(slots.held(device(2)), (MAX_CONNECTIONS_PER_DEVICE, 0));
    }

    /// Takes a slot for `key` whose handshake then finishes; returns the
    /// buffers it got.
    fn sized(slots: &Slots, key: SourceKey) -> Option<Size> {
        let size = slots.take(key);
        if size.is_some() {
            slots.handshake_over(key);
        }
        size
    }

    #[test]
    fn a_devices_first_32_connections_get_big_buffers() {
        for key in [device(1), address(1)] {
            let slots = Slots::default();
            for _ in 0..MAX_BIG_PER_DEVICE {
                assert_eq!(sized(&slots, key), Some(Size::Big));
            }
            assert_eq!(sized(&slots, key), Some(Size::Small), "a 33rd at once");
            assert_eq!(slots.big(key), (MAX_BIG_PER_DEVICE, MAX_BIG_PER_DEVICE));
            assert_eq!(sized(&slots, device(2)), Some(Size::Big), "another device is held back");

            // A connection that ends gives its big buffers' slot back, and the
            // next one gets them; one with small buffers gives none back.
            slots.give_back(key, false, Size::Small);
            assert_eq!(slots.big(key).0, MAX_BIG_PER_DEVICE);
            slots.give_back(key, false, Size::Big);
            assert_eq!(slots.big(key), (MAX_BIG_PER_DEVICE - 1, MAX_BIG_PER_DEVICE));
            assert_eq!(sized(&slots, key), Some(Size::Big));
            // So does one given up during its handshake.
            assert_eq!(slots.take(device(3)), Some(Size::Big));
            slots.give_back(device(3), true, Size::Big);
            assert_eq!(slots.big(device(3)), (0, MAX_BIG_PER_DEVICE + 1));
        }
    }

    #[test]
    fn unlisted_addresses_never_get_big_buffers() {
        let slots = Slots::default();
        while let Some(size) = sized(&slots, SourceKey::Unlisted) {
            assert_eq!(size, Size::Small);
        }
        assert_eq!(slots.big(SourceKey::Unlisted), (0, 0));
        // Made-up addresses leave the big buffers to the listed devices.
        assert_eq!(sized(&slots, device(1)), Some(Size::Big));
    }

    #[test]
    fn the_engine_has_1024_connections_with_big_buffers_at_most() {
        let slots = Slots::default();
        let devices = u8::try_from(MAX_BIG / MAX_BIG_PER_DEVICE).unwrap();
        for n in 0..devices {
            for _ in 0..MAX_BIG_PER_DEVICE {
                assert_eq!(sized(&slots, device(n)), Some(Size::Big));
            }
        }
        assert_eq!(slots.big(device(0)), (MAX_BIG_PER_DEVICE, MAX_BIG));
        assert_eq!(sized(&slots, device(devices)), Some(Size::Small), "past the engine's big buffers");
        assert_eq!(slots.big(device(devices)), (0, MAX_BIG));

        slots.give_back(device(0), false, Size::Big);
        assert_eq!(sized(&slots, device(devices + 1)), Some(Size::Big));
        assert_eq!(slots.big(device(devices + 1)), (1, MAX_BIG));
    }

    const DEVICE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 40_000);
    const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443);

    fn tuple() -> Tuple {
        (SocketAddr::V4(DEVICE), SocketAddr::V4(SERVER))
    }

    /// Opens a connection drawing on `key`: the device's SYN, the stack's
    /// SYN-ACK and the device's ACK. Returns its id.
    fn handshake(stack: &mut Stack, key: SourceKey) -> u64 {
        stack.receive(raw_tcp(DEVICE, SERVER, TcpControl::Syn, 1000, None, &[]), tuple(), Some(key));
        let synack = stack.poll().packets.iter().find_map(|packet| {
            let ip = Ipv4Packet::new_checked(packet.as_slice()).ok()?;
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            tcp.syn().then(|| tcp.seq_number().0 as u32)
        });
        let synack = synack.expect("the stack answered the SYN");
        stack.receive(raw_tcp(DEVICE, SERVER, TcpControl::None, 1001, Some(synack.wrapping_add(1)), &[]), tuple(), None);
        let opened = stack.poll().opened;
        assert_eq!(opened.len(), 1, "the handshake did not finish");
        opened[0].0
    }

    /// The relay lets go of connection `id`, and the stack clears it away.
    fn end(stack: &mut Stack, id: u64) {
        stack.release(id, Ended { from_device: 0, to_device: 0, age: Duration::ZERO });
        stack.stir(id);
        stack.poll();
        stack.sweep();
    }

    #[tokio::test]
    async fn a_connection_gives_its_slot_back_to_the_budget_it_drew_on() {
        let slots = Arc::new(Slots::default());
        let mut stack = Stack::new(1500, slots.clone());

        // A handshake the device gives up: its reset sends the socket back to
        // listening, and the connection is forgotten.
        stack.receive(raw_tcp(DEVICE, SERVER, TcpControl::Syn, 1000, None, &[]), tuple(), Some(device(1)));
        assert_eq!(slots.held(device(1)), (1, 1));
        assert_eq!(slots.big(device(1)), (1, 1));
        assert_eq!(slots.held(SourceKey::Address(IpAddr::V4(*DEVICE.ip()))), (0, 0), "counted by its address");
        stack.receive(raw_tcp(DEVICE, SERVER, TcpControl::Rst, 1001, None, &[]), tuple(), None);
        assert_eq!((slots.held(device(1)), slots.big(device(1)), slots.total()), ((0, 0), (0, 0), 0));

        // A connection that finishes its handshake, then ends.
        let id = handshake(&mut stack, device(1));
        assert_eq!(slots.held(device(1)), (1, 0));
        end(&mut stack, id);
        assert_eq!((slots.held(device(1)), slots.big(device(1)), slots.total()), ((0, 0), (0, 0), 0));
    }

    #[tokio::test]
    async fn a_connection_gets_the_buffers_of_its_slot_and_gives_them_back() {
        let slots = Arc::new(Slots::default());
        let mut stack = Stack::new(1500, slots.clone());
        let id = handshake(&mut stack, device(1));
        let socket = stack.socket(id).unwrap();
        assert_eq!((socket.recv_capacity(), socket.send_capacity()), (BIG_RX_BUFFER, BIG_TX_BUFFER));
        assert_eq!(slots.big(device(1)), (1, 1));
        end(&mut stack, id);
        assert_eq!(slots.big(device(1)), (0, 0), "the big buffers' slot was kept");

        // Once the device's are taken, the next gets small ones.
        for _ in 0..MAX_BIG_PER_DEVICE {
            assert_eq!(sized(&slots, device(1)), Some(Size::Big));
        }
        let id = handshake(&mut stack, device(1));
        let socket = stack.socket(id).unwrap();
        assert_eq!((socket.recv_capacity(), socket.send_capacity()), (RX_BUFFER, TX_BUFFER));
        end(&mut stack, id);
        assert_eq!(slots.big(device(1)), (MAX_BIG_PER_DEVICE, MAX_BIG_PER_DEVICE), "a small one gave a big one back");

        // An unlisted connection's are small.
        let id = handshake(&mut stack, SourceKey::Unlisted);
        assert_eq!(stack.socket(id).unwrap().send_capacity(), TX_BUFFER);
    }

    #[tokio::test]
    async fn an_unlisted_connection_moves_to_its_device_once_listed() {
        let slots = Arc::new(Slots::default());
        let mut stack = Stack::new(1500, slots.clone());
        let id = handshake(&mut stack, SourceKey::Unlisted);
        assert_eq!(stack.sweep(), vec![(id, IpAddr::V4(*DEVICE.ip()))]);

        stack.move_to(id, device(1));
        assert_eq!(slots.held(SourceKey::Unlisted), (0, 0));
        assert_eq!(slots.held(device(1)), (1, 0));
        assert!(stack.sweep().is_empty(), "still counted as unlisted");

        // Its slot goes back to its device.
        end(&mut stack, id);
        assert_eq!((slots.held(device(1)), slots.total()), ((0, 0), 0));
    }
}
