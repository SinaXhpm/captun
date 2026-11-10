use std::{
    io,
    net::IpAddr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};

use captun_core::TargetAddr;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::mpsc,
    task::{AbortHandle, JoinHandle, JoinSet},
    time::{Instant, MissedTickBehavior},
};
use tracing::{debug, info, warn};

use crate::{
    control::FlowControl,
    dispatch::{Dispatcher, SourceKey},
    flow::{UdpRelays, is_dial_error, serve_tcp, serve_udp},
    meter::TrafficMeter,
    packet::{self, Packet},
    shard::{self, Picker, Segment, TraceBudget},
    tcp::{self, Slots, TcpConnection},
    udp::{UdpConnection, UdpTable},
};

/// A source of hotspot IP packets: a TUN/utun device on Linux and macOS, or the
/// captured-and-reinjected stream from WinDivert on Windows. Anything that
/// reads and writes raw IP packets, one per read and one per write, fits.
pub trait PacketDevice: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> PacketDevice for T {}

/// Owns the running engine. Dropping it stops the engine and, with it, every
/// in-flight flow.
#[derive(Debug)]
pub struct EngineHandle {
    task: JoinHandle<()>,
}

impl EngineHandle {
    pub fn is_running(&self) -> bool {
        !self.task.is_finished()
    }

    /// Spawns `future` as the engine's task; dropping the handle aborts it.
    /// Shared by the packet engine and the proxy inbound.
    pub(crate) fn spawn(future: impl std::future::Future<Output = ()> + Send + 'static) -> Self {
        Self { task: tokio::spawn(future) }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The largest packet devices send and receive (Ethernet and Wi-Fi).
const MTU: usize = 1500;
/// Read buffer: any IP packet fits, whatever the device's MTU.
const PACKET_MAX: usize = 65_535;
/// Packets taken from the device in one go before they are handed on.
pub(crate) const READ_BATCH: usize = 64;
/// Replies from UDP flows waiting to be written to the device.
const REPLY_QUEUE: usize = 1024;
/// TCP packets waiting for each stack; more are dropped, as on a congested
/// link, rather than holding up the other stacks.
const STACK_QUEUE: usize = 1024;
/// Runs of the stacks' packets waiting to be written to the device. A stack
/// whose packets cannot be written yet waits.
const WRITE_QUEUE: usize = 256;
/// TCP stacks run side by side: one per processor, up to this many.
const MAX_STACKS: usize = 8;
/// How often finished connections are cleared away.
pub(crate) const SWEEP_EVERY: Duration = Duration::from_secs(1);
/// How often the engine reports what it carries, while it carries anything.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// Starts the routing engine over `device`. Each flow the device delivers is
/// classified by `dispatcher` and relayed through the chosen egress, with its
/// traffic recorded in `meter`. `control` ends open flows when settings
/// change, every one or one device's, and has them checked against the rules
/// again.
pub fn run<D: PacketDevice>(
    device: D,
    dispatcher: Arc<dyn Dispatcher>,
    meter: Arc<TrafficMeter>,
    control: FlowControl,
) -> EngineHandle {
    start(device, dispatcher, meter, control, stack_count()).0
}

/// How many TCP stacks to run: one per processor, up to [`MAX_STACKS`].
fn stack_count() -> usize {
    std::thread::available_parallelism().map_or(1, NonZeroUsize::get).clamp(1, MAX_STACKS)
}

/// [`run`] with `stacks` TCP stacks. The engine's tasks are one that reads
/// the device, one per stack, and one that writes the device. They run as
/// one: when any ends, the others are stopped. Also returns the stacks'
/// tasks, for tests that stop one.
pub(crate) fn start<D: PacketDevice>(
    device: D,
    dispatcher: Arc<dyn Dispatcher>,
    meter: Arc<TrafficMeter>,
    control: FlowControl,
    stacks: usize,
) -> (EngineHandle, Vec<AbortHandle>) {
    info!("routing engine started");
    let tally = Arc::new(Tally::default());
    let flows = Flows { dispatcher, meter, control, udp: tally.udp.clone() };
    let (reader, writer) = tokio::io::split(device);
    let slots = Arc::new(Slots::default());
    let budget = Arc::new(TraceBudget::default());
    let (to_writer, from_stacks) = mpsc::channel(WRITE_QUEUE);
    let (replies, outgoing) = mpsc::channel(REPLY_QUEUE);
    let mut tasks = JoinSet::new();
    let (mut inboxes, mut stack_tasks) = (Vec::new(), Vec::new());
    for _ in 0..stacks.max(1) {
        let (inbox, segments) = mpsc::channel(STACK_QUEUE);
        let stack = tcp::Shared::new(MTU, slots.clone());
        let served = shard::serve(stack, segments, to_writer.clone(), flows.clone(), tally.clone(), budget.clone());
        stack_tasks.push(tasks.spawn(served));
        inboxes.push(inbox);
    }
    drop(to_writer);
    tasks.spawn(write(writer, from_stacks, outgoing, tally.clone()));
    tasks.spawn(read(reader, inboxes, UdpTable::new(replies, MTU), flows, tally, slots));
    (EngineHandle::spawn(supervise(tasks)), stack_tasks)
}

/// Waits for any of the engine's tasks to end, then stops the others: the
/// engine runs whole or not at all.
async fn supervise(mut tasks: JoinSet<()>) {
    let Some(first) = tasks.join_next().await else { return };
    tasks.abort_all();
    // The reader says itself why it ended; a task that failed is told here.
    if let Err(e) = first {
        warn!("routing engine stopped: {e}");
    }
    while let Some(ended) = tasks.join_next().await {
        if let Err(e) = ended
            && e.is_panic()
        {
            warn!("routing engine stopped: {e}");
        }
    }
}

/// What every flow needs to be served.
#[derive(Clone)]
pub(crate) struct Flows {
    dispatcher: Arc<dyn Dispatcher>,
    meter: Arc<TrafficMeter>,
    control: FlowControl,
    udp: Arc<UdpRelays>,
}

impl Flows {
    // Each flow's watch is taken here, as it starts: a reset or a recheck
    // from now on reaches it, even before it is decided.
    pub(crate) fn serve_tcp(&self, conn: TcpConnection) {
        let (device, server) = conn.tuple();
        let destination = TargetAddr::Ip(server);
        let (dispatcher, meter, watch) = (self.dispatcher.clone(), self.meter.clone(), self.control.watch());
        let flow = serve_tcp(conn, device.ip(), destination.clone(), dispatcher, meter, watch);
        spawn_flow("tcp", device.ip(), destination, flow);
    }

    fn serve_udp(&self, conn: UdpConnection) {
        let (device, server) = conn.tuple();
        let destination = TargetAddr::Ip(server);
        let (dispatcher, meter, watch) = (self.dispatcher.clone(), self.meter.clone(), self.control.watch());
        let flow = serve_udp(conn, device.ip(), destination.clone(), dispatcher, meter, watch, self.udp.clone());
        spawn_flow("udp", device.ip(), destination, flow);
    }

    /// The budget a new connection or flow from `ip` draws on.
    pub(crate) fn source_key(&self, ip: IpAddr) -> SourceKey {
        self.dispatcher.source_key(ip)
    }
}

/// Packets and flows since the last report, counted by all the engine's tasks.
#[derive(Debug, Default)]
pub(crate) struct Tally {
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    ignored: AtomicU64,
    pub(crate) tcp_opened: AtomicU64,
    udp_opened: AtomicU64,
    /// TCP segments the engine sent the devices again, and those the devices
    /// sent again: many of the first mean packets are not reaching the
    /// devices, many of the second that the engine's are not.
    pub(crate) resent_to_devices: AtomicU64,
    pub(crate) resent_by_devices: AtomicU64,
    /// Full-size packets sent to the devices (over 1400 bytes).
    pub(crate) large_out: AtomicU64,
    /// TCP packets dropped because their stack had fallen behind.
    dropped: AtomicU64,
    /// UDP datagrams dropped because their flow's relay had fallen behind.
    udp_dropped: AtomicU64,
    /// What the UDP relays share, with the datagrams they dropped over the
    /// devices' speed limits and the answers too big to read.
    udp: Arc<UdpRelays>,
}

/// Adds `n` to one of the tally's counts.
pub(crate) fn count(counter: &AtomicU64, n: u64) {
    if n > 0 {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}

/// Logs what the engine carried since the last report, if anything, and
/// starts the counts over.
fn report(tally: &Tally, tcp_open: usize, udp_open: usize) {
    let take = |counter: &AtomicU64| counter.swap(0, Ordering::Relaxed);
    let (packets_in, packets_out) = (take(&tally.packets_in), take(&tally.packets_out));
    let (tcp_new, udp_new, ignored) = (take(&tally.tcp_opened), take(&tally.udp_opened), take(&tally.ignored));
    let (resent_to_devices, resent_by_devices) = (take(&tally.resent_to_devices), take(&tally.resent_by_devices));
    let (large_out, dropped) = (take(&tally.large_out), take(&tally.dropped));
    let (udp_dropped, over_limit) = (take(&tally.udp_dropped), take(&tally.udp.over_limit));
    let too_big = take(&tally.udp.too_big);
    if packets_in > 0 || packets_out > 0 {
        info!(
            tcp_open,
            udp_open,
            tcp_new,
            udp_new,
            packets_in,
            packets_out,
            ignored,
            resent_to_devices,
            resent_by_devices,
            large_out,
            "routing engine at work"
        );
    }
    if dropped > 0 {
        info!(dropped, "routing engine fell behind: TCP packets dropped");
    }
    if udp_dropped > 0 {
        info!(dropped = udp_dropped, "routing engine fell behind: UDP datagrams dropped");
    }
    if over_limit > 0 {
        info!(dropped = over_limit, "UDP datagrams dropped over devices' speed limits");
    }
    if too_big > 0 {
        info!(dropped = too_big, "UDP answers dropped as too big to read");
    }
}

/// Reads the devices' packets and hands each TCP one to its connection's
/// stack and each UDP one to its flow. Also clears away finished UDP flows,
/// moves those opened before their device was listed to its own budget, and
/// reports now and then. Ends when the device does.
async fn read<R: AsyncRead + Unpin>(
    mut reader: R,
    stacks: Vec<mpsc::Sender<Segment>>,
    mut udp: UdpTable,
    flows: Flows,
    tally: Arc<Tally>,
    slots: Arc<Slots>,
) {
    let picker = Picker::new(stacks.len());
    let mut inbox = Vec::with_capacity(READ_BATCH);
    let mut buf = vec![0u8; PACKET_MAX];
    let mut sweep = tokio::time::interval(SWEEP_EVERY);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reported = Instant::now();

    loop {
        tokio::select! {
            read = read_packets(&mut reader, &mut buf, &mut inbox) => {
                match read {
                    Ok(true) => {}
                    Ok(false) => {
                        info!("routing engine stopped: the packet source closed");
                        return;
                    }
                    Err(e) => {
                        warn!("routing engine stopped: cannot read packets: {e}");
                        return;
                    }
                }
                count(&tally.packets_in, inbox.len() as u64);
                let (mut ignored, mut udp_opened, mut dropped) = (0, 0, 0);
                for packet in inbox.drain(..) {
                    match packet::parse(&packet) {
                        Packet::Tcp { tuple, opening } => {
                            // Whose budget a connection draws on is asked only
                            // when one opens: the packets of open connections
                            // cost nothing more.
                            let opening = opening.then(|| flows.source_key(tuple.0.ip()));
                            // A stack that has fallen behind loses packets, as
                            // a congested link would; TCP sends them again.
                            if stacks[picker.pick(tuple)].try_send(Segment { packet, tuple, opening }).is_err() {
                                dropped += 1;
                            }
                        }
                        Packet::Udp { tuple, payload } => {
                            // The same for a datagram the table has no flow for.
                            if let Some(conn) = udp.receive(tuple, payload, || flows.source_key(tuple.0.ip())) {
                                udp_opened += 1;
                                flows.serve_udp(conn);
                            }
                        }
                        // ICMP and the like: nothing routes them yet.
                        Packet::Other => ignored += 1,
                    }
                }
                count(&tally.ignored, ignored);
                count(&tally.udp_opened, udp_opened);
                count(&tally.dropped, dropped);
                count(&tally.udp_dropped, udp.take_dropped());
            }
            _ = sweep.tick() => {
                udp.sweep(|ip| flows.source_key(ip));
                if reported.elapsed() >= REPORT_EVERY {
                    report(&tally, slots.total(), udp.len());
                    reported = Instant::now();
                }
            }
        }
    }
}

/// Writes the stacks' packets and the UDP flows' replies to the device: the
/// one place that writes it.
async fn write<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut stacks: mpsc::Receiver<Vec<Vec<u8>>>,
    mut replies: mpsc::Receiver<Vec<u8>>,
    tally: Arc<Tally>,
) {
    loop {
        let written = tokio::select! {
            Some(packets) = stacks.recv() => {
                for packet in &packets {
                    send(&mut writer, packet).await;
                }
                packets.len()
            }
            Some(packet) = replies.recv() => {
                send(&mut writer, &packet).await;
                let mut written = 1;
                while written < READ_BATCH {
                    let Ok(packet) = replies.try_recv() else { break };
                    send(&mut writer, &packet).await;
                    written += 1;
                }
                written
            }
            // Nothing is left to write for: the engine is stopping.
            else => return,
        };
        count(&tally.packets_out, written as u64);
    }
}

/// Waits for packets from the device, then takes every one already waiting,
/// up to a batch. False once the device has closed.
async fn read_packets<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8], inbox: &mut Vec<Vec<u8>>) -> io::Result<bool> {
    std::future::poll_fn(|cx| {
        while inbox.len() < READ_BATCH {
            let mut read = ReadBuf::new(buf);
            match Pin::new(&mut *reader).poll_read(cx, &mut read) {
                // End of the device; whatever came before is handled first.
                Poll::Ready(Ok(())) if read.filled().is_empty() => return Poll::Ready(Ok(!inbox.is_empty())),
                Poll::Ready(Ok(())) => inbox.push(read.filled().to_vec()),
                Poll::Ready(Err(e)) if inbox.is_empty() => return Poll::Ready(Err(e)),
                Poll::Ready(Err(_)) => break,
                Poll::Pending if inbox.is_empty() => return Poll::Pending,
                Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(true))
    })
    .await
}

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) {
    // A packet that cannot be written is lost like any other; TCP sends it again.
    if let Err(e) = writer.write(packet).await {
        debug!("packet not written to the device: {e}");
    }
}

fn spawn_flow(
    kind: &'static str,
    client_ip: IpAddr,
    destination: TargetAddr,
    future: impl std::future::Future<Output = io::Result<()>> + Send + 'static,
) {
    tokio::spawn(async move {
        if let Err(e) = future.await {
            if is_dial_error(&e) {
                report_dial_failure(kind, client_ip, &destination, &e);
            } else {
                debug!(%client_ip, %destination, "{kind} flow ended: {e}");
            }
        }
    });
}

/// An outbound that cannot be reached is worth seeing in the log, but when it
/// is down every flow fails: one line per few seconds, with a count of the rest.
fn report_dial_failure(kind: &str, client_ip: IpAddr, destination: &TargetAddr, error: &io::Error) {
    const QUIET_FOR: Duration = Duration::from_secs(5);
    static LAST: Mutex<Option<(Instant, u64)>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((at, skipped)) = last.as_mut()
        && at.elapsed() < QUIET_FOR
    {
        *skipped += 1;
        return;
    }
    let skipped = last.map_or(0, |(_, skipped)| skipped);
    *last = Some((Instant::now(), 0));
    drop(last);
    if skipped > 0 {
        info!(%client_ip, %destination, "{kind} flow failed: {error} ({skipped} more failed before it)");
    } else {
        info!(%client_ip, %destination, "{kind} flow failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn a_task_that_fails_stops_the_others() {
        let mut tasks = JoinSet::new();
        let (alive, stopped) = oneshot::channel::<()>();
        tasks.spawn(async move {
            let _alive = alive;
            std::future::pending::<()>().await;
        });
        tasks.spawn(async { panic!("a stack failed") });
        tokio::time::timeout(Duration::from_secs(5), supervise(tasks)).await.expect("the engine kept running");
        assert!(stopped.await.is_err(), "the other task was not stopped");
    }
}
