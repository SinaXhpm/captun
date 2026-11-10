//! The engine end to end. A device, played by a second smoltcp stack, talks to
//! the engine over an in-memory link that can lose packets; the engine relays
//! the device's flows to servers on this computer's loopback through a direct
//! outbound. No device packet may name loopback, so the device addresses the
//! servers as [`SERVERS`] and the outbound takes that address there and back.
//! For thousands of connections at once, a [`RawDevice`] writes its TCP
//! packets by hand instead.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use captun_core::{EgressId, MacAddr, TargetAddr};
use captun_outbound::{BoxStream, Direct, Outbound, UdpSession};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::ChecksumCapabilities,
    socket::tcp,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
        TcpSeqNumber,
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, UdpSocket},
    sync::mpsc,
    task::AbortHandle,
    time::Instant,
};

use crate::{
    EngineHandle,
    control::FlowControl,
    dispatch::{Dispatcher, FlowAction, FlowRequest, Forward, SourceKey},
    engine::{run, start},
    meter::TrafficMeter,
    packet::{self, Packet},
    tcp::{Clock, MAX_UNLISTED_OPENING, Queues},
};

const DEVICE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

/// The engine's end of the link: one packet per read and per write.
struct EngineEnd {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncRead for EngineEnd {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                buf.put_slice(&packet);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for EngineEnd {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        let _ = self.tx.send(packet.to_vec());
        Poll::Ready(Ok(packet.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// An engine over an in-memory link, and the device's ends of the link.
struct Link {
    to_engine: mpsc::UnboundedSender<Vec<u8>>,
    from_engine: mpsc::UnboundedReceiver<Vec<u8>>,
    engine: EngineHandle,
    /// The tasks of the engine's TCP stacks, when the test chose how many.
    stacks: Vec<AbortHandle>,
    /// Kept, as the daemon keeps its own: flows outlive a control that is
    /// gone. Tests reset flows and check them again through it.
    control: FlowControl,
}

impl Link {
    /// An engine that answers every flow with `action`, with `stacks` TCP
    /// stacks, or as many as [`run`] gives it.
    fn new(action: FlowAction, stacks: Option<usize>) -> Self {
        Self::with(Arc::new(Fixed(action)), stacks)
    }

    /// An engine that asks `dispatcher` about every flow.
    fn with(dispatcher: Arc<dyn Dispatcher>, stacks: Option<usize>) -> Self {
        let (to_engine, engine_rx) = mpsc::unbounded_channel();
        let (engine_tx, from_engine) = mpsc::unbounded_channel();
        let end = EngineEnd { rx: engine_rx, tx: engine_tx };
        let (meter, control) = (Arc::new(TrafficMeter::new()), FlowControl::new());
        let (engine, stacks) = match stacks {
            Some(stacks) => start(end, dispatcher, meter, control.clone(), stacks),
            None => (run(end, dispatcher, meter, control.clone()), Vec::new()),
        };
        Self { to_engine, from_engine, engine, stacks, control }
    }
}

/// Answers every flow the same way.
struct Fixed(FlowAction);

impl Dispatcher for Fixed {
    fn needs_domain(&self) -> bool {
        false
    }

    fn dispatch(&self, _request: &FlowRequest<'_>) -> FlowAction {
        self.0.clone()
    }
}

fn forward_direct() -> FlowAction {
    FlowAction::Forward(Forward {
        client: None,
        outbound: Arc::new(ToLoopback(Direct::new(EgressId::new("direct"), None))),
        down_kbps: None,
        up_kbps: None,
    })
}

/// Where the device finds the test servers (a documentation address).
const SERVERS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

/// A direct outbound that takes [`SERVERS`] to this computer's loopback,
/// where the test servers listen, and answers from there back to it.
#[derive(Debug)]
struct ToLoopback(Direct);

fn to_loopback(target: &TargetAddr) -> TargetAddr {
    match target {
        TargetAddr::Ip(addr) => TargetAddr::Ip(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port())),
        other => other.clone(),
    }
}

#[async_trait]
impl Outbound for ToLoopback {
    fn id(&self) -> &EgressId {
        self.0.id()
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        self.0.connect_tcp(&to_loopback(target)).await
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        Ok(Box::new(LoopbackSession(self.0.udp_session().await?)))
    }
}

#[derive(Debug)]
struct LoopbackSession(Box<dyn UdpSession>);

#[async_trait]
impl UdpSession for LoopbackSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        self.0.send_to(payload, &to_loopback(target)).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let (n, from) = self.0.recv_from(buf).await?;
        let from = match from {
            TargetAddr::Ip(addr) => TargetAddr::Ip(SocketAddr::new(SERVERS.into(), addr.port())),
            other => other,
        };
        Ok((n, from))
    }
}

/// Decides which packets the link loses.
type Loss = Box<dyn FnMut(&[u8]) -> bool + Send>;

/// The device: its own TCP stack, its packets crossing the link.
struct Device {
    iface: Interface,
    queues: Queues,
    sockets: SocketSet<'static>,
    clock: Clock,
    link: Link,
    /// Losses on the way to the device, and on the way to the engine.
    lose_in: Loss,
    lose_out: Loss,
    /// Every packet the engine sent, lost or not.
    received: Vec<Vec<u8>>,
}

impl Device {
    fn start(action: FlowAction) -> Self {
        Self::over(Link::new(action, None))
    }

    fn over(link: Link) -> Self {
        let clock = Clock::start();
        let mut queues = Queues::new(1500);
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut queues, clock.now());
        iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(IpAddress::Ipv4(DEVICE_IP), 24)).unwrap());
        iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1)).unwrap();
        Self {
            iface,
            queues,
            sockets: SocketSet::new(Vec::new()),
            clock,
            link,
            lose_in: Box::new(|_| false),
            lose_out: Box::new(|_| false),
            received: Vec::new(),
        }
    }

    fn connect(&mut self, server: SocketAddr, local_port: u16) -> SocketHandle {
        let mut socket =
            tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 64 * 1024]), tcp::SocketBuffer::new(vec![0; 64 * 1024]));
        socket.connect(self.iface.context(), server, local_port).unwrap();
        self.sockets.add(socket)
    }

    fn socket(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(handle)
    }

    /// One step: take what the engine sent, let the device's stack run, send
    /// what it produced. True when any packet moved.
    fn step(&mut self) -> bool {
        let mut moved = false;
        while let Ok(packet) = self.link.from_engine.try_recv() {
            moved = true;
            self.received.push(packet.clone());
            if !(self.lose_in)(&packet) {
                self.queues.rx.push_back(packet);
            }
        }
        self.iface.poll(self.clock.now(), &mut self.queues, &mut self.sockets);
        for packet in std::mem::take(&mut self.queues.tx) {
            moved = true;
            if !(self.lose_out)(&packet) {
                let _ = self.link.to_engine.send(packet);
            }
        }
        moved
    }

    /// Steps until `done` holds, failing after `limit`.
    async fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&mut Self) -> bool) {
        let deadline = Instant::now() + limit;
        while !done(self) {
            assert!(Instant::now() < deadline, "timed out");
            if self.step() {
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    /// Steps for `time`, whatever happens.
    async fn run_for(&mut self, time: Duration) {
        let end = Instant::now() + time;
        self.run_until(time + Duration::from_secs(1), |_| Instant::now() >= end).await;
    }

    /// Sends a packet to the engine past the device's stack.
    fn send_raw(&mut self, packet: Vec<u8>) {
        let _ = self.link.to_engine.send(packet);
    }

    fn received_reset(&self) -> bool {
        self.received.iter().any(|p| tcp_flags(p).is_some_and(|(_, rst, _)| rst))
    }
}

/// SYN, RST and payload length of a TCP packet.
fn tcp_flags(packet: &[u8]) -> Option<(bool, bool, usize)> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    Some((tcp.syn(), tcp.rst(), tcp.payload().len()))
}

fn carries_data(packet: &[u8]) -> bool {
    tcp_flags(packet).is_some_and(|(_, _, len)| len > 0)
}

fn read_all(socket: &mut tcp::Socket<'static>, into: &mut Vec<u8>) {
    let mut buf = [0u8; 4096];
    while socket.can_recv() {
        let n = socket.recv_slice(&mut buf).unwrap();
        into.extend_from_slice(&buf[..n]);
    }
}

/// An echo server on loopback, as the device addresses it.
async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = SocketAddr::new(SERVERS.into(), listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = SocketAddr::new(SERVERS.into(), socket.local_addr().unwrap().port());
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// Sends `payload` through the echo and waits for all of it to come back.
async fn echo_round_trip(device: &mut Device, socket: SocketHandle, payload: &[u8], limit: Duration) {
    let (mut sent, mut got) = (0, Vec::new());
    device
        .run_until(limit, |d| {
            let s = d.socket(socket);
            if sent < payload.len() && s.can_send() {
                sent += s.send_slice(&payload[sent..]).unwrap();
            }
            read_all(s, &mut got);
            got.len() >= payload.len()
        })
        .await;
    assert!(got == payload, "the echo came back different");
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn a_tcp_flow_is_relayed_both_ways_and_closed() {
    let echo = tcp_echo().await;
    let mut device = Device::start(forward_direct());
    let socket = device.connect(echo, 40000);
    echo_round_trip(&mut device, socket, &pattern(300_000), Duration::from_secs(20)).await;

    // The device's FIN reaches the server, and the server's close comes back.
    device.socket(socket).close();
    device
        .run_until(Duration::from_secs(5), |d| matches!(d.socket(socket).state(), tcp::State::TimeWait | tcp::State::Closed))
        .await;
    assert!(!device.received_reset(), "a clean close must not end in a reset");
}

/// The failure that broke browsing: the last packet of a reply is lost, so
/// nothing after it can reveal the loss. Only a retransmission timer saves it.
#[tokio::test]
async fn a_lost_last_packet_is_sent_again() {
    let echo = tcp_echo().await;
    let mut device = Device::start(forward_direct());
    let mut lost = false;
    device.lose_in = Box::new(move |packet| {
        let lose = !lost && carries_data(packet);
        lost |= lose;
        lose
    });
    let socket = device.connect(echo, 40001);
    echo_round_trip(&mut device, socket, b"ping", Duration::from_secs(10)).await;
    let data_packets = device.received.iter().filter(|p| carries_data(p)).count();
    assert!(data_packets >= 2, "the reply should have been sent twice, was sent {data_packets} times");
}

#[tokio::test]
async fn a_lossy_link_still_delivers_everything() {
    let echo = tcp_echo().await;
    let mut device = Device::start(forward_direct());
    // Toward the device: the first SYN-ACK and a few data packets.
    let (mut synacks, mut data_in) = (0, 0);
    device.lose_in = Box::new(move |packet| match tcp_flags(packet) {
        Some((true, _, _)) => {
            synacks += 1;
            synacks == 1
        }
        Some((_, _, len)) if len > 0 => {
            data_in += 1;
            matches!(data_in, 3 | 4 | 20 | 41)
        }
        _ => false,
    });
    // Toward the engine: a few of the device's data packets.
    let mut data_out = 0;
    device.lose_out = Box::new(move |packet| {
        if carries_data(packet) {
            data_out += 1;
            return matches!(data_out, 2 | 9);
        }
        false
    });
    let socket = device.connect(echo, 40002);
    echo_round_trip(&mut device, socket, &pattern(120_000), Duration::from_secs(30)).await;
}

#[tokio::test]
async fn a_packet_for_an_unknown_connection_is_reset() {
    let mut device = Device::start(forward_direct());
    let (from, to) = (SocketAddrV4::new(DEVICE_IP, 40003), SocketAddrV4::new(SERVERS, 9));
    let repr = TcpRepr {
        src_port: from.port(),
        dst_port: to.port(),
        control: TcpControl::None,
        seq_number: TcpSeqNumber(1000),
        ack_number: Some(TcpSeqNumber(2000)),
        window_len: 1024,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: b"stale",
    };
    let caps = ChecksumCapabilities::default();
    let mut buf = vec![0u8; 20 + repr.buffer_len()];
    let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
    Ipv4Repr { src_addr: *from.ip(), dst_addr: *to.ip(), next_header: IpProtocol::Tcp, payload_len: repr.buffer_len(), hop_limit: 64 }
        .emit(&mut ip, &caps);
    repr.emit(&mut TcpPacket::new_unchecked(ip.payload_mut()), &(*from.ip()).into(), &(*to.ip()).into(), &caps);
    device.send_raw(buf);
    device.run_until(Duration::from_secs(5), |d| d.received_reset()).await;
}

#[tokio::test]
async fn a_rejected_tcp_flow_is_reset() {
    let mut device = Device::start(FlowAction::Reject);
    let socket = device.connect(SocketAddr::from((SERVERS, 9)), 40004);
    device.run_until(Duration::from_secs(5), |d| d.received_reset()).await;
    device.run_until(Duration::from_secs(1), |d| d.socket(socket).state() == tcp::State::Closed).await;
}

#[tokio::test]
async fn a_dropped_tcp_flow_goes_silent() {
    let mut device = Device::start(FlowAction::Drop);
    let socket = device.connect(SocketAddr::from((SERVERS, 9)), 40005);
    device.run_until(Duration::from_secs(5), |d| d.socket(socket).state() == tcp::State::Established).await;
    device.socket(socket).send_slice(b"hello").unwrap();
    device.run_for(Duration::from_millis(1500)).await;
    assert!(!device.received_reset(), "a silent refusal must not reset");
    assert_eq!(device.socket(socket).state(), tcp::State::Established);
}

#[tokio::test]
async fn a_udp_flow_is_relayed_both_ways() {
    let echo = udp_echo().await;
    let mut device = Device::start(forward_direct());
    let me = SocketAddr::from((DEVICE_IP, 5000));
    for packet in packet::udp_datagram(me, echo, b"question", 1, 1500) {
        device.send_raw(packet);
    }
    device
        .run_until(Duration::from_secs(5), |d| {
            d.received
                .iter()
                .any(|p| packet::parse(p) == Packet::Udp { tuple: (echo, me), payload: b"question" })
        })
        .await;
}

/// Whether `p` is ICMP "destination unreachable: port unreachable".
fn is_port_unreachable(p: &[u8]) -> bool {
    Ipv4Packet::new_checked(p).is_ok_and(|ip| {
        ip.next_header() == IpProtocol::Icmp && ip.payload().first() == Some(&3) && ip.payload().get(1) == Some(&3)
    })
}

#[tokio::test]
async fn a_rejected_udp_flow_hears_port_unreachable() {
    let mut device = Device::start(FlowAction::Reject);
    let (me, server) = (SocketAddr::from((DEVICE_IP, 5001)), SocketAddr::from((SERVERS, 9)));
    for packet in packet::udp_datagram(me, server, b"question", 1, 1500) {
        device.send_raw(packet);
    }
    device.run_until(Duration::from_secs(5), |d| d.received.iter().any(|p| is_port_unreachable(p))).await;
}

/// A proxy that carries only TCP, as many local SOCKS5 proxies do.
#[derive(Debug)]
struct TcpOnly(EgressId);

#[async_trait]
impl Outbound for TcpOnly {
    fn id(&self) -> &EgressId {
        &self.0
    }

    async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxStream> {
        Err(io::Error::other("not used here"))
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "the proxy does not carry UDP"))
    }
}

#[tokio::test]
async fn quic_through_a_proxy_without_udp_hears_port_unreachable() {
    let mut device = Device::start(FlowAction::Forward(Forward {
        client: None,
        outbound: Arc::new(TcpOnly(EgressId::new("socks5"))),
        down_kbps: None,
        up_kbps: None,
    }));
    // A QUIC Initial: a full-size datagram to port 443.
    let (me, server) = (SocketAddr::from((DEVICE_IP, 50_000)), SocketAddr::from((SERVERS, 443)));
    for packet in packet::udp_datagram(me, server, &pattern(1200), 1, 1500) {
        device.send_raw(packet);
    }
    device.run_until(Duration::from_secs(5), |d| d.received.iter().any(|p| is_port_unreachable(p))).await;
}

/// A server that takes whatever it is sent and never answers. It counts
/// itself among its outbound's connections while open.
#[derive(Debug)]
struct Quiet(Arc<AtomicUsize>);

impl Drop for Quiet {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AsyncRead for Quiet {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Quiet {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// An outbound to [`Quiet`] servers: connections stay open, and what the
/// devices send is taken at once. `open` counts its connections still open,
/// that is, the relay tasks still running.
#[derive(Debug)]
struct ToQuiet {
    id: EgressId,
    open: Arc<AtomicUsize>,
}

#[async_trait]
impl Outbound for ToQuiet {
    fn id(&self) -> &EgressId {
        &self.id
    }

    async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxStream> {
        self.open.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Quiet(self.open.clone())))
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no UDP here"))
    }
}

fn forward_quiet(open: Arc<AtomicUsize>) -> FlowAction {
    FlowAction::Forward(Forward {
        client: None,
        outbound: Arc::new(ToQuiet { id: EgressId::new("quiet"), open }),
        down_kbps: None,
        up_kbps: None,
    })
}

/// A TCP packet written by hand. The engine checks no checksums, so none
/// are written.
pub(crate) fn raw_tcp(from: SocketAddrV4, to: SocketAddrV4, control: TcpControl, seq: u32, ack: Option<u32>, payload: &[u8]) -> Vec<u8> {
    let repr = TcpRepr {
        src_port: from.port(),
        dst_port: to.port(),
        control,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: ack.map(|ack| TcpSeqNumber(ack as i32)),
        window_len: u16::MAX,
        window_scale: None,
        // Small, so the two segments of a pair are more than one and the
        // engine acknowledges them at once rather than after its delay.
        max_seg_size: (control == TcpControl::Syn).then_some(536),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload,
    };
    let caps = ChecksumCapabilities::ignored();
    let mut buf = vec![0u8; 20 + repr.buffer_len()];
    let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
    Ipv4Repr { src_addr: *from.ip(), dst_addr: *to.ip(), next_header: IpProtocol::Tcp, payload_len: repr.buffer_len(), hop_limit: 64 }
        .emit(&mut ip, &caps);
    repr.emit(&mut TcpPacket::new_unchecked(ip.payload_mut()), &(*from.ip()).into(), &(*to.ip()).into(), &caps);
    buf
}

/// The parts of the engine's packets a raw device reads.
#[derive(Debug)]
struct Reply {
    device: SocketAddrV4,
    syn: bool,
    rst: bool,
    seq: u32,
    ack: u32,
}

fn reply(packet: &[u8]) -> Option<Reply> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    Some(Reply {
        device: SocketAddrV4::new(ip.dst_addr(), tcp.dst_port()),
        syn: tcp.syn(),
        rst: tcp.rst(),
        seq: tcp.seq_number().0 as u32,
        ack: tcp.ack_number().0 as u32,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawState {
    Idle,
    Opening,
    Open,
}

/// One connection of a [`RawDevice`].
#[derive(Debug)]
struct RawConn {
    device: SocketAddrV4,
    server: SocketAddrV4,
    state: RawState,
    /// The next sequence number to send, the engine's next one, and the
    /// furthest the engine has acknowledged.
    seq: u32,
    ack: u32,
    acked: u32,
}

/// Devices that write their TCP packets by hand: cheap enough to hold
/// thousands of connections at once.
struct RawDevice {
    link: Link,
    conns: Vec<RawConn>,
    by_addr: HashMap<SocketAddrV4, usize>,
}

/// Handshakes a raw device keeps in progress per device, well inside the
/// engine's limit even if the previous round is still being counted.
const RAW_OPENING: usize = 32;

/// `connections` device ends spread over `devices` devices.
fn spread(devices: usize, connections: usize) -> Vec<SocketAddrV4> {
    (0..connections)
        .map(|i| SocketAddrV4::new(Ipv4Addr::new(10, 0, 1, 1 + (i % devices) as u8), 10_000 + (i / devices) as u16))
        .collect()
}

impl RawDevice {
    /// One connection, not yet open, from each of `ends` to the servers.
    fn new(link: Link, ends: Vec<SocketAddrV4>) -> Self {
        let mut device = Self { link, conns: Vec::new(), by_addr: HashMap::new() };
        device.add(ends);
        device
    }

    /// More connections, not yet open; returns where they start.
    fn add(&mut self, ends: Vec<SocketAddrV4>) -> usize {
        let first = self.conns.len();
        for end in ends {
            self.by_addr.insert(end, self.conns.len());
            let server = SocketAddrV4::new(SERVERS, 443);
            self.conns.push(RawConn { device: end, server, state: RawState::Idle, seq: 0, ack: 0, acked: 0 });
        }
        first
    }

    fn send(&self, packet: Vec<u8>) {
        let _ = self.link.to_engine.send(packet);
    }

    /// The engine's next packets: at least one, then all that are waiting.
    async fn replies(&mut self) -> Vec<Reply> {
        let first = tokio::time::timeout(Duration::from_secs(30), self.link.from_engine.recv())
            .await
            .expect("the engine went quiet")
            .expect("the engine stopped");
        let mut all = vec![first];
        while let Ok(packet) = self.link.from_engine.try_recv() {
            all.push(packet);
        }
        all.iter().filter_map(|p| reply(p)).collect()
    }

    /// Sends a SYN on each connection of `batch` and completes the handshake
    /// of those the engine answers. Returns those it refused with a reset.
    async fn handshake(&mut self, batch: &[usize]) -> Vec<usize> {
        for &i in batch {
            let c = &mut self.conns[i];
            c.state = RawState::Opening;
            c.seq = 1000;
            let syn = raw_tcp(c.device, c.server, TcpControl::Syn, c.seq, None, &[]);
            self.send(syn);
        }
        let mut refused = Vec::new();
        let mut waiting = batch.len();
        while waiting > 0 {
            for r in self.replies().await {
                let Some(&i) = self.by_addr.get(&r.device) else { continue };
                let c = &mut self.conns[i];
                if c.state != RawState::Opening {
                    continue;
                }
                waiting -= 1;
                if r.rst {
                    c.state = RawState::Idle;
                    refused.push(i);
                } else if r.syn {
                    c.state = RawState::Open;
                    c.seq = c.seq.wrapping_add(1);
                    c.ack = r.seq.wrapping_add(1);
                    c.acked = r.ack;
                    let ack = raw_tcp(c.device, c.server, TcpControl::None, c.seq, Some(c.ack), &[]);
                    self.send(ack);
                }
            }
        }
        refused
    }

    /// Opens the connections of `wanted`, a few handshakes per device at a
    /// time; a refused one is tried again in a later round.
    async fn open(&mut self, wanted: std::ops::Range<usize>) {
        let devices = self.conns[wanted.clone()].iter().map(|c| *c.device.ip()).collect::<HashSet<_>>().len();
        loop {
            let idle: Vec<usize> = wanted.clone().filter(|&i| self.conns[i].state == RawState::Idle).collect();
            if idle.is_empty() {
                return;
            }
            for batch in idle.chunks(RAW_OPENING * devices) {
                if !self.handshake(batch).await.is_empty() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    async fn open_all(&mut self) {
        self.open(0..self.conns.len()).await;
    }

    /// Resets connection `i` from the device's side.
    fn reset(&mut self, i: usize) {
        let c = &mut self.conns[i];
        c.state = RawState::Idle;
        let rst = raw_tcp(c.device, c.server, TcpControl::Rst, c.seq, None, &[]);
        self.send(rst);
    }

    /// Sends `pairs` pairs of segments over the connections in turn, at most
    /// `in_flight` pairs not yet acknowledged, until all are acknowledged.
    async fn exchange(&mut self, payload: &[u8], pairs: usize, in_flight: usize) {
        let n = self.conns.len();
        let len = payload.len() as u32;
        let mut waiting = vec![false; n];
        let (mut sent, mut done, mut flying, mut next) = (0, 0, 0, 0);
        while done < pairs {
            while flying < in_flight && sent < pairs && !waiting[next] {
                let c = &mut self.conns[next];
                let first = raw_tcp(c.device, c.server, TcpControl::None, c.seq, Some(c.ack), payload);
                let second = raw_tcp(c.device, c.server, TcpControl::Psh, c.seq.wrapping_add(len), Some(c.ack), payload);
                c.seq = c.seq.wrapping_add(2 * len);
                self.send(first);
                self.send(second);
                waiting[next] = true;
                flying += 1;
                sent += 1;
                next = (next + 1) % n;
            }
            for r in self.replies().await {
                let Some(&i) = self.by_addr.get(&r.device) else { continue };
                assert!(!r.rst, "the engine reset connection {i}");
                let c = &mut self.conns[i];
                if (r.ack.wrapping_sub(c.acked) as i32) > 0 {
                    c.acked = r.ack;
                }
                if waiting[i] && c.acked == c.seq {
                    waiting[i] = false;
                    flying -= 1;
                    done += 1;
                }
            }
        }
    }
}

/// Connections spread over several stacks are each relayed whole: every
/// packet of a connection reaches the stack that holds it, both ways.
#[tokio::test]
async fn connections_over_several_stacks_are_each_relayed_whole() {
    let echo = tcp_echo().await;
    let mut device = Device::over(Link::new(forward_direct(), Some(4)));
    let sockets: Vec<SocketHandle> = (0..16).map(|i| device.connect(echo, 41_000 + i)).collect();
    let payload = pattern(20_000);
    let (mut sent, mut got) = (vec![0; sockets.len()], vec![Vec::new(); sockets.len()]);
    device
        .run_until(Duration::from_secs(20), |d| {
            for (i, &handle) in sockets.iter().enumerate() {
                let s = d.socket(handle);
                if sent[i] < payload.len() && s.can_send() {
                    sent[i] += s.send_slice(&payload[sent[i]..]).unwrap();
                }
                read_all(s, &mut got[i]);
            }
            got.iter().all(|g| g.len() >= payload.len())
        })
        .await;
    assert!(got.iter().all(|g| *g == payload), "an echo came back different");

    for &handle in &sockets {
        device.socket(handle).close();
    }
    device
        .run_until(Duration::from_secs(5), |d| {
            sockets.iter().all(|&s| matches!(d.socket(s).state(), tcp::State::TimeWait | tcp::State::Closed))
        })
        .await;
    assert!(!device.received_reset(), "a clean close must not end in a reset");
}

/// A device's 256 connections are counted over all the stacks, not per stack.
#[tokio::test]
async fn a_devices_connection_cap_holds_across_stacks() {
    let first = Ipv4Addr::new(10, 0, 1, 1);
    let ends = (0..260).map(|i| SocketAddrV4::new(first, 20_000 + i)).collect();
    let mut device = RawDevice::new(Link::new(forward_quiet(Arc::default()), Some(4)), ends);
    device.open(0..256).await;
    // Every handshake has been counted out.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let refused = device.handshake(&[256, 257, 258, 259]).await;
    assert_eq!(refused.len(), 4, "a device opened more than 256 connections");

    // Another device is not held back by the first one's connections.
    let other = device.add(vec![SocketAddrV4::new(Ipv4Addr::new(10, 0, 1, 2), 20_000)]);
    assert!(device.handshake(&[other]).await.is_empty());

    // Connections that end give their slots back, whichever stack they were on.
    for i in 0..8 {
        device.reset(i);
    }
    tokio::time::timeout(Duration::from_secs(10), device.open(256..260)).await.expect("no slot came back");
}

/// The device the listing dispatchers below know.
const LISTED: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 5]);

/// Knows one device, at [`DEVICE_IP`], and answers its flows with the action.
/// Every other address is no listed device's, and is refused, as the daemon
/// refuses sources it does not know.
struct OneListed(FlowAction);

impl Dispatcher for OneListed {
    fn needs_domain(&self) -> bool {
        false
    }

    fn dispatch(&self, request: &FlowRequest<'_>) -> FlowAction {
        if request.client_ip == IpAddr::V4(DEVICE_IP) { self.0.clone() } else { FlowAction::Reject }
    }

    fn source_key(&self, ip: IpAddr) -> SourceKey {
        if ip == IpAddr::V4(DEVICE_IP) { SourceKey::Device(LISTED) } else { SourceKey::Unlisted }
    }
}

/// A direct outbound whose TCP goes to the test servers on loopback, as
/// [`ToLoopback`]'s does, and whose UDP all goes to one loopback server that
/// answers as [`SERVERS`] port 53: a DNS server, where tests cannot listen.
#[derive(Debug)]
struct DnsOnLoopback {
    direct: Direct,
    server: u16,
}

#[async_trait]
impl Outbound for DnsOnLoopback {
    fn id(&self) -> &EgressId {
        self.direct.id()
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        self.direct.connect_tcp(&to_loopback(target)).await
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        Ok(Box::new(DnsSession { session: self.direct.udp_session().await?, server: self.server }))
    }
}

#[derive(Debug)]
struct DnsSession {
    session: Box<dyn UdpSession>,
    server: u16,
}

#[async_trait]
impl UdpSession for DnsSession {
    async fn send_to(&self, payload: &[u8], _target: &TargetAddr) -> io::Result<()> {
        let server = TargetAddr::Ip(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), self.server));
        self.session.send_to(payload, &server).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let (n, _) = self.session.recv_from(buf).await?;
        Ok((n, TargetAddr::Ip(SocketAddr::from((SERVERS, 53)))))
    }
}

/// Made-up addresses by the thousand cannot crowd out a listed device: they
/// share one small pool, so its connections and name lookups still go
/// through. There are enough of them to fill every cap if each address had a
/// budget of its own: the handshakes the engine takes at once, its UDP table
/// and the lookups' reserve.
#[tokio::test]
async fn made_up_addresses_cannot_crowd_out_a_listed_device() {
    const SYNS: usize = 4200;
    const FLOWS: usize = 4500;
    const LOOKUPS: usize = 600;
    let (echo, dns) = (tcp_echo().await, udp_echo().await);
    let outbound = Arc::new(DnsOnLoopback { direct: Direct::new(EgressId::new("direct"), None), server: dns.port() });
    let action = FlowAction::Forward(Forward { client: Some(LISTED), outbound, down_kbps: None, up_kbps: None });
    // Enough stacks that none of them is a whole queue behind.
    let mut device = Device::over(Link::with(Arc::new(OneListed(action)), Some(8)));
    // A hundred made-up addresses, next to the device's own.
    let made_up = |i: usize| SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 100 + (i % 100) as u8), 30_000 + (i / 100) as u16);

    // SYNs that are never followed up, each answered with a SYN-ACK or, past
    // the pool, a reset.
    let server = SocketAddrV4::new(SERVERS, 443);
    for i in 0..SYNS {
        device.send_raw(raw_tcp(made_up(i), server, TcpControl::Syn, 1000, None, &[]));
    }
    let flood: HashSet<SocketAddrV4> = (0..SYNS).map(made_up).collect();
    let (mut answered, mut accepted, mut seen) = (HashSet::new(), HashSet::new(), 0);
    device
        .run_until(Duration::from_secs(20), |d| {
            for r in d.received[seen..].iter().filter_map(|p| reply(p)) {
                if flood.contains(&r.device) {
                    answered.insert(r.device);
                    if r.syn {
                        accepted.insert(r.device);
                    }
                }
            }
            seen = d.received.len();
            answered.len() == flood.len()
        })
        .await;
    assert!(
        (1..=MAX_UNLISTED_OPENING).contains(&accepted.len()),
        "{} handshakes from made-up addresses at once",
        accepted.len()
    );

    // Datagrams, each one a flow of its own: more than the UDP table holds,
    // then more name lookups than its reserve holds.
    let datagrams = (0..FLOWS).map(|i| (made_up(i), 443)).chain((0..LOOKUPS).map(|i| (made_up(i), 53)));
    for (from, port) in datagrams {
        for packet in packet::udp_datagram(SocketAddr::V4(from), SocketAddr::from((SERVERS, port)), b"x", 1, 1500) {
            device.send_raw(packet);
        }
    }

    // The listed device still connects...
    let socket = device.connect(echo, 40_100);
    echo_round_trip(&mut device, socket, b"still here", Duration::from_secs(10)).await;
    // ...and still looks names up.
    let (me, resolver) = (SocketAddr::from((DEVICE_IP, 5353)), SocketAddr::from((SERVERS, 53)));
    for packet in packet::udp_datagram(me, resolver, b"lookup", 1, 1500) {
        device.send_raw(packet);
    }
    device
        .run_until(Duration::from_secs(5), |d| {
            d.received.iter().any(|p| packet::parse(p) == Packet::Udp { tuple: (resolver, me), payload: b"lookup" })
        })
        .await;
}

/// Lists the device at `device` once `listed` is set. Until then, and every
/// other address always, sources are unlisted.
struct ListedLater {
    action: FlowAction,
    device: IpAddr,
    listed: AtomicBool,
}

impl Dispatcher for ListedLater {
    fn needs_domain(&self) -> bool {
        false
    }

    fn dispatch(&self, _request: &FlowRequest<'_>) -> FlowAction {
        self.action.clone()
    }

    fn source_key(&self, ip: IpAddr) -> SourceKey {
        if ip == self.device && self.listed.load(Ordering::SeqCst) { SourceKey::Device(LISTED) } else { SourceKey::Unlisted }
    }
}

/// A device's first connections, opened before the device list had it, take
/// the pool unlisted addresses share. Once it is listed they move to its own
/// budget, whichever stack holds them, and the pool has room again.
#[tokio::test]
async fn first_connections_move_to_their_device_once_it_is_listed() {
    let first = Ipv4Addr::new(10, 0, 1, 1);
    let dispatcher =
        Arc::new(ListedLater { action: forward_quiet(Arc::default()), device: first.into(), listed: AtomicBool::new(false) });
    let ends = (0..64).map(|i| SocketAddrV4::new(first, 20_000 + i)).collect();
    let mut device = RawDevice::new(Link::with(dispatcher.clone(), Some(4)), ends);
    device.open_all().await;
    // Every handshake has been counted out.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stranger = device.add(vec![SocketAddrV4::new(Ipv4Addr::new(10, 0, 1, 2), 20_000)]);
    assert_eq!(device.handshake(&[stranger]).await, vec![stranger], "the pool had room for another connection");

    dispatcher.listed.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(10), device.open(stranger..stranger + 1)).await.expect("the pool stayed full");
}

const DEVICE_A: MacAddr = MacAddr::new([0x02, 0, 0, 0, 1, 1]);
const DEVICE_B: MacAddr = MacAddr::new([0x02, 0, 0, 0, 1, 2]);
/// Where [`spread`] puts the first two devices' connections.
const ADDRESS_A: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1);
const ADDRESS_B: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);

/// Knows devices by address, each with an action of its own, and names the
/// device whatever the decision, as the daemon does. Open flows of the
/// devices in `refused` may no longer go on. Counts its decisions and the
/// times open flows asked to go on.
struct PerDevice {
    devices: Vec<(IpAddr, MacAddr, FlowAction)>,
    refused: std::sync::Mutex<HashSet<MacAddr>>,
    decided: AtomicUsize,
    asked: AtomicUsize,
}

impl PerDevice {
    fn new(devices: Vec<(IpAddr, MacAddr, FlowAction)>) -> Arc<Self> {
        Arc::new(Self { devices, refused: Default::default(), decided: Default::default(), asked: Default::default() })
    }
}

impl Dispatcher for PerDevice {
    fn needs_domain(&self) -> bool {
        false
    }

    fn dispatch(&self, request: &FlowRequest<'_>) -> FlowAction {
        self.dispatch_device(request).0
    }

    fn dispatch_device(&self, request: &FlowRequest<'_>) -> (FlowAction, Option<MacAddr>) {
        self.decided.fetch_add(1, Ordering::SeqCst);
        match self.devices.iter().find(|(ip, ..)| *ip == request.client_ip) {
            Some((_, device, action)) => (action.clone(), Some(*device)),
            None => (FlowAction::Reject, None),
        }
    }

    fn still_allowed(&self, _request: &FlowRequest<'_>, device: Option<MacAddr>, _outbound: &EgressId) -> bool {
        self.asked.fetch_add(1, Ordering::SeqCst);
        device.is_none_or(|device| !self.refused.lock().unwrap().contains(&device))
    }
}

/// Waits up to five seconds for `done`.
async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Two devices, A and B, with 16 connections open each, through outbounds
/// that count each device's relay tasks apart.
async fn two_devices() -> (RawDevice, Arc<PerDevice>, [Arc<AtomicUsize>; 2]) {
    let open = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let dispatcher = PerDevice::new(vec![
        (ADDRESS_A.into(), DEVICE_A, forward_quiet(open[0].clone())),
        (ADDRESS_B.into(), DEVICE_B, forward_quiet(open[1].clone())),
    ]);
    let mut device = RawDevice::new(Link::with(dispatcher.clone(), Some(4)), spread(2, 32));
    device.open_all().await;
    let count = |i: usize| open[i].load(Ordering::SeqCst);
    wait_for("the relay tasks did not all start", || count(0) == 16 && count(1) == 16).await;
    (device, dispatcher, open)
}

/// Waits for the engine to reset every connection of the device at `ip`,
/// failing if it resets one of the device at `spared`.
async fn resets_of(device: &mut RawDevice, ip: Ipv4Addr, spared: Option<Ipv4Addr>) {
    let ends: HashSet<SocketAddrV4> = device.conns.iter().filter(|c| *c.device.ip() == ip).map(|c| c.device).collect();
    let mut reset = HashSet::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while reset.len() < ends.len() {
            for r in device.replies().await.into_iter().filter(|r| r.rst) {
                assert_ne!(Some(*r.device.ip()), spared, "another device's connection was reset");
                if ends.contains(&r.device) {
                    reset.insert(r.device);
                }
            }
        }
    })
    .await
    .expect("not every connection of the device was reset");
}

/// A change to one device ends only that device's connections, and a reset
/// of every flow still ends them all.
#[tokio::test]
async fn a_device_reset_ends_only_that_devices_connections() {
    let (mut device, _dispatcher, open) = two_devices().await;
    let count = |i: usize| open[i].load(Ordering::SeqCst);
    device.link.control.reset_devices(&[DEVICE_A]);
    resets_of(&mut device, ADDRESS_A, Some(ADDRESS_B)).await;
    wait_for("device A's relay tasks went on", || count(0) == 0).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(count(1), 16, "device B's connections ended");

    device.link.control.reset_all();
    resets_of(&mut device, ADDRESS_B, None).await;
    wait_for("device B's relay tasks went on", || count(1) == 0).await;
}

/// When the rules are checked again, every open connection asks whether it
/// may go on: those of the device no longer allowed end, the others go on.
#[tokio::test]
async fn a_recheck_ends_only_the_connections_no_longer_allowed() {
    let (mut device, dispatcher, open) = two_devices().await;
    let count = |i: usize| open[i].load(Ordering::SeqCst);
    let asked = || dispatcher.asked.load(Ordering::SeqCst);
    device.link.control.recheck_all();
    wait_for("not every connection asked to go on", || asked() == 32).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!((count(0), count(1)), (16, 16), "a connection still allowed ended");

    dispatcher.refused.lock().unwrap().insert(DEVICE_A);
    device.link.control.recheck_all();
    resets_of(&mut device, ADDRESS_A, Some(ADDRESS_B)).await;
    wait_for("device A's relay tasks went on", || count(0) == 0).await;
    wait_for("not every connection asked to go on", || asked() == 64).await;
    assert_eq!(count(1), 16, "device B's connections ended");
    assert_eq!(dispatcher.decided.load(Ordering::SeqCst), 32, "a recheck decided a connection as a new one");
}

/// Sends the device's datagram from `me` to `server`.
fn send_datagram(device: &mut Device, me: SocketAddr, server: SocketAddr) {
    for packet in packet::udp_datagram(me, server, b"question", 1, 1500) {
        device.send_raw(packet);
    }
}

fn refusals(device: &Device) -> usize {
    device.received.iter().filter(|p| is_port_unreachable(p)).count()
}

/// A UDP flow the policy refused refuses the device's later datagrams
/// without asking again, for a while, unless `end` ends it: then the next
/// datagram is decided again, long before the hold would be over. Another
/// device's reset leaves it be.
async fn a_refused_udp_flow_ends_by(end: impl FnOnce(&FlowControl)) {
    let dispatcher = PerDevice::new(vec![(IpAddr::V4(DEVICE_IP), DEVICE_A, FlowAction::Reject)]);
    let mut device = Device::over(Link::with(dispatcher.clone(), None));
    let (me, server) = (SocketAddr::from((DEVICE_IP, 5003)), SocketAddr::from((SERVERS, 9)));
    let decided = || dispatcher.decided.load(Ordering::SeqCst);
    let started = Instant::now();
    send_datagram(&mut device, me, server);
    device.run_until(Duration::from_secs(2), |d| refusals(d) >= 1).await;
    device.link.control.reset_devices(&[DEVICE_B]);
    send_datagram(&mut device, me, server);
    device.run_until(Duration::from_secs(2), |d| refusals(d) >= 2).await;
    assert_eq!(decided(), 1, "the refused flow asked again, or another device's reset ended it");

    end(&device.link.control);
    while decided() < 2 {
        // The flow holds its refusal for 5 s.
        assert!(started.elapsed() < Duration::from_secs(4), "the refused flow went on");
        send_datagram(&mut device, me, server);
        device.run_for(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_refused_udp_flow_ends_when_its_device_is_reset() {
    a_refused_udp_flow_ends_by(|control| control.reset_devices(&[DEVICE_A])).await;
}

#[tokio::test]
async fn a_refused_udp_flow_ends_at_the_first_recheck() {
    a_refused_udp_flow_ends_by(FlowControl::recheck_all).await;
}

/// When one stack's task ends, the whole engine stops, and the relay tasks of
/// every stack's connections end rather than wait on a stack nobody runs.
#[tokio::test]
async fn the_engine_stops_when_a_stack_dies() {
    let open = Arc::new(AtomicUsize::new(0));
    let mut device = RawDevice::new(Link::new(forward_quiet(open.clone()), Some(4)), spread(1, 32));
    device.open_all().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while open.load(Ordering::SeqCst) < 32 {
        assert!(Instant::now() < deadline, "the relay tasks did not all start");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    device.link.stacks[0].abort();
    let deadline = Instant::now() + Duration::from_secs(5);
    while device.link.engine.is_running() || open.load(Ordering::SeqCst) > 0 {
        assert!(Instant::now() < deadline, "the engine or a relay task kept running");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Time per packet with `connections` connections open, over `stacks` TCP
/// stacks or as many as [`run`] gives. Each connection takes pairs of
/// 300-byte segments in turn, 256 pairs in flight; the time is until the
/// last is acknowledged, so it covers the whole path.
async fn time_per_packet(connections: usize, stacks: Option<usize>) {
    const PAIRS: usize = 10_000;
    let devices = connections.div_ceil(250);
    let link = Link::new(forward_quiet(Arc::default()), stacks);
    let mut device = RawDevice::new(link, spread(devices, connections));
    let opening = std::time::Instant::now();
    device.open_all().await;
    let opened = opening.elapsed();
    let payload = [7u8; 300];
    // A first pair on every connection, so each relay task has started.
    device.exchange(&payload, connections, 256).await;
    let started = std::time::Instant::now();
    device.exchange(&payload, PAIRS, 256).await;
    let elapsed = started.elapsed();
    let packets = 2 * PAIRS;
    let stacks = stacks.map_or("the usual".to_owned(), |n| n.to_string());
    println!(
        "{connections} connections from {devices} devices over {stacks} stacks (opened in {} ms): \
         {packets} packets in {} ms, {:.1} us per packet",
        opened.as_millis(),
        elapsed.as_millis(),
        elapsed.as_secs_f64() * 1e6 / packets as f64
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a benchmark: cargo test -p captun-engine -- --ignored --nocapture time_per_packet"]
async fn time_per_packet_1000_connections() {
    time_per_packet(1000, None).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a benchmark: cargo test -p captun-engine -- --ignored --nocapture time_per_packet"]
async fn time_per_packet_4000_connections() {
    time_per_packet(4000, None).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a benchmark: cargo test -p captun-engine -- --ignored --nocapture time_per_packet"]
async fn time_per_packet_4000_connections_one_stack() {
    time_per_packet(4000, Some(1)).await;
}
