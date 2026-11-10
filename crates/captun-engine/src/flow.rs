//! Per-flow handling, kept generic over the client stream so the whole
//! decision-and-relay path is testable without a packet device.

use std::{
    io,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use captun_core::{TargetAddr, config::Protocol};
use captun_outbound::{Outbound, PrefixedStream, UdpSession};
use captun_sniff::{MAX_SNIFF_BYTES, Sniff, sniff};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    time::timeout,
};
use tracing::{debug, info};

use crate::{
    control::FlowWatch,
    dispatch::{Dispatcher, FlowAction, FlowRequest, Forward},
    meter::{Direction, FlowMeter, SharedBucket, TrafficMeter},
    relay::{relay_stream, within_limit},
    udp::DNS_PORT,
};

/// How long we wait to sniff a destination name before giving up and dialing
/// anyway. Short, because a client that is going to speak first already has.
const SNIFF_TIMEOUT: Duration = Duration::from_millis(500);
/// A device's datagrams come from single packets (fragments are dropped), so
/// they fit a few kilobytes.
const UDP_UP_BUF: usize = 4096;
/// Answers are read into a buffer for the usual ones first: a full-size
/// packet's payload, and DNS answers up to 4 KiB, EDNS's usual largest.
/// Only a flow that receives a larger one moves to a buffer for the largest
/// a UDP payload can be, while the engine's [`MAX_BIG_ANSWERS`] last, so
/// 4608 flows do not hold 64 KiB each. Each buffer is one byte longer than
/// the answers it is for, so an answer that fills it was cut short.
const USUAL_ANSWER: usize = 4096;
const LARGEST_ANSWER: usize = 65_535;
/// Flows reading their answers into a big buffer at most: 16 MiB.
const MAX_BIG_ANSWERS: usize = 256;
/// A name lookup gets one answer on its own source port, so growing after an
/// answer cut short would come too late: it starts with a big buffer, while
/// no more than this many are taken. The rest stay for flows that grow.
/// Lookups end after 5 s quiet, so they give theirs back soon.
const MAX_BIG_LOOKUPS: usize = MAX_BIG_ANSWERS / 2;
/// How long a refused UDP flow, or one whose outbound could not carry it,
/// keeps refusing the device's datagrams before the policy or the outbound is
/// asked again. A device that keeps sending cannot hold the flow's slot past it.
const FAILED_UDP_HOLD: Duration = Duration::from_secs(5);

/// What the engine's UDP relays share: the counts of datagrams they dropped,
/// and the big buffers some of them read answers into.
#[derive(Debug, Default)]
pub(crate) struct UdpRelays {
    /// Datagrams dropped over a device's speed limit, since the last report.
    pub(crate) over_limit: AtomicU64,
    /// Answers dropped as too big for their flow's buffer, since the last
    /// report.
    pub(crate) too_big: AtomicU64,
    /// Relays reading into a big buffer.
    big_answers: AtomicUsize,
}

impl UdpRelays {
    /// Takes one of the big answer buffers, if fewer than `up_to` are taken.
    fn take_big(&self, up_to: usize) -> bool {
        let mut taken = self.big_answers.load(Ordering::Relaxed);
        while taken < up_to {
            match self.big_answers.compare_exchange_weak(taken, taken + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(now) => taken = now,
            }
        }
        false
    }
}

/// How a refused flow ends for the device that opened it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Say nothing: the device's packets go unanswered, as if lost.
    Silent,
    /// Answer with a TCP reset or an ICMP "port unreachable", so apps give up
    /// at once.
    Reset,
}

/// The device's side of a flow: a byte stream for TCP, one datagram per read
/// and write for UDP.
pub(crate) trait ClientSide: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Ends the flow the way the policy refused it. Streams that cannot do
    /// better just close when dropped.
    fn refuse(&mut self, _how: Refusal) {}

    /// Whether how the flow ends is worth describing in the log.
    fn described(&self) -> bool {
        false
    }
}

/// Flow ends the relay has described so far.
static DESCRIBED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Proxy connections: refusing one closes it.
impl ClientSide for tokio::net::TcpStream {}

#[cfg(test)]
impl ClientSide for tokio::io::DuplexStream {}

fn refusal(action: &FlowAction) -> Refusal {
    match action {
        FlowAction::Reject => Refusal::Reset,
        _ => Refusal::Silent,
    }
}

/// An outbound that could not be reached, kept apart from the ordinary ends
/// of flows (resets, closed apps) because it means the outbound is failing.
#[derive(Debug)]
pub(crate) struct DialError {
    egress: String,
    source: io::Error,
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "could not connect through \"{}\": {}", self.egress, self.source)
    }
}

impl std::error::Error for DialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn dial_error(outbound: &dyn Outbound, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), DialError { egress: outbound.id().to_string(), source })
}

/// Whether a flow ended because its outbound could not be reached.
pub(crate) fn is_dial_error(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<DialError>())
}

/// Handles one accepted TCP flow end to end. `watch`, taken when the flow
/// started, ends it early on a reset or a recheck that no longer allows it.
pub(crate) async fn serve_tcp<C: ClientSide>(
    mut client: C,
    client_ip: IpAddr,
    destination: TargetAddr,
    dispatcher: Arc<dyn Dispatcher>,
    meter: Arc<TrafficMeter>,
    mut watch: FlowWatch,
) -> io::Result<()> {
    // Learn the destination name first, but only when a rule could use it.
    let (prefix, domain) =
        if dispatcher.needs_domain() { watch.until_reset(peek_domain(&mut client)).await? } else { (Vec::new(), None) };

    let request = FlowRequest {
        client_ip,
        protocol: Protocol::Tcp,
        destination: &destination,
        domain: domain.as_deref(),
    };
    let (action, device) = dispatcher.dispatch_device(&request);
    // Whatever the decision, a reset of the device ends the flow from now on.
    // One while the flow was being decided may have come after the decision:
    // the flow ends, unrefused, and the device's next try is decided again.
    watch.set_device(device)?;
    let Forward { client: mac, outbound, down_kbps, up_kbps } = match action {
        FlowAction::Forward(forward) => forward,
        refused => {
            debug!(%client_ip, %destination, domain = domain.as_deref(), "tcp flow refused by policy ({refused:?})");
            client.refuse(refusal(&refused));
            return Ok(());
        }
    };
    let allowed = || dispatcher.still_allowed(&request, device, outbound.id());

    let started = std::time::Instant::now();
    let described = client.described();
    let dial = async { outbound.connect_tcp(&destination).await.map_err(|e| dial_error(outbound.as_ref(), e)) };
    let upstream = watch.guard(dial, &allowed).await?;
    let dialed = started.elapsed();
    let flow = FlowMeter::new(meter.counters(mac));
    let (down, up) = (meter.bucket(mac, Direction::Down, down_kbps), meter.bucket(mac, Direction::Up, up_kbps));
    let relay = relay_stream(PrefixedStream::new(prefix, client), upstream, down, up, flow);
    let result = watch.guard(relay, &allowed).await;
    if described && DESCRIBED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 100 {
        let how = match &result {
            Ok(()) => "both sides closed".to_owned(),
            Err(e) => e.to_string(),
        };
        info!(
            %client_ip,
            %destination,
            dial_ms = dialed.as_millis(),
            "tcp flow through \"{}\" ended after {} ms: {how}",
            outbound.id(),
            started.elapsed().as_millis()
        );
    }
    result
}

/// Reads the opening bytes of a client stream far enough to recognise a TLS
/// ClientHello or HTTP request, and returns those bytes, to be replayed, with
/// the name found. On timeout or a non-matching protocol, the name is `None`.
async fn peek_domain<C>(client: &mut C) -> (Vec<u8>, Option<String>)
where
    C: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let domain = timeout(SNIFF_TIMEOUT, async {
        loop {
            match sniff(&buf) {
                Sniff::Found(detected) => return detected.host().map(str::to_owned),
                Sniff::NoMatch => return None,
                Sniff::NeedMore if buf.len() >= MAX_SNIFF_BYTES => return None,
                Sniff::NeedMore => {}
            }
            match client.read(&mut chunk).await {
                Ok(0) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                // A read error here surfaces when we try to relay; sniff with
                // what we have.
                Err(_) => return None,
            }
        }
    })
    .await
    .unwrap_or(None);

    (buf, domain)
}

/// Handles one accepted UDP flow (a single client/destination pair). The
/// stream yields and accepts one datagram at a time. `watch` as for
/// [`serve_tcp`]; `relays` is what the engine's UDP relays share.
pub(crate) async fn serve_udp<C: ClientSide>(
    mut client: C,
    client_ip: IpAddr,
    destination: TargetAddr,
    dispatcher: Arc<dyn Dispatcher>,
    meter: Arc<TrafficMeter>,
    mut watch: FlowWatch,
    relays: Arc<UdpRelays>,
) -> io::Result<()> {
    let request = FlowRequest { client_ip, protocol: Protocol::Udp, destination: &destination, domain: None };
    let (action, device) = dispatcher.dispatch_device(&request);
    // As for TCP: the device's next datagram is decided again.
    watch.set_device(device)?;
    let Forward { client: mac, outbound, down_kbps, up_kbps } = match action {
        FlowAction::Forward(forward) => forward,
        refused => {
            debug!(%client_ip, %destination, "udp flow refused by policy ({refused:?})");
            client.refuse(refusal(&refused));
            // For a while the flow refuses its later datagrams the same way,
            // without asking the policy for each one. Then it ends and gives
            // its slot back, even if the device keeps sending. A reset of its
            // device or a recheck of the rules ends it at once, so its next
            // datagram is decided again.
            let held = watch.until_recheck(timeout(FAILED_UDP_HOLD, until_quiet(&mut client))).await;
            return held.and_then(Result::ok).unwrap_or(Ok(()));
        }
    };
    let allowed = || dispatcher.still_allowed(&request, device, outbound.id());

    // A flow has one destination: the outbound opens only what reaching it takes.
    let session = match watch.guard(async { Ok(outbound.udp_session_to(&destination).await) }, &allowed).await? {
        Ok(session) => session,
        Err(e) => {
            // Say no at once (ICMP "port unreachable") instead of leaving the
            // device waiting: browsers then fall back from QUIC to TCP. For a
            // while the flow refuses its later datagrams the same way, rather
            // than trying the outbound again for each one; a reset or a
            // recheck ends that at once, as for a refused flow.
            client.refuse(Refusal::Reset);
            let _ = watch.until_recheck(timeout(FAILED_UDP_HOLD, until_quiet(&mut client))).await;
            // An outbound that carries only TCP is not failing; it says so
            // once in the log itself.
            if e.kind() == io::ErrorKind::Unsupported {
                debug!(%client_ip, %destination, "udp flow refused: {e}");
                return Ok(());
            }
            return Err(dial_error(outbound.as_ref(), e));
        }
    };
    let flow = FlowMeter::new(meter.counters(mac));
    let (down, up) = (meter.bucket(mac, Direction::Down, down_kbps), meter.bucket(mac, Direction::Up, up_kbps));
    let limits = Limits { down, up, relays: &relays };
    watch.guard(relay_datagrams(client, session, &destination, limits, flow), &allowed).await
}

/// Reads a refused flow until it goes quiet; its datagrams are refused as
/// they come.
async fn until_quiet<C: AsyncRead + Unpin>(client: &mut C) -> io::Result<()> {
    let mut sink = [0u8; 1];
    while client.read(&mut sink).await? > 0 {}
    Ok(())
}

/// A UDP flow's speed limits, and what the engine's relays share.
struct Limits<'a> {
    down: Option<SharedBucket>,
    up: Option<SharedBucket>,
    relays: &'a UdpRelays,
}

impl Limits<'_> {
    /// Whether a datagram of `bytes` may go `direction` now. One over the
    /// device's limit is dropped and counted, never held back: a queue of
    /// them would only grow, and the apps that send them slow down when
    /// they see datagrams lost.
    fn allow(&self, direction: Direction, bytes: usize) -> bool {
        let bucket = match direction {
            Direction::Down => self.down.as_ref(),
            Direction::Up => self.up.as_ref(),
        };
        let allowed = within_limit(bucket, bytes);
        if !allowed {
            self.relays.over_limit.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }
}

async fn relay_datagrams<C>(
    client: C,
    session: Box<dyn UdpSession>,
    destination: &TargetAddr,
    limits: Limits<'_>,
    meter: FlowMeter,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncWriteExt;

    let (mut client_r, mut client_w) = tokio::io::split(client);
    // Shared by reference across both directions (references are Copy, so each
    // `async move` block captures its own copy of the borrow).
    let session = &*session;
    let meter = &meter;
    let limits = &limits;

    // Upload: each datagram the client sends goes to the one destination.
    let up = async move {
        let mut buf = vec![0u8; UDP_UP_BUF];
        loop {
            let n = client_r.read(&mut buf).await?;
            if n == 0 {
                return io::Result::Ok(());
            }
            if !limits.allow(Direction::Up, n) {
                continue;
            }
            session.send_to(&buf[..n], destination).await?;
            meter.add(Direction::Up, n as u64);
        }
    };

    // Download: datagrams coming back from the destination go to the client;
    // anything else that finds the socket is dropped, not passed off as the
    // destination's answer.
    let down = async move {
        let mut answers = Answers::new(limits.relays, destination);
        loop {
            let Some((answer, from)) = answers.recv(session).await? else { continue };
            if !answers_for(destination, &from) || !limits.allow(Direction::Down, answer.len()) {
                continue;
            }
            client_w.write_all(answer).await?;
            meter.add(Direction::Down, answer.len() as u64);
        }
    };

    // Either direction ending (the flow going quiet on the device side, or the
    // session closing) tears the flow down.
    tokio::select! {
        result = up => result,
        result = down => result,
    }
}

/// Where a UDP flow's answers are read: a buffer for the usual ones, and
/// for the largest once one did not fit, or from the start for a name
/// lookup, while the engine has big buffers left. Answers are read while the
/// flow waits for them, so the buffer is held for the flow's whole life.
struct Answers<'a> {
    buf: Vec<u8>,
    relays: &'a UdpRelays,
    big: bool,
}

impl<'a> Answers<'a> {
    /// The buffer of a flow to `destination`.
    fn new(relays: &'a UdpRelays, destination: &TargetAddr) -> Self {
        let big = destination.port() == DNS_PORT && relays.take_big(MAX_BIG_LOOKUPS);
        Self { buf: vec![0; if big { LARGEST_ANSWER } else { USUAL_ANSWER } + 1], relays, big }
    }

    /// The next answer and who sent it, or `None` for one that did not fit
    /// the buffer: it is dropped, as if lost, counted, and the buffer grows
    /// for the next. On Windows a socket says so with an error; elsewhere,
    /// and through a SOCKS5 proxy, the answer comes cut short.
    async fn recv(&mut self, session: &dyn UdpSession) -> io::Result<Option<(&[u8], TargetAddr)>> {
        match session.recv_from(&mut self.buf).await {
            Ok((n, from)) if n < self.buf.len() => Ok(Some((&self.buf[..n], from))),
            Ok(_) => {
                self.grow();
                Ok(None)
            }
            Err(e) if cut_short(&e) => {
                self.grow();
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Counts an answer that did not fit, and moves to a buffer for the
    /// largest answers, if the engine has one left.
    fn grow(&mut self) {
        self.relays.too_big.fetch_add(1, Ordering::Relaxed);
        if !self.big && self.relays.take_big(MAX_BIG_ANSWERS) {
            self.buf = vec![0; LARGEST_ANSWER + 1];
            self.big = true;
        }
    }
}

impl Drop for Answers<'_> {
    fn drop(&mut self) {
        if self.big {
            self.relays.big_answers.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Whether a read failed only because the datagram did not fit the buffer
/// (Windows' WSAEMSGSIZE); the rest of it is lost.
fn cut_short(error: &io::Error) -> bool {
    cfg!(windows) && error.raw_os_error() == Some(10040)
}

/// Whether a datagram from `from` can be the answer of the flow to
/// `destination`. A dual-stack socket reports IPv4 senders as mapped IPv6.
fn answers_for(destination: &TargetAddr, from: &TargetAddr) -> bool {
    match (destination, from) {
        (TargetAddr::Ip(to), TargetAddr::Ip(from)) => to.port() == from.port() && to.ip().to_canonical() == from.ip().to_canonical(),
        // A name was dialed: the proxy resolved it, so any address may answer.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::Mutex,
    };

    use captun_core::EgressId;
    use captun_outbound::Direct;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        net::{TcpListener, UdpSocket},
    };

    use super::*;
    use crate::{
        control::FlowControl,
        dispatch::{FlowAction, SourceKey},
    };

    /// The watch of a flow nothing resets or checks again: its control is gone.
    fn watch() -> FlowWatch {
        FlowControl::new().watch()
    }

    /// Records the domain it was asked about and answers with a fixed action.
    struct MockDispatcher {
        needs_domain: bool,
        action: Box<dyn Fn() -> FlowAction + Send + Sync>,
        seen_domain: Mutex<Option<Option<String>>>,
    }

    impl Dispatcher for MockDispatcher {
        fn needs_domain(&self) -> bool {
            self.needs_domain
        }

        fn dispatch(&self, request: &FlowRequest<'_>) -> FlowAction {
            *self.seen_domain.lock().unwrap() = Some(request.domain.map(str::to_owned));
            (self.action)()
        }
    }

    fn direct() -> Arc<dyn Outbound> {
        Arc::new(Direct::new(EgressId::new("direct"), None))
    }

    async fn tcp_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn tcp_forward_relays_and_meters() {
        let echo = TargetAddr::Ip(tcp_echo().await);
        let meter = Arc::new(TrafficMeter::new());
        let client_mac = "02:00:00:00:00:07".parse().unwrap();
        let dispatcher = Arc::new(MockDispatcher {
            needs_domain: false,
            action: {
                let out = direct();
                Box::new(move || {
                    FlowAction::Forward(Forward {
                        client: Some(client_mac),
                        outbound: out.clone(),
                        down_kbps: None,
                        up_kbps: None,
                    })
                })
            },
            seen_domain: Mutex::new(None),
        });

        let (client_outer, client_inner) = duplex(4096);
        let served = tokio::spawn(serve_tcp(
            client_inner,
            "10.0.0.5".parse().unwrap(),
            echo,
            dispatcher,
            meter.clone(),
            watch(),
        ));

        let (mut r, mut w) = tokio::io::split(client_outer);
        w.write_all(b"round trip").await.unwrap();
        w.shutdown().await.unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"round trip");
        served.await.unwrap().unwrap();

        let snap = meter.snapshot(&client_mac).unwrap();
        assert_eq!((snap.up_bytes, snap.down_bytes), (10, 10));
    }

    #[tokio::test]
    async fn tcp_drop_never_dials() {
        let meter = Arc::new(TrafficMeter::new());
        let dispatcher = Arc::new(MockDispatcher {
            needs_domain: false,
            action: Box::new(|| FlowAction::Drop),
            seen_domain: Mutex::new(None),
        });
        let (client_outer, client_inner) = duplex(4096);
        // Unroutable destination: if the handler tried to dial it, the test
        // would hang or error instead of returning Ok promptly.
        let dst = TargetAddr::Ip("203.0.113.1:9".parse().unwrap());
        serve_tcp(client_inner, "10.0.0.5".parse().unwrap(), dst, dispatcher, meter, watch()).await.unwrap();
        drop(client_outer);
    }

    #[tokio::test]
    async fn tcp_sniffs_sni_before_dispatch() {
        let echo = TargetAddr::Ip(tcp_echo().await);
        let meter = Arc::new(TrafficMeter::new());
        let dispatcher = Arc::new(MockDispatcher {
            needs_domain: true,
            action: {
                let out = direct();
                Box::new(move || {
                    FlowAction::Forward(Forward { client: None, outbound: out.clone(), down_kbps: None, up_kbps: None })
                })
            },
            seen_domain: Mutex::new(None),
        });

        let (client_outer, client_inner) = duplex(8192);
        let served = tokio::spawn(serve_tcp(
            client_inner,
            "10.0.0.5".parse().unwrap(),
            echo,
            dispatcher.clone(),
            meter,
            watch(),
        ));

        // A real ClientHello carrying SNI, built by the sniff crate's helper.
        let hello = captun_sniff::test_support::client_hello_record(Some("chat.example.com"), &["h2"]);
        let (mut r, mut w) = tokio::io::split(client_outer);
        w.write_all(&hello).await.unwrap();
        // The echo server returns our ClientHello bytes; the prefix must be replayed.
        let mut got = vec![0u8; hello.len()];
        r.read_exact(&mut got).await.unwrap();
        assert_eq!(got, hello);
        w.shutdown().await.unwrap();
        served.await.unwrap().unwrap();

        let seen = dispatcher.seen_domain.lock().unwrap().clone();
        assert_eq!(seen, Some(Some("chat.example.com".to_owned())));
    }

    /// An outbound that carries only TCP, like a SOCKS5 proxy with UDP off.
    #[derive(Debug)]
    struct TcpOnly(EgressId, std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl Outbound for TcpOnly {
        fn id(&self) -> &EgressId {
            &self.0
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<captun_outbound::BoxStream> {
            Err(io::Error::other("not used here"))
        }

        async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(io::Error::new(io::ErrorKind::Unsupported, "no UDP here"))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn udp_the_outbound_cannot_carry_is_refused_out_loud() {
        use std::sync::atomic::Ordering;
        let (replies, mut out) = tokio::sync::mpsc::channel(8);
        let mut table = crate::udp::UdpTable::new(replies, 1500);
        let tuple: crate::packet::Tuple = ("10.0.0.5:5000".parse().unwrap(), "142.250.1.1:443".parse().unwrap());
        let key = || SourceKey::Address(tuple.0.ip());
        let conn = table.receive(tuple, b"quic initial", key).unwrap();
        let outbound = Arc::new(TcpOnly(EgressId::new("socks"), Default::default()));
        let dispatcher = Arc::new(MockDispatcher {
            needs_domain: false,
            action: {
                let out: Arc<dyn Outbound> = outbound.clone();
                Box::new(move || {
                    FlowAction::Forward(Forward { client: None, outbound: out.clone(), down_kbps: None, up_kbps: None })
                })
            },
            seen_domain: Mutex::new(None),
        });
        let served = tokio::spawn(serve_udp(
            conn,
            "10.0.0.5".parse().unwrap(),
            TargetAddr::Ip(tuple.1),
            dispatcher,
            Arc::new(TrafficMeter::new()),
            watch(),
            Arc::default(),
        ));

        // The device hears "port unreachable" at once, so QUIC gives way to TCP.
        assert_eq!(out.recv().await.unwrap()[9], 1, "an ICMP packet");
        // Its retransmissions are refused the same way, without the outbound.
        assert!(table.receive(tuple, b"retransmission", key).is_none());
        assert_eq!(out.recv().await.unwrap()[9], 1);
        assert_eq!(outbound.1.load(Ordering::SeqCst), 1);

        // A while later the flow ends, not counted as a failing outbound, and
        // the next datagram tries the outbound again.
        served.await.unwrap().unwrap();
        assert!(table.receive(tuple, b"later", key).is_some());
    }

    /// A flow the policy refuses gives its slot back within seconds, though
    /// the device keeps sending more often than the flow's idle time, and it
    /// refuses every datagram out loud while it lasts.
    #[tokio::test(start_paused = true)]
    async fn udp_refused_by_policy_gives_its_slot_back_while_the_device_keeps_sending() {
        let (replies, mut out) = tokio::sync::mpsc::channel(64);
        let mut table = crate::udp::UdpTable::new(replies, 1500);
        let tuple: crate::packet::Tuple = ("10.0.0.5:5000".parse().unwrap(), "142.250.1.1:443".parse().unwrap());
        let key = || SourceKey::Address(tuple.0.ip());
        let conn = table.receive(tuple, b"first", key).unwrap();
        let dispatcher =
            Arc::new(MockDispatcher { needs_domain: false, action: Box::new(|| FlowAction::Reject), seen_domain: Mutex::new(None) });
        let served = tokio::spawn(serve_udp(
            conn,
            tuple.0.ip(),
            TargetAddr::Ip(tuple.1),
            dispatcher,
            Arc::new(TrafficMeter::new()),
            watch(),
            Arc::default(),
        ));

        let started = tokio::time::Instant::now();
        let mut sent = 1;
        while !served.is_finished() {
            assert!(started.elapsed() <= FAILED_UDP_HOLD + Duration::from_secs(1), "the refused flow kept its slot");
            assert!(table.receive(tuple, b"again", key).is_none(), "a second flow for the same datagrams");
            sent += 1;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        served.await.unwrap().unwrap();
        let mut refusals = 0;
        while let Ok(packet) = out.try_recv() {
            assert_eq!(packet[9], 1, "an ICMP packet");
            refusals += 1;
        }
        // The last datagram may have come after the flow ended.
        assert!(refusals >= sent - 1, "{refusals} of {sent} datagrams refused out loud");

        // The slot is free: the next datagram opens a flow, and asks the
        // policy again.
        assert!(table.receive(tuple, b"later", key).is_some());
    }

    #[tokio::test]
    async fn udp_forward_relays_datagrams() {
        // A local UDP echo plays the destination.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = TargetAddr::Ip(server.local_addr().unwrap());
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = server.recv_from(&mut buf).await {
                let _ = server.send_to(&buf[..n], from).await;
            }
        });

        let meter = Arc::new(TrafficMeter::new());
        let mac = "02:00:00:00:00:09".parse().unwrap();
        let dispatcher = Arc::new(MockDispatcher {
            needs_domain: false,
            action: {
                let out = direct();
                Box::new(move || {
                    FlowAction::Forward(Forward {
                        client: Some(mac),
                        outbound: out.clone(),
                        down_kbps: None,
                        up_kbps: None,
                    })
                })
            },
            seen_domain: Mutex::new(None),
        });

        let (client_outer, client_inner) = duplex(65_535);
        let served = tokio::spawn(serve_udp(
            client_inner,
            "10.0.0.5".parse().unwrap(),
            dst,
            dispatcher,
            meter.clone(),
            watch(),
            Arc::default(),
        ));

        let (mut r, mut w) = tokio::io::split(client_outer);
        w.write_all(b"datagram").await.unwrap();
        let mut got = [0u8; 8];
        r.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"datagram");

        drop(w);
        drop(r);
        let _ = served.await;
        let snap = meter.snapshot(&mac).unwrap();
        assert_eq!(snap.up_bytes, 8);
        assert!(snap.down_bytes >= 8);
    }

    /// The device every flow of [`Checked`] belongs to.
    const DEVICE: captun_core::MacAddr = captun_core::MacAddr::new([0x02, 0, 0, 0, 0, 0x0c]);

    /// What an open flow said of itself when it asked to go on.
    type Asked = (IpAddr, TargetAddr, Option<captun_core::MacAddr>, EgressId);

    /// Answers every flow with `action` and names [`DEVICE`] whatever the
    /// decision; lets open flows go on while `allowed` holds, and records
    /// what it was asked.
    struct Checked {
        needs_domain: bool,
        action: FlowAction,
        allowed: std::sync::atomic::AtomicBool,
        asked: Mutex<Vec<Asked>>,
    }

    impl Checked {
        fn new(action: FlowAction) -> Arc<Self> {
            Self::sniffing(false, action)
        }

        fn sniffing(needs_domain: bool, action: FlowAction) -> Arc<Self> {
            Arc::new(Self { needs_domain, action, allowed: true.into(), asked: Mutex::default() })
        }
    }

    impl Dispatcher for Checked {
        fn needs_domain(&self) -> bool {
            self.needs_domain
        }

        fn dispatch(&self, _request: &FlowRequest<'_>) -> FlowAction {
            self.action.clone()
        }

        fn dispatch_device(&self, request: &FlowRequest<'_>) -> (FlowAction, Option<captun_core::MacAddr>) {
            (self.dispatch(request), Some(DEVICE))
        }

        fn still_allowed(
            &self,
            request: &FlowRequest<'_>,
            device: Option<captun_core::MacAddr>,
            outbound: &EgressId,
        ) -> bool {
            self.asked.lock().unwrap().push((request.client_ip, request.destination.clone(), device, outbound.clone()));
            self.allowed.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn forward(outbound: Arc<dyn Outbound>) -> FlowAction {
        FlowAction::Forward(Forward { client: Some(DEVICE), outbound, down_kbps: None, up_kbps: None })
    }

    /// At a recheck an open flow asks whether it may go on, naming itself,
    /// its device and its outbound; it goes on while the answer is yes and
    /// ends when it is no.
    #[tokio::test]
    async fn a_recheck_ends_a_flow_only_when_it_is_no_longer_allowed() {
        let echo = TargetAddr::Ip(tcp_echo().await);
        let control = FlowControl::new();
        let dispatcher = Checked::new(forward(direct()));
        let (client_outer, client_inner) = duplex(4096);
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let served = tokio::spawn(serve_tcp(
            client_inner,
            ip,
            echo.clone(),
            dispatcher.clone(),
            Arc::new(TrafficMeter::new()),
            control.watch(),
        ));
        let (mut r, mut w) = tokio::io::split(client_outer);
        let mut got = [0u8; 5];
        w.write_all(b"first").await.unwrap();
        r.read_exact(&mut got).await.unwrap();

        control.recheck_all();
        w.write_all(b"again").await.unwrap();
        r.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"again", "the flow went on");
        assert_eq!(*dispatcher.asked.lock().unwrap(), vec![(ip, echo, Some(DEVICE), EgressId::new("direct"))]);

        dispatcher.allowed.store(false, std::sync::atomic::Ordering::SeqCst);
        control.recheck_all();
        let ended = tokio::time::timeout(Duration::from_secs(1), served).await.expect("the flow went on").unwrap();
        assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(r.read(&mut got).await.unwrap(), 0, "the device's side was closed");
    }

    /// A reset of the device while the flow's name was still being sniffed,
    /// before the flow knew its device, ends it once the device is known,
    /// and it is never dialed.
    #[tokio::test(start_paused = true)]
    async fn a_flow_whose_device_is_learned_after_its_reset_still_ends() {
        let control = FlowControl::new();
        let outbound = Arc::new(TcpOnly(EgressId::new("socks"), Default::default()));
        let dispatcher = Checked::sniffing(true, forward(outbound));
        let (_client_outer, client_inner) = duplex(4096);
        let served = tokio::spawn(serve_tcp(
            client_inner,
            "10.0.0.5".parse().unwrap(),
            TargetAddr::Ip("203.0.113.1:443".parse().unwrap()),
            dispatcher,
            Arc::new(TrafficMeter::new()),
            control.watch(),
        ));
        // The device says nothing yet: the flow waits to sniff its name.
        tokio::time::sleep(SNIFF_TIMEOUT / 5).await;
        assert!(!served.is_finished());
        control.reset_devices(&[DEVICE]);

        let ended = served.await.unwrap().unwrap_err();
        assert_eq!(ended.kind(), io::ErrorKind::ConnectionAborted);
        assert!(!is_dial_error(&ended), "the flow was dialed");
    }

    /// A UDP flow the policy refused ends when its device is reset, well
    /// before its hold is over, so its next datagram is decided again.
    #[tokio::test(start_paused = true)]
    async fn a_refused_udp_flow_ends_when_its_device_is_reset() {
        let (replies, _out) = tokio::sync::mpsc::channel(64);
        let mut table = crate::udp::UdpTable::new(replies, 1500);
        let tuple: crate::packet::Tuple = ("10.0.0.5:5000".parse().unwrap(), "142.250.1.1:443".parse().unwrap());
        let key = || SourceKey::Address(tuple.0.ip());
        let conn = table.receive(tuple, b"first", key).unwrap();
        let control = FlowControl::new();
        let served = tokio::spawn(serve_udp(
            conn,
            tuple.0.ip(),
            TargetAddr::Ip(tuple.1),
            Checked::new(FlowAction::Reject),
            Arc::new(TrafficMeter::new()),
            control.watch(),
            Arc::default(),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!served.is_finished(), "the refusal was not held");
        // Another device's reset leaves it be.
        control.reset_devices(&[captun_core::MacAddr::new([0x02, 0, 0, 0, 0, 0x0d])]);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!served.is_finished(), "another device's reset ended it");

        let started = tokio::time::Instant::now();
        control.reset_devices(&[DEVICE]);
        served.await.unwrap().unwrap();
        assert!(started.elapsed() < FAILED_UDP_HOLD / 10);
        assert!(table.receive(tuple, b"later", key).is_some(), "the next datagram opens a flow");
    }

    /// The same at a recheck of the rules: a refused flow, and one whose
    /// outbound could not carry it, end at once.
    #[tokio::test(start_paused = true)]
    async fn refused_udp_flows_end_at_the_first_recheck() {
        let outbound: Arc<dyn Outbound> = Arc::new(TcpOnly(EgressId::new("socks"), Default::default()));
        for action in [FlowAction::Reject, FlowAction::Drop, forward(outbound)] {
            let (replies, _out) = tokio::sync::mpsc::channel(64);
            let mut table = crate::udp::UdpTable::new(replies, 1500);
            let tuple: crate::packet::Tuple = ("10.0.0.5:5000".parse().unwrap(), "142.250.1.1:443".parse().unwrap());
            let conn = table.receive(tuple, b"first", || SourceKey::Address(tuple.0.ip())).unwrap();
            let control = FlowControl::new();
            let dispatcher = Checked::new(action.clone());
            let served = tokio::spawn(serve_udp(
                conn,
                tuple.0.ip(),
                TargetAddr::Ip(tuple.1),
                dispatcher.clone(),
                Arc::new(TrafficMeter::new()),
                control.watch(),
                Arc::default(),
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!served.is_finished(), "{action:?}: the refusal was not held");

            let started = tokio::time::Instant::now();
            control.recheck_all();
            let _ = served.await.unwrap();
            assert!(started.elapsed() < FAILED_UDP_HOLD / 10, "{action:?}: the hold went on");
            assert!(dispatcher.asked.lock().unwrap().is_empty(), "{action:?}: a refused flow was asked to go on");
        }
    }

    /// A UDP session whose answers the test feeds, cut short to the buffer
    /// as a socket on Linux or a SOCKS5 proxy cuts them, and which records
    /// the length of what it sends.
    #[derive(Debug)]
    struct Fed {
        answers: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
        from: TargetAddr,
        sent: Arc<Mutex<Vec<usize>>>,
    }

    type Feed = tokio::sync::mpsc::UnboundedSender<Vec<u8>>;

    impl Fed {
        fn new(from: TargetAddr) -> (Self, Feed, Arc<Mutex<Vec<usize>>>) {
            let (feed, answers) = tokio::sync::mpsc::unbounded_channel();
            let sent = Arc::new(Mutex::new(Vec::new()));
            (Self { answers: answers.into(), from, sent: sent.clone() }, feed, sent)
        }
    }

    #[async_trait::async_trait]
    impl UdpSession for Fed {
        async fn send_to(&self, payload: &[u8], _target: &TargetAddr) -> io::Result<()> {
            self.sent.lock().unwrap().push(payload.len());
            Ok(())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
            let Some(answer) = self.answers.lock().await.recv().await else {
                return Err(io::ErrorKind::ConnectionAborted.into());
            };
            let n = answer.len().min(buf.len());
            buf[..n].copy_from_slice(&answer[..n]);
            Ok((n, self.from.clone()))
        }
    }

    /// An outbound whose one UDP session is `Fed`.
    #[derive(Debug)]
    struct FedOutbound(EgressId, Mutex<Option<Fed>>);

    #[async_trait::async_trait]
    impl Outbound for FedOutbound {
        fn id(&self) -> &EgressId {
            &self.0
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<captun_outbound::BoxStream> {
            Err(io::Error::other("not used here"))
        }

        async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
            let session = self.1.lock().unwrap().take().ok_or_else(|| io::Error::other("used once"))?;
            Ok(Box::new(session))
        }
    }

    /// Over a device's speed limit, datagrams are dropped at once both ways
    /// and counted, rather than held back in a queue that only grows.
    #[tokio::test]
    async fn udp_over_the_speed_limit_is_dropped_both_ways_never_held_back() {
        let (replies, mut out) = tokio::sync::mpsc::channel(256);
        let mut table = crate::udp::UdpTable::new(replies, 1500);
        let tuple: crate::packet::Tuple = ("10.0.0.5:5000".parse().unwrap(), "142.250.1.1:443".parse().unwrap());
        let key = || SourceKey::Address(tuple.0.ip());
        let (session, feed, sent) = Fed::new(TargetAddr::Ip(tuple.1));
        let outbound: Arc<dyn Outbound> = Arc::new(FedOutbound(EgressId::new("fed"), Mutex::new(Some(session))));
        // 80 kbit/s each way: 10 000 B/s, with a burst of 16 KiB.
        let action = FlowAction::Forward(Forward { client: Some(DEVICE), outbound, down_kbps: Some(80), up_kbps: Some(80) });
        let (meter, relays) = (Arc::new(TrafficMeter::new()), Arc::new(UdpRelays::default()));

        // The device sends 64 datagrams of 1 000 B at once, and the server
        // answers as many.
        let conn = table.receive(tuple, &[1; 1_000], key).unwrap();
        for _ in 1..64 {
            assert!(table.receive(tuple, &[1; 1_000], key).is_none());
        }
        assert_eq!(table.take_dropped(), 0, "the flow's queue took them all");
        for _ in 0..64 {
            feed.send(vec![2; 1_000]).unwrap();
        }
        let started = std::time::Instant::now();
        let served = tokio::spawn(serve_udp(
            conn,
            tuple.0.ip(),
            TargetAddr::Ip(tuple.1),
            Checked::new(action),
            meter.clone(),
            watch(),
            relays.clone(),
        ));

        let mut delivered = 0;
        let handled = |delivered: usize| sent.lock().unwrap().len() + delivered + relays.over_limit.load(Ordering::Relaxed) as usize;
        while handled(delivered) < 128 {
            assert!(started.elapsed() < Duration::from_secs(2), "datagrams over the limit were held back");
            while out.try_recv().is_ok() {
                delivered += 1;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Each way, a full bucket and a burst of credit pay for 32 of them,
        // and the bucket refills one more per 100 ms (the first sooner) for
        // as long as a slow machine takes.
        let up = sent.lock().unwrap().len();
        let most = 32 + started.elapsed().as_millis() as usize / 100 + 1;
        assert!((32..=most).contains(&up), "{up} datagrams sent, {most} at most");
        assert!((32..=most).contains(&delivered), "{delivered} answers delivered, {most} at most");
        assert_eq!(relays.over_limit.load(Ordering::Relaxed) as usize, 128 - up - delivered);
        let snap = meter.snapshot(&DEVICE).unwrap();
        assert_eq!((snap.up_bytes, snap.down_bytes), (up as u64 * 1_000, delivered as u64 * 1_000));
        served.abort();
    }

    /// The length of the answer `recv` read, if one came whole.
    async fn next(answers: &mut Answers<'_>, session: &dyn UdpSession) -> Option<usize> {
        answers.recv(session).await.unwrap().map(|(answer, _)| answer.len())
    }

    /// Where the flows of the answer tests go: a server, and a DNS server.
    fn server() -> TargetAddr {
        TargetAddr::Ip("203.0.113.7:443".parse().unwrap())
    }

    fn dns_server() -> TargetAddr {
        TargetAddr::Ip("203.0.113.53:53".parse().unwrap())
    }

    #[tokio::test]
    async fn answers_too_big_for_the_usual_buffer_move_the_flow_to_a_big_one() {
        let relays = UdpRelays::default();
        let (session, feed, _) = Fed::new(server());
        for len in [100, USUAL_ANSWER, 10_000, 10_000, LARGEST_ANSWER, 100] {
            feed.send(vec![7; len]).unwrap();
        }
        let mut answers = Answers::new(&relays, &server());
        assert_eq!(next(&mut answers, &session).await, Some(100));
        assert_eq!(next(&mut answers, &session).await, Some(USUAL_ANSWER), "a 4 KiB DNS answer fits");
        assert_eq!(relays.big_answers.load(Ordering::Relaxed), 0);
        assert_eq!(next(&mut answers, &session).await, None, "an answer cut short");
        assert_eq!(relays.too_big.load(Ordering::Relaxed), 1, "the dropped answer is counted");
        assert_eq!(next(&mut answers, &session).await, Some(10_000));
        assert_eq!(next(&mut answers, &session).await, Some(LARGEST_ANSWER));
        assert_eq!(next(&mut answers, &session).await, Some(100));
        assert_eq!(relays.big_answers.load(Ordering::Relaxed), 1);
        assert_eq!(relays.too_big.load(Ordering::Relaxed), 1);
        // The flow's end gives the big buffer back.
        drop(answers);
        assert_eq!(relays.big_answers.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn the_engine_has_256_big_answer_buffers_at_most() {
        let relays = UdpRelays::default();
        relays.big_answers.store(MAX_BIG_ANSWERS - 1, Ordering::Relaxed);
        let (first_session, first_feed, _) = Fed::new(server());
        let (second_session, second_feed, _) = Fed::new(server());
        for _ in 0..2 {
            first_feed.send(vec![7; 10_000]).unwrap();
        }
        for _ in 0..4 {
            second_feed.send(vec![7; 10_000]).unwrap();
        }
        let mut first = Answers::new(&relays, &server());
        assert_eq!(next(&mut first, &first_session).await, None);
        assert_eq!(next(&mut first, &first_session).await, Some(10_000), "the last big buffer");
        // None is left: another flow's big answers are dropped, as before.
        let mut second = Answers::new(&relays, &server());
        assert_eq!(next(&mut second, &second_session).await, None);
        assert_eq!(next(&mut second, &second_session).await, None);
        assert_eq!(relays.big_answers.load(Ordering::Relaxed), MAX_BIG_ANSWERS);
        // Until one is given back.
        drop(first);
        assert_eq!(next(&mut second, &second_session).await, None);
        assert_eq!(next(&mut second, &second_session).await, Some(10_000));
        assert_eq!(relays.big_answers.load(Ordering::Relaxed), MAX_BIG_ANSWERS);
        assert_eq!(relays.too_big.load(Ordering::Relaxed), 4, "every dropped answer is counted");
    }

    /// A lookup's one answer, larger than 4 KiB, comes whole: its flow
    /// starts with a big buffer and gives it back when it ends.
    #[tokio::test]
    async fn a_lookups_one_big_answer_comes_whole() {
        let relays = UdpRelays::default();
        let (session, feed, _) = Fed::new(dns_server());
        feed.send(vec![7; 10_000]).unwrap();
        let mut answers = Answers::new(&relays, &dns_server());
        assert_eq!(relays.big_answers.load(Ordering::Relaxed), 1);
        assert_eq!(next(&mut answers, &session).await, Some(10_000));
        assert_eq!(relays.too_big.load(Ordering::Relaxed), 0);
        drop(answers);
        assert_eq!(relays.big_answers.load(Ordering::Relaxed), 0);
    }

    /// Lookups take half the big buffers at most; the rest stay for flows
    /// that grow. A lookup that started small still grows like any flow.
    #[tokio::test]
    async fn lookups_start_big_while_half_the_big_buffers_are_free() {
        let relays = UdpRelays::default();
        let lookups: Vec<_> = (0..MAX_BIG_LOOKUPS).map(|_| Answers::new(&relays, &dns_server())).collect();
        assert!(lookups.iter().all(|answers| answers.big));
        let (session, feed, _) = Fed::new(dns_server());
        for _ in 0..2 {
            feed.send(vec![7; 10_000]).unwrap();
        }
        let mut late = Answers::new(&relays, &dns_server());
        assert!(!late.big, "a lookup took more than half");
        assert_eq!(next(&mut late, &session).await, None, "its big answer is cut short");
        assert_eq!(next(&mut late, &session).await, Some(10_000), "and it grows for the next");
        assert_eq!(relays.too_big.load(Ordering::Relaxed), 1);

        // Flows that grow find the rest.
        let grown: Vec<_> = (MAX_BIG_LOOKUPS + 1..MAX_BIG_ANSWERS)
            .map(|_| {
                let mut flow = Answers::new(&relays, &server());
                flow.grow();
                flow
            })
            .collect();
        assert!(grown.iter().all(|flow| flow.big), "lookups took the flows' half");
        assert_eq!(relays.big_answers.load(Ordering::Relaxed), MAX_BIG_ANSWERS);
        drop((lookups, late, grown));
        assert_eq!(relays.big_answers.load(Ordering::Relaxed), 0, "every big buffer was given back");
    }

    /// The same through a real socket, which on Windows reports an answer
    /// too big for the buffer as an error rather than cutting it short.
    #[tokio::test]
    async fn a_direct_flows_big_answers_come_whole_after_the_first() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = TargetAddr::Ip(server.local_addr().unwrap());
        let session = direct().udp_session().await.unwrap();
        session.send_to(b"hello", &destination).await.unwrap();
        let mut buf = [0u8; 64];
        let (_, device) = server.recv_from(&mut buf).await.unwrap();
        for len in [10_000, 20_000, 100] {
            server.send_to(&vec![7; len], device).await.unwrap();
        }
        let relays = UdpRelays::default();
        let mut answers = Answers::new(&relays, &destination);
        assert_eq!(next(&mut answers, session.as_ref()).await, None, "the first was cut short");
        assert_eq!(relays.too_big.load(Ordering::Relaxed), 1, "and counted");
        assert_eq!(next(&mut answers, session.as_ref()).await, Some(20_000));
        assert_eq!(next(&mut answers, session.as_ref()).await, Some(100));
    }
}
