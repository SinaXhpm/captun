//! A local proxy inbound: a SOCKS5 + HTTP CONNECT server on a (usually loopback)
//! port that terminates incoming proxy connections and feeds each one into the
//! same policy-and-relay path the packet engine uses.
//!
//! This is how traffic that is *not* captured at the IP layer still flows through
//! per-client egress, limits and accounting. Its first use is reverse tethering:
//! a phone's system HTTP proxy, tunnelled to this port over `adb reverse`, with
//! every flow attributed to the phone's stand-in [`InboundConfig::client_ip`]. It
//! is equally a plain local proxy for any app pointed at the port.
//!
//! It handles the CONNECT-style tunnels that carry TLS/HTTPS (the bulk of a
//! phone's traffic). Plain-HTTP absolute-form requests and UDP are not proxied
//! here; the helper-based reverse-tethering method covers full traffic instead.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use captun_core::TargetAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::{
    control::{FlowControl, FlowWatch},
    dispatch::Dispatcher,
    engine::EngineHandle,
    flow::serve_tcp,
    meter::TrafficMeter,
};

/// Largest request head we read before a CONNECT line must have arrived.
const MAX_HTTP_HEAD: usize = 16 * 1024;

/// Which proxy handshakes the inbound accepts. Both are on by default; the first
/// byte of a connection selects between them (`0x05` is SOCKS5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboundProtocols {
    pub socks5: bool,
    pub http_connect: bool,
}

impl Default for InboundProtocols {
    fn default() -> Self {
        Self { socks5: true, http_connect: true }
    }
}

/// How an inbound listener attributes and accepts its flows.
#[derive(Clone, Debug)]
pub struct InboundConfig {
    /// The identity every flow from this inbound is charged to, so the
    /// dispatcher applies one device's policy. For reverse tethering this is the
    /// phone's stand-in address.
    pub client_ip: IpAddr,
    pub protocols: InboundProtocols,
}

impl InboundConfig {
    pub fn new(client_ip: IpAddr) -> Self {
        Self { client_ip, protocols: InboundProtocols::default() }
    }
}

/// Serves proxy connections from `listener` until the returned handle is
/// dropped. Each connection is classified by `dispatcher` and relayed through the
/// chosen egress, with traffic recorded in `meter` — exactly as for packet flows.
pub fn serve_inbound(
    listener: TcpListener,
    config: InboundConfig,
    dispatcher: Arc<dyn Dispatcher>,
    meter: Arc<TrafficMeter>,
    control: FlowControl,
) -> EngineHandle {
    EngineHandle::spawn(accept_loop(listener, config, dispatcher, meter, control))
}

async fn accept_loop(
    listener: TcpListener,
    config: InboundConfig,
    dispatcher: Arc<dyn Dispatcher>,
    meter: Arc<TrafficMeter>,
    control: FlowControl,
) {
    info!(client = %config.client_ip, "proxy inbound started");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!("proxy inbound stopped: {e}");
                return;
            }
        };
        let config = config.clone();
        let dispatcher = dispatcher.clone();
        let meter = meter.clone();
        // Taken as the connection is accepted, as the packet engine does for
        // its flows: resets and rechecks from now on reach it.
        let watch = control.watch();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, config, dispatcher, meter, watch).await {
                debug!(%peer, "proxy inbound connection ended: {e}");
            }
        });
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    config: InboundConfig,
    dispatcher: Arc<dyn Dispatcher>,
    meter: Arc<TrafficMeter>,
    mut watch: FlowWatch,
) -> io::Result<()> {
    let Some(destination) = watch.until_reset(handshake(&mut stream, &config)).await?? else {
        return Ok(());
    };
    serve_tcp(stream, config.client_ip, destination, dispatcher, meter, watch).await
}

/// Reads the proxy request, SOCKS5 or HTTP CONNECT, and returns where it asks
/// to go, or `None` when it was answered without a flow to relay.
async fn handshake(stream: &mut TcpStream, config: &InboundConfig) -> io::Result<Option<TargetAddr>> {
    let mut first = [0u8; 1];
    if stream.peek(&mut first).await? == 0 {
        return Ok(None);
    }

    if first[0] == 0x05 {
        if !config.protocols.socks5 {
            return Ok(None);
        }
        socks5_handshake(stream).await
    } else {
        if !config.protocols.http_connect {
            return Ok(None);
        }
        http_connect_handshake(stream).await
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Performs the SOCKS5 (RFC 1928) no-auth handshake for a CONNECT request and
/// returns the requested destination, or `None` when the request was answered
/// without a flow to relay (unsupported method or command).
async fn socks5_handshake<S>(stream: &mut S) -> io::Result<Option<TargetAddr>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Greeting: VER, NMETHODS, METHODS...
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(invalid("not a socks5 greeting"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        // No acceptable methods.
        stream.write_all(&[0x05, 0xff]).await?;
        return Ok(None);
    }
    stream.write_all(&[0x05, 0x00]).await?;

    // Request: VER, CMD, RSV, ATYP, ADDR, PORT.
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(invalid("bad socks5 request"));
    }
    let destination = match req[3] {
        0x01 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), u16::from_be_bytes([b[4], b[5]])))
        }
        0x04 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[..16]);
            let ip = Ipv6Addr::from(octets);
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), u16::from_be_bytes([b[16], b[17]])))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
            let (host, port) = rest.split_at(len[0] as usize);
            let host = std::str::from_utf8(host).map_err(|_| invalid("socks5 domain is not utf-8"))?;
            let port = u16::from_be_bytes([port[0], port[1]]);
            TargetAddr::parse_with_default_port(host, port).map_err(|_| invalid("invalid socks5 domain"))?
        }
        _ => {
            reply_socks5(stream, 0x08).await?; // address type not supported
            return Ok(None);
        }
    };

    if req[1] != 0x01 {
        reply_socks5(stream, 0x07).await?; // command not supported
        return Ok(None);
    }

    reply_socks5(stream, 0x00).await?; // succeeded
    Ok(Some(destination))
}

/// Sends a SOCKS5 reply with the given status and a zero bound address.
async fn reply_socks5<S>(stream: &mut S, status: u8) -> io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    stream.write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await
}

/// Reads an HTTP request head and, for a CONNECT, acknowledges it and returns the
/// target. Non-CONNECT requests are refused (plain-HTTP proxying is not done
/// here) and yield `None`.
async fn http_connect_handshake<S>(stream: &mut S) -> io::Result<Option<TargetAddr>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).await? == 0 {
            return Ok(None);
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HTTP_HEAD {
            return Err(invalid("http request head too large"));
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let request_line = text.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");

    if !method.eq_ignore_ascii_case("CONNECT") {
        stream
            .write_all(b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(None);
    }

    let destination = match TargetAddr::parse_with_default_port(authority, 443) {
        Ok(dst) => dst,
        Err(_) => {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await?;
            return Ok(None);
        }
    };
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    Ok(Some(destination))
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Mutex};

    use captun_core::EgressId;
    use captun_outbound::{Direct, Outbound};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener as StdTcpListener, TcpStream},
    };

    use super::*;
    use crate::dispatch::{FlowAction, FlowRequest, Forward};

    struct MockDispatcher {
        seen: Mutex<Option<TargetAddr>>,
    }

    impl Dispatcher for MockDispatcher {
        fn needs_domain(&self) -> bool {
            false
        }

        fn dispatch(&self, request: &FlowRequest<'_>) -> FlowAction {
            *self.seen.lock().unwrap() = Some(request.destination.clone());
            FlowAction::Forward(Forward {
                client: None,
                outbound: Arc::new(Direct::new(EgressId::new("direct"), None)) as Arc<dyn Outbound>,
                down_kbps: None,
                up_kbps: None,
            })
        }
    }

    /// A local TCP echo that plays the upstream destination.
    async fn tcp_echo() -> SocketAddr {
        let listener = StdTcpListener::bind("127.0.0.1:0").await.unwrap();
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

    async fn start_inbound() -> (SocketAddr, Arc<MockDispatcher>, crate::EngineHandle) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dispatcher = Arc::new(MockDispatcher { seen: Mutex::new(None) });
        let handle = serve_inbound(
            listener,
            InboundConfig::new("10.9.9.9".parse().unwrap()),
            dispatcher.clone(),
            Arc::new(TrafficMeter::new()),
            FlowControl::new(),
        );
        (addr, dispatcher, handle)
    }

    #[tokio::test]
    async fn socks5_connect_relays_to_the_requested_ipv4() {
        let echo = tcp_echo().await;
        let (inbound, dispatcher, _handle) = start_inbound().await;

        let mut c = TcpStream::connect(inbound).await.unwrap();
        // Greeting: one method, no-auth.
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0x00]);
        // CONNECT to the echo server (IPv4).
        let SocketAddr::V4(v4) = echo else { panic!("ipv4") };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&v4.ip().octets());
        req.extend_from_slice(&v4.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00, "socks5 success");

        c.write_all(b"ping through socks").await.unwrap();
        let mut got = [0u8; 18];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping through socks");

        assert_eq!(dispatcher.seen.lock().unwrap().as_ref().map(|t| t.port()), Some(echo.port()));
    }

    #[tokio::test]
    async fn socks5_rejects_when_no_auth_method_offered() {
        let (inbound, _dispatcher, _handle) = start_inbound().await;
        let mut c = TcpStream::connect(inbound).await.unwrap();
        // Offer only username/password (0x02), which we do not support.
        c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut sel = [0u8; 2];
        c.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0xff]);
    }

    #[tokio::test]
    async fn http_connect_tunnels_to_the_target() {
        let echo = tcp_echo().await;
        let (inbound, dispatcher, _handle) = start_inbound().await;

        let mut c = TcpStream::connect(inbound).await.unwrap();
        c.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes()).await.unwrap();

        // Read the status line.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            c.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));

        c.write_all(b"after connect").await.unwrap();
        let mut got = [0u8; 13];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"after connect");

        assert_eq!(dispatcher.seen.lock().unwrap().as_ref().map(|t| t.port()), Some(echo.port()));
    }

    #[tokio::test]
    async fn http_non_connect_is_refused() {
        let (inbound, _dispatcher, _handle) = start_inbound().await;
        let mut c = TcpStream::connect(inbound).await.unwrap();
        c.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 501"));
    }

    /// The phone every connection of [`Phone`] is counted against.
    const PHONE: captun_core::MacAddr = captun_core::MacAddr::new([0x06, 0, 0, 0, 0, 1]);

    /// Forwards every connection for [`PHONE`]; open ones may go on while
    /// `allowed` holds.
    struct Phone {
        allowed: std::sync::atomic::AtomicBool,
    }

    impl Dispatcher for Phone {
        fn needs_domain(&self) -> bool {
            false
        }

        // The default `dispatch_device` names the phone from the forward.
        fn dispatch(&self, _request: &FlowRequest<'_>) -> FlowAction {
            FlowAction::Forward(Forward {
                client: Some(PHONE),
                outbound: Arc::new(Direct::new(EgressId::new("direct"), None)) as Arc<dyn Outbound>,
                down_kbps: None,
                up_kbps: None,
            })
        }

        fn still_allowed(
            &self,
            _request: &FlowRequest<'_>,
            device: Option<captun_core::MacAddr>,
            outbound: &EgressId,
        ) -> bool {
            assert_eq!((device, outbound.as_str()), (Some(PHONE), "direct"));
            self.allowed.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A connection through the inbound to `echo`, tunnel made and tried.
    async fn tunnel(inbound: SocketAddr, echo: SocketAddr) -> TcpStream {
        let mut c = TcpStream::connect(inbound).await.unwrap();
        c.write_all(format!("CONNECT {echo} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            c.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        round_trip(&mut c).await;
        c
    }

    async fn round_trip(c: &mut TcpStream) {
        c.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }

    /// Whether the inbound closed `c` within a second.
    async fn closed(c: &mut TcpStream) -> bool {
        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), c.read(&mut buf)).await;
        matches!(read, Ok(Ok(0) | Err(_)))
    }

    /// The USB proxy's connections end as the packet engine's do: at a
    /// reset of their device or of every flow, also mid-handshake, and at a
    /// recheck that no longer allows them.
    #[tokio::test]
    async fn proxied_connections_end_at_resets_and_rechecks() {
        let echo = tcp_echo().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound = listener.local_addr().unwrap();
        let dispatcher = Arc::new(Phone { allowed: true.into() });
        let control = FlowControl::new();
        let config = InboundConfig::new("10.9.9.9".parse().unwrap());
        let _handle =
            serve_inbound(listener, config, dispatcher.clone(), Arc::new(TrafficMeter::new()), control.clone());

        let mut c = tunnel(inbound, echo).await;
        control.reset_devices(&[captun_core::MacAddr::new([0x06, 0, 0, 0, 0, 2])]);
        round_trip(&mut c).await;
        control.reset_devices(&[PHONE]);
        assert!(closed(&mut c).await, "the phone's reset left its connection open");

        let mut c = TcpStream::connect(inbound).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        control.reset_all();
        assert!(closed(&mut c).await, "a reset of every flow left a handshake open");

        let mut c = tunnel(inbound, echo).await;
        control.recheck_all();
        round_trip(&mut c).await;
        dispatcher.allowed.store(false, std::sync::atomic::Ordering::SeqCst);
        control.recheck_all();
        assert!(closed(&mut c).await, "a recheck that refuses it left the connection open");
    }
}
