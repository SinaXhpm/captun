//! SOCKS5 client (RFC 1928) with username/password auth (RFC 1929) and UDP
//! ASSOCIATE. The proxy is reached through another [`Outbound`], which is how
//! chains like "SOCKS5 via HTTP via Ethernet" are built.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use captun_core::{EgressId, TargetAddr};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{BoxStream, Credentials, HANDSHAKE_TIMEOUT, Outbound, UdpSession, timed_out};

const VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_UNACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
/// Largest possible SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) LEN(1) NAME(255) PORT(2).
const MAX_UDP_HEADER: usize = 262;
/// After a proxy refuses UDP, how long until it is asked again (UDP may have
/// been turned on in it since).
const ASK_FOR_UDP_AGAIN: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct Socks5 {
    id: EgressId,
    server: TargetAddr,
    auth: Option<Credentials>,
    dialer: Arc<dyn Outbound>,
    /// When the proxy last refused UDP ASSOCIATE, if it ever has. Many local
    /// proxies carry only TCP; remembering it spares one refused handshake per
    /// UDP flow.
    udp_refused: Mutex<Option<Instant>>,
}

impl Socks5 {
    pub fn new(id: EgressId, server: TargetAddr, auth: Option<Credentials>, dialer: Arc<dyn Outbound>) -> Self {
        Self { id, server, auth, dialer, udp_refused: Mutex::new(None) }
    }

    fn no_udp(&self) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, format!("the SOCKS5 proxy of \"{}\" does not carry UDP", self.id))
    }

    fn udp_refused(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        self.udp_refused.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Notes what the proxy answered to UDP ASSOCIATE, saying so in the log
    /// when that changes.
    fn note_udp(&self, carried: bool) {
        let mut refused = self.udp_refused();
        let before = refused.is_some();
        *refused = (!carried).then(Instant::now);
        drop(refused);
        match (before, carried) {
            (false, false) => warn!(
                egress = %self.id,
                "the SOCKS5 proxy does not carry UDP: devices' UDP through it is refused, so web pages fall back to TCP, \
                 but calls and games that need UDP do not work until UDP is turned on in the proxy"
            ),
            (true, true) => info!(egress = %self.id, "the SOCKS5 proxy carries UDP now"),
            _ => {}
        }
    }

    async fn open_control(&self, cmd: u8, target: &TargetAddr) -> io::Result<(BoxStream, TargetAddr)> {
        let mut stream = self.dialer.connect_tcp(&self.server).await?;
        let bound = timeout(HANDSHAKE_TIMEOUT, async {
            handshake(&mut stream, self.auth.as_ref()).await?;
            request(&mut stream, cmd, target).await
        })
        .await
        .map_err(|_| timed_out("SOCKS5 handshake"))??;
        Ok((stream, bound))
    }
}

#[async_trait]
impl Outbound for Socks5 {
    fn id(&self) -> &EgressId {
        &self.id
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let (stream, _) = self.open_control(CMD_CONNECT, target).await?;
        Ok(stream)
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        if self.udp_refused().is_some_and(|at| at.elapsed() < ASK_FOR_UDP_AGAIN) {
            return Err(self.no_udp());
        }
        let unspecified = TargetAddr::Ip(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let mut control = self.dialer.connect_tcp(&self.server).await?;
        let asked = timeout(HANDSHAKE_TIMEOUT, async {
            handshake(&mut control, self.auth.as_ref()).await?;
            // Past the greeting, what the proxy does with the request is its
            // answer about UDP.
            io::Result::Ok(request(&mut control, CMD_UDP_ASSOCIATE, &unspecified).await)
        })
        .await
        .map_err(|_| timed_out("SOCKS5 handshake"))??;
        let bound = match asked {
            Ok(bound) => bound,
            // "Command not supported" (or no IPv4 address type for it), or the
            // connection cut at the request, as some proxies answer: the proxy
            // carries only TCP.
            Err(e) if is_refusal(&e) => {
                self.note_udp(false);
                return Err(self.no_udp());
            }
            Err(e) => return Err(e),
        };
        self.note_udp(true);

        // Many servers answer 0.0.0.0, meaning "the address you reached me on".
        let relay = match bound {
            TargetAddr::Ip(addr) if addr.ip().is_unspecified() => match &self.server {
                TargetAddr::Ip(server) => TargetAddr::Ip(SocketAddr::new(server.ip(), addr.port())),
                TargetAddr::Domain(host, _) => TargetAddr::Domain(host.clone(), addr.port()),
            },
            other => other,
        };
        // Every datagram goes to the relay, so the dialer opens only what it needs.
        let inner = self.dialer.udp_session_to(&relay).await?;

        // The association lives exactly as long as the TCP control connection.
        let closed = CancellationToken::new();
        let watch = {
            let closed = closed.clone();
            tokio::spawn(async move {
                let mut sink = [0u8; 64];
                while matches!(control.read(&mut sink).await, Ok(n) if n > 0) {}
                closed.cancel();
            })
        };
        Ok(Box::new(Socks5Udp { inner, relay, closed, watch, scratch: tokio::sync::Mutex::new(Vec::new()) }))
    }
}

#[derive(Debug)]
struct Socks5Udp {
    inner: Box<dyn UdpSession>,
    relay: TargetAddr,
    closed: CancellationToken,
    watch: JoinHandle<()>,
    /// Where relayed datagrams land with their header, kept between reads
    /// rather than allocated for each one.
    scratch: tokio::sync::Mutex<Vec<u8>>,
}

impl Drop for Socks5Udp {
    fn drop(&mut self) {
        // Dropping the watcher drops the control stream, ending the association.
        self.watch.abort();
    }
}

#[async_trait]
impl UdpSession for Socks5Udp {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        let mut packet = Vec::with_capacity(MAX_UDP_HEADER + payload.len());
        packet.extend_from_slice(&[0, 0, 0]);
        encode_addr(&mut packet, target)?;
        packet.extend_from_slice(payload);
        self.inner.send_to(&packet, &self.relay).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let mut packet = self.scratch.lock().await;
        if packet.len() < buf.len() + MAX_UDP_HEADER {
            packet.resize(buf.len() + MAX_UDP_HEADER, 0);
        }
        loop {
            let (n, _) = tokio::select! {
                _ = self.closed.cancelled() => {
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "SOCKS5 UDP association closed"));
                }
                r = self.inner.recv_from(&mut packet) => r?,
            };
            // Malformed or fragmented datagrams are dropped, as RFC 1928 allows.
            let Ok((source, header_len)) = parse_udp_header(&packet[..n]) else { continue };
            let len = (n - header_len).min(buf.len());
            buf[..len].copy_from_slice(&packet[header_len..header_len + len]);
            return Ok((len, source));
        }
    }
}

/// How a proxy that let us in turns down a UDP ASSOCIATE request.
fn is_refusal(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(e.kind(), Unsupported | ConnectionReset | ConnectionAborted | UnexpectedEof)
}

fn proto_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, auth: Option<&Credentials>) -> io::Result<()> {
    if auth.is_some() {
        s.write_all(&[VERSION, 2, AUTH_NONE, AUTH_PASSWORD]).await?;
    } else {
        s.write_all(&[VERSION, 1, AUTH_NONE]).await?;
    }
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply[0] != VERSION {
        return Err(proto_err(format!("not a SOCKS5 server (version byte {:#04x})", reply[0])));
    }
    match (reply[1], auth) {
        (AUTH_NONE, _) => Ok(()),
        (AUTH_PASSWORD, Some(creds)) => authenticate(s, creds).await,
        (AUTH_PASSWORD, None) | (AUTH_UNACCEPTABLE, None) => {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS5 server requires a username and password"))
        }
        (AUTH_UNACCEPTABLE, Some(_)) => {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS5 server accepts none of our auth methods"))
        }
        (method, _) => Err(proto_err(format!("SOCKS5 server chose unsupported auth method {method:#04x}"))),
    }
}

async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, creds: &Credentials) -> io::Result<()> {
    let user = creds.username.as_bytes();
    let pass = creds.password.expose().as_bytes();
    let (Ok(user_len), Ok(pass_len)) = (u8::try_from(user.len()), u8::try_from(pass.len())) else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "SOCKS5 username and password must be at most 255 bytes"));
    };
    let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
    msg.push(0x01);
    msg.push(user_len);
    msg.extend_from_slice(user);
    msg.push(pass_len);
    msg.extend_from_slice(pass);
    s.write_all(&msg).await?;

    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS5 authentication failed"));
    }
    Ok(())
}

async fn request<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, cmd: u8, target: &TargetAddr) -> io::Result<TargetAddr> {
    let mut msg = vec![VERSION, cmd, 0x00];
    encode_addr(&mut msg, target)?;
    s.write_all(&msg).await?;

    let mut head = [0u8; 3];
    s.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(proto_err("malformed SOCKS5 reply"));
    }
    if head[1] != 0 {
        return Err(reply_error(head[1], target));
    }
    read_addr(s).await
}

fn reply_error(code: u8, target: &TargetAddr) -> io::Error {
    use io::ErrorKind::*;
    let (kind, what) = match code {
        0x01 => (Other, "general server failure"),
        0x02 => (PermissionDenied, "connection not allowed by ruleset"),
        0x03 => (NetworkUnreachable, "network unreachable"),
        0x04 => (HostUnreachable, "host unreachable"),
        0x05 => (ConnectionRefused, "connection refused"),
        0x06 => (TimedOut, "TTL expired"),
        0x07 => (Unsupported, "command not supported"),
        0x08 => (Unsupported, "address type not supported"),
        _ => (Other, "unknown error"),
    };
    io::Error::new(kind, format!("SOCKS5 proxy could not reach {target}: {what}"))
}

pub(crate) fn encode_addr(buf: &mut Vec<u8>, target: &TargetAddr) -> io::Result<()> {
    match target {
        TargetAddr::Ip(SocketAddr::V4(a)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Ip(SocketAddr::V6(a)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&a.ip().octets());
        }
        TargetAddr::Domain(host, _) => {
            let len = u8::try_from(host.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "domain longer than 255 bytes"))?;
            buf.push(ATYP_DOMAIN);
            buf.push(len);
            buf.extend_from_slice(host.as_bytes());
        }
    }
    buf.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

async fn read_addr<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<TargetAddr> {
    let atyp = s.read_u8().await?;
    let target = match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), s.read_u16().await?))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            s.read_exact(&mut ip).await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), s.read_u16().await?))
        }
        ATYP_DOMAIN => {
            let len = s.read_u8().await?;
            let mut host = vec![0u8; usize::from(len)];
            s.read_exact(&mut host).await?;
            let host = String::from_utf8(host).map_err(|_| proto_err("non-UTF-8 domain in SOCKS5 reply"))?;
            TargetAddr::Domain(host, s.read_u16().await?)
        }
        other => return Err(proto_err(format!("unknown SOCKS5 address type {other:#04x}"))),
    };
    Ok(target)
}

/// Parses the header of a relayed datagram; returns the source and the header length.
pub(crate) fn parse_udp_header(packet: &[u8]) -> io::Result<(TargetAddr, usize)> {
    let short = || proto_err("truncated SOCKS5 UDP header");
    if packet.len() < 4 {
        return Err(short());
    }
    if packet[2] != 0 {
        return Err(proto_err("fragmented SOCKS5 UDP datagrams are not supported"));
    }
    let port_at = |offset: usize| -> io::Result<u16> {
        let bytes = packet.get(offset..offset + 2).ok_or_else(short)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    };
    match packet[3] {
        ATYP_IPV4 => {
            let ip: [u8; 4] = packet.get(4..8).ok_or_else(short)?.try_into().map_err(|_| short())?;
            Ok((TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip.into()), port_at(8)?)), 10))
        }
        ATYP_IPV6 => {
            let ip: [u8; 16] = packet.get(4..20).ok_or_else(short)?.try_into().map_err(|_| short())?;
            Ok((TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip.into()), port_at(20)?)), 22))
        }
        ATYP_DOMAIN => {
            let len = usize::from(*packet.get(4).ok_or_else(short)?);
            let host = packet.get(5..5 + len).ok_or_else(short)?;
            let host = std::str::from_utf8(host).map_err(|_| proto_err("non-UTF-8 domain"))?.to_owned();
            Ok((TargetAddr::Domain(host, port_at(5 + len)?), 7 + len))
        }
        other => Err(proto_err(format!("unknown SOCKS5 address type {other:#04x}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_header_round_trip() {
        for target in ["1.2.3.4:53", "[2001:db8::1]:443", "example.com:8080"] {
            let target: TargetAddr = target.parse().unwrap();
            let mut packet = vec![0, 0, 0];
            encode_addr(&mut packet, &target).unwrap();
            let header_len = packet.len();
            packet.extend_from_slice(b"payload");
            let (parsed, len) = parse_udp_header(&packet).unwrap();
            assert_eq!(parsed, target);
            assert_eq!(len, header_len);
        }
    }

    /// A proxy that carries only TCP: it answers UDP ASSOCIATE with "command
    /// not supported", or with `cut`, closes the connection instead. Counts
    /// the connections made to it.
    async fn tcp_only_proxy(cut: bool) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let mut greeting = [0u8; 3];
                s.read_exact(&mut greeting).await.unwrap();
                s.write_all(&[VERSION, AUTH_NONE]).await.unwrap();
                let mut request = [0u8; 10];
                s.read_exact(&mut request).await.unwrap();
                assert_eq!(request[1], CMD_UDP_ASSOCIATE);
                if !cut {
                    s.write_all(&[VERSION, 0x07, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await.unwrap();
                }
            }
        });
        (addr, connections)
    }

    #[tokio::test]
    async fn a_proxy_that_cuts_udp_requests_is_taken_at_its_word() {
        use std::sync::atomic::Ordering;
        let (addr, connections) = tcp_only_proxy(true).await;
        let dialer = Arc::new(crate::Direct::new(EgressId::new("direct"), None));
        let socks = Socks5::new(EgressId::new("socks"), TargetAddr::Ip(addr), None, dialer);
        for _ in 0..2 {
            assert_eq!(socks.udp_session().await.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_proxy_without_udp_is_asked_once() {
        use std::sync::atomic::Ordering;
        let (addr, connections) = tcp_only_proxy(false).await;
        let dialer = Arc::new(crate::Direct::new(EgressId::new("direct"), None));
        let socks = Socks5::new(EgressId::new("socks"), TargetAddr::Ip(addr), None, dialer);

        for _ in 0..3 {
            let error = socks.udp_session().await.unwrap_err();
            // Unsupported is what lets DNS fall back to TCP through the proxy.
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(error.to_string().contains("does not carry UDP"), "{error}");
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1, "the refusal is remembered");

        // A while later the proxy is asked again: UDP may be on by then.
        *socks.udp_refused() = Some(Instant::now() - ASK_FOR_UDP_AGAIN);
        assert!(socks.udp_session().await.is_err());
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn udp_header_rejects_garbage() {
        assert!(parse_udp_header(&[0, 0, 0]).is_err());
        assert!(parse_udp_header(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 53]).is_err(), "fragment");
        assert!(parse_udp_header(&[0, 0, 0, 3, 10, b'a']).is_err(), "truncated name");
        assert!(parse_udp_header(&[0, 0, 0, 9, 0, 0]).is_err(), "bad atyp");
    }
}
