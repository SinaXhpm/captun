//! Downloads over HTTP(S) through any outbound, for the online lists rules
//! use: a list is fetched the way the user picks, so a filtered network does
//! not keep it from updating. Plain HTTP/1.1, one request per connection,
//! gzip understood, redirects followed (never from HTTPS down to HTTP, nor
//! from a server on the internet onto this computer or the local network).

use std::{
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use captun_core::TargetAddr;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::{BoxStream, Outbound, direct, tls};

/// Redirects followed before giving up.
const MAX_REDIRECTS: usize = 5;
/// The most a response head may take.
const MAX_HEAD: usize = 32 * 1024;

/// One parsed `http://` or `https://` address.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Url {
    https: bool,
    host: String,
    port: u16,
    /// Path and query, starting with `/`.
    path: String,
}

impl Url {
    fn parse(url: &str) -> io::Result<Self> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("{url:?} is not an http:// or https:// address"));
        let (https, rest) = match url.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => (true, rest),
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => (false, rest),
            _ => return Err(bad()),
        };
        let rest = rest.split('#').next().unwrap_or("");
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(split);
        if authority.contains('@') {
            return Err(bad());
        }
        let default_port = if https { 443 } else { 80 };
        let (host, port) = match authority.strip_prefix('[') {
            // [IPv6]:port
            Some(v6) => {
                let (host, after) = v6.split_once(']').ok_or_else(bad)?;
                let port = match after.strip_prefix(':') {
                    Some(port) => port.parse().map_err(|_| bad())?,
                    None if after.is_empty() => default_port,
                    None => return Err(bad()),
                };
                (host.to_owned(), port)
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host.to_owned(), port.parse().map_err(|_| bad())?),
                None => (authority.to_owned(), default_port),
            },
        };
        if host.is_empty() {
            return Err(bad());
        }
        let path = if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_owned()
        };
        // A host of numbers alone is an IPv4 address however it is written
        // (`127.1`, `0x7f.0.0.1`, `2130706433`), so it is checked as one.
        let host = match ipv4_as_browsers_read(&host) {
            Some(ip) => ip.to_string(),
            None => host.to_ascii_lowercase(),
        };
        Ok(Self { https, host, port, path })
    }

    /// Where a redirect's `Location` points, from this address.
    fn join(&self, location: &str) -> io::Result<Self> {
        if location.contains("://") {
            return Self::parse(location);
        }
        let scheme = if self.https { "https" } else { "http" };
        if let Some(rest) = location.strip_prefix("//") {
            return Self::parse(&format!("{scheme}://{rest}"));
        }
        let path = if location.starts_with('/') {
            location.to_owned()
        } else {
            let dir = self.path.split('?').next().unwrap_or("/");
            let dir = &dir[..dir.rfind('/').map_or(0, |i| i + 1)];
            format!("{dir}{location}")
        };
        Ok(Self { path, ..self.clone() })
    }

    /// The host, when it is written as an address.
    fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// Whether the host names this computer or the local network by itself,
    /// whoever looks it up: an address there, `localhost`, a name under a
    /// suffix kept for local networks (`.local`, `.lan`, `.home.arpa`, ...),
    /// or a name of one label, which only a resolver on the local network
    /// answers.
    fn names_local_network(&self) -> bool {
        const LOCAL: [&str; 6] = ["localhost", "localdomain", "local", "lan", "home.arpa", "internal"];
        if let Some(ip) = self.ip() {
            return !is_public(ip);
        }
        let host = self.host.strip_suffix('.').unwrap_or(&self.host);
        !host.contains('.')
            || LOCAL.iter().any(|suffix| host.strip_suffix(suffix).is_some_and(|rest| rest.is_empty() || rest.ends_with('.')))
    }

    /// The `Host` header: the port only when it is not the scheme's own.
    fn host_header(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let default_port = if self.https { 443 } else { 80 };
        if self.port == default_port { host } else { format!("{host}:{}", self.port) }
    }
}

/// `host` as the URL standard's IPv4 parser reads it: up to four parts, each
/// decimal, octal (a leading 0) or hex (0x), the last filling the bytes left,
/// and a trailing dot allowed. Hosts it does not read stay names.
fn ipv4_as_browsers_read(host: &str) -> Option<Ipv4Addr> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let numbers = parts.iter().map(|part| ipv4_number(part)).collect::<Option<Vec<u64>>>()?;
    let (last, leading) = numbers.split_last()?;
    if leading.iter().any(|n| *n > 255) || *last >= 1 << (8 * (4 - leading.len())) {
        return None;
    }
    let ip = leading.iter().enumerate().fold(*last, |ip, (i, n)| ip | (n << (8 * (3 - i))));
    u32::try_from(ip).ok().map(Ipv4Addr::from)
}

/// One part of an IPv4 address as the URL standard reads it.
fn ipv4_number(part: &str) -> Option<u64> {
    let (digits, radix) = match part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None if part.len() > 1 && part.starts_with('0') => (&part[1..], 8),
        None if part.is_empty() => return None,
        None => (part, 10),
    };
    if digits.is_empty() {
        return Some(0);
    }
    // from_str_radix would also take a leading '+'.
    if !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// Fetches `url` through `outbound` and returns the body, decompressed, of at
/// most `max_bytes`. Fails on any answer but success, after following up to
/// five redirects. The caller bounds the time it may take.
///
/// The link itself may lead anywhere, a company's list server on its own
/// network included. Unless it leads onto this computer or the local network
/// itself, though, no redirect may lead there: the list's server must not
/// make this service reach what only it can.
pub async fn fetch(outbound: &dyn Outbound, url: &str, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut url = Url::parse(url)?;
    let from_here = outbound.connects_from_here();
    let mut targets = connect_targets(&url, from_here, true).await?;
    // Decided once, by the link the user gave.
    let inside = leads_inside(&url, &targets);
    let mut redirects = 0;
    loop {
        match get(outbound, &url, &targets, max_bytes).await? {
            Answer::Body(body) => return Ok(body),
            Answer::Redirect(location) => {
                redirects += 1;
                if redirects > MAX_REDIRECTS {
                    return Err(io::Error::other("the server redirected the download too many times"));
                }
                let next = url.join(&location)?;
                if url.https && !next.https {
                    return Err(io::Error::other(format!("the server sent the download from https to plain http ({location})")));
                }
                targets = connect_targets(&next, from_here, inside).await?;
                url = next;
            }
        }
    }
}

/// Whether the user's link leads onto this computer or the local network:
/// its host says so by itself, or, looked up here, it has addresses there
/// only (`targets`). A name a proxy looks up says neither.
fn leads_inside(url: &Url, targets: &[TargetAddr]) -> bool {
    url.names_local_network()
        || (!targets.is_empty() && targets.iter().all(|target| target.ip().is_some_and(|ip| !is_public(ip))))
}

/// Where `url`'s server is reached, in the order to try. Unless `local_ok`,
/// an address on this computer or the local network is refused.
///
/// A host that names one by itself is refused whichever outbound is used: a
/// proxy running on this computer answers `localhost` or `router.lan` here.
/// An outbound that connects from here also gets the addresses looked up
/// here, so the ones checked are the ones used: a second lookup cannot answer
/// differently. Other outbounds look names up on their side, where this
/// computer cannot see.
async fn connect_targets(url: &Url, from_here: bool, local_ok: bool) -> io::Result<Vec<TargetAddr>> {
    if !local_ok && url.names_local_network() {
        return Err(not_followed());
    }
    if let Some(ip) = url.ip() {
        return Ok(vec![TargetAddr::Ip(SocketAddr::new(ip, url.port))]);
    }
    let named = TargetAddr::Domain(url.host.clone(), url.port);
    if !from_here {
        return Ok(vec![named]);
    }
    allowed_addresses(url, direct::resolve_for_service(&named).await?, local_ok)
}

/// The addresses found here for `url`'s name that it may be reached at:
/// unless `local_ok`, those on the internet only.
fn allowed_addresses(url: &Url, found: Vec<SocketAddr>, local_ok: bool) -> io::Result<Vec<TargetAddr>> {
    let allowed: Vec<TargetAddr> =
        found.into_iter().filter(|addr| local_ok || is_public(addr.ip())).map(TargetAddr::Ip).collect();
    if !allowed.is_empty() {
        return Ok(allowed);
    }
    // The name looked public, so this is most likely how a filtered network
    // blocks it: its DNS answers with a local address for blocked names.
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "the list's server sent the download on to {}, which leads to an address on this computer or your local \
             network here, so Captun does not follow it (this network may be blocking that name: pick another \
             outbound under Download through)",
            url.host
        ),
    ))
}

/// Whether `ip` can be a server on the internet: not this computer, the
/// local network, a provider's shared space (carrier-grade NAT), broadcast or
/// multicast. An IPv4 address written as IPv6 (`::ffff:127.0.0.1`, or behind
/// the NAT64 prefix `64:ff9b::`) counts as itself.
fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            // 64:ff9b::/96: where this network has NAT64 (or Windows' CLAT),
            // the translator passes it on to the IPv4 address in its last
            // 32 bits.
            if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [.., a, b, c, d] = ip.octets();
                return is_public_v4(Ipv4Addr::new(a, b, c, d));
            }
            // 64:ff9b:1::/48, NAT64 a network sets up for its own use, with
            // the IPv4 address placed as that network picks.
            let local_nat64 = segments[..3] == [0x64, 0xff9b, 1];
            // ::/96 holds :: and ::1, and the retired IPv4-compatible form.
            let embedded = segments[..6] == [0; 6];
            // fec0::/10, site-local: retired, but local wherever it is still used.
            let site_local = (segments[0] & 0xffc0) == 0xfec0;
            !(local_nat64
                || embedded
                || site_local
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
                || ip.is_multicast())
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    // 0.0.0.0/8, "this network": Linux connects 0.0.0.0 to itself.
    let this_network = first == 0;
    // 100.64.0.0/10, the provider's side of carrier-grade NAT.
    let shared = first == 100 && (second & 0xc0) == 64;
    !(this_network
        || shared
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast())
}

fn not_followed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "the list's server tried to send the download to an address on this computer or your local network, which Captun does not follow",
    )
}

/// Connects to the first of `targets` that answers, as a browser tries each
/// address a name has.
async fn connect(outbound: &dyn Outbound, targets: &[TargetAddr]) -> io::Result<BoxStream> {
    let mut last: Option<io::Error> = None;
    for target in targets {
        match outbound.connect_tcp(target).await {
            Ok(stream) => return Ok(stream),
            // "No address of that family here" says less than why one that
            // could be tried failed.
            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable && last.is_some() => {}
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("the server has no address to connect to")))
}

enum Answer {
    Body(Vec<u8>),
    Redirect(String),
}

/// One request for `url`, sent to the first of `targets` that answers; the
/// name in the link is still what TLS checks and what `Host` says.
async fn get(outbound: &dyn Outbound, url: &Url, targets: &[TargetAddr], max_bytes: usize) -> io::Result<Answer> {
    let stream = connect(outbound, targets).await?;
    let mut stream: BoxStream = if url.https {
        let name = ServerName::try_from(url.host.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not a valid server name", url.host)))?;
        let tls = TlsConnector::from(tls::client_config()?)
            .connect(name, stream)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("secure connection to {} failed: {e}", url.host)))?;
        Box::new(tls)
    } else {
        stream
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Captun/{}\r\nAccept: */*\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
        url.path,
        url.host_header(),
        env!("CARGO_PKG_VERSION"),
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut buf = Vec::with_capacity(64 * 1024);
    let (head_len, head) = loop {
        if read_some(&mut stream, &mut buf).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the server closed the connection without an answer"));
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&buf) {
            Ok(httparse::Status::Complete(len)) => break (len, Head::from(&response)),
            Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => {}
            Ok(httparse::Status::Partial) => return Err(io::Error::new(io::ErrorKind::InvalidData, "the server's answer is too large to read")),
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the server's answer is not HTTP: {e}"))),
        }
    };
    match head.status {
        200 => {}
        301 | 302 | 303 | 307 | 308 => {
            let location = head.location.ok_or_else(|| io::Error::other("the server redirected the download without saying where"))?;
            return Ok(Answer::Redirect(location));
        }
        code => return Err(io::Error::other(format!("the server answered {code} {}", head.reason))),
    }

    let mut body = buf.split_off(head_len);
    match head.length {
        Some(length) if length > max_bytes => return Err(too_large(max_bytes)),
        Some(length) => {
            while body.len() < length {
                if read_some(&mut stream, &mut body).await? == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the download was cut short"));
                }
            }
            body.truncate(length);
        }
        // Read until the server closes, as asked.
        None => {
            while read_some(&mut stream, &mut body).await? > 0 {
                if body.len() > max_bytes.saturating_mul(2) {
                    return Err(too_large(max_bytes));
                }
            }
        }
    }
    if head.chunked {
        body = dechunk(&body)?;
    }
    let body = match head.encoding.as_deref() {
        None | Some("identity") => body,
        Some("gzip" | "x-gzip") => {
            let mut out = Vec::with_capacity(body.len().saturating_mul(4).min(max_bytes));
            flate2::read::MultiGzDecoder::new(body.as_slice())
                .take(max_bytes as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("the download is not valid gzip: {e}")))?;
            out
        }
        Some(other) => return Err(io::Error::other(format!("the server sent the download encoded as {other:?}"))),
    };
    if body.len() > max_bytes {
        return Err(too_large(max_bytes));
    }
    Ok(Answer::Body(body))
}

/// What matters in a response head.
struct Head {
    status: u16,
    reason: String,
    location: Option<String>,
    length: Option<usize>,
    chunked: bool,
    encoding: Option<String>,
}

impl From<&httparse::Response<'_, '_>> for Head {
    fn from(response: &httparse::Response<'_, '_>) -> Self {
        let header = |name: &str| {
            response
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .map(|h| String::from_utf8_lossy(h.value).trim().to_owned())
        };
        Self {
            status: response.code.unwrap_or(0),
            reason: response.reason.unwrap_or("").to_owned(),
            location: header("location"),
            length: header("content-length").and_then(|v| v.parse().ok()),
            chunked: header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")),
            encoding: header("content-encoding").map(|v| v.to_ascii_lowercase()),
        }
    }
}

/// Reads what has arrived into `buf`; 0 once the server has closed. A TLS
/// connection closed without saying so counts as closed: the body's own
/// framing (length, final chunk) tells whether it all arrived.
async fn read_some(stream: &mut BoxStream, buf: &mut Vec<u8>) -> io::Result<usize> {
    let mut chunk = [0u8; 16 * 1024];
    match stream.read(&mut chunk).await {
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(n)
        }
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
        Err(e) => Err(e),
    }
}

/// A body sent in chunks, put back together. It must end with the final,
/// empty chunk: anything less was cut short.
fn dechunk(mut raw: &[u8]) -> io::Result<Vec<u8>> {
    let broken = || io::Error::new(io::ErrorKind::InvalidData, "the download's chunks are broken or cut short");
    let mut out = Vec::with_capacity(raw.len());
    loop {
        let line_end = raw.windows(2).position(|w| w == b"\r\n").ok_or_else(broken)?;
        let size_line = std::str::from_utf8(&raw[..line_end]).map_err(|_| broken())?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| broken())?;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        // Sliced with checks, never added to: the server picks the size, and
        // one near usize::MAX would wrap.
        let data = raw.get(..size).ok_or_else(broken)?;
        let rest = raw.get(size..).and_then(|rest| rest.strip_prefix(b"\r\n")).ok_or_else(broken)?;
        out.extend_from_slice(data);
        raw = rest;
    }
}

fn too_large(max_bytes: usize) -> io::Error {
    io::Error::other(format!("the download is larger than {} MB", max_bytes / (1024 * 1024)))
}

#[cfg(test)]
mod tests {
    use std::{io::Write, sync::Mutex};

    use async_trait::async_trait;
    use captun_core::EgressId;
    use tokio::{
        net::{TcpListener, TcpStream},
        sync::mpsc::UnboundedReceiver,
    };

    use super::*;
    use crate::UdpSession;

    /// Reaches the test server whatever address is asked for.
    #[derive(Debug)]
    struct ToServer {
        id: EgressId,
        server: SocketAddr,
        /// Stands for an outbound on this computer, as Direct is.
        from_here: bool,
        /// Every address it was asked to connect to.
        asked: Mutex<Vec<TargetAddr>>,
    }

    impl ToServer {
        /// The addresses asked for since the last call.
        fn asked(&self) -> Vec<TargetAddr> {
            std::mem::take(&mut *self.asked.lock().unwrap())
        }
    }

    #[async_trait]
    impl Outbound for ToServer {
        fn id(&self) -> &EgressId {
            &self.id
        }

        async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
            self.asked.lock().unwrap().push(target.clone());
            Ok(Box::new(TcpStream::connect(self.server).await?))
        }

        async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn connects_from_here(&self) -> bool {
            self.from_here
        }
    }

    /// Serves one canned answer per path, passing on each request's head.
    async fn server(answers: Vec<(&str, Vec<u8>)>) -> (ToServer, UnboundedReceiver<String>) {
        let answers: Vec<(String, Vec<u8>)> = answers.into_iter().map(|(path, answer)| (path.to_owned(), answer)).collect();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let (seen, requests) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut byte = [0u8; 1];
                    if socket.read(&mut byte).await.unwrap_or(0) == 0 {
                        break;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let path = head.split(' ').nth(1).unwrap_or("").to_owned();
                let _ = seen.send(head);
                let answer = answers.iter().find(|(p, _)| *p == path).map(|(_, a)| a.clone()).unwrap_or_else(|| b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec());
                let _ = socket.write_all(&answer).await;
                let _ = socket.shutdown().await;
            }
        });
        (ToServer { id: EgressId::new("test"), server, from_here: false, asked: Mutex::new(Vec::new()) }, requests)
    }

    /// The request line of the next request the server got.
    async fn next_request(requests: &mut UnboundedReceiver<String>) -> String {
        requests.recv().await.unwrap().lines().next().unwrap_or("").to_owned()
    }

    fn redirect(location: &str) -> Vec<u8> {
        format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n").into_bytes()
    }

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    fn ip(addr: &str) -> TargetAddr {
        TargetAddr::Ip(addr.parse().unwrap())
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn a_list_comes_back_whole_however_it_is_sent() {
        let list = b"0.0.0.0 ads.example\n1.2.3.0/24\n".to_vec();
        let mut plain = b"HTTP/1.1 200 OK\r\nContent-Length: 31\r\n\r\n".to_vec();
        plain.extend_from_slice(&list);
        let packed = gzip(&list);
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        for part in packed.chunks(7) {
            chunked.extend_from_slice(format!("{:x};ext=1\r\n", part.len()).as_bytes());
            chunked.extend_from_slice(part);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\n\r\n");
        let mut until_close = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        until_close.extend_from_slice(&list);
        let (out, mut requests) = server(vec![("/plain", plain), ("/chunked", chunked), ("/close", until_close)]).await;

        assert_eq!(fetch(&out, "http://lists.example/plain", 1024).await.unwrap(), list);
        assert_eq!(fetch(&out, "http://lists.example:8080/chunked", 1024).await.unwrap(), list);
        assert_eq!(fetch(&out, "http://lists.example/close", 1024).await.unwrap(), list);
        assert_eq!(next_request(&mut requests).await, "GET /plain HTTP/1.1");
    }

    #[tokio::test]
    async fn redirects_are_followed_but_never_down_to_plain_http() {
        let found = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let (out, mut requests) = server(vec![
            ("/old/list.txt", b"HTTP/1.1 302 Found\r\nLocation: new/list.txt\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("/old/new/list.txt", b"HTTP/1.1 301 Moved\r\nLocation: /final?v=2\r\n\r\n".to_vec()),
            ("/final?v=2", found),
            ("/loop", b"HTTP/1.1 307 Again\r\nLocation: /loop\r\n\r\n".to_vec()),
        ])
        .await;
        assert_eq!(fetch(&out, "http://lists.example/old/list.txt", 1024).await.unwrap(), b"ok");
        for expected in ["GET /old/list.txt HTTP/1.1", "GET /old/new/list.txt HTTP/1.1", "GET /final?v=2 HTTP/1.1"] {
            assert_eq!(next_request(&mut requests).await, expected);
        }
        let looping = fetch(&out, "http://lists.example/loop", 1024).await.unwrap_err();
        assert!(looping.to_string().contains("too many"), "{looping}");

        let https = Url::parse("https://lists.example/a").unwrap();
        assert!(!https.join("http://lists.example/b").unwrap().https, "the join itself is plain; fetch refuses it");
    }

    #[tokio::test]
    async fn failures_say_what_went_wrong() {
        let big = format!("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n{}", "x".repeat(5000)).into_bytes();
        let bomb = {
            let packed = gzip(&vec![b'a'; 100_000]);
            let mut answer = format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", packed.len()).into_bytes();
            answer.extend_from_slice(&packed);
            answer
        };
        let cut = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n".to_vec();
        let huge_chunk = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nabc\r\n0\r\n\r\n".to_vec();
        let (out, _) = server(vec![("/big", big), ("/bomb", bomb), ("/cut", cut), ("/huge-chunk", huge_chunk)]).await;
        let message = |r: io::Result<Vec<u8>>| r.unwrap_err().to_string();
        assert!(message(fetch(&out, "http://lists.example/missing", 1024).await).contains("404"));
        assert!(message(fetch(&out, "http://lists.example/big", 1024).await).contains("larger"));
        assert!(message(fetch(&out, "http://lists.example/bomb", 1024).await).contains("larger"));
        assert!(message(fetch(&out, "http://lists.example/cut", 1024).await).contains("cut short"));
        assert!(message(fetch(&out, "http://lists.example/huge-chunk", 1024).await).contains("chunks are broken"));
        assert!(fetch(&out, "ftp://lists.example/x", 1024).await.is_err());
    }

    #[test]
    fn a_chunk_size_too_large_to_add_to_is_broken_not_a_panic() {
        let sizes = ["ffffffffffffffff".to_owned(), "fffffffffffffffe".to_owned(), format!("{:x}", usize::MAX), format!("{:x}", usize::MAX - 1)];
        for size in sizes {
            let raw = format!("{size}\r\nabc\r\n0\r\n\r\n");
            let error = dechunk(raw.as_bytes()).unwrap_err();
            assert!(error.to_string().contains("chunks are broken or cut short"), "{size}: {error}");
        }
        assert_eq!(dechunk(b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n").unwrap(), b"abcde");
        assert!(dechunk(b"3\r\nabcX\r\n0\r\n\r\n").is_err(), "a chunk ends where its size says");
        assert!(dechunk(b"5\r\nabc").is_err(), "cut short");
    }

    #[tokio::test]
    async fn a_server_on_the_internet_cannot_send_the_download_onto_this_computer() {
        let local = [
            "http://127.0.0.1/list",
            "http://[::ffff:127.0.0.1]/list",
            "http://127.1/list",
            "http://0.0.0.0/list",
            "http://[::1]:8080/list",
            "http://192.168.1.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/list",
            "http://[fe80::1]/list",
            "http://[fd00::1]/list",
            "http://[64:ff9b::c0a8:101]/list",
            "//10.0.0.1/list",
            // Names that point here by themselves: a proxy on this computer
            // answers them here, so they are refused without asking it.
            "http://localhost:8080/list",
            "http://app.localhost/list",
            "http://router.lan/list",
            "http://printer.local./list",
            "http://intranet/list",
            "http://nas.home.arpa/list",
            "http://db.internal/list",
            "http://localhost.localdomain/list",
        ];
        let paths: Vec<String> = (0..local.len()).map(|i| format!("/to-{i}")).collect();
        let mut answers: Vec<(&str, Vec<u8>)> = paths.iter().zip(local).map(|(path, to)| (path.as_str(), redirect(to))).collect();
        answers.push(("/elsewhere", redirect("http://cdn.example/list")));
        answers.push(("/list", OK.to_vec()));
        let (out, _) = server(answers).await;

        for (path, to) in paths.iter().zip(local) {
            let refused = fetch(&out, &format!("http://lists.example{path}"), 1024).await.unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{to}: {refused}");
            assert_eq!(refused.to_string(), not_followed().to_string(), "{to}");
            assert_eq!(out.asked(), [TargetAddr::Domain("lists.example".into(), 80)], "{to} is never connected to");
        }
        // A proxy looks a name up on its side, where this computer cannot see.
        assert_eq!(fetch(&out, "http://lists.example/elsewhere", 1024).await.unwrap(), b"ok");
        assert_eq!(out.asked(), [TargetAddr::Domain("lists.example".into(), 80), TargetAddr::Domain("cdn.example".into(), 80)]);
    }

    #[tokio::test]
    async fn from_this_computer_a_redirect_is_checked_where_it_really_leads() {
        let (out, _) = server(vec![
            ("/name", redirect("http://localhost/list")),
            ("/number", redirect("http://2130706433/list")),
            ("/mapped", redirect("http://[::ffff:127.0.0.1]/list")),
            ("/unspecified", redirect("http://0.0.0.0/list")),
            ("/public", redirect("http://192.0.2.80/list")),
            ("/list", OK.to_vec()),
        ])
        .await;
        let out = ToServer { from_here: true, ..out };
        let first = ip("203.0.113.7:80");
        for path in ["/name", "/number", "/mapped", "/unspecified"] {
            let refused = fetch(&out, &format!("http://203.0.113.7{path}"), 1024).await.unwrap_err();
            // What the server wrote says where it leads, so it is the
            // server that is blamed.
            assert_eq!(refused.to_string(), not_followed().to_string(), "{path}");
            assert_eq!(out.asked(), std::slice::from_ref(&first), "{path}");
        }
        assert_eq!(fetch(&out, "http://203.0.113.7/public", 1024).await.unwrap(), b"ok");
        assert_eq!(out.asked(), [first, ip("192.0.2.80:80")]);
    }

    #[tokio::test]
    async fn from_this_computer_the_link_is_reached_by_address_but_keeps_its_name() {
        let (out, mut requests) = server(vec![("/list", OK.to_vec())]).await;
        let out = ToServer { from_here: true, ..out };
        assert_eq!(fetch(&out, "http://localhost:8080/list", 1024).await.unwrap(), b"ok");
        let asked = out.asked();
        assert!(matches!(asked.as_slice(), [TargetAddr::Ip(addr)] if addr.ip().is_loopback() && addr.port() == 8080), "{asked:?}");
        let head = requests.recv().await.unwrap();
        assert!(head.contains("\r\nHost: localhost:8080\r\n"), "{head}");
    }

    #[test]
    fn a_name_found_here_to_lead_inside_is_refused_with_what_to_do() {
        // Filtered networks answer a name they block with a local address.
        let hop = Url::parse("https://objects.githubusercontent.com/list").unwrap();
        let blocked = vec![SocketAddr::from(([10, 10, 34, 35], 443)), "[fd00::1]:443".parse().unwrap()];
        let refused = allowed_addresses(&hop, blocked, false).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        let text = refused.to_string();
        assert!(text.contains("objects.githubusercontent.com"), "{text}");
        assert!(text.contains("pick another outbound under Download through"), "{text}");
        assert_ne!(text, not_followed().to_string(), "the server did not write a local address");

        // An address on the internet among them is the only one used...
        let mixed = vec![SocketAddr::from(([10, 10, 34, 35], 443)), SocketAddr::from(([185, 199, 108, 133], 443))];
        assert_eq!(allowed_addresses(&hop, mixed.clone(), false).unwrap(), [ip("185.199.108.133:443")]);
        // ...unless the link itself leads inside.
        assert_eq!(allowed_addresses(&hop, mixed, true).unwrap(), [ip("10.10.34.35:443"), ip("185.199.108.133:443")]);
    }

    #[tokio::test]
    async fn a_link_into_the_local_network_may_redirect_within_it() {
        let (out, _) = server(vec![
            ("/moved", redirect("http://10.0.0.5:8080/list")),
            ("/named", redirect("http://intranet/list")),
            ("/list", OK.to_vec()),
        ])
        .await;
        for link in ["http://nas.lan/moved", "http://intranet/moved", "http://192.168.1.20/moved"] {
            assert_eq!(fetch(&out, link, 1024).await.unwrap(), b"ok", "{link}");
            assert_eq!(out.asked().last(), Some(&ip("10.0.0.5:8080")), "{link}");
        }
        assert_eq!(fetch(&out, "http://nas.lan/named", 1024).await.unwrap(), b"ok");
        assert_eq!(out.asked().last(), Some(&TargetAddr::Domain("intranet".into(), 80)));
        let out = ToServer { from_here: true, ..out };
        assert_eq!(fetch(&out, "http://192.168.1.20/moved", 1024).await.unwrap(), b"ok");
        assert_eq!(out.asked(), [ip("192.168.1.20:80"), ip("10.0.0.5:8080")]);
    }

    /// Has no IPv6, as a network adapter without it, and finds every IPv4
    /// server down.
    #[derive(Debug)]
    struct NothingAnswers(EgressId);

    #[async_trait]
    impl Outbound for NothingAnswers {
        fn id(&self) -> &EgressId {
            &self.0
        }

        async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
            match target {
                TargetAddr::Ip(addr) if addr.is_ipv6() => Err(io::ErrorKind::AddrNotAvailable.into()),
                _ => Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("{target} refused"))),
            }
        }

        async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    #[tokio::test]
    async fn each_address_is_tried_and_the_telling_failure_reported() {
        let out = NothingAnswers(EgressId::new("pinned"));
        let targets = [ip("[2001:db8::1]:80"), ip("192.0.2.1:80"), ip("[2001:db8::2]:80")];
        let error = connect(&out, &targets).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused, "{error}");
        assert!(error.to_string().contains("192.0.2.1:80"), "{error}");
        let error = connect(&out, &targets[..1]).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable, "the only failure there is");
    }

    #[test]
    fn whether_the_link_leads_inside_is_decided_by_the_link() {
        let named = |url: &Url| [TargetAddr::Domain(url.host.clone(), url.port)];
        let link = Url::parse("https://lists.corp.example/x").unwrap();
        assert!(leads_inside(&link, &[ip("10.1.2.3:443"), ip("[fd00::3]:443")]), "looked up here to local addresses only");
        assert!(!leads_inside(&link, &[ip("10.1.2.3:443"), ip("198.51.100.3:443")]), "one address is on the internet");
        assert!(!leads_inside(&link, &named(&link)), "a proxy looks it up");
        for inside in [
            "http://localhost:8080/x",
            "http://app.localhost/x",
            "http://intranet/x",
            "http://nas.lan/x",
            "http://printer.local./x",
            "http://nas.home.arpa/x",
            "http://home.arpa/x",
            "http://db.internal/x",
            "http://localhost.localdomain/x",
            "http://10.0.0.5/x",
            "http://127.1/x",
            "http://[fd00::5]/x",
            "http://[::ffff:192.168.1.1]/x",
            "http://[64:ff9b::a00:5]/x",
        ] {
            let url = Url::parse(inside).unwrap();
            assert!(leads_inside(&url, &named(&url)), "{inside}");
        }
        for outside in [
            "https://lists.example/x",
            "https://raw.githubusercontent.com/x",
            "http://1.1.1.1/x",
            "http://[2606:4700::1111]/x",
            "http://[64:ff9b::808:808]/x",
            // A local suffix counts only as whole labels.
            "http://cdn.notlocal/x",
            "http://lan.example/x",
            "http://mirror.myinternal/x",
        ] {
            let url = Url::parse(outside).unwrap();
            assert!(!leads_inside(&url, &named(&url)), "{outside}");
        }
    }

    #[test]
    fn only_addresses_on_the_internet_are_public() {
        let local = [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.254",
            "255.255.255.255",
            "224.0.0.251",
            "::",
            "::1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            // NAT64 passes these on to 192.168.1.1, 127.0.0.1 and 10.0.0.1.
            "64:ff9b::c0a8:101",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            // NAT64 for a network's own use.
            "64:ff9b:1::1",
            "64:ff9b:1:ffff::808:808",
        ];
        for addr in local {
            assert!(!is_public(addr.parse().unwrap()), "{addr} is local");
        }
        let public = [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.0.2.80",
            "203.0.113.7",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "64:ff9b:2::1",
            "2606:4700::1111",
            "2001:4860:4860::8888",
        ];
        for addr in public {
            assert!(is_public(addr.parse().unwrap()), "{addr} is public");
        }
    }

    #[test]
    fn addresses_are_read_as_browsers_do() {
        let url = Url::parse("HTTPS://Lists.Example:8443/a/b.txt?x=1#top").unwrap();
        assert_eq!(url, Url { https: true, host: "lists.example".into(), port: 8443, path: "/a/b.txt?x=1".into() });
        assert_eq!(url.host_header(), "lists.example:8443");
        let v6 = Url::parse("http://[2001:db8::1]/list").unwrap();
        assert_eq!((v6.host.as_str(), v6.port, v6.host_header()), ("2001:db8::1", 80, "[2001:db8::1]".to_owned()));
        assert_eq!(Url::parse("https://example.com?q").unwrap().path, "/?q");
        assert!(Url::parse("https://user@example.com/").is_err());
        assert_eq!(url.join("//cdn.example/x").unwrap().host, "cdn.example");
        assert_eq!(url.join("c.txt").unwrap().path, "/a/c.txt");

        // Numbers alone are an IPv4 address, in the forms browsers read.
        for (written, read) in [
            ("127.1", "127.0.0.1"),
            ("2130706433", "127.0.0.1"),
            ("0x7f.0.0.1", "127.0.0.1"),
            ("0X7F.1", "127.0.0.1"),
            ("0177.0.0.1", "127.0.0.1"),
            ("127.0.0.1.", "127.0.0.1"),
            ("10.0.258", "10.0.1.2"),
            ("1.2.3.4", "1.2.3.4"),
            ("0", "0.0.0.0"),
        ] {
            let url = Url::parse(&format!("http://{written}:81/")).unwrap();
            assert_eq!((url.host.as_str(), url.port), (read, 81), "{written}");
        }
        for name in ["lists.example", "1.2.3.4.5", "foo.123", "256.0.0.1", "1.256.1", "4294967296", "0x1g.1", "1e3", "+1.2.3.4", "1..2"] {
            assert_eq!(Url::parse(&format!("http://{name}/")).unwrap().host, name.to_ascii_lowercase(), "{name}");
        }
    }
}
