//! Upstream resolvers. Every transport runs over an [`Outbound`], so the
//! bytes leave through whatever egress the asking client is routed to.

use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    fmt, io,
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use captun_core::{
    TargetAddr,
    config::{DnsProtocol, DnsUpstreamConfig},
};
use captun_outbound::{BoxStream, Outbound};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{timeout, timeout_at},
};
use tokio_rustls::TlsConnector;

use crate::{
    DnsError,
    message::{HEADER_LEN, header_id, is_response, is_truncated},
};

/// Budget for one query against one upstream, fallbacks and the wait for a
/// turn ([`STREAMS_AT_ONCE`]) included.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Resend a UDP query once if nothing came back by then.
const UDP_RETRY_AFTER: Duration = Duration::from_millis(1500);
/// Connections (TCP, TLS, HTTPS) kept open for the next queries: a lookup
/// then costs one round trip instead of a new connection and handshake each
/// time, which through a proxy is most of half a second.
const KEEP_IDLE_FOR: Duration = Duration::from_secs(25);
/// Idle connections kept for each outbound once its queries are answered
/// (while others are being asked, as many as they may want) ...
const KEEP_PER_OUTBOUND: usize = 16;
/// ... and over all outbounds, for one upstream. The one put back longest ago
/// goes first.
const KEEP_AT_MOST: usize = 64;
/// Queries asking over connections to one upstream through one outbound at
/// once. The others wait their turn and then take a connection one of these
/// put back, so a burst of queries opens this many connections at most
/// instead of one (and a handshake) each.
const STREAMS_AT_ONCE: usize = 32;
/// Of those, the turns one device may have. Its other queries wait behind its
/// own, not in front of other devices' queries, so a device whose names take
/// long to look up does not hold up the others.
const TURNS_PER_DEVICE: usize = STREAMS_AT_ONCE / 4;
/// A kept connection idle longer than this may have been dropped by the
/// network without a word, so it gets only [`KEPT_ANSWER_WITHIN`] to answer,
/// leaving time to ask again on a new one. One used more recently is alive
/// and gets the whole [`QUERY_TIMEOUT`]: an upstream slow to look a name up
/// is then waited for, not asked twice.
const TRUST_KEPT_FOR: Duration = Duration::from_secs(3);
const KEPT_ANSWER_WITHIN: Duration = Duration::from_millis(1500);
/// UDP answers are read into this much. We ask for 1232 bytes at most (see
/// `forward`), so a datagram that fills it may have been cut short, and the
/// query is asked again over TCP.
const UDP_BUFFER: usize = 4096;
const MAX_HTTP_HEAD: usize = 16 * 1024;
const MAX_HTTP_BODY: usize = 65_535;

#[derive(Debug)]
pub struct Upstream {
    id: String,
    target: TargetAddr,
    kind: Kind,
    /// Open connections waiting for the next query, and turns to ask over
    /// them, by the outbound they go through.
    pools: Mutex<HashMap<OutboundKey, Pool>>,
}

/// Where an outbound lives in memory. Its [`Pool`] holds on to that memory
/// (not to the outbound), so while the pool exists the address cannot be
/// given to another outbound, such as one rebuilt with new settings under the
/// same id: that one never gets the old one's connections.
type OutboundKey = usize;

fn key(outbound: &Arc<dyn Outbound>) -> OutboundKey {
    Arc::as_ptr(outbound).cast::<()>().addr()
}

/// The connections to the upstream through one outbound.
struct Pool {
    /// Keeps the outbound's memory, and so its key, from being reused; also
    /// tells when the outbound is gone.
    outbound: Weak<dyn Outbound>,
    /// [`STREAMS_AT_ONCE`] turns. A query holds one from before it looks for
    /// a kept connection until it has put its connection back.
    turns: Arc<Semaphore>,
    /// The devices whose queries hold a turn or wait for one, by address.
    devices: HashMap<IpAddr, Share>,
    /// Idle connections, the one put back last at the back.
    idle: VecDeque<Idle>,
}

/// One device's share of a pool's turns: it takes one of these before one
/// of the pool's.
struct Share {
    /// [`TURNS_PER_DEVICE`].
    turns: Arc<Semaphore>,
    /// The device's queries holding a turn or waiting for one; the share goes
    /// when the last one ends.
    queries: usize,
}

struct Idle {
    stream: BoxStream,
    since: Instant,
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("idle", &self.idle.len())
            .field("free_turns", &self.turns.available_permits())
            .field("devices", &self.devices.len())
            .finish_non_exhaustive()
    }
}

impl Pool {
    fn new(outbound: &Arc<dyn Outbound>) -> Self {
        Self {
            outbound: Arc::downgrade(outbound),
            turns: Arc::new(Semaphore::new(STREAMS_AT_ONCE)),
            devices: HashMap::new(),
            idle: VecDeque::new(),
        }
    }

    /// Whether a query holds a turn or waits for one.
    fn in_use(&self) -> bool {
        !self.devices.is_empty()
    }

    /// Queries other than the caller's that hold a turn or wait for one.
    fn others_asking(&self) -> usize {
        self.devices.values().map(|share| share.queries).sum::<usize>().saturating_sub(1)
    }

    /// Moves the connections idle too long to `gone`; all of them once the
    /// outbound is gone.
    fn expire(&mut self, now: Instant, gone: &mut Vec<Idle>) {
        let expired = if self.outbound.strong_count() == 0 {
            self.idle.len()
        } else {
            // Oldest first, so the expired ones lead.
            self.idle.partition_point(|idle| now.duration_since(idle.since) >= KEEP_IDLE_FOR)
        };
        gone.extend(self.idle.drain(..expired));
    }
}

/// Moves the connections no longer worth keeping to `gone`, and forgets the
/// outbounds no query uses that have none left (the ones gone among them).
fn sweep(pools: &mut HashMap<OutboundKey, Pool>, now: Instant, gone: &mut Vec<Idle>) {
    pools.retain(|_, pool| {
        pool.expire(now, gone);
        pool.in_use() || !pool.idle.is_empty()
    });
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Who a query is for, when it runs out of time, and whether it is waiting
/// for a turn: one that runs out of time then was never sent, which says
/// nothing about the server.
struct Asking {
    client: IpAddr,
    deadline: tokio::time::Instant,
    waiting: AtomicBool,
}

/// A query's turn to ask over a connection through one outbound
/// ([`Upstream::turn`]).
struct Turn<'a> {
    _permits: (OwnedSemaphorePermit, OwnedSemaphorePermit),
    _counted: Counted<'a>,
}

/// A query counted among its device's in a pool, from before it waits for a
/// turn until it ends, however it ends.
struct Counted<'a> {
    upstream: &'a Upstream,
    key: OutboundKey,
    client: IpAddr,
}

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        let mut pools = lock(&self.upstream.pools);
        // The pool is there while one of its devices has a query.
        if let Some(pool) = pools.get_mut(&self.key)
            && let Entry::Occupied(mut share) = pool.devices.entry(self.client)
        {
            share.get_mut().queries = share.get().queries.saturating_sub(1);
            if share.get().queries == 0 {
                share.remove();
            }
        }
    }
}

#[derive(Debug)]
enum Kind {
    Udp,
    Tcp,
    Tls { server_name: ServerName<'static>, tls: Arc<ClientConfig> },
    Https { server_name: ServerName<'static>, host: String, path: String, tls: Arc<ClientConfig> },
}

/// TLS settings shared by all upstreams of one settings generation.
#[derive(Debug, Clone)]
pub(crate) struct TlsConfigs {
    pub(crate) dot: Arc<ClientConfig>,
    pub(crate) doh: Arc<ClientConfig>,
}

impl Upstream {
    pub(crate) fn from_config(config: &DnsUpstreamConfig, tls: &TlsConfigs) -> Result<Self, DnsError> {
        let err = |reason: String| DnsError::Upstream { id: config.id.clone(), reason };
        let target = config.target().map_err(|e| err(e.to_string()))?;
        let server_name = || -> Result<ServerName<'static>, DnsError> {
            let name = config.tls_server_name().map_err(|e| err(e.to_string()))?;
            ServerName::try_from(name.clone()).map_err(|_| err(format!("invalid TLS server name {name:?}")))
        };
        let kind = match config.protocol {
            DnsProtocol::Udp => Kind::Udp,
            DnsProtocol::Tcp => Kind::Tcp,
            DnsProtocol::Tls => Kind::Tls { server_name: server_name()?, tls: tls.dot.clone() },
            DnsProtocol::Https => {
                let server_name = server_name()?;
                let name = config.tls_server_name().map_err(|e| err(e.to_string()))?;
                let host = if target.port() == 443 { name } else { format!("{name}:{}", target.port()) };
                Kind::Https { server_name, host, path: config.doh_path().to_owned(), tls: tls.doh.clone() }
            }
        };
        Ok(Self { id: config.id.clone(), target, kind, pools: Mutex::new(HashMap::new()) })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn target(&self) -> &TargetAddr {
        &self.target
    }

    /// Sends `query` for the device at `client` and returns the raw response,
    /// whose ID is guaranteed to match the query's.
    pub(crate) async fn exchange(
        &self,
        query: &[u8],
        outbound: &Arc<dyn Outbound>,
        client: IpAddr,
    ) -> io::Result<Vec<u8>> {
        let id = header_id(query).ok_or_else(|| invalid("query shorter than a DNS header"))?;
        let asking = Asking {
            client: client.to_canonical(),
            deadline: tokio::time::Instant::now() + QUERY_TIMEOUT,
            waiting: AtomicBool::new(false),
        };
        let response = match timeout_at(asking.deadline, self.exchange_inner(query, id, outbound, &asking)).await {
            Ok(answered) => answered?,
            Err(_) if asking.waiting.load(Ordering::Relaxed) => return Err(self.too_busy()),
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, format!("DNS server {} did not answer in time", self.id)));
            }
        };
        if header_id(&response) != Some(id) || !is_response(&response) {
            return Err(invalid("upstream answered with a mismatched ID"));
        }
        Ok(response)
    }

    /// For a query that ran out of time waiting for a turn. Not an error that
    /// says the server cannot be reached (`reach::cannot_reach`): it was never
    /// asked.
    fn too_busy(&self) -> io::Error {
        io::Error::new(io::ErrorKind::ResourceBusy, format!("too many queries waiting for DNS server {}", self.id))
    }

    async fn exchange_inner(
        &self,
        query: &[u8],
        id: u16,
        outbound: &Arc<dyn Outbound>,
        asking: &Asking,
    ) -> io::Result<Vec<u8>> {
        match &self.kind {
            Kind::Udp => match self.udp(query, id, outbound.as_ref()).await {
                Ok(Some(response)) if !is_truncated(&response) => Ok(response),
                // Too big for UDP: RFC 7766 says retry over TCP.
                Ok(_) => self.tcp(query, outbound, asking).await,
                // The egress cannot carry UDP (e.g. an HTTP proxy).
                Err(e) if e.kind() == io::ErrorKind::Unsupported => self.tcp(query, outbound, asking).await,
                Err(e) => Err(e),
            },
            Kind::Tcp | Kind::Tls { .. } | Kind::Https { .. } => self.over_stream(query, outbound, asking).await,
        }
    }

    /// One query over a kept connection when there is one, else over a new
    /// one. A kept connection the server has closed meanwhile fails at once
    /// (and one idle a while and dropped silently, soon); the query then goes
    /// over a new one.
    async fn over_stream(&self, query: &[u8], outbound: &Arc<dyn Outbound>, asking: &Asking) -> io::Result<Vec<u8>> {
        let key = key(outbound);
        // Held until the connection is back in the pool, where the query that
        // gets the turn next finds it.
        let _turn = self.turn(key, outbound, asking).await?;
        if let Some(Idle { mut stream, since }) = self.take_kept(key) {
            let asking = self.ask(&mut stream, query);
            let answered = if since.elapsed() > TRUST_KEPT_FOR {
                timeout(KEPT_ANSWER_WITHIN, asking).await.ok()
            } else {
                Some(asking.await)
            };
            if let Some(Ok((response, reusable))) = answered {
                if reusable {
                    self.keep(key, stream);
                }
                return Ok(response);
            }
        }
        let mut stream = self.open(outbound.as_ref()).await?;
        let (response, reusable) = self.ask(&mut stream, query).await?;
        if reusable {
            self.keep(key, stream);
        }
        Ok(response)
    }

    /// Waits for a turn to ask over a connection through `outbound`, within
    /// the query's [`QUERY_TIMEOUT`]: one of the device's
    /// [`TURNS_PER_DEVICE`] first, then one of the outbound's
    /// [`STREAMS_AT_ONCE`].
    async fn turn(&self, key: OutboundKey, outbound: &Arc<dyn Outbound>, asking: &Asking) -> io::Result<Turn<'_>> {
        let mut gone = Vec::new();
        let (device_turns, turns) = {
            let mut pools = lock(&self.pools);
            if !pools.contains_key(&key) {
                // A new outbound; the ones gone are forgotten.
                sweep(&mut pools, Instant::now(), &mut gone);
            }
            let pool = pools.entry(key).or_insert_with(|| Pool::new(outbound));
            let share = pool
                .devices
                .entry(asking.client)
                .or_insert_with(|| Share { turns: Arc::new(Semaphore::new(TURNS_PER_DEVICE)), queries: 0 });
            share.queries += 1;
            (share.turns.clone(), pool.turns.clone())
        };
        let counted = Counted { upstream: self, key, client: asking.client };
        // Closed after the lock is let go, and not kept while waiting.
        drop(gone);
        asking.waiting.store(true, Ordering::Relaxed);
        // The turns are never closed.
        let device = device_turns.acquire_owned().await.map_err(io::Error::other)?;
        let turn = turns.acquire_owned().await.map_err(io::Error::other)?;
        // A query that runs out of time hands its turn on at once, and a
        // timeout polls its query before its clock: when many run out of time
        // together, the ones waiting get their turns after their own time is
        // up, and must not ask then.
        if tokio::time::Instant::now() >= asking.deadline {
            return Err(self.too_busy());
        }
        asking.waiting.store(false, Ordering::Relaxed);
        Ok(Turn { _permits: (turn, device), _counted: counted })
    }

    /// The connection through this outbound put back last, if one is still
    /// fresh: the likeliest to be alive. The others may expire unused.
    fn take_kept(&self, key: OutboundKey) -> Option<Idle> {
        let mut gone = Vec::new();
        let taken = {
            let mut pools = lock(&self.pools);
            let pool = pools.get_mut(&key)?;
            pool.expire(Instant::now(), &mut gone);
            pool.idle.pop_back()
        };
        drop(gone);
        taken
    }

    /// Puts a connection back for the next query through the same outbound.
    fn keep(&self, key: OutboundKey, stream: BoxStream) {
        let mut gone = Vec::new();
        {
            let mut pools = lock(&self.pools);
            let now = Instant::now();
            sweep(&mut pools, now, &mut gone);
            // There while the caller holds a turn.
            let Some(pool) = pools.get_mut(&key) else { return };
            // Each other query holding or waiting for a turn here may want a
            // connection soon: closing one would only make it open another.
            // A pool has no more connections than turns.
            let room = KEEP_PER_OUTBOUND.max(pool.others_asking());
            while pool.idle.len() >= room {
                gone.extend(pool.idle.pop_front());
            }
            // `now` was read under the lock, so each pool stays oldest first.
            pool.idle.push_back(Idle { stream, since: now });

            let mut kept: usize = pools.values().map(|pool| pool.idle.len()).sum();
            while kept > KEEP_AT_MOST {
                let oldest = pools
                    .values_mut()
                    .filter_map(|pool| Some((pool.idle.front()?.since, pool)))
                    .min_by_key(|(since, _)| *since);
                let Some((_, pool)) = oldest else { break };
                gone.extend(pool.idle.pop_front());
                kept -= 1;
            }
        }
        // Closed after the lock is let go.
        drop(gone);
    }

    /// A new connection to the upstream through `outbound`: TLS for DoT and
    /// DoH, plain TCP otherwise (also for a UDP upstream falling back to TCP).
    async fn open(&self, outbound: &dyn Outbound) -> io::Result<BoxStream> {
        let stream = outbound.connect_tcp(&self.target).await?;
        match &self.kind {
            Kind::Tls { server_name, tls } | Kind::Https { server_name, tls, .. } => {
                Ok(Box::new(TlsConnector::from(tls.clone()).connect(server_name.clone(), stream).await?))
            }
            Kind::Udp | Kind::Tcp => Ok(stream),
        }
    }

    /// Sends `query` on `stream`; also says whether the connection can carry
    /// another one.
    async fn ask(&self, stream: &mut BoxStream, query: &[u8]) -> io::Result<(Vec<u8>, bool)> {
        match &self.kind {
            Kind::Https { host, path, .. } => doh_post(stream, host, path, query).await,
            Kind::Udp | Kind::Tcp | Kind::Tls { .. } => Ok((exchange_framed(stream, query).await?, true)),
        }
    }

    /// The answer over UDP, or `None` when it came cut short, to be asked for
    /// again over TCP. Each query has a socket (or proxy association) of its
    /// own, never shared: a new random source port each time is what makes a
    /// forged answer hard to slip in (RFC 5452).
    async fn udp(&self, query: &[u8], id: u16, outbound: &dyn Outbound) -> io::Result<Option<Vec<u8>>> {
        // Only to the DNS server: one socket, not one per address family.
        let session = outbound.udp_session_to(&self.target).await?;
        let mut buf = vec![0u8; UDP_BUFFER];
        for attempt in 0..2 {
            session.send_to(query, &self.target).await?;
            let wait = async {
                loop {
                    let (n, from) = match session.recv_from(&mut buf).await {
                        Ok(received) => received,
                        // From whoever: the rest of it is lost.
                        Err(e) if is_cut_short(&e) => return Ok(None),
                        Err(e) => return Err(e),
                    };
                    // Ignore strays and spoofs: wrong sender, wrong ID, not a response.
                    let from_upstream = match &self.target {
                        TargetAddr::Ip(addr) => from == TargetAddr::Ip(*addr),
                        TargetAddr::Domain(..) => true,
                    };
                    let reply = &buf[..n];
                    if from_upstream && n >= HEADER_LEN && header_id(reply) == Some(id) && is_response(reply) {
                        // Other systems cut a datagram that does not fit
                        // without a word: one that fills the buffer may be cut.
                        return io::Result::Ok((n < UDP_BUFFER).then(|| reply.to_vec()));
                    }
                }
            };
            match timeout(UDP_RETRY_AFTER, wait).await {
                Ok(result) => return result,
                Err(_) if attempt == 0 => continue,
                Err(_) => break,
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, format!("no UDP answer from {}", self.target)))
    }

    async fn tcp(&self, query: &[u8], outbound: &Arc<dyn Outbound>, asking: &Asking) -> io::Result<Vec<u8>> {
        self.over_stream(query, outbound, asking).await
    }
}

/// Whether a read failed because the datagram did not fit the buffer, which
/// Windows says (WSAEMSGSIZE) while dropping the rest of it.
#[cfg(windows)]
fn is_cut_short(e: &io::Error) -> bool {
    const WSAEMSGSIZE: i32 = 10040;
    e.raw_os_error() == Some(WSAEMSGSIZE)
}

/// Other systems cut such a datagram without a word.
#[cfg(not(windows))]
fn is_cut_short(_: &io::Error) -> bool {
    false
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// DNS over a byte stream (TCP, TLS): 2-byte big-endian length prefix.
async fn exchange_framed<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, query: &[u8]) -> io::Result<Vec<u8>> {
    let len = u16::try_from(query.len()).map_err(|_| invalid("query too large for TCP framing"))?;
    let mut frame = Vec::with_capacity(2 + query.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(query);
    stream.write_all(&frame).await?;
    stream.flush().await?;

    let len = stream.read_u16().await?;
    let mut response = vec![0u8; usize::from(len)];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

/// RFC 8484 POST over HTTP/1.1, keeping the connection for the next query.
/// Also says whether it can carry one: not when the server closes it, or ends
/// the answer by closing.
async fn doh_post<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    path: &str,
    query: &[u8],
) -> io::Result<(Vec<u8>, bool)> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Captun\r\nAccept: application/dns-message\r\n\
         Content-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        query.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(query);
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let (head_len, body, closes) = loop {
        let n = read_some(stream, &mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoH server closed before responding"));
        }
        buf.extend_from_slice(&chunk[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&buf).map_err(|e| invalid(format!("bad DoH response: {e}")))? {
            httparse::Status::Complete(head_len) => {
                let code = response.code.unwrap_or(0);
                if code != 200 {
                    return Err(io::Error::other(format!("DoH server answered HTTP {code}")));
                }
                let header = |name: &str| {
                    response
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case(name))
                        .and_then(|h| std::str::from_utf8(h.value).ok())
                        .map(str::trim)
                };
                if let Some(ct) = header("content-type")
                    && !ct.to_ascii_lowercase().starts_with("application/dns-message")
                {
                    return Err(invalid(format!("DoH server sent content type {ct:?}")));
                }
                let body = if header("transfer-encoding").is_some_and(|te| te.eq_ignore_ascii_case("chunked")) {
                    Body::Chunked
                } else if let Some(len) = header("content-length") {
                    Body::Length(len.parse().map_err(|_| invalid("bad Content-Length"))?)
                } else {
                    Body::UntilEof
                };
                let closes = header("connection").is_some_and(|c| c.eq_ignore_ascii_case("close"));
                break (head_len, body, closes);
            }
            httparse::Status::Partial if buf.len() < MAX_HTTP_HEAD => continue,
            httparse::Status::Partial => return Err(invalid("DoH response head too large")),
        }
    };

    let mut data = buf.split_off(head_len);
    match body {
        Body::Length(len) => {
            if len > MAX_HTTP_BODY {
                return Err(invalid("DoH response body too large"));
            }
            while data.len() < len {
                let n = read_some(stream, &mut chunk).await?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoH body cut short"));
                }
                data.extend_from_slice(&chunk[..n]);
            }
            // Anything past the body would be read as the next answer.
            let exact = data.len() == len;
            data.truncate(len);
            Ok((data, exact && !closes))
        }
        Body::UntilEof => {
            loop {
                let n = read_some(stream, &mut chunk).await?;
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&chunk[..n]);
                if data.len() > MAX_HTTP_BODY {
                    return Err(invalid("DoH response body too large"));
                }
            }
            Ok((data, false))
        }
        // The chunked framing's last bytes may still be on the way; the
        // connection is not reused, which DoH servers rarely make necessary.
        Body::Chunked => {
            loop {
                if let Some(decoded) = decode_chunked(&data)? {
                    return Ok((decoded, false));
                }
                if data.len() > MAX_HTTP_BODY + MAX_HTTP_HEAD {
                    return Err(invalid("DoH response body too large"));
                }
                let n = read_some(stream, &mut chunk).await?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoH chunked body cut short"));
                }
                data.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

enum Body {
    Length(usize),
    UntilEof,
    Chunked,
}

/// Reads, treating a TLS peer that closes without close_notify as plain EOF:
/// with `Connection: close` many servers simply drop the socket.
async fn read_some<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> io::Result<usize> {
    match stream.read(buf).await {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
        other => other,
    }
}

/// Decodes a complete chunked body, or returns `None` if more bytes are needed.
fn decode_chunked(mut data: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = data.windows(2).position(|w| w == b"\r\n") else { return Ok(None) };
        let size_field = std::str::from_utf8(&data[..line_end]).map_err(|_| invalid("bad chunk size"))?;
        let size_hex = size_field.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| invalid("bad chunk size"))?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        if size > MAX_HTTP_BODY || out.len() + size > MAX_HTTP_BODY {
            return Err(invalid("DoH response body too large"));
        }
        if data.len() < size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use captun_core::EgressId;
    use captun_outbound::Direct;
    use tokio::net::{TcpListener, UdpSocket};

    use super::*;

    /// How long a test server takes to answer a query, by the query's ID;
    /// `None` is never.
    type Delay = Arc<dyn Fn(u16) -> Option<Duration> + Send + Sync>;

    fn at_once() -> Delay {
        Arc::new(|_| Some(Duration::ZERO))
    }

    fn after(wait: Duration) -> Delay {
        Arc::new(move |_| Some(wait))
    }

    /// A DNS-over-TCP server answering each query with itself marked as an
    /// answer, closing after each one with `close`; counts the connections.
    async fn tcp_server(close: bool) -> (String, Arc<AtomicUsize>) {
        tcp_server_on("127.0.0.1:0", close, at_once()).await
    }

    async fn tcp_server_on(bind: &str, close: bool, delay: Delay) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let delay = delay.clone();
                tokio::spawn(async move {
                    loop {
                        let Ok(len) = s.read_u16().await else { return };
                        let mut query = vec![0u8; usize::from(len)];
                        if s.read_exact(&mut query).await.is_err() {
                            return;
                        }
                        match delay(header_id(&query).unwrap_or(0)) {
                            Some(wait) => tokio::time::sleep(wait).await,
                            None => std::future::pending::<()>().await,
                        }
                        query[2] |= 0x80;
                        if s.write_u16(len).await.is_err() || s.write_all(&query).await.is_err() || close {
                            return;
                        }
                    }
                });
            }
        });
        (addr, connections)
    }

    /// A DNS server on UDP answering each query with `size` bytes: the query's
    /// header marked as an answer, then zeros. Counts the queries.
    async fn udp_server(size: usize) -> (String, Arc<AtomicUsize>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                counted.fetch_add(1, Ordering::SeqCst);
                let mut answer = vec![0u8; size];
                answer[..HEADER_LEN].copy_from_slice(&buf[..HEADER_LEN.min(n)]);
                answer[2] |= 0x80;
                let _ = socket.send_to(&answer, peer).await;
            }
        });
        (addr, asked)
    }

    fn upstream_at(protocol: DnsProtocol, address: String) -> Upstream {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let base = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let tls = TlsConfigs { dot: Arc::new(base.clone()), doh: Arc::new(base) };
        let config = DnsUpstreamConfig { id: "local".into(), protocol, address, server_name: None, path: None };
        Upstream::from_config(&config, &tls).unwrap()
    }

    fn tcp_upstream(address: String) -> Upstream {
        upstream_at(DnsProtocol::Tcp, address)
    }

    fn outbound(id: &str) -> Arc<dyn Outbound> {
        Arc::new(Direct::new(EgressId::new(id), None))
    }

    fn device(i: u16) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 137, u8::try_from(i).unwrap()))
    }

    async fn ask(upstream: &Upstream, outbound: &Arc<dyn Outbound>, id: u16) -> io::Result<Vec<u8>> {
        ask_from(upstream, outbound, device(10), id).await
    }

    async fn ask_from(upstream: &Upstream, outbound: &Arc<dyn Outbound>, client: IpAddr, id: u16) -> io::Result<Vec<u8>> {
        let mut query = vec![0u8; HEADER_LEN];
        query[..2].copy_from_slice(&id.to_be_bytes());
        upstream.exchange(&query, outbound, client).await
    }

    /// Asks query `id` from device `device_of(id)` for each id at once.
    fn spawn_asking(
        upstream: &Arc<Upstream>,
        outbound: &Arc<dyn Outbound>,
        ids: std::ops::Range<u16>,
        device_of: impl Fn(u16) -> u16,
    ) -> Vec<tokio::task::JoinHandle<io::Result<Vec<u8>>>> {
        ids.map(|id| {
            let (upstream, outbound, client) = (upstream.clone(), outbound.clone(), device(device_of(id)));
            tokio::spawn(async move { ask_from(&upstream, &outbound, client, id).await })
        })
        .collect()
    }

    /// Asks `count` queries at once from 8 devices, all answered.
    async fn ask_at_once(upstream: &Arc<Upstream>, outbound: &Arc<dyn Outbound>, count: u16) {
        let asking = spawn_asking(upstream, outbound, 0..count, |id| 20 + id % 8);
        for (id, asked) in (0..count).zip(asking) {
            assert_eq!(header_id(&asked.await.unwrap().unwrap()), Some(id));
        }
        assert_eq!(upstream.devices_asking(), 0, "devices with no query left are forgotten");
    }

    async fn ask_three(upstream: &Upstream) {
        let direct = outbound("direct");
        for id in [0x1234u16, 0x5678, 0x9abc] {
            assert_eq!(header_id(&ask(upstream, &direct, id).await.unwrap()), Some(id));
        }
    }

    impl Upstream {
        fn idle_for(&self, outbound: &Arc<dyn Outbound>) -> usize {
            lock(&self.pools).get(&key(outbound)).map_or(0, |pool| pool.idle.len())
        }

        fn idle_total(&self) -> usize {
            lock(&self.pools).values().map(|pool| pool.idle.len()).sum()
        }

        fn devices_asking(&self) -> usize {
            lock(&self.pools).values().map(|pool| pool.devices.len()).sum()
        }

        /// Makes the kept connections look idle `by` longer than they have been.
        fn age_kept(&self, by: Duration) {
            for pool in lock(&self.pools).values_mut() {
                for idle in &mut pool.idle {
                    idle.since = idle.since.checked_sub(by).unwrap();
                }
            }
        }
    }

    #[tokio::test]
    async fn one_connection_carries_many_queries() {
        let (address, connections) = tcp_server(false).await;
        ask_three(&tcp_upstream(address)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_connection_the_server_closed_is_replaced() {
        let (address, connections) = tcp_server(true).await;
        ask_three(&tcp_upstream(address)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 3, "each query after a close went over a new connection");
    }

    #[tokio::test]
    async fn a_burst_of_queries_shares_32_connections() {
        let (address, connections) = tcp_server_on("127.0.0.1:0", false, after(Duration::from_millis(50))).await;
        let upstream = Arc::new(tcp_upstream(address));
        let direct = outbound("direct");
        ask_at_once(&upstream, &direct, 100).await;
        assert_eq!(connections.load(Ordering::SeqCst), STREAMS_AT_ONCE, "the others waited their turn and took one of these");
        assert_eq!(upstream.idle_total(), KEEP_PER_OUTBOUND, "once all are answered, the others are closed");
    }

    #[tokio::test]
    async fn a_server_that_does_not_answer_gets_32_connections_at_most() {
        let (address, connections) = tcp_server_on("127.0.0.1:0", false, Arc::new(|_| None)).await;
        let upstream = Arc::new(tcp_upstream(address));
        let direct = outbound("direct");
        let started = Instant::now();
        // 5 devices with 8 queries each.
        let asking = spawn_asking(&upstream, &direct, 0..40, |id| 20 + id % 5);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(connections.load(Ordering::SeqCst), STREAMS_AT_ONCE, "the other 8 wait for a turn");
        let mut timed_out = 0;
        for asked in asking {
            // A waiting one whose time ends a moment after the others' may get
            // a turn and then time out itself.
            match asked.await.unwrap().unwrap_err().kind() {
                io::ErrorKind::TimedOut => timed_out += 1,
                kind => assert_eq!(kind, io::ErrorKind::ResourceBusy),
            }
        }
        assert!(timed_out >= STREAMS_AT_ONCE);
        assert!(started.elapsed() < QUERY_TIMEOUT + Duration::from_secs(1), "those waiting for a turn gave up in time too");
        assert_eq!((upstream.idle_total(), upstream.devices_asking()), (0, 0));
    }

    #[tokio::test]
    async fn one_device_does_not_take_the_turns_of_the_others() {
        // Device 1's names take 4 s to look up, as when their own name
        // servers are slow; device 2's are found at once.
        let slow: Delay = Arc::new(|id| Some(if id < 1000 { Duration::from_secs(4) } else { Duration::ZERO }));
        let (address, connections) = tcp_server_on("127.0.0.1:0", false, slow).await;
        let upstream = Arc::new(tcp_upstream(address));
        let direct = outbound("direct");
        let flood = spawn_asking(&upstream, &direct, 0..40, |_| 1);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(connections.load(Ordering::SeqCst), TURNS_PER_DEVICE, "the rest wait for the device's own turns");

        let asked = Instant::now();
        assert_eq!(header_id(&ask_from(&upstream, &direct, device(2), 1000).await.unwrap()), Some(1000));
        assert!(asked.elapsed() < Duration::from_secs(1), "the other device got a turn at once");

        let (mut answered, mut busy) = (0, 0);
        for asked in flood {
            match asked.await.unwrap() {
                Ok(_) => answered += 1,
                Err(e) if e.kind() == io::ErrorKind::ResourceBusy => busy += 1,
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            }
        }
        assert_eq!(answered, TURNS_PER_DEVICE, "the first 8 were answered after 4 s, the next 8 asked then");
        // The 24 never asked say so, also those handed a turn as the 8 asked
        // second ran out of time; up to 8 whose time ends a moment later may
        // still ask.
        assert!(busy >= 40 - 3 * TURNS_PER_DEVICE, "{busy}");
        assert_eq!(upstream.devices_asking(), 0);
    }

    #[tokio::test]
    async fn a_query_that_never_got_a_turn_does_not_blame_the_server() {
        let (address, connections) = tcp_server(false).await;
        let upstream = tcp_upstream(address);
        let direct = outbound("direct");
        // Other queries hold every turn.
        let turns = lock(&upstream.pools).entry(key(&direct)).or_insert_with(|| Pool::new(&direct)).turns.clone();
        let held = turns.acquire_many_owned(u32::try_from(STREAMS_AT_ONCE).unwrap()).await.unwrap();

        let e = ask(&upstream, &direct, 1).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ResourceBusy);
        assert!(!crate::reach::cannot_reach(&e), "it was never sent");
        assert_eq!(e.to_string(), "too many queries waiting for DNS server local");
        assert_eq!((connections.load(Ordering::SeqCst), upstream.devices_asking()), (0, 0));

        drop(held);
        assert_eq!(header_id(&ask(&upstream, &direct, 2).await.unwrap()), Some(2));
    }

    #[tokio::test]
    async fn idle_connections_are_kept_16_per_outbound_and_64_in_all() {
        let (address, _) = tcp_server_on("127.0.0.1:0", false, after(Duration::from_millis(20))).await;
        let upstream = Arc::new(tcp_upstream(address));
        let outbounds: Vec<_> = (0..5).map(|i| outbound(&format!("out{i}"))).collect();
        for outbound in &outbounds {
            ask_at_once(&upstream, outbound, 16).await;
            assert_eq!(upstream.idle_for(outbound), KEEP_PER_OUTBOUND);
        }
        let kept: Vec<_> = outbounds.iter().map(|outbound| upstream.idle_for(outbound)).collect();
        assert_eq!(kept, [0, 16, 16, 16, 16], "the ones put back longest ago went first");
        assert_eq!(upstream.idle_total(), KEEP_AT_MOST);
    }

    #[tokio::test]
    async fn an_outbound_rebuilt_under_the_same_id_opens_its_own_connections() {
        let (address, connections) = tcp_server(false).await;
        let upstream = tcp_upstream(address);
        let first = outbound("proxy");
        ask(&upstream, &first, 1).await.unwrap();
        let other = outbound("proxy");
        ask(&upstream, &other, 2).await.unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 2, "two outbounds alive under one id share nothing");

        drop(first);
        let rebuilt = outbound("proxy");
        ask(&upstream, &rebuilt, 3).await.unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 3, "the old one's connection is not reused");
        assert_eq!((upstream.idle_for(&other), upstream.idle_for(&rebuilt)), (1, 1));
        assert_eq!(lock(&upstream.pools).len(), 2, "the old one's connection was closed and the outbound forgotten");
    }

    /// The server takes 2 s over query 2, longer than a doubtful connection
    /// is given.
    fn slow_second() -> Delay {
        Arc::new(|id| Some(if id == 2 { Duration::from_secs(2) } else { Duration::ZERO }))
    }

    #[tokio::test]
    async fn a_connection_used_moments_ago_is_waited_for() {
        let (address, connections) = tcp_server_on("127.0.0.1:0", false, slow_second()).await;
        let upstream = tcp_upstream(address);
        let direct = outbound("direct");
        ask(&upstream, &direct, 1).await.unwrap();
        let asked = Instant::now();
        assert_eq!(header_id(&ask(&upstream, &direct, 2).await.unwrap()), Some(2));
        assert!(asked.elapsed() >= Duration::from_millis(1900));
        assert_eq!(connections.load(Ordering::SeqCst), 1, "asked once, on the kept connection");
    }

    #[tokio::test]
    async fn a_connection_idle_a_while_is_given_up_on_soon() {
        let (address, connections) = tcp_server_on("127.0.0.1:0", false, slow_second()).await;
        let upstream = tcp_upstream(address);
        let direct = outbound("direct");
        ask(&upstream, &direct, 1).await.unwrap();
        upstream.age_kept(TRUST_KEPT_FOR + Duration::from_secs(1));
        let asked = Instant::now();
        assert_eq!(header_id(&ask(&upstream, &direct, 2).await.unwrap()), Some(2));
        assert!(asked.elapsed() >= KEPT_ANSWER_WITHIN + Duration::from_millis(1900), "then asked again on a new one");
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn udp_answers_that_may_not_fit_are_asked_for_again_over_tcp() {
        for (size, fits) in [(UDP_BUFFER + 1000, false), (UDP_BUFFER, false), (UDP_BUFFER - 1, true)] {
            let (address, udp_asked) = udp_server(size).await;
            let (_, connections) = tcp_server_on(&address, false, at_once()).await;
            let upstream = upstream_at(DnsProtocol::Udp, address);
            let answer = ask(&upstream, &outbound("direct"), 7).await.unwrap();
            assert_eq!(udp_asked.load(Ordering::SeqCst), 1, "{size}");
            if fits {
                assert_eq!((answer.len(), connections.load(Ordering::SeqCst)), (size, 0), "{size}");
            } else {
                assert_eq!((answer.len(), connections.load(Ordering::SeqCst)), (HEADER_LEN, 1), "{size}");
            }
        }
    }

    #[test]
    fn chunked_decoding() {
        assert_eq!(decode_chunked(b"3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\n\r\n").unwrap().unwrap(), b"abcde");
        assert!(decode_chunked(b"3\r\nab").unwrap().is_none());
        assert!(decode_chunked(b"zz\r\n").is_err());
    }
}
