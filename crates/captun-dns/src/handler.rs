use std::{
    collections::HashMap,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use captun_core::{config::BlockResponse, domain::normalize_domain, time::now_millis};
use captun_outbound::Outbound;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    DnsRouter, DnsSettings, Outcome, QueryEvent, QueryObserver, Transport, Upstream,
    cache::{CacheKey, DnsCache, aged_answer, cacheable_ttl},
    message::{
        ADVERTISED_PAYLOAD, MAX_UDP_PAYLOAD, answered_addrs, describe_answers, format_error, header_id, is_response,
        our_edns, response_to,
    },
    reach::{Reach, cannot_reach},
};

/// TTL for answers we synthesize (blocked names, overrides, the system
/// resolver's answers).
const LOCAL_TTL: u32 = 60;
/// Budget for one lookup by the system resolver.
const SYSTEM_TIMEOUT: Duration = Duration::from_secs(5);
/// Lookups by the system resolver running at once. Each holds a thread until
/// it ends, which can be long after the device was told it failed ...
const MAX_SYSTEM_LOOKUPS: usize = 16;
/// ... and for one device, so one whose names never resolve leaves places for
/// the others.
const MAX_SYSTEM_LOOKUPS_PER_DEVICE: usize = 4;
/// The system resolver's answers are kept this long at most, so a burst of
/// queries for the same names takes one lookup each ...
const SYSTEM_KEEP_SECS: u32 = 30;
/// ... and this many of them.
const SYSTEM_KEEP_AT_MOST: usize = 1024;
/// Queries being answered at once, over all devices; more are dropped and the
/// devices ask again.
const MAX_IN_FLIGHT: usize = 1024;
/// Queries one device may have being answered at once, so a device that
/// floods queries leaves the others most of [`MAX_IN_FLIGHT`].
const MAX_IN_FLIGHT_PER_DEVICE: usize = 64;
/// What localhost names stand for (RFC 6761).
const LOOPBACK: [IpAddr; 2] = [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A DNS server's id and the id of the outbound it is reached through.
type ServerVia = (String, String);

/// Looks up a name's addresses; blocks.
type Resolve = Arc<dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync>;

/// Resolves one query at a time; shared by the UDP and TCP servers. All locks
/// are synchronous and never held across an await.
pub struct DnsHandler {
    settings: RwLock<Arc<DnsSettings>>,
    cache: Mutex<DnsCache>,
    /// Whether each DNS server can be reached on each outbound, for routes
    /// that can fall back to the system resolver. A server that answered last
    /// has no entry.
    reach: Mutex<HashMap<ServerVia, Reach>>,
    system: SystemDns,
    /// Queries being answered at once ([`Self::admit`]).
    queries: Places,
    router: Arc<dyn DnsRouter>,
    observer: Option<Arc<dyn QueryObserver>>,
}

/// This computer's own resolver, which answers devices that go out directly
/// when their DNS server cannot be reached.
struct SystemDns {
    /// Lookups running: [`MAX_SYSTEM_LOOKUPS`], and
    /// [`MAX_SYSTEM_LOOKUPS_PER_DEVICE`] for one device.
    running: Places,
    /// Tests put a stand-in here.
    resolve: Resolve,
    timeout: Duration,
    /// Answers kept for [`SYSTEM_KEEP_SECS`], apart from the DNS servers'
    /// answers: they are given only while a server cannot be reached.
    kept: Mutex<DnsCache>,
}

/// A limited number of places, for all devices together and for each one.
#[derive(Debug)]
struct Places {
    all: Arc<Semaphore>,
    each: usize,
    /// Places taken by each device, by address. A device with none has no
    /// entry, so there are never more entries than places.
    taken: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Places {
    fn new(all: usize, each: usize) -> Self {
        Self { all: Arc::new(Semaphore::new(all)), each, taken: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// A place for `client`, or `None` when all are taken or the device has
    /// its share.
    fn take(&self, client: IpAddr) -> Option<Place> {
        // However its address is written, a device counts once.
        let client = client.to_canonical();
        let mut taken = lock(&self.taken);
        let count = taken.get(&client).copied().unwrap_or(0);
        if count >= self.each {
            return None;
        }
        let permit = self.all.clone().try_acquire_owned().ok()?;
        taken.insert(client, count + 1);
        Some(Place { client, taken: self.taken.clone(), _permit: permit })
    }
}

/// One of [`Places`], given back when dropped.
#[derive(Debug)]
struct Place {
    client: IpAddr,
    taken: Arc<Mutex<HashMap<IpAddr, usize>>>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut taken = lock(&self.taken);
        if let Some(count) = taken.get_mut(&self.client) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                taken.remove(&self.client);
            }
        }
    }
}

/// A query let in by [`DnsHandler::admit`]. It counts against the limits until
/// this is dropped.
#[derive(Debug)]
#[must_use = "the query counts as being answered only while this is kept"]
pub struct Admitted {
    _place: Place,
}

impl fmt::Debug for DnsHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsHandler")
            .field("cached", &lock(&self.cache).len())
            .field("in_flight", &MAX_IN_FLIGHT.saturating_sub(self.queries.all.available_permits()))
            .finish_non_exhaustive()
    }
}

impl DnsHandler {
    pub fn new(settings: DnsSettings, router: Arc<dyn DnsRouter>, observer: Option<Arc<dyn QueryObserver>>) -> Self {
        let cache = DnsCache::new(settings.cache_size);
        let system = SystemDns {
            running: Places::new(MAX_SYSTEM_LOOKUPS, MAX_SYSTEM_LOOKUPS_PER_DEVICE),
            resolve: Arc::new(resolve_here),
            timeout: SYSTEM_TIMEOUT,
            kept: Mutex::new(DnsCache::new(settings.cache_size.min(SYSTEM_KEEP_AT_MOST))),
        };
        Self {
            settings: RwLock::new(Arc::new(settings)),
            cache: Mutex::new(cache),
            reach: Mutex::new(HashMap::new()),
            system,
            queries: Places::new(MAX_IN_FLIGHT, MAX_IN_FLIGHT_PER_DEVICE),
            router,
            observer,
        }
    }

    /// Hot reload. The cache is cleared because upstreams, overrides or the
    /// blocklist may have changed what a name should resolve to; what was
    /// learned about reaching the DNS servers goes too, as their addresses may
    /// have changed.
    pub fn update_settings(&self, settings: DnsSettings) {
        let capacity = settings.cache_size;
        *self.settings.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(settings);
        lock(&self.cache).clear(capacity);
        lock(&self.system.kept).clear(capacity.min(SYSTEM_KEEP_AT_MOST));
        lock(&self.reach).clear();
    }

    fn settings(&self) -> Arc<DnsSettings> {
        self.settings.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Lets one UDP query from `client` in to be answered, or `None` when too
    /// many are being answered already, over all devices or for this one: the
    /// caller then drops the query and the device asks again. The query counts
    /// until the [`Admitted`] is dropped, so keep it until the answer is sent.
    /// The hub's UDP server and the engine's path share these limits.
    pub fn admit(&self, client: IpAddr) -> Option<Admitted> {
        self.queries.take(client).map(|place| Admitted { _place: place })
    }

    /// Answers one wire-format query. `None` means "send nothing": the input
    /// was too short to be DNS, or was itself a response.
    pub async fn handle(&self, query: &[u8], client: IpAddr, transport: Transport) -> Option<Vec<u8>> {
        let started = Instant::now();
        header_id(query)?;
        if is_response(query) {
            return None;
        }
        let Ok(request) = Message::from_vec(query) else { return format_error(query) };
        if request.message_type() != MessageType::Query
            || request.op_code() != OpCode::Query
            || request.queries().len() != 1
        {
            return finish(response_to(&request, ResponseCode::NotImp), &request, transport);
        }

        let question = request.queries()[0].clone();
        let name = normalize_domain(&question.name().to_ascii()).into_owned();
        let route = self.router.route(client, &name);
        let (response, outcome, upstream) = self.resolve(&request, &question, &name, route.as_ref(), client).await;

        if let Some(observer) = &self.observer {
            observer.on_query(QueryEvent {
                at_ms: now_millis(),
                client: route.as_ref().and_then(|r| r.client),
                client_ip: client,
                name,
                qtype: question.query_type().to_string(),
                outcome,
                answers: describe_answers(&response),
                addrs: answered_addrs(&response),
                upstream,
                latency_ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
            });
        }
        finish(response, &request, transport)
    }

    async fn resolve(
        &self,
        request: &Message,
        question: &Query,
        name: &str,
        route: Option<&crate::DnsRoute>,
        client: IpAddr,
    ) -> (Message, Outcome, Option<String>) {
        let settings = self.settings();
        let qtype = question.query_type();

        if settings.blocklist.matches(name) {
            return (blocked(request, qtype, settings.block_response), Outcome::Blocked, None);
        }
        if let Some(addrs) = settings.override_for(name) {
            return (local_answer(request, qtype, addrs), Outcome::Override, None);
        }
        let Some(route) = route else {
            return (response_to(request, ResponseCode::Refused), Outcome::Refused, None);
        };
        if route.blocked {
            return (blocked(request, qtype, settings.block_response), Outcome::Blocked, None);
        }
        let upstream_id = Some(route.upstream.clone());
        let Some(upstream) = settings.upstream(&route.upstream) else {
            tracing::warn!(upstream = %route.upstream, "DNS route points at an unknown upstream");
            return (response_to(request, ResponseCode::ServFail), Outcome::Failed, upstream_id);
        };

        let key = CacheKey {
            upstream: route.upstream.clone(),
            outbound: route.outbound.id().to_string(),
            name: question.name().to_lowercase(),
            qtype,
            qclass: question.query_class(),
        };
        if let Some(cached) = cached_reply(&self.cache, &key, request) {
            return (cached, Outcome::Cached, upstream_id);
        }

        // A DNS server that cannot be reached on this outbound is not waited
        // on by every query, when the computer's own resolver can answer.
        let via = (key.upstream.clone(), key.outbound.clone());
        if route.system_fallback && !self.asks_server(&via) {
            let (response, outcome) = self.system_answer(request, qtype, name, &key, &settings, client).await;
            return (response, outcome, upstream_id);
        }

        match forward(upstream, request, &key, &route.outbound, client).await {
            Ok((response, raw)) => {
                if route.system_fallback {
                    self.answered(&via);
                }
                if let Some(ttl) = cacheable_ttl(&response, settings.min_ttl, settings.max_ttl) {
                    // Copied to an exact-size buffer before the lock is taken.
                    let wire: Arc<[u8]> = raw.into();
                    lock(&self.cache).insert(key, wire, ttl, Instant::now());
                }
                let outcome = match response.response_code() {
                    ResponseCode::NoError => Outcome::NoError,
                    ResponseCode::NXDomain => Outcome::NxDomain,
                    ResponseCode::ServFail => Outcome::ServFail,
                    ResponseCode::Refused => Outcome::Refused,
                    _ => Outcome::Failed,
                };
                (response, outcome, upstream_id)
            }
            // This query is answered by the computer's own resolver whatever
            // the error; only those that say the server cannot be reached
            // count towards skipping it for everyone (see `Reach`).
            Err(e) if route.system_fallback => {
                tracing::debug!(server = %via.0, outbound = %via.1, %name, "DNS server failed ({e}); asking this computer's DNS");
                if cannot_reach(&e) {
                    self.not_reached(&via, &e);
                }
                let (response, outcome) = self.system_answer(request, qtype, name, &key, &settings, client).await;
                (response, outcome, upstream_id)
            }
            Err(e) => {
                tracing::debug!(upstream = %route.upstream, %name, "DNS upstream failed: {e}");
                (response_to(request, ResponseCode::ServFail), Outcome::Failed, upstream_id)
            }
        }
    }

    /// Whether this query asks the DNS server: always, unless the server
    /// cannot be reached on this outbound (see [`Reach`]).
    fn asks_server(&self, via: &ServerVia) -> bool {
        lock(&self.reach).get_mut(via).is_none_or(|reach| reach.should_ask(Instant::now()))
    }

    /// The server answered: the errors before no longer count.
    fn answered(&self, via: &ServerVia) {
        // Its own statement, so the lock is let go before logging.
        let known = lock(&self.reach).remove(via);
        if known.is_some_and(|reach| reach.unreachable()) {
            tracing::info!(server = %via.0, outbound = %via.1, "DNS server answers again");
        }
    }

    fn not_reached(&self, via: &ServerVia, e: &io::Error) {
        let marked = lock(&self.reach).entry(via.clone()).or_default().failed(Instant::now());
        if marked {
            tracing::info!(
                server = %via.0,
                outbound = %via.1,
                "DNS server cannot be reached ({e}); devices that go out directly get this computer's DNS answers until it answers again"
            );
        }
    }

    /// Answers from this computer's own resolver, which only looks up
    /// addresses: other record types get an empty answer.
    async fn system_answer(
        &self,
        request: &Message,
        qtype: RecordType,
        name: &str,
        key: &CacheKey,
        settings: &DnsSettings,
        client: IpAddr,
    ) -> (Message, Outcome) {
        let failed = || (response_to(request, ResponseCode::ServFail), Outcome::Failed);
        if !matches!(qtype, RecordType::A | RecordType::AAAA) {
            return (response_to(request, ResponseCode::NoError), Outcome::System);
        }
        // Localhost names are the device itself (RFC 6761): nobody needs asking.
        if name == "localhost" || name.ends_with(".localhost") {
            return (local_answer(request, qtype, &LOOPBACK), Outcome::System);
        }
        // The resolver would look for these on this computer's own networks
        // (LLMNR, NetBIOS, mDNS): slowly, and what it finds there is not for
        // the devices to see.
        if !name.contains('.') || name.ends_with(".local") {
            return failed();
        }
        if let Some(kept) = cached_reply(&self.system.kept, key, request) {
            return (kept, Outcome::System);
        }
        // The resolver does not say whether the name is missing or the lookup
        // failed; a failure lets the device try again.
        let Some(addrs) = self.system.lookup(name, client).await else { return failed() };
        let response = local_answer(request, qtype, &addrs);
        if let Ok(wire) = response.to_vec() {
            let keep = SYSTEM_KEEP_SECS.min(settings.max_ttl);
            lock(&self.system.kept).insert(key.clone(), wire.into(), keep, Instant::now());
        }
        (response, Outcome::System)
    }
}

impl SystemDns {
    /// The addresses `name` has, or `None` when the lookup failed, took too
    /// long, or [`MAX_SYSTEM_LOOKUPS`] are running already, or
    /// [`MAX_SYSTEM_LOOKUPS_PER_DEVICE`] for `client`.
    async fn lookup(&self, name: &str, client: IpAddr) -> Option<Vec<IpAddr>> {
        let place = self.running.take(client)?;
        let (resolve, name) = (self.resolve.clone(), name.to_owned());
        // A lookup cannot be stopped, so it keeps its place (and its thread)
        // until it ends, even when the device has been told it failed.
        let lookup = tokio::task::spawn_blocking(move || {
            let _place = place;
            resolve(&name)
        });
        match tokio::time::timeout(self.timeout, lookup).await {
            Ok(Ok(Ok(addrs))) => Some(addrs),
            _ => None,
        }
    }
}

/// Looks `name` up the way programs on this computer do.
fn resolve_here(name: &str) -> io::Result<Vec<IpAddr>> {
    Ok((name, 0).to_socket_addrs()?.map(|addr| addr.ip()).collect())
}

/// The answer to `key` kept in `cache`, as the reply to `request`.
fn cached_reply(cache: &Mutex<DnsCache>, key: &CacheKey, request: &Message) -> Option<Message> {
    // Its own statement, so the lock is let go before the answer is parsed.
    let (wire, elapsed) = lock(cache).get(key, Instant::now())?;
    let mut cached = aged_answer(&wire, elapsed)?;
    cached.set_id(request.id());
    // Echo the client's own spelling of the question (0x20 case
    // randomization checks rely on it).
    *cached.queries_mut() = request.queries().to_vec();
    Some(cached)
}

/// Re-encodes the query with a fresh random ID (cache-poisoning defence:
/// the client's ID is predictable to whoever sent it) and an EDNS payload
/// size, so large answers rarely need a TCP retry. Also gives the answer's
/// bytes as they came, which is what the cache keeps.
async fn forward(
    upstream: &Upstream,
    request: &Message,
    key: &CacheKey,
    outbound: &Arc<dyn Outbound>,
    client: IpAddr,
) -> io::Result<(Message, Vec<u8>)> {
    let mut outgoing = request.clone();
    outgoing.set_id(rand::random());
    // At most 1232 bytes, whatever the device asked for: a bigger UDP answer
    // comes in IP fragments, which get lost on the way and are easier to
    // forge. A bigger answer comes truncated and is asked for over TCP.
    if let Some(edns) = outgoing.extensions_mut() {
        let size = edns.max_payload().min(ADVERTISED_PAYLOAD);
        edns.set_max_payload(size);
    } else {
        outgoing.set_edns(our_edns());
    }
    let wire = outgoing.to_vec().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let raw = upstream.exchange(&wire, outbound, client).await?;

    let mut response =
        Message::from_vec(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let answers_our_question = response
        .queries()
        .first()
        .is_some_and(|q| q.name().to_lowercase() == key.name && q.query_type() == key.qtype && q.query_class() == key.qclass);
    if !answers_our_question {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "upstream answered a different question"));
    }
    response.set_id(request.id());
    *response.queries_mut() = request.queries().to_vec();
    Ok((response, raw))
}

fn blocked(request: &Message, qtype: RecordType, mode: BlockResponse) -> Message {
    match mode {
        BlockResponse::NxDomain => response_to(request, ResponseCode::NXDomain),
        BlockResponse::Refused => response_to(request, ResponseCode::Refused),
        BlockResponse::NullIp => {
            local_answer(request, qtype, &[IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V6(Ipv6Addr::UNSPECIFIED)])
        }
    }
}

/// Answers A/AAAA from `addrs`; any other type (or a family with no address)
/// gets NOERROR with no records, i.e. NODATA, so clients stop asking.
fn local_answer(request: &Message, qtype: RecordType, addrs: &[IpAddr]) -> Message {
    let mut response = response_to(request, ResponseCode::NoError);
    let owner = request.queries()[0].name().clone();
    for addr in addrs {
        let rdata = match (qtype, addr) {
            (RecordType::A, IpAddr::V4(v4)) => RData::A(A(*v4)),
            (RecordType::AAAA, IpAddr::V6(v6)) => RData::AAAA(AAAA(*v6)),
            _ => continue,
        };
        response.add_answer(Record::from_rdata(owner.clone(), LOCAL_TTL, rdata));
    }
    response
}

/// Serializes the response for the transport: OPT only if the client sent
/// one (RFC 6891), and UDP answers that exceed the client's advertised size
/// are replaced by an empty TC response so it retries over TCP.
fn finish(mut response: Message, request: &Message, transport: Transport) -> Option<Vec<u8>> {
    if request.extensions().is_none() {
        *response.extensions_mut() = None;
    } else {
        response.set_edns(our_edns());
    }
    let wire = match response.to_vec() {
        Ok(wire) => wire,
        Err(e) => {
            tracing::warn!("cannot encode DNS response: {e}");
            return response_to(request, ResponseCode::ServFail).to_vec().ok();
        }
    };
    if transport == Transport::Udp {
        let limit = usize::from(request.max_payload().min(MAX_UDP_PAYLOAD));
        if wire.len() > limit {
            return response.truncate().to_vec().ok();
        }
    }
    Some(wire)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{
            Condvar,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use hickory_proto::rr::Name;
    use captun_core::{
        EgressId,
        config::{DnsConfig, DnsProtocol, DnsUpstreamConfig},
    };
    use captun_outbound::Direct;
    use tokio::net::UdpSocket;

    use super::*;
    use crate::{
        DnsRoute,
        reach::{MARK_AFTER, TRY_EVERY},
    };

    const DEVICE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 137, 10));
    /// What the stand-in for this computer's resolver finds.
    const FOUND: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    /// What the DNS server finds.
    const SERVER_FOUND: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));

    /// Every query goes out directly to DNS server "u", and may be answered
    /// by this computer's resolver instead.
    struct GoesDirect(Arc<dyn Outbound>);

    impl DnsRouter for GoesDirect {
        fn route(&self, _client: IpAddr, _name: &str) -> Option<DnsRoute> {
            Some(DnsRoute { upstream: "u".into(), outbound: self.0.clone(), client: None, system_fallback: true, blocked: false })
        }
    }

    /// A handler whose DNS server "u" is at `server`, over UDP.
    fn handler(server: SocketAddr) -> DnsHandler {
        let upstream =
            DnsUpstreamConfig { id: "u".into(), protocol: DnsProtocol::Udp, address: server.to_string(), server_name: None, path: None };
        let config = DnsConfig { default_upstream: "u".into(), upstreams: vec![upstream], ..DnsConfig::default() };
        let direct: Arc<dyn Outbound> = Arc::new(Direct::new(EgressId::new("direct"), None));
        DnsHandler::new(DnsSettings::from_config(&config).unwrap(), Arc::new(GoesDirect(direct)), None)
    }

    fn nowhere() -> SocketAddr {
        "127.0.0.1:9".parse().unwrap()
    }

    /// Server "u" counts as unreachable, and was last tried at `at`.
    fn unreachable_since(h: &DnsHandler, at: Instant) {
        let mut reach = Reach::default();
        for _ in 0..MARK_AFTER {
            reach.failed(at);
        }
        lock(&h.reach).insert(("u".into(), "direct".into()), reach);
    }

    /// Server "u" counts as unreachable and is not tried again during a test.
    fn unreachable(h: &DnsHandler) {
        unreachable_since(h, Instant::now() + Duration::from_secs(3600));
    }

    /// Puts a stand-in for this computer's resolver in place that finds every
    /// name at [`FOUND`], and counts the lookups.
    fn counted_lookups(h: &mut DnsHandler) -> Arc<AtomicUsize> {
        let lookups = Arc::new(AtomicUsize::new(0));
        let counted = lookups.clone();
        h.system.resolve = Arc::new(move |_name: &str| -> io::Result<Vec<IpAddr>> {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(vec![FOUND])
        });
        lookups
    }

    /// Lets the lookups of a stand-in for this computer's resolver through
    /// (all at once, from then on) when opened.
    type Gate = Arc<(Mutex<bool>, Condvar)>;

    fn open(gate: &Gate) {
        *lock(&gate.0) = true;
        gate.1.notify_all();
    }

    /// Puts a stand-in for this computer's resolver in place whose lookups
    /// each say when they start, then wait until the gate opens (20 s at most,
    /// so that a failing test still ends) and find the name at [`FOUND`].
    fn held_lookups(h: &mut DnsHandler) -> (tokio::sync::mpsc::UnboundedReceiver<()>, Gate) {
        let (entered, started) = tokio::sync::mpsc::unbounded_channel();
        let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
        let held = gate.clone();
        h.system.resolve = Arc::new(move |_name: &str| -> io::Result<Vec<IpAddr>> {
            let _ = entered.send(());
            let (open, opened) = &*held;
            let _ = opened.wait_timeout_while(lock(open), Duration::from_secs(20), |open| !*open);
            Ok(vec![FOUND])
        });
        (started, gate)
    }

    async fn ask(h: &DnsHandler, name: &str, qtype: RecordType) -> Message {
        ask_from(h, DEVICE, name, qtype).await
    }

    async fn ask_from(h: &DnsHandler, client: IpAddr, name: &str, qtype: RecordType) -> Message {
        let mut query = Message::new();
        query
            .set_id(7)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            // As spelled: `from_str` would lowercase it.
            .add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        let answer = h.handle(&query.to_vec().unwrap(), client, Transport::Udp).await.unwrap();
        Message::from_vec(&answer).unwrap()
    }

    /// A DNS server on UDP that finds every name at [`SERVER_FOUND`]; counts
    /// the queries.
    async fn answering_server() -> (SocketAddr, Arc<AtomicUsize>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(received) => received,
                    // Windows reports an earlier ICMP port-unreachable here.
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                    Err(_) => return,
                };
                counted.fetch_add(1, Ordering::SeqCst);
                let request = Message::from_vec(&buf[..n]).unwrap();
                let answer = local_answer(&request, RecordType::A, &[SERVER_FOUND]);
                let _ = socket.send_to(&answer.to_vec().unwrap(), peer).await;
            }
        });
        (addr, asked)
    }

    fn device(i: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 137, i))
    }

    #[test]
    fn a_device_may_have_64_queries_answered_at_once() {
        let h = handler(nowhere());
        let mut first: Vec<Admitted> = (0..MAX_IN_FLIGHT_PER_DEVICE).map(|_| h.admit(device(1)).unwrap()).collect();
        assert!(h.admit(device(1)).is_none(), "the 65th is dropped");
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 168, 137, 1).to_ipv6_mapped());
        assert!(h.admit(mapped).is_none(), "however its address is written");
        let other = h.admit(device(2));
        assert!(other.is_some(), "other devices are not held up");

        first.pop();
        first.push(h.admit(device(1)).unwrap());
        assert!(h.admit(device(1)).is_none(), "one answered made room for one more");

        drop((first, other));
        assert!(lock(&h.queries.taken).is_empty(), "devices with nothing being answered are not kept");
        assert_eq!(h.queries.all.available_permits(), MAX_IN_FLIGHT);
    }

    #[test]
    fn all_devices_together_may_have_1024() {
        let h = handler(nowhere());
        let devices = u8::try_from(MAX_IN_FLIGHT / MAX_IN_FLIGHT_PER_DEVICE).unwrap();
        let mut all = Vec::new();
        for i in 0..devices {
            for _ in 0..MAX_IN_FLIGHT_PER_DEVICE {
                all.push(h.admit(device(10 + i)).unwrap());
            }
        }
        assert!(h.admit(device(200)).is_none(), "even a device with none being answered waits");
        all.pop();
        let next = h.admit(device(200));
        assert!(next.is_some());
        drop((all, next));
        assert!(lock(&h.queries.taken).is_empty());
        assert_eq!(h.queries.all.available_permits(), MAX_IN_FLIGHT);
    }

    /// Asks for `count` names from `client` at once, each looked up by this
    /// computer's resolver.
    fn lookups_from(h: &Arc<DnsHandler>, client: IpAddr, count: usize) -> Vec<tokio::task::JoinHandle<Message>> {
        (0..count)
            .map(|i| {
                let h = h.clone();
                tokio::spawn(async move { ask_from(&h, client, &format!("n{i}.{client}.test."), RecordType::A).await })
            })
            .collect()
    }

    #[tokio::test]
    async fn at_most_16_lookups_by_this_computer_run_at_once() {
        let mut h = handler(nowhere());
        let (mut started, gate) = held_lookups(&mut h);
        h.system.timeout = Duration::from_secs(2);
        unreachable(&h);
        let h = Arc::new(h);

        let devices = u8::try_from(MAX_SYSTEM_LOOKUPS / MAX_SYSTEM_LOOKUPS_PER_DEVICE).unwrap();
        let lookups: Vec<_> =
            (0..devices).flat_map(|i| lookups_from(&h, device(10 + i), MAX_SYSTEM_LOOKUPS_PER_DEVICE)).collect();
        for _ in 0..MAX_SYSTEM_LOOKUPS {
            started.recv().await.unwrap();
        }
        let asked = Instant::now();
        assert_eq!(ask(&h, "late.test.", RecordType::A).await.response_code(), ResponseCode::ServFail);
        assert!(asked.elapsed() < Duration::from_secs(1), "the 17th is told at once");

        // Given up on after their time, the lookups keep their places until
        // they end: one each.
        for lookup in lookups {
            assert_eq!(lookup.await.unwrap().response_code(), ResponseCode::ServFail);
        }
        assert_eq!(h.system.running.all.available_permits(), 0);
        assert_eq!(ask(&h, "late.test.", RecordType::A).await.response_code(), ResponseCode::ServFail);

        open(&gate);
        let deadline = Instant::now() + Duration::from_secs(10);
        while h.system.running.all.available_permits() < MAX_SYSTEM_LOOKUPS {
            assert!(Instant::now() < deadline, "the lookups ended and gave their places back");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(lock(&h.system.running.taken).is_empty());
        assert_eq!(answered_addrs(&ask(&h, "late.test.", RecordType::A).await), [FOUND]);
    }

    #[tokio::test]
    async fn one_device_gets_4_of_this_computers_lookups_at_once() {
        let mut h = handler(nowhere());
        let (mut started, gate) = held_lookups(&mut h);
        unreachable(&h);
        let h = Arc::new(h);

        let first = lookups_from(&h, device(1), MAX_SYSTEM_LOOKUPS_PER_DEVICE);
        for _ in 0..MAX_SYSTEM_LOOKUPS_PER_DEVICE {
            started.recv().await.unwrap();
        }
        let asked = Instant::now();
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 168, 137, 1).to_ipv6_mapped());
        for client in [device(1), mapped] {
            let answer = ask_from(&h, client, "fifth.test.", RecordType::A).await;
            assert_eq!(answer.response_code(), ResponseCode::ServFail, "{client}");
        }
        assert!(asked.elapsed() < Duration::from_secs(1), "the device's 5th is told at once, however its address is written");

        // Another device's lookup still runs.
        let other = lookups_from(&h, device(2), 1);
        tokio::time::timeout(Duration::from_secs(5), started.recv()).await.unwrap().unwrap();
        open(&gate);
        for lookup in first.into_iter().chain(other) {
            assert_eq!(answered_addrs(&lookup.await.unwrap()), [FOUND]);
        }
        assert!(lock(&h.system.running.taken).is_empty(), "devices with no lookups running are not kept");
        assert_eq!(answered_addrs(&ask_from(&h, device(1), "later.test.", RecordType::A).await), [FOUND]);
    }

    #[tokio::test]
    async fn localhost_and_names_of_nearby_networks_are_never_looked_up() {
        let mut h = handler(nowhere());
        let lookups = counted_lookups(&mut h);
        unreachable(&h);
        for name in ["localhost.", "app.LocalHost."] {
            assert_eq!(answered_addrs(&ask(&h, name, RecordType::A).await), [IpAddr::V4(Ipv4Addr::LOCALHOST)]);
            assert_eq!(answered_addrs(&ask(&h, name, RecordType::AAAA).await), [IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        }
        for name in ["printer.", "nas.local.", "local.", "."] {
            assert_eq!(ask(&h, name, RecordType::A).await.response_code(), ResponseCode::ServFail, "{name}");
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn this_computers_answers_are_kept_for_a_while() {
        let mut h = handler(nowhere());
        let lookups = counted_lookups(&mut h);
        unreachable(&h);
        for spelling in ["Example.com.", "example.COM."] {
            let answer = ask(&h, spelling, RecordType::A).await;
            assert_eq!(answered_addrs(&answer), [FOUND]);
            assert_eq!(answer.queries()[0].name().to_ascii(), spelling, "the question is echoed as asked");
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
        ask(&h, "example.com.", RecordType::AAAA).await;
        assert_eq!(lookups.load(Ordering::SeqCst), 2, "another type is another lookup");

        // New settings start over.
        h.update_settings(DnsSettings::from_config(&DnsConfig::default()).unwrap());
        assert_eq!(lock(&h.system.kept).len(), 0);
        assert!(lock(&h.reach).is_empty());
    }

    #[tokio::test]
    async fn a_server_that_cannot_be_reached_is_tried_now_and_then() {
        let (server, asked) = answering_server().await;
        let mut h = handler(server);
        let lookups = counted_lookups(&mut h);
        unreachable(&h);
        assert_eq!(answered_addrs(&ask(&h, "a.test.", RecordType::A).await), [FOUND], "not its turn: this computer answers");
        assert_eq!(asked.load(Ordering::SeqCst), 0);

        // Its turn to be tried: it answers, and counts as reachable again.
        unreachable_since(&h, Instant::now().checked_sub(TRY_EVERY).unwrap());
        assert_eq!(answered_addrs(&ask(&h, "b.test.", RecordType::A).await), [SERVER_FOUND]);
        assert!(lock(&h.reach).is_empty());
        assert_eq!(answered_addrs(&ask(&h, "c.test.", RecordType::A).await), [SERVER_FOUND]);
        assert_eq!((asked.load(Ordering::SeqCst), lookups.load(Ordering::SeqCst)), (2, 1));
    }
}
