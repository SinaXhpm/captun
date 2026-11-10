//! End-to-end tests against in-process mock upstreams (UDP, TCP, DoT, DoH)
//! and the real UDP/TCP server.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, SOA, TXT},
    },
};
use captun_core::{
    DomainPattern, EgressId, MacAddr, TargetAddr,
    config::{BlockResponse, DnsConfig, DnsOverride, DnsProtocol, DnsUpstreamConfig},
};
use captun_dns::{
    DnsHandler, DnsRoute, DnsRouter, DnsSettings, Outcome, QueryEvent, QueryObserver, Transport, serve,
};
use captun_outbound::{BoxStream, Direct, Outbound, UdpSession};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_rustls::TlsAcceptor;

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 137, 10));

// ---------------------------------------------------------------- helpers

fn direct() -> Arc<dyn Outbound> {
    Arc::new(Direct::new(EgressId::new("direct"), None))
}

fn client_mac() -> MacAddr {
    "02:00:00:00:00:01".parse().unwrap()
}

/// One route for every query; names ending in `blocked_suffix` are blocked.
struct FixedRouter(Option<DnsRoute>, Option<&'static str>);

impl DnsRouter for FixedRouter {
    fn route(&self, _client: IpAddr, name: &str) -> Option<DnsRoute> {
        let mut route = self.0.clone()?;
        route.blocked = self.1.is_some_and(|suffix| name.ends_with(suffix));
        Some(route)
    }
}

fn route(upstream: &str, outbound: Arc<dyn Outbound>) -> DnsRoute {
    DnsRoute { upstream: upstream.into(), outbound, client: Some(client_mac()), system_fallback: false, blocked: false }
}

fn router(upstream: &str, outbound: Arc<dyn Outbound>) -> Arc<dyn DnsRouter> {
    Arc::new(FixedRouter(Some(route(upstream, outbound)), None))
}

/// A device that goes out directly: an unreachable upstream falls back to
/// this computer's resolver.
fn direct_router(upstream: &str) -> Arc<dyn DnsRouter> {
    Arc::new(FixedRouter(Some(DnsRoute { system_fallback: true, ..route(upstream, direct()) }), None))
}

#[derive(Default)]
struct Recorder(Mutex<Vec<QueryEvent>>);

impl QueryObserver for Recorder {
    fn on_query(&self, event: QueryEvent) {
        self.0.lock().unwrap().push(event);
    }
}

impl Recorder {
    fn last(&self) -> QueryEvent {
        self.0.lock().unwrap().last().cloned().unwrap()
    }
}

/// An outbound that cannot carry UDP, like an HTTP CONNECT proxy.
#[derive(Debug)]
struct TcpOnly(Arc<dyn Outbound>);

#[async_trait]
impl Outbound for TcpOnly {
    fn id(&self) -> &EgressId {
        self.0.id()
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        self.0.connect_tcp(target).await
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "TCP only"))
    }
}

/// An outbound whose every connection is refused, as on a network that blocks
/// the DNS server; counts the attempts.
#[derive(Debug)]
struct Refusing {
    id: EgressId,
    attempts: AtomicUsize,
}

#[async_trait]
impl Outbound for Refusing {
    fn id(&self) -> &EgressId {
        &self.id
    }

    async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxStream> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::ConnectionRefused.into())
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(io::ErrorKind::ConnectionRefused.into())
    }
}

fn query(name: &str, qtype: RecordType, id: u16, edns: Option<u16>) -> Vec<u8> {
    let mut m = Message::new();
    m.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    if let Some(size) = edns {
        let mut e = Edns::new();
        e.set_max_payload(size);
        m.set_edns(e);
    }
    m.to_vec().unwrap()
}

fn parse(wire: &[u8]) -> Message {
    Message::from_vec(wire).unwrap()
}

fn reply(q: &Message, code: ResponseCode) -> Message {
    let mut r = Message::new();
    r.set_id(q.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_response_code(code)
        .set_recursion_desired(q.recursion_desired())
        .set_recursion_available(true)
        .add_queries(q.queries().iter().cloned());
    r
}

fn first_a(m: &Message) -> Ipv4Addr {
    match m.answers()[0].data() {
        RData::A(a) => a.0,
        other => panic!("expected A, got {other:?}"),
    }
}

fn upstream(id: &str, protocol: DnsProtocol, addr: SocketAddr) -> DnsUpstreamConfig {
    let tls = matches!(protocol, DnsProtocol::Tls | DnsProtocol::Https);
    DnsUpstreamConfig {
        id: id.into(),
        protocol,
        address: addr.to_string(),
        server_name: tls.then(|| "localhost".into()),
        path: None,
    }
}

fn config(upstreams: Vec<DnsUpstreamConfig>) -> DnsConfig {
    DnsConfig { default_upstream: upstreams[0].id.clone(), upstreams, ..DnsConfig::default() }
}

fn handler(cfg: &DnsConfig, router: Arc<dyn DnsRouter>, recorder: &Arc<Recorder>) -> DnsHandler {
    let observer: Arc<dyn QueryObserver> = recorder.clone();
    DnsHandler::new(DnsSettings::from_config(cfg).unwrap(), router, Some(observer))
}

// ---------------------------------------------------------- mock upstreams

type Responder = Arc<dyn Fn(&Message, bool) -> Message + Send + Sync>;

struct Mock {
    addr: SocketAddr,
    udp_hits: Arc<AtomicUsize>,
    tcp_hits: Arc<AtomicUsize>,
}

impl Mock {
    fn hits(&self) -> usize {
        self.udp_hits.load(Ordering::SeqCst) + self.tcp_hits.load(Ordering::SeqCst)
    }
}

fn answer_a(ip: [u8; 4], ttl: u32) -> Responder {
    Arc::new(move |q, _udp| {
        let mut r = reply(q, ResponseCode::NoError);
        r.add_answer(Record::from_rdata(q.queries()[0].name().clone(), ttl, RData::A(A(ip.into()))));
        r
    })
}

async fn read_framed<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Vec<u8>> {
    let len = s.read_u16().await?;
    let mut buf = vec![0u8; usize::from(len)];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_framed<S: AsyncWrite + Unpin>(s: &mut S, msg: &[u8]) -> io::Result<()> {
    let mut frame = (msg.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(msg);
    s.write_all(&frame).await
}

async fn serve_framed<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, responder: Responder, hits: Arc<AtomicUsize>) {
    while let Ok(q) = read_framed(&mut s).await {
        hits.fetch_add(1, Ordering::SeqCst);
        let r = responder(&parse(&q), false);
        if write_framed(&mut s, &r.to_vec().unwrap()).await.is_err() {
            return;
        }
    }
}

/// Plain DNS upstream on UDP and TCP (same port).
async fn mock_upstream(responder: Responder) -> Mock {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    let (udp_hits, tcp_hits) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));

    let (r, hits) = (responder.clone(), udp_hits.clone());
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
            hits.fetch_add(1, Ordering::SeqCst);
            let response = r(&parse(&buf[..n]), true);
            let _ = udp.send_to(&response.to_vec().unwrap(), peer).await;
        }
    });
    let hits = tcp_hits.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = tcp.accept().await {
            tokio::spawn(serve_framed(s, responder.clone(), hits.clone()));
        }
    });
    Mock { addr, udp_hits, tcp_hits }
}

/// A DNS server that takes each connection and drops it unanswered, as a
/// filtered network does; counts the connections.
async fn mock_dropping() -> Mock {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = tcp.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    });
    Mock { addr, udp_hits: Arc::new(AtomicUsize::new(0)), tcp_hits: hits }
}

/// A private CA plus a `localhost` leaf it signed.
fn test_pki() -> (RootCertStore, Arc<ServerConfig>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Captun Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let server = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())))
        .unwrap();
    (roots, Arc::new(server))
}

async fn mock_dot(server: Arc<ServerConfig>, responder: Responder) -> Mock {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let acceptor = TlsAcceptor::from(server);
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = tcp.accept().await {
            let (acceptor, responder, h) = (acceptor.clone(), responder.clone(), h.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    serve_framed(tls, responder, h).await;
                }
            });
        }
    });
    Mock { addr, udp_hits: Arc::new(AtomicUsize::new(0)), tcp_hits: hits }
}

async fn mock_doh(server: Arc<ServerConfig>, status: u16, responder: Responder) -> Mock {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let acceptor = TlsAcceptor::from(server);
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = tcp.accept().await {
            let (acceptor, responder, h) = (acceptor.clone(), responder.clone(), h.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(s).await else { return };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if tls.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8(head).unwrap();
                assert!(head.starts_with("POST /dns-query HTTP/1.1\r\n"), "{head}");
                assert!(head.contains("Content-Type: application/dns-message"));
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap();
                let mut body = vec![0u8; len];
                tls.read_exact(&mut body).await.unwrap();
                h.fetch_add(1, Ordering::SeqCst);
                let answer = responder(&parse(&body), false).to_vec().unwrap();
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    answer.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.write_all(&answer).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Mock { addr, udp_hits: Arc::new(AtomicUsize::new(0)), tcp_hits: hits }
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn blocklist_answers_per_mode() {
    let mock = mock_upstream(answer_a([1, 2, 3, 4], 300)).await;
    for mode in [BlockResponse::NxDomain, BlockResponse::NullIp, BlockResponse::Refused] {
        let mut cfg = config(vec![upstream("u", DnsProtocol::Udp, mock.addr)]);
        cfg.blocklist = vec![DomainPattern::from_str("ads.example").unwrap()];
        cfg.block_response = mode;
        let rec = Arc::new(Recorder::default());
        let h = handler(&cfg, router("u", direct()), &rec);

        let a = parse(&h.handle(&query("x.ads.example.", RecordType::A, 1, None), CLIENT, Transport::Udp).await.unwrap());
        assert_eq!(rec.last().outcome, Outcome::Blocked);
        match mode {
            BlockResponse::NxDomain => assert_eq!(a.response_code(), ResponseCode::NXDomain),
            BlockResponse::Refused => assert_eq!(a.response_code(), ResponseCode::Refused),
            BlockResponse::NullIp => {
                assert_eq!(first_a(&a), Ipv4Addr::UNSPECIFIED);
                let aaaa = parse(&h.handle(&query("ads.example.", RecordType::AAAA, 2, None), CLIENT, Transport::Udp).await.unwrap());
                assert!(matches!(aaaa.answers()[0].data(), RData::AAAA(v6) if v6.0 == Ipv6Addr::UNSPECIFIED));
                let txt = parse(&h.handle(&query("ads.example.", RecordType::TXT, 3, None), CLIENT, Transport::Udp).await.unwrap());
                assert_eq!(txt.response_code(), ResponseCode::NoError);
                assert!(txt.answers().is_empty());
            }
        }
    }
    assert_eq!(mock.hits(), 0, "blocked names never reach the upstream");
}

#[tokio::test]
async fn overrides_answer_and_nodata() {
    let mock = mock_upstream(answer_a([1, 2, 3, 4], 300)).await;
    let mut cfg = config(vec![upstream("u", DnsProtocol::Udp, mock.addr)]);
    cfg.overrides = vec![DnsOverride {
        domain: DomainPattern::from_str("full:hub.lan").unwrap(),
        addrs: vec!["192.168.137.1".parse().unwrap()],
    }];
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, router("u", direct()), &rec);

    let a = parse(&h.handle(&query("HUB.lan.", RecordType::A, 1, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(first_a(&a), Ipv4Addr::new(192, 168, 137, 1));
    assert_eq!(rec.last().outcome, Outcome::Override);
    assert_eq!(rec.last().answers, vec!["A 192.168.137.1".to_string()]);

    for qtype in [RecordType::AAAA, RecordType::MX] {
        let r = parse(&h.handle(&query("hub.lan.", qtype, 2, None), CLIENT, Transport::Udp).await.unwrap());
        assert_eq!(r.response_code(), ResponseCode::NoError);
        assert!(r.answers().is_empty(), "{qtype} should be NODATA");
    }

    // `full:` does not cover subdomains, so this one is forwarded.
    let fwd = parse(&h.handle(&query("x.hub.lan.", RecordType::A, 3, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(first_a(&fwd), Ipv4Addr::new(1, 2, 3, 4));
    assert_eq!(mock.hits(), 1);
}

#[tokio::test]
async fn forwards_and_caches_with_aging() {
    let mock = mock_upstream(answer_a([1, 2, 3, 4], 300)).await;
    let cfg = config(vec![upstream("u", DnsProtocol::Udp, mock.addr)]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, router("u", direct()), &rec);

    let first = parse(&h.handle(&query("example.com.", RecordType::A, 100, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(first.id(), 100);
    assert_eq!(first_a(&first), Ipv4Addr::new(1, 2, 3, 4));
    assert!(first.extensions().is_none(), "no OPT for a client that sent none");
    let event = rec.last();
    assert_eq!((event.outcome, event.upstream.as_deref(), event.client), (Outcome::NoError, Some("u"), Some(client_mac())));
    assert_eq!(event.qtype, "A");
    assert_eq!(mock.udp_hits.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = parse(&h.handle(&query("Example.COM.", RecordType::A, 200, Some(1232)), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(second.id(), 200);
    assert!(second.answers()[0].ttl() <= 299, "TTL must age while cached");
    assert_eq!(second.queries()[0].name().to_ascii(), "Example.COM.", "question echoes the client's spelling");
    assert!(second.extensions().is_some());
    assert_eq!(rec.last().outcome, Outcome::Cached);
    assert_eq!(mock.hits(), 1);

    // Hot reload drops the cache.
    h.update_settings(DnsSettings::from_config(&cfg).unwrap());
    h.handle(&query("example.com.", RecordType::A, 300, None), CLIENT, Transport::Udp).await.unwrap();
    assert_eq!(mock.hits(), 2);
}

#[tokio::test]
async fn negative_answers_are_cached_servfail_is_not() {
    let responder: Responder = Arc::new(|q, _| {
        let name = q.queries()[0].name().to_ascii();
        if name == "nx.test." {
            let mut r = reply(q, ResponseCode::NXDomain);
            let soa = SOA::new(Name::from_str("ns.test.").unwrap(), Name::from_str("admin.test.").unwrap(), 1, 60, 60, 60, 30);
            r.add_name_server(Record::from_rdata(Name::from_str("test.").unwrap(), 300, RData::SOA(soa)));
            r
        } else {
            reply(q, ResponseCode::ServFail)
        }
    });
    let mock = mock_upstream(responder).await;
    let cfg = config(vec![upstream("u", DnsProtocol::Udp, mock.addr)]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, router("u", direct()), &rec);

    for _ in 0..2 {
        let nx = parse(&h.handle(&query("nx.test.", RecordType::A, 1, None), CLIENT, Transport::Udp).await.unwrap());
        assert_eq!(nx.response_code(), ResponseCode::NXDomain);
        let fail = parse(&h.handle(&query("fail.test.", RecordType::A, 2, None), CLIENT, Transport::Udp).await.unwrap());
        assert_eq!(fail.response_code(), ResponseCode::ServFail);
        assert_eq!(rec.last().outcome, Outcome::ServFail);
    }
    assert_eq!(mock.hits(), 3, "NXDOMAIN cached once, SERVFAIL asked twice");
}

#[tokio::test]
async fn answers_too_big_to_keep_are_still_given() {
    // About 5 KiB of TXT for big.test., one short string for other names.
    let responder: Responder = Arc::new(|q, _| {
        let name = q.queries()[0].name().clone();
        let strings = if name.to_ascii() == "big.test." { vec!["x".repeat(250); 20] } else { vec!["small".into()] };
        let mut r = reply(q, ResponseCode::NoError);
        r.add_answer(Record::from_rdata(name, 300, RData::TXT(TXT::new(strings))));
        r
    });
    let mock = mock_upstream(responder).await;
    let cfg = config(vec![upstream("u", DnsProtocol::Tcp, mock.addr)]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, router("u", direct()), &rec);

    for id in [1, 2] {
        let r = parse(&h.handle(&query("big.test.", RecordType::TXT, id, None), CLIENT, Transport::Tcp).await.unwrap());
        assert_eq!((r.id(), r.answers().len()), (id, 1));
        assert_eq!(rec.last().outcome, Outcome::NoError, "asked again, not taken from the cache");
    }
    assert_eq!(mock.hits(), 2);

    for id in [3, 4] {
        h.handle(&query("small.test.", RecordType::TXT, id, None), CLIENT, Transport::Tcp).await.unwrap();
    }
    assert_eq!(rec.last().outcome, Outcome::Cached);
    assert_eq!(mock.hits(), 3);
}

#[tokio::test]
async fn truncated_udp_answer_retries_over_tcp() {
    let full = answer_a([5, 6, 7, 8], 60);
    let responder: Responder = Arc::new(move |q, udp| {
        if udp {
            let mut r = reply(q, ResponseCode::NoError);
            r.set_truncated(true);
            r
        } else {
            full(q, udp)
        }
    });
    let mock = mock_upstream(responder).await;
    let cfg = config(vec![upstream("u", DnsProtocol::Udp, mock.addr)]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, router("u", direct()), &rec);

    let r = parse(&h.handle(&query("big.test.", RecordType::A, 9, None), CLIENT, Transport::Udp).await.unwrap());
    assert!(!r.truncated());
    assert_eq!(first_a(&r), Ipv4Addr::new(5, 6, 7, 8));
    assert_eq!((mock.udp_hits.load(Ordering::SeqCst), mock.tcp_hits.load(Ordering::SeqCst)), (1, 1));
}

#[tokio::test]
async fn the_dns_server_is_asked_for_udp_answers_of_at_most_1232_bytes() {
    let asked_for = Arc::new(Mutex::new(Vec::new()));
    let seen = asked_for.clone();
    let full = answer_a([1, 2, 3, 4], 60);
    let responder: Responder = Arc::new(move |q, udp| {
        seen.lock().unwrap().push(q.extensions().as_ref().map(Edns::max_payload));
        full(q, udp)
    });
    let mock = mock_upstream(responder).await;
    let cfg = config(vec![upstream("u", DnsProtocol::Udp, mock.addr)]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, router("u", direct()), &rec);

    // What the device asked for: more, as much, less, nothing.
    for (i, edns) in [Some(4096), Some(1232), Some(512), None].into_iter().enumerate() {
        let r = parse(&h.handle(&query(&format!("n{i}.test."), RecordType::A, 1, edns), CLIENT, Transport::Udp).await.unwrap());
        assert_eq!(first_a(&r), Ipv4Addr::new(1, 2, 3, 4));
    }
    assert_eq!(*asked_for.lock().unwrap(), [Some(1232), Some(1232), Some(512), Some(1232)]);
}

#[tokio::test]
async fn udp_less_egress_falls_back_to_tcp() {
    let mock = mock_upstream(answer_a([9, 9, 9, 9], 60)).await;
    let cfg = config(vec![upstream("u", DnsProtocol::Udp, mock.addr)]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, router("u", Arc::new(TcpOnly(direct()))), &rec);

    let r = parse(&h.handle(&query("a.test.", RecordType::A, 1, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(first_a(&r), Ipv4Addr::new(9, 9, 9, 9));
    assert_eq!((mock.udp_hits.load(Ordering::SeqCst), mock.tcp_hits.load(Ordering::SeqCst)), (0, 1));
}

#[tokio::test]
async fn dns_over_tls() {
    let (roots, server) = test_pki();
    let mock = mock_dot(server, answer_a([10, 0, 0, 1], 60)).await;
    let cfg = config(vec![upstream("dot", DnsProtocol::Tls, mock.addr)]);
    let rec = Arc::new(Recorder::default());
    let observer: Arc<dyn QueryObserver> = rec.clone();
    let h = DnsHandler::new(DnsSettings::from_config_with_roots(&cfg, roots).unwrap(), router("dot", direct()), Some(observer));

    let r = parse(&h.handle(&query("secure.test.", RecordType::A, 1, None), CLIENT, Transport::Tcp).await.unwrap());
    assert_eq!(first_a(&r), Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(mock.hits(), 1);

    // The bundled public roots do not trust the test CA.
    let untrusted = handler(&cfg, router("dot", direct()), &rec);
    let r = parse(&untrusted.handle(&query("other.test.", RecordType::A, 2, None), CLIENT, Transport::Tcp).await.unwrap());
    assert_eq!(r.response_code(), ResponseCode::ServFail);
    assert_eq!(rec.last().outcome, Outcome::Failed);
}

#[tokio::test]
async fn dns_over_https_and_http_errors() {
    let (roots, server) = test_pki();
    let ok = mock_doh(server.clone(), 200, answer_a([10, 0, 0, 2], 60)).await;
    let broken = mock_doh(server, 500, answer_a([10, 0, 0, 3], 60)).await;
    let cfg = config(vec![upstream("doh", DnsProtocol::Https, ok.addr), upstream("bad", DnsProtocol::Https, broken.addr)]);
    let rec = Arc::new(Recorder::default());
    let settings = || DnsSettings::from_config_with_roots(&cfg, roots.clone()).unwrap();

    let observer: Arc<dyn QueryObserver> = rec.clone();
    let h = DnsHandler::new(settings(), router("doh", direct()), Some(observer.clone()));
    let r = parse(&h.handle(&query("web.test.", RecordType::A, 1, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(first_a(&r), Ipv4Addr::new(10, 0, 0, 2));

    let h = DnsHandler::new(settings(), router("bad", direct()), Some(observer));
    let r = parse(&h.handle(&query("web.test.", RecordType::A, 2, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(r.response_code(), ResponseCode::ServFail);
    assert_eq!(rec.last().outcome, Outcome::Failed);
    assert_eq!(broken.hits(), 1);
}

#[tokio::test]
async fn a_direct_device_falls_back_to_this_computers_resolver() {
    let dropping = mock_dropping().await;
    let cfg = config(vec![upstream("gone", DnsProtocol::Tcp, dropping.addr)]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, direct_router("gone"), &rec);

    // Each query the server drops is answered all the same; localhost is the
    // device itself, which the hub answers on its own.
    for id in 1..=3 {
        let r = parse(&h.handle(&query("localhost.", RecordType::A, id, None), CLIENT, Transport::Udp).await.unwrap());
        assert_eq!(first_a(&r), Ipv4Addr::LOCALHOST);
        assert_eq!(rec.last().outcome, Outcome::System);
        assert_eq!(dropping.hits(), usize::from(id));
    }

    // After three dropped connections the server is not waited on for a while.
    let r = parse(&h.handle(&query("localhost.", RecordType::AAAA, 4, None), CLIENT, Transport::Udp).await.unwrap());
    assert!(matches!(r.answers()[0].data(), RData::AAAA(v6) if v6.0 == Ipv6Addr::LOCALHOST));
    assert_eq!(rec.last().outcome, Outcome::System);
    // Only addresses can be asked of the system resolver.
    let r = parse(&h.handle(&query("localhost.", RecordType::MX, 5, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(r.response_code(), ResponseCode::NoError);
    assert!(r.answers().is_empty());
    // Names it would look for on this computer's own networks are not asked.
    for name in ["printer.", "nas.local."] {
        let r = parse(&h.handle(&query(name, RecordType::A, 6, None), CLIENT, Transport::Udp).await.unwrap());
        assert_eq!(r.response_code(), ResponseCode::ServFail, "{name}");
        assert_eq!(rec.last().outcome, Outcome::Failed);
    }
    assert_eq!(dropping.hits(), 3);
}

#[tokio::test]
async fn bad_answers_do_not_make_a_server_count_as_unreachable() {
    // Answers a question it was not asked, which cannot be used.
    let responder: Responder = Arc::new(|q, _| {
        let mut r = reply(q, ResponseCode::NoError);
        *r.queries_mut() = vec![Query::query(Name::from_ascii("other.test.").unwrap(), RecordType::A)];
        r
    });
    let mock = mock_upstream(responder).await;
    let cfg = config(vec![upstream("odd", DnsProtocol::Udp, mock.addr)]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, direct_router("odd"), &rec);

    for id in 1..=5 {
        let r = parse(&h.handle(&query("localhost.", RecordType::A, id, None), CLIENT, Transport::Udp).await.unwrap());
        assert_eq!(first_a(&r), Ipv4Addr::LOCALHOST, "each is answered all the same");
        assert_eq!(rec.last().outcome, Outcome::System);
        assert_eq!(mock.hits(), usize::from(id), "and the server is still asked every time");
    }
}

#[tokio::test]
async fn refused_connections_make_a_server_count_as_unreachable() {
    let refusing = Arc::new(Refusing { id: EgressId::new("direct"), attempts: AtomicUsize::new(0) });
    let outbound: Arc<dyn Outbound> = refusing.clone();
    let cfg = config(vec![upstream("u", DnsProtocol::Tcp, "127.0.0.1:53".parse().unwrap())]);
    let router: Arc<dyn DnsRouter> =
        Arc::new(FixedRouter(Some(DnsRoute { system_fallback: true, ..route("u", outbound) }), None));
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, router, &rec);

    for id in 1..=5 {
        let r = parse(&h.handle(&query("localhost.", RecordType::A, id, None), CLIENT, Transport::Udp).await.unwrap());
        assert_eq!(first_a(&r), Ipv4Addr::LOCALHOST);
        assert_eq!(rec.last().outcome, Outcome::System);
    }
    assert_eq!(refusing.attempts.load(Ordering::SeqCst), 3, "after the third refusal the server is not tried for a while");
}

#[tokio::test]
async fn the_server_answers_at_most_64_queries_of_one_device_at_once() {
    // A DNS server that never answers; notes the names it is asked for.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let names = Arc::new(Mutex::new(HashSet::new()));
    let seen = names.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match silent.recv_from(&mut buf).await {
                Ok((n, _)) => {
                    seen.lock().unwrap().insert(parse(&buf[..n]).queries()[0].name().to_ascii());
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                Err(_) => return,
            }
        }
    });
    let cfg = config(vec![upstream("silent", DnsProtocol::Udp, silent_addr)]);
    let rec = Arc::new(Recorder::default());
    let server = serve("127.0.0.1:0".parse().unwrap(), Arc::new(handler(&cfg, router("silent", direct()), &rec))).await.unwrap();

    let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..100u16 {
        device.send_to(&query(&format!("n{i}.test."), RecordType::A, i, None), server.local_addr()).await.unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while names.lock().unwrap().len() < 64 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // A moment more, for any that should not have been let in.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(names.lock().unwrap().len(), 64, "the other 36 were dropped while 64 waited for answers");
}

#[tokio::test]
async fn server_truncates_udp_to_client_edns_size() {
    let mut cfg = config(vec![upstream("u", DnsProtocol::Udp, "127.0.0.1:9".parse().unwrap())]);
    cfg.overrides = vec![DnsOverride {
        domain: DomainPattern::from_str("full:big.lan").unwrap(),
        addrs: (1..=60).map(|i| IpAddr::V4(Ipv4Addr::new(10, 1, 0, i))).collect(),
    }];
    let rec = Arc::new(Recorder::default());
    let server = serve("127.0.0.1:0".parse().unwrap(), Arc::new(handler(&cfg, router("u", direct()), &rec))).await.unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 8192];
    let mut ask = async |edns: Option<u16>| {
        client.send_to(&query("big.lan.", RecordType::A, 7, edns), server.local_addr()).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await.unwrap().unwrap();
        parse(&buf[..n])
    };

    let small = ask(None).await;
    assert!(small.truncated() && small.answers().is_empty(), "60 A records exceed 512 bytes");
    let large = ask(Some(4096)).await;
    assert!(!large.truncated());
    assert_eq!(large.answers().len(), 60);

    let mut tcp = TcpStream::connect(server.local_addr()).await.unwrap();
    for id in [1, 2] {
        write_framed(&mut tcp, &query("big.lan.", RecordType::A, id, None)).await.unwrap();
        let r = parse(&read_framed(&mut tcp).await.unwrap());
        assert_eq!((r.id(), r.answers().len()), (id, 60), "TCP is not size-limited and serves several queries");
    }
}

#[tokio::test]
async fn unknown_client_is_refused() {
    let mock = mock_upstream(answer_a([1, 2, 3, 4], 300)).await;
    let cfg = config(vec![upstream("u", DnsProtocol::Udp, mock.addr)]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, Arc::new(FixedRouter(None, None)), &rec);

    let r = parse(&h.handle(&query("example.com.", RecordType::A, 1, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(r.response_code(), ResponseCode::Refused);
    let event = rec.last();
    assert_eq!((event.outcome, event.client, event.client_ip), (Outcome::Refused, None, CLIENT));
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn names_the_rules_block_are_answered_as_blocked() {
    let mock = mock_upstream(answer_a([1, 2, 3, 4], 300)).await;
    let mut cfg = config(vec![upstream("u", DnsProtocol::Udp, mock.addr)]);
    cfg.block_response = BlockResponse::NxDomain;
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, Arc::new(FixedRouter(Some(route("u", direct())), Some("ads.example"))), &rec);

    let r = parse(&h.handle(&query("x.ads.example.", RecordType::A, 1, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(r.response_code(), ResponseCode::NXDomain);
    assert_eq!((rec.last().outcome, rec.last().client), (Outcome::Blocked, Some(client_mac())));
    assert_eq!(mock.hits(), 0, "a blocked name never reaches the upstream");

    // Other names resolve, and the addresses given are reported.
    let r = parse(&h.handle(&query("example.com.", RecordType::A, 2, None), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(first_a(&r), Ipv4Addr::new(1, 2, 3, 4));
    assert_eq!(rec.last().addrs, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
}

#[tokio::test]
async fn malformed_input() {
    let cfg = config(vec![upstream("u", DnsProtocol::Udp, "127.0.0.1:9".parse().unwrap())]);
    let rec = Arc::new(Recorder::default());
    let h = handler(&cfg, router("u", direct()), &rec);

    assert!(h.handle(b"short", CLIENT, Transport::Udp).await.is_none());

    let mut garbage = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x05];
    garbage.extend_from_slice(&[0xff; 10]);
    let r = parse(&h.handle(&garbage, CLIENT, Transport::Udp).await.unwrap());
    assert_eq!((r.id(), r.response_code()), (0x1234, ResponseCode::FormErr));

    let mut response = parse(&query("a.test.", RecordType::A, 5, None));
    response.set_message_type(MessageType::Response);
    assert!(h.handle(&response.to_vec().unwrap(), CLIENT, Transport::Udp).await.is_none(), "responses are dropped");

    let mut two = parse(&query("a.test.", RecordType::A, 6, None));
    two.add_query(Query::query(Name::from_str("b.test.").unwrap(), RecordType::A));
    let r = parse(&h.handle(&two.to_vec().unwrap(), CLIENT, Transport::Udp).await.unwrap());
    assert_eq!(r.response_code(), ResponseCode::NotImp);
}
