use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Mutex,
    time::Duration,
};

use async_trait::async_trait;
use captun_core::{EgressId, TargetAddr};
use socket2::SockRef;
use tokio::{
    net::{TcpSocket, UdpSocket},
    sync::Semaphore,
    time::{Instant, timeout, timeout_at},
};

use crate::{BoxStream, Outbound, UdpSession, sys, timed_out};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long looking up a name may take, waiting for a slot included. The
/// system's resolver can stall for much longer, and a proxy or DNS server
/// named by host must never leave its dial waiting with it.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// A share of the system's resolver: how many lookups may run on it at once
/// and how long each may take. Each lookup holds a thread of the blocking
/// pool the rest of the service shares until the system answers, even after
/// its caller gave up, so a stalled resolver can take only the slots.
#[derive(Debug)]
struct Lookups {
    slots: Semaphore,
    limit: Duration,
}

/// For devices' traffic, which may ask for any name, however slow to answer.
static LOOKUPS: Lookups = Lookups { slots: Semaphore::const_new(16), limit: LOOKUP_TIMEOUT };
/// For the service's own connections: a proxy's server named by host and list
/// downloads. Kept apart, so names devices ask for never leave these waiting.
/// Every connection through a proxy named by host looks its name up, so this
/// is not much smaller than the devices' share.
static SERVICE_LOOKUPS: Lookups = Lookups { slots: Semaphore::const_new(8), limit: LOOKUP_TIMEOUT };

/// The OS interface a direct egress is pinned to, resolved by the platform
/// layer from the configured name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceBinding {
    pub name: String,
    pub index: u32,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl InterfaceBinding {
    fn local_ip(&self, ipv4: bool) -> Option<IpAddr> {
        if ipv4 { self.ipv4.map(IpAddr::V4) } else { self.ipv6.map(IpAddr::V6) }
    }
}

/// Connects straight from the host. With a binding, sockets are pinned both
/// by source address and by the OS-specific "send through this interface"
/// option, so traffic cannot slip out of the default route instead.
#[derive(Debug)]
pub struct Direct {
    id: EgressId,
    binding: Option<InterfaceBinding>,
    /// Whose share of the resolver its name lookups use.
    lookups: &'static Lookups,
}

impl Direct {
    pub fn new(id: EgressId, binding: Option<InterfaceBinding>) -> Self {
        Self { id, binding, lookups: &LOOKUPS }
    }

    /// The way a proxy's own server is reached: its lookups use the service's
    /// share of the resolver, which devices' traffic cannot fill.
    pub(crate) fn for_service(id: EgressId) -> Self {
        Self { id, binding: None, lookups: &SERVICE_LOOKUPS }
    }

    pub fn binding(&self) -> Option<&InterfaceBinding> {
        self.binding.as_ref()
    }

    fn can_reach(&self, addr: &SocketAddr) -> bool {
        self.binding.as_ref().is_none_or(|b| b.local_ip(addr.is_ipv4()).is_some())
    }

    /// Why `target` cannot be reached: the pinned network adapter has no
    /// address of the family it needs.
    fn cannot_reach(&self, target: &TargetAddr) -> io::Error {
        let adapter = self.binding.as_ref().map_or("", |b| b.name.as_str());
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("the network adapter {adapter} has no address that can reach {target}"),
        )
    }

    fn pin(&self, socket: SockRef<'_>, ipv4: bool) -> io::Result<Option<SocketAddr>> {
        let Some(binding) = &self.binding else { return Ok(None) };
        sys::bind_to_interface(&socket, binding, ipv4)?;
        Ok(binding.local_ip(ipv4).map(|ip| SocketAddr::new(ip, 0)))
    }

    fn tcp_socket(&self, dest: &SocketAddr) -> io::Result<TcpSocket> {
        let socket = if dest.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        if let Some(local) = self.pin(SockRef::from(&socket), dest.is_ipv4())? {
            socket.bind(local)?;
        }
        Ok(socket)
    }

    fn udp_socket(&self, ipv4: bool) -> io::Result<UdpSocket> {
        let domain = if ipv4 { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        let local = match self.pin(SockRef::from(&socket), ipv4)? {
            Some(local) => local,
            None if ipv4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            None => {
                socket.set_only_v6(true)?;
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            }
        };
        socket.bind(&local.into())?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    }
}

/// The addresses of `target` for one of the service's own connections; a name
/// is looked up on this computer's resolver, in the service's share of it.
pub(crate) async fn resolve_for_service(target: &TargetAddr) -> io::Result<Vec<SocketAddr>> {
    resolve(&SERVICE_LOOKUPS, target).await
}

/// The addresses of `target`; a name is looked up in `lookups`.
async fn resolve(lookups: &'static Lookups, target: &TargetAddr) -> io::Result<Vec<SocketAddr>> {
    match target {
        TargetAddr::Ip(addr) => Ok(vec![*addr]),
        TargetAddr::Domain(host, port) => {
            let addrs = look_up(lookups, host, *port, system_lookup).await?;
            if addrs.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, format!("{host} has no addresses")));
            }
            Ok(addrs)
        }
    }
}

/// getaddrinfo, which blocks its thread until the system answers.
fn system_lookup(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

/// Runs `lookup` on a blocking thread once a slot of `lookups` is free,
/// giving up after its limit in all. The slot goes with the lookup rather
/// than its caller: getaddrinfo cannot be stopped, so one that outlives the
/// limit keeps its slot until the system answers, and stalled lookups never
/// hold more threads than there are slots.
async fn look_up<F>(lookups: &'static Lookups, host: &str, port: u16, lookup: F) -> io::Result<Vec<SocketAddr>>
where
    F: FnOnce(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    // An address given where a name could be needs no lookup.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let stopped = || io::Error::other(format!("looking up {host} was stopped"));
    let deadline = Instant::now() + lookups.limit;
    let slot = match timeout_at(deadline, lookups.slots.acquire()).await {
        Ok(slot) => slot.map_err(|_| stopped())?,
        // Said apart from a slow answer: the name may be fine, the resolver
        // busy with others the system has not answered yet.
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("looking up {host} timed out: too many names are being looked up at once"),
            ));
        }
    };
    let name = host.to_owned();
    let work = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        lookup(&name, port)
    });
    timeout_at(deadline, work).await.map_err(|_| timed_out(&format!("looking up {host}")))?.map_err(|_| stopped())?
}

#[async_trait]
impl Outbound for Direct {
    fn id(&self) -> &EgressId {
        &self.id
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let addrs: Vec<_> = resolve(self.lookups, target).await?.into_iter().filter(|a| self.can_reach(a)).collect();
        if addrs.is_empty() {
            return Err(self.cannot_reach(target));
        }

        let mut last_err = None;
        for addr in addrs {
            let attempt = async {
                let stream = self.tcp_socket(&addr)?.connect(addr).await?;
                stream.set_nodelay(true)?;
                io::Result::Ok(stream)
            };
            match timeout(CONNECT_TIMEOUT, attempt).await {
                Ok(Ok(stream)) => return Ok(Box::new(stream)),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => last_err = Some(timed_out(&format!("connect to {addr}"))),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no address to connect to")))
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        let wants = |v4: bool| self.binding.as_ref().is_none_or(|b| b.local_ip(v4).is_some());
        let v4 = if wants(true) { Some(self.udp_socket(true)?) } else { None };
        // IPv6 is opportunistic: many uplinks have none, which is not an error.
        let v6 = if wants(false) { self.udp_socket(false).ok() } else { None };
        if v4.is_none() && v6.is_none() {
            let adapter = self.binding.as_ref().map_or("", |b| b.name.as_str());
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("the network adapter {adapter} has no usable address"),
            ));
        }
        Ok(Box::new(DirectUdp::new(v4, v6, self.lookups)))
    }

    /// One socket, of the target's family: a flow, a DNS query or a SOCKS5
    /// relay only ever sends to one address. A name may lead to either
    /// family, so it gets the general session.
    async fn udp_session_to(&self, target: &TargetAddr) -> io::Result<Box<dyn UdpSession>> {
        let TargetAddr::Ip(addr) = target else { return self.udp_session().await };
        if !self.can_reach(addr) {
            return Err(self.cannot_reach(target));
        }
        let socket = Some(self.udp_socket(addr.is_ipv4())?);
        let (v4, v6) = if addr.is_ipv4() { (socket, None) } else { (None, socket) };
        Ok(Box::new(DirectUdp::new(v4, v6, self.lookups)))
    }

    fn connects_from_here(&self) -> bool {
        true
    }
}

const RESOLVE_CACHE_LIMIT: usize = 256;

#[derive(Debug)]
struct DirectUdp {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    /// Domain targets are resolved once per session rather than per datagram.
    resolved: Mutex<HashMap<(String, u16), SocketAddr>>,
    /// The share of the resolver of the [`Direct`] that opened it.
    lookups: &'static Lookups,
}

impl DirectUdp {
    fn new(v4: Option<UdpSocket>, v6: Option<UdpSocket>, lookups: &'static Lookups) -> Self {
        Self { v4, v6, resolved: Mutex::new(HashMap::new()), lookups }
    }

    fn socket_for(&self, addr: &SocketAddr) -> Option<&UdpSocket> {
        if addr.is_ipv4() { self.v4.as_ref() } else { self.v6.as_ref() }
    }

    async fn resolve_cached(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        let key = (host.to_owned(), port);
        if let Some(addr) = self.resolved.lock().ok().and_then(|m| m.get(&key).copied()) {
            return Ok(addr);
        }
        let addrs = resolve(self.lookups, &TargetAddr::Domain(host.to_owned(), port)).await?;
        let addr = addrs
            .iter()
            .find(|a| self.socket_for(a).is_some())
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, format!("no usable address for {host}")))?;
        if let Ok(mut map) = self.resolved.lock() {
            if map.len() >= RESOLVE_CACHE_LIMIT {
                map.clear();
            }
            map.insert(key, addr);
        }
        Ok(addr)
    }
}

fn try_recv(socket: &UdpSocket, buf: &mut [u8]) -> Option<io::Result<(usize, TargetAddr)>> {
    match socket.try_recv_from(buf) {
        Ok((n, from)) => Some(Ok((n, TargetAddr::Ip(from)))),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
        Err(e) => Some(Err(e)),
    }
}

#[async_trait]
impl UdpSession for DirectUdp {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        let addr = match target {
            TargetAddr::Ip(addr) => *addr,
            TargetAddr::Domain(host, port) => self.resolve_cached(host, *port).await?,
        };
        let socket = self
            .socket_for(&addr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, format!("no socket for {addr}")))?;
        socket.send_to(payload, addr).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        match (&self.v4, &self.v6) {
            (Some(a), Some(b)) => loop {
                tokio::select! {
                    ready = a.readable() => {
                        ready?;
                        if let Some(r) = try_recv(a, buf) { return r; }
                    }
                    ready = b.readable() => {
                        ready?;
                        if let Some(r) = try_recv(b, buf) { return r; }
                    }
                }
            },
            (Some(s), None) | (None, Some(s)) => {
                let (n, from) = s.recv_from(buf).await?;
                Ok((n, TargetAddr::Ip(from)))
            }
            (None, None) => Err(io::Error::new(io::ErrorKind::NotConnected, "UDP session has no sockets")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    fn direct(binding: Option<InterfaceBinding>) -> Direct {
        Direct::new(EgressId::new("direct"), binding)
    }

    #[tokio::test]
    async fn a_session_to_an_ipv4_address_opens_only_ipv4() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = TargetAddr::Ip(echo.local_addr().unwrap());
        let session = direct(None).udp_session_to(&target).await.unwrap();

        // No IPv6 socket was opened, so there is nothing to send this on.
        let elsewhere = TargetAddr::Ip("[::1]:53".parse().unwrap());
        let refused = session.send_to(b"stray", &elsewhere).await.unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::AddrNotAvailable, "{refused}");

        session.send_to(b"ping", &target).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = echo.recv_from(&mut buf).await.unwrap();
        echo.send_to(&buf[..n], from).await.unwrap();
        let (n, back) = session.recv_from(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], back), (&b"ping"[..], target));
    }

    #[tokio::test]
    async fn a_pinned_session_refuses_a_family_its_adapter_lacks_at_once() {
        let binding =
            InterfaceBinding { name: "Ethernet".into(), index: 7, ipv4: Some(Ipv4Addr::new(192, 0, 2, 10)), ipv6: None };
        let target = TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap());
        let refused = direct(Some(binding)).udp_session_to(&target).await.unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::AddrNotAvailable);
        assert!(refused.to_string().contains("network adapter Ethernet"), "{refused}");
    }

    #[tokio::test]
    async fn a_stalled_lookup_times_out_but_keeps_its_slot_until_it_ends() {
        static ONE: Lookups = Lookups { slots: Semaphore::const_new(1), limit: Duration::from_millis(100) };
        let (answer, stalled) = std::sync::mpsc::channel::<()>();
        let error = look_up(&ONE, "stalled.example", 53, move |_, _| {
            let _ = stalled.recv();
            Ok(Vec::new())
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "looking up stalled.example timed out");

        // getaddrinfo is still running and holds the only slot: the next
        // lookup waits for it, and gives up in time without running.
        assert_eq!(ONE.slots.available_permits(), 0);
        let ran = Arc::new(AtomicBool::new(false));
        let flag = ran.clone();
        let error = look_up(&ONE, "next.example", 53, move |_, _| {
            flag.store(true, Ordering::SeqCst);
            Ok(Vec::new())
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("too many names are being looked up at once"), "{error}");
        assert!(!ran.load(Ordering::SeqCst), "it never got a slot");

        // Once the system answers, the slot is free again.
        answer.send(()).unwrap();
        timeout(Duration::from_secs(10), async {
            while ONE.slots.available_permits() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let found =
            look_up(&ONE, "later.example", 53, |_, port| Ok(vec![SocketAddr::from(([192, 0, 2, 1], port))])).await.unwrap();
        assert_eq!(found, vec![SocketAddr::from(([192, 0, 2, 1], 53))]);
    }

    #[tokio::test]
    async fn an_address_needs_no_lookup() {
        // No slot at all: anything that waited for one would time out.
        static NONE: Lookups = Lookups { slots: Semaphore::const_new(0), limit: Duration::from_millis(50) };
        let asked = |_: &str, _: u16| Err(io::Error::other("looked up"));
        assert_eq!(
            look_up(&NONE, "2001:db8::1", 443, asked).await.unwrap(),
            vec!["[2001:db8::1]:443".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(look_up(&NONE, "192.0.2.1", 53, asked).await.unwrap(), vec![SocketAddr::from(([192, 0, 2, 1], 53))]);
        assert_eq!(look_up(&NONE, "lists.example", 80, asked).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn the_service_looks_names_up_even_while_devices_hold_every_slot() {
        // Devices' traffic gets its own share; a proxy's server and list
        // downloads get the service's.
        assert!(std::ptr::eq(direct(None).lookups, &LOOKUPS));
        assert!(std::ptr::eq(Direct::for_service(EgressId::new("proxy")).lookups, &SERVICE_LOOKUPS));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = TargetAddr::Domain("localhost".into(), listener.local_addr().unwrap().port());
        // As when devices' slow names hold every slot of their share.
        static FULL: Lookups = Lookups { slots: Semaphore::const_new(0), limit: Duration::from_millis(100) };
        let devices = Direct { lookups: &FULL, ..direct(None) };
        let error = devices.connect_tcp(&server).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("too many names are being looked up at once"), "{error}");
        let error = devices.udp_session().await.unwrap().send_to(b"x", &server).await.unwrap_err();
        assert!(error.to_string().contains("too many names are being looked up at once"), "{error}");

        // The service's share is untouched by them.
        static SERVICE: Lookups = Lookups { slots: Semaphore::const_new(1), limit: LOOKUP_TIMEOUT };
        let service = Direct { lookups: &SERVICE, ..direct(None) };
        service.connect_tcp(&server).await.unwrap();
        assert_eq!(SERVICE.slots.available_permits(), 1, "the slot comes back once the system answers");
    }
}
