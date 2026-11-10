//! The network around an access point whose OS side hands out no addresses
//! and no internet (the Windows hosted network, hostapd): Captun gives the
//! interface the gateway address, shares the internet with NAT (unless the
//! routing engine carries the devices' traffic) and runs DHCP itself, the
//! same pieces cable sharing uses.
//!
//! Unlike a cable, the access point knows exactly who is connected, so DHCP
//! answers only the stations associated with it ([`StationGate`]) and the
//! device list shows a lease only while its station is there.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ipnet::Ipv4Net;
use captun_core::{MacAddr, ObservedClient};
use captun_dhcp::{Admission, DhcpServer, LeasePool, ServerConfig};

use crate::{
    HotspotError,
    access::{self, AccessGuard, AccessSetup},
    iface::Interface,
};

/// Clear of cable sharing's default 10.73.0.0/24 and of Windows ICS.
pub(crate) const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 1);
const NETWORK: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 0);
const PREFIX_LEN: u8 = 24;
const POOL_START: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 10);
const POOL_END: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 200);
const LEASE_MS: u64 = 60 * 60 * 1000;
/// Handed out when Captun's resolver is off and the system has none to copy.
const FALLBACK_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
/// How often a DHCP request from an unknown MAC may read the station list
/// again: often enough that a station's first DISCOVER is answered, rarely
/// enough that a flood of made-up MACs cannot keep the reader busy.
const REREAD_EVERY: Duration = Duration::from_millis(250);

/// The network own networks use, known before they start.
pub(crate) fn network() -> Option<Ipv4Net> {
    Ipv4Net::new(NETWORK, PREFIX_LEN).ok()
}

/// Reads the MACs of the stations associated with the access point right
/// now, or `None` when they cannot be read. May block for a moment.
pub(crate) type StationReader = Box<dyn Fn() -> Option<Vec<MacAddr>> + Send + Sync>;

/// Admits a MAC to DHCP only while it is associated with the access point.
/// Anything else on the adapter (or a request under a made-up MAC) is not a
/// device on this Wi-Fi network. When the list cannot be read at all, every
/// MAC is admitted, as before there was a list.
pub(crate) struct StationGate {
    read: StationReader,
    state: Mutex<GateState>,
}

struct GateState {
    known: HashSet<MacAddr>,
    /// The last read worked (nothing read yet counts as working).
    readable: bool,
    last_read: Option<Instant>,
}

impl std::fmt::Debug for StationGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StationGate").finish_non_exhaustive()
    }
}

impl StationGate {
    pub(crate) fn new(read: StationReader) -> Self {
        Self { read, state: Mutex::new(GateState { known: HashSet::new(), readable: true, last_read: None }) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn admits(&self, mac: MacAddr) -> bool {
        self.admits_at(mac, Instant::now())
    }

    /// A miss reads the list again, at most once per [`REREAD_EVERY`]; the
    /// read runs without the lock held.
    fn admits_at(&self, mac: MacAddr, now: Instant) -> bool {
        {
            let mut state = self.lock();
            if state.known.contains(&mac) {
                return true;
            }
            if state.last_read.is_some_and(|at| now.saturating_duration_since(at) < REREAD_EVERY) {
                return !state.readable;
            }
            state.last_read = Some(now);
        }
        let read = (self.read)();
        let mut state = self.lock();
        match read {
            Some(stations) => {
                state.known = stations.into_iter().collect();
                state.readable = true;
            }
            None => state.readable = false,
        }
        state.known.contains(&mac) || !state.readable
    }

    /// A list read elsewhere (the device list), so the next DHCP request
    /// need not read it again.
    fn update(&self, stations: &[MacAddr]) {
        let mut state = self.lock();
        state.known = stations.iter().copied().collect();
        state.readable = true;
    }
}

/// A running hotspot network. Dropping it stops DHCP, then reverts the address
/// and NAT.
pub(crate) struct OwnNetwork {
    dhcp: DhcpServer,
    gate: Option<Arc<StationGate>>,
    _net: AccessGuard,
}

impl std::fmt::Debug for OwnNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnNetwork").field("gateway", &GATEWAY).finish()
    }
}

fn netmask(prefix_len: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(prefix_len)).unwrap_or(0))
}

/// The DNS server devices are told to use: Captun's own on the gateway when
/// it runs, otherwise the one this computer uses.
fn dns_for_clients(dns_on_gateway: bool) -> Ipv4Addr {
    if dns_on_gateway {
        return GATEWAY;
    }
    crate::iface::read_quietly(netdev::get_default_interface)
        .and_then(Result::ok)
        .and_then(|i| {
            i.dns_servers.iter().find_map(|ip| match ip {
                IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(*v4),
                _ => None,
            })
        })
        .unwrap_or(FALLBACK_DNS)
}

/// The leases to list, given the associated stations (when they could be
/// read): a lease whose station has left is no device on the network, and a
/// station without a lease yet is.
fn merge_clients(leases: Vec<captun_dhcp::Lease>, stations: Option<&[MacAddr]>) -> Vec<ObservedClient> {
    let mut clients: Vec<ObservedClient> = leases
        .into_iter()
        .map(|lease| ObservedClient { mac: MacAddr::new(lease.mac), addrs: vec![IpAddr::V4(lease.ip)], hostname: lease.hostname })
        .filter(|client| stations.is_none_or(|list| list.contains(&client.mac)))
        .collect();
    for mac in stations.unwrap_or_default() {
        if !clients.iter().any(|c| c.mac == *mac) {
            clients.push(ObservedClient { mac: *mac, addrs: Vec::new(), hostname: None });
        }
    }
    clients
}

impl OwnNetwork {
    /// Brings the network up on `iface`. `nat` shares the internet through the
    /// system; it is off when the routing engine carries the devices' traffic,
    /// as for cable sharing. With `stations`, DHCP answers only associated
    /// stations. Must run inside the Tokio runtime, which serves DHCP.
    pub(crate) fn bring_up(
        iface: &Interface,
        dns_on_gateway: bool,
        nat: bool,
        stations: Option<StationReader>,
    ) -> Result<Self, HotspotError> {
        let net = access::bring_up(&AccessSetup {
            interface_index: iface.index,
            interface_system_name: iface.system_name.clone(),
            interface_alias: iface.name.clone(),
            gateway: GATEWAY,
            prefix_len: PREFIX_LEN,
            network: NETWORK,
            nat,
        })
        .map_err(|e| HotspotError::Failed(format!("cannot set up the hotspot's network: {e}")))?;
        let socket = access::bind_dhcp_socket(iface)
            .map_err(|e| HotspotError::Failed(format!("cannot hand out addresses (is UDP port 67 free?): {e}")))?;
        let pool = Arc::new(Mutex::new(LeasePool::new(GATEWAY, POOL_START, POOL_END, LEASE_MS)));
        let config = ServerConfig { gateway: GATEWAY, subnet_mask: netmask(PREFIX_LEN), dns: dns_for_clients(dns_on_gateway) };
        let gate = stations.map(|read| Arc::new(StationGate::new(read)));
        let admission = gate.clone().map(|gate| -> Admission { Arc::new(move |mac| gate.admits(MacAddr::new(mac))) });
        Ok(Self { dhcp: DhcpServer::start_with_admission(socket, config, pool, admission), gate, _net: net })
    }

    /// Devices on the network. With the associated stations (`None` when they
    /// could not be read), a lease is listed only while its station is
    /// associated, and stations without an address yet are listed too.
    pub(crate) fn clients(&self, stations: Option<&[MacAddr]>) -> Vec<ObservedClient> {
        if let (Some(gate), Some(list)) = (&self.gate, stations) {
            gate.update(list);
        }
        merge_clients(self.dhcp.leases(), stations)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn subnet_constants_agree() {
        assert_eq!(netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(netmask(0), Ipv4Addr::UNSPECIFIED);
        let mask = u32::from(netmask(PREFIX_LEN));
        for ip in [GATEWAY, POOL_START, POOL_END] {
            assert_eq!(u32::from(ip) & mask, u32::from(NETWORK), "{ip} is outside the subnet");
        }
        assert!(!(u32::from(POOL_START)..=u32::from(POOL_END)).contains(&u32::from(GATEWAY)));
        let net = network().unwrap();
        assert_eq!(net.to_string(), "10.74.0.0/24");
        assert!(net.contains(&GATEWAY));
    }

    #[test]
    fn devices_get_captun_dns_only_when_it_runs() {
        assert_eq!(dns_for_clients(true), GATEWAY);
        assert_ne!(dns_for_clients(false), GATEWAY);
    }

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([2, 0, 0, 0, 0, n])
    }

    /// A gate over a list the test changes, counting the reads.
    fn gate(list: Arc<Mutex<Option<Vec<MacAddr>>>>, reads: Arc<AtomicUsize>) -> StationGate {
        StationGate::new(Box::new(move || {
            reads.fetch_add(1, Ordering::SeqCst);
            list.lock().unwrap().clone()
        }))
    }

    #[test]
    fn only_associated_stations_are_admitted() {
        let list = Arc::new(Mutex::new(Some(vec![mac(1)])));
        let reads = Arc::new(AtomicUsize::new(0));
        let gate = gate(list, reads.clone());
        let t0 = Instant::now();
        assert!(gate.admits_at(mac(1), t0), "the first request reads the list");
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert!(gate.admits_at(mac(1), t0), "a hit needs no read");
        assert!(!gate.admits_at(mac(2), t0 + Duration::from_millis(10)), "not associated");
        assert_eq!(reads.load(Ordering::SeqCst), 1, "a miss right after a read does not read again");
    }

    #[test]
    fn a_new_stations_first_request_reads_the_list_again() {
        let list = Arc::new(Mutex::new(Some(vec![mac(1)])));
        let reads = Arc::new(AtomicUsize::new(0));
        let gate = gate(list.clone(), reads.clone());
        let t0 = Instant::now();
        assert!(gate.admits_at(mac(1), t0));
        // mac(2) associates; its DISCOVER comes in after the re-read interval.
        list.lock().unwrap().as_mut().unwrap().push(mac(2));
        assert!(gate.admits_at(mac(2), t0 + REREAD_EVERY));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_flood_of_unknown_macs_reads_a_few_times_a_second_at_most() {
        let list = Arc::new(Mutex::new(Some(vec![mac(1)])));
        let reads = Arc::new(AtomicUsize::new(0));
        let gate = gate(list, reads.clone());
        let t0 = Instant::now();
        let admitted = (0..1000u32)
            .filter(|n| gate.admits_at(MacAddr::new([6, 0, 0, 0, (n >> 8) as u8, *n as u8]), t0 + Duration::from_millis(u64::from(*n))))
            .count();
        assert_eq!(admitted, 0);
        assert_eq!(reads.load(Ordering::SeqCst), 4, "one read per {REREAD_EVERY:?} over one second");
    }

    #[test]
    fn everyone_is_admitted_when_the_list_cannot_be_read() {
        let list = Arc::new(Mutex::new(None));
        let reads = Arc::new(AtomicUsize::new(0));
        let gate = gate(list.clone(), reads);
        let t0 = Instant::now();
        assert!(gate.admits_at(mac(7), t0));
        assert!(gate.admits_at(mac(8), t0), "still unreadable: admitted without another read");
        // Readable again: back to stations only.
        *list.lock().unwrap() = Some(vec![mac(1)]);
        assert!(!gate.admits_at(mac(8), t0 + REREAD_EVERY));
        // A list read for the device list counts too.
        gate.update(&[mac(8)]);
        assert!(gate.admits_at(mac(8), t0 + REREAD_EVERY));
    }

    fn lease(n: u8) -> captun_dhcp::Lease {
        captun_dhcp::Lease { mac: [2, 0, 0, 0, 0, n], ip: Ipv4Addr::new(10, 74, 0, 10 + n), hostname: None, expires_at_ms: u64::MAX }
    }

    #[test]
    fn leases_are_listed_only_while_their_station_is_associated() {
        let clients = merge_clients(vec![lease(1), lease(2)], Some(&[mac(1), mac(3)]));
        let macs: Vec<MacAddr> = clients.iter().map(|c| c.mac).collect();
        assert_eq!(macs, [mac(1), mac(3)], "mac(2) left; mac(3) has no address yet");
        assert_eq!(clients[0].addrs, [IpAddr::V4(Ipv4Addr::new(10, 74, 0, 11))]);
        assert!(clients[1].addrs.is_empty());
        // Without a station list, every lease counts, as on a cable.
        assert_eq!(merge_clients(vec![lease(1), lease(2)], None).len(), 2);
    }
}
