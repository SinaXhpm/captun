//! Network interface discovery, used to resolve the `interface` of direct
//! egresses and to show the user what they can pick.

use std::{
    cell::Cell,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use captun_core::{InterfaceKind, MacAddr};
use captun_outbound::InterfaceBinding;

use crate::refresh::Refreshed;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    /// The name users type into config: the adapter's friendly name on
    /// Windows ("Wi-Fi", "Ethernet 2"), the kernel name elsewhere.
    pub name: String,
    /// The OS-internal name (a GUID on Windows).
    pub system_name: String,
    pub description: Option<String>,
    pub kind: InterfaceKind,
    /// Backed by hardware rather than software (best effort).
    pub physical: bool,
    pub mac: Option<MacAddr>,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub up: bool,
    pub loopback: bool,
    pub has_gateway: bool,
    pub gateway: Option<IpAddr>,
    /// Carries the OS's default route, i.e. this computer's own internet.
    pub default_route: bool,
    /// Link speed, when the driver reports one.
    pub speed_mbps: Option<u64>,
}

impl Interface {
    pub fn has_addr(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.ipv4.contains(v4),
            IpAddr::V6(v6) => self.ipv6.contains(v6),
        }
    }

    /// Socket binding for this interface. IPv6 prefers a global address over
    /// link-local, which cannot reach the internet.
    pub fn binding(&self) -> InterfaceBinding {
        let global_v6 = self.ipv6.iter().find(|ip| !is_unicast_link_local(ip)).copied();
        InterfaceBinding { name: self.system_name.clone(), index: self.index, ipv4: self.ipv4.first().copied(), ipv6: global_v6 }
    }
}

fn is_unicast_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Words in an adapter's name or description that give away what it is. They
/// win over the interface type, which says "Ethernet" for most of them.
const MOBILE_HINTS: &[&str] = &["rndis", "remote ndis", "ncm", "android", "iphone", "apple mobile device", "usb0"];
const VPN_HINTS: &[&str] = &[
    "vpn", "tap-windows", "tap0", "tun", "wireguard", "wintun", "openvpn", "tailscale", "zerotier", "anyconnect",
    "fortinet", "wg0", "ppp",
];
const VIRTUAL_HINTS: &[&str] = &[
    "wi-fi direct", "hyper-v", "vethernet", "vmware", "vmnet", "virtualbox", "vboxnet", "docker", "wsl", "veth",
    "virbr", "br-", "lxc", "cni", "kernel debug", "teredo", "6to4", "isatap", "ip-https", "wan miniport",
    "bluetooth",
];

/// Linux drivers of phones sharing their data over USB.
#[cfg(target_os = "linux")]
fn is_tethering_driver(name: &str) -> bool {
    std::fs::read_link(format!("/sys/class/net/{name}/device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .is_some_and(|driver| matches!(driver.as_str(), "rndis_host" | "cdc_ncm" | "ipheth"))
}

#[cfg(not(target_os = "linux"))]
fn is_tethering_driver(_name: &str) -> bool {
    false
}

fn classify(i: &netdev::Interface) -> InterfaceKind {
    use netdev::interface::InterfaceType as T;

    if i.is_loopback() || i.if_type == T::Loopback {
        return InterfaceKind::Loopback;
    }
    let text = format!(
        "{} {} {}",
        i.name,
        i.friendly_name.as_deref().unwrap_or(""),
        i.description.as_deref().unwrap_or("")
    )
    .to_lowercase();
    let hinted = |hints: &[&str]| hints.iter().any(|h| text.contains(h));
    if hinted(MOBILE_HINTS) || is_tethering_driver(&i.name) {
        return InterfaceKind::Mobile;
    }
    if hinted(VIRTUAL_HINTS) {
        return InterfaceKind::Virtual;
    }
    if hinted(VPN_HINTS) || i.if_type == T::Tunnel || i.is_tun() {
        return InterfaceKind::Vpn;
    }
    match i.if_type {
        T::Wireless80211 => InterfaceKind::Wifi,
        T::Wwanpp | T::Wwanpp2 | T::GenericModem => InterfaceKind::Mobile,
        T::Ethernet | T::GigabitEthernet | T::FastEthernetT | T::FastEthernetFx | T::Ethernet3Megabit => {
            if i.is_physical() { InterfaceKind::Ethernet } else { InterfaceKind::Virtual }
        }
        T::Bridge => InterfaceKind::Virtual,
        _ => InterfaceKind::Other,
    }
}

/// Drivers report a nonsense speed for disconnected adapters; keep sane ones.
fn speed_mbps(i: &netdev::Interface) -> Option<u64> {
    let bps = i.transmit_speed.or(i.receive_speed)?;
    let mbps = bps / 1_000_000;
    (1..=1_000_000).contains(&mbps).then_some(mbps)
}

thread_local! {
    /// Set while netdev reads the adapters, so the service's panic report can
    /// tell netdev's known failure (below) from a real one.
    static LISTING: Cell<bool> = const { Cell::new(false) };
}

/// Whether this thread is reading the adapters right now.
pub fn listing() -> bool {
    LISTING.with(Cell::get)
}

/// The last list read, shared by every caller, and whether reading is failing.
static LIST: Refreshed<Vec<Interface>> = Refreshed::new(Vec::new(), FRESH_FOR, REST, WAIT_AT_MOST);
static FAILING: AtomicBool = AtomicBool::new(false);
/// How long a read serves later callers, from when it began: several ask each
/// second (status, device rules, the hotspot), and on Windows each read asks
/// every gateway for its MAC address, which can take seconds when one does
/// not answer. Longer than the monitor's 2 s tick, so one read serves a tick.
const FRESH_FOR: Duration = Duration::from_secs(3);
/// How old a list [`list`] gives may be: as before reads were shared. Its
/// callers include loops that look for a change every half second (the
/// phone's route gone, a USB adapter come up) for a few seconds only; at
/// [`FRESH_FOR`] they could see one read for their whole wait, and give up.
const POLLED_FRESH_FOR: Duration = Duration::from_millis(1500);
/// After a read slower than that, how long its list still serves, so slow
/// reads do not run back to back.
const REST: Duration = Duration::from_secs(1);
/// How long a caller waits for a read already running before it takes the
/// last list: a read that never ends must not hold everyone up.
const WAIT_AT_MOST: Duration = Duration::from_secs(10);

/// Runs a netdev read. netdev asks every gateway for its MAC address and
/// asserts on an empty answer, which some virtual adapters (VPN tunnels)
/// give; that panic is caught here, quietly, and reads as `None`.
pub(crate) fn read_quietly<T>(read: impl FnOnce() -> T + std::panic::UnwindSafe) -> Option<T> {
    LISTING.with(|l| l.set(true));
    let result = std::panic::catch_unwind(read);
    LISTING.with(|l| l.set(false));
    result.ok()
}

/// Reads the adapters from the system. A failed read must not take the caller
/// down: it gives `None`, and the last good list stands in until a read works
/// again.
fn read() -> Option<Vec<Interface>> {
    match read_quietly(netdev::get_interfaces) {
        Some(interfaces) => {
            if FAILING.swap(false, Ordering::Relaxed) {
                tracing::info!("the network adapters can be read again");
            }
            Some(interfaces.into_iter().map(convert).collect())
        }
        None => {
            if !FAILING.swap(true, Ordering::Relaxed) {
                tracing::warn!("cannot read the network adapters (one of them confuses netdev); using the last list read");
            }
            None
        }
    }
}

/// The network adapters, from a read that began at most 1.5 s ago. Only one
/// read runs at a time: a caller that finds one running waits for its
/// result. A read may take seconds, so async code calls [`list_async`]
/// instead, and code that has just changed the adapters, or waits for one
/// to change, calls [`list_fresh`].
pub fn list() -> Vec<Interface> {
    LIST.get_within(POLLED_FRESH_FOR, read)
}

/// The network adapters from a read that began after this call: for a caller
/// that has just changed them, or waits for one to appear. Blocks like
/// [`list`]; async code calls [`list_fresh_async`].
pub fn list_fresh() -> Vec<Interface> {
    LIST.get_since(Instant::now(), read)
}

/// The network adapters for async code, from a read that began at most 3 s
/// ago (one read serves a whole monitor tick); a read runs on a blocking
/// thread, never on the caller's. A loop that waits for a change calls
/// [`list_fresh_async`].
pub async fn list_async() -> Vec<Interface> {
    if let Some(list) = LIST.fresh() {
        return list;
    }
    off_thread(|| LIST.get(read)).await
}

/// [`list_fresh`] for async code.
pub async fn list_fresh_async() -> Vec<Interface> {
    let since = Instant::now();
    off_thread(move || LIST.get_since(since, read)).await
}

async fn off_thread(list: impl FnOnce() -> Vec<Interface> + Send + 'static) -> Vec<Interface> {
    // A read that panicked past `read_quietly`, or a runtime shutting down:
    // the last list stands in.
    tokio::task::spawn_blocking(list).await.unwrap_or_else(|_| LIST.value())
}

fn convert(i: netdev::Interface) -> Interface {
    let kind = classify(&i);
    let up = i.is_up();
    let loopback = i.is_loopback();
    let physical =
        matches!(kind, InterfaceKind::Ethernet | InterfaceKind::Wifi | InterfaceKind::Mobile) && i.is_physical();
    let gateway = i
        .gateway
        .as_ref()
        .and_then(|g| g.ipv4.first().map(|v4| IpAddr::V4(*v4)).or_else(|| g.ipv6.first().map(|v6| IpAddr::V6(*v6))));
    Interface {
        index: i.index,
        name: i.friendly_name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| i.name.clone()),
        description: i.description.clone(),
        kind,
        physical,
        mac: i.mac_addr.map(|m| MacAddr::new(m.octets())).filter(|m| m.octets() != [0; 6]),
        ipv4: i.ipv4.iter().map(|n| n.addr()).collect(),
        ipv6: i.ipv6.iter().map(|n| n.addr()).collect(),
        up,
        loopback,
        has_gateway: i.gateway.is_some(),
        gateway,
        default_route: i.default,
        speed_mbps: speed_mbps(&i),
        system_name: i.name,
    }
}

/// Resolves a configured interface name (friendly or system name, case
/// insensitive) to a binding. Interfaces that are down or have no address are
/// treated as missing, so the egress fails closed.
pub fn find_binding(name: &str) -> Option<InterfaceBinding> {
    binding_in(&list(), name)
}

/// [`find_binding`] in a list already read, e.g. with [`list_async`].
pub fn binding_in(interfaces: &[Interface], name: &str) -> Option<InterfaceBinding> {
    interfaces
        .iter()
        .find(|i| i.name.eq_ignore_ascii_case(name) || i.system_name.eq_ignore_ascii_case(name))
        .filter(|i| i.up && !(i.ipv4.is_empty() && i.ipv6.is_empty()))
        .map(Interface::binding)
}

/// The interface holding `ip`, e.g. to find which adapter the hotspot is on.
pub fn find_by_addr(ip: &IpAddr) -> Option<Interface> {
    list().into_iter().find(|i| i.has_addr(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_listed() {
        let all = list();
        assert!(!all.is_empty());
        assert!(all.iter().any(|i| i.has_addr(&IpAddr::V4(Ipv4Addr::LOCALHOST)) || i.loopback));
        assert!(all.iter().filter(|i| i.loopback).all(|i| i.kind == InterfaceKind::Loopback));
    }

    #[test]
    fn binding_skips_link_local_v6() {
        let iface = Interface {
            index: 7,
            name: "Wi-Fi".into(),
            system_name: "{GUID}".into(),
            description: None,
            kind: InterfaceKind::Wifi,
            physical: true,
            mac: None,
            ipv4: vec![Ipv4Addr::new(192, 168, 1, 10)],
            ipv6: vec!["fe80::1".parse().unwrap(), "2001:db8::10".parse().unwrap()],
            up: true,
            loopback: false,
            has_gateway: true,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            default_route: true,
            speed_mbps: Some(866),
        };
        let b = iface.binding();
        assert_eq!(b.name, "{GUID}");
        assert_eq!(b.ipv6, Some("2001:db8::10".parse().unwrap()));
        assert!(find_binding("definitely-not-an-interface").is_none());

        // Found by either name, whatever the case; down or address-less is missing.
        let listed = [iface.clone()];
        assert_eq!(binding_in(&listed, "wi-fi"), Some(b.clone()));
        assert_eq!(binding_in(&listed, "{guid}"), Some(b));
        assert!(binding_in(&listed, "Ethernet").is_none());
        let down = [Interface { up: false, ..iface.clone() }];
        assert!(binding_in(&down, "Wi-Fi").is_none());
        let bare = [Interface { ipv4: Vec::new(), ipv6: Vec::new(), ..iface }];
        assert!(binding_in(&bare, "Wi-Fi").is_none());
    }

    #[tokio::test]
    async fn async_callers_get_the_list_too() {
        // Read anew on a blocking thread, then served from what that read.
        let fresh = list_fresh_async().await;
        assert!(!fresh.is_empty());
        let cached = list_async().await;
        assert!(!cached.is_empty());
        assert!(!list_fresh().is_empty());
    }

    fn named(name: &str, description: &str, if_type: netdev::interface::InterfaceType) -> netdev::Interface {
        let mut i = netdev::Interface::dummy();
        i.name = name.into();
        i.description = Some(description.into());
        i.if_type = if_type;
        i
    }

    #[test]
    fn adapters_are_told_apart_by_what_they_say_they_are() {
        use netdev::interface::InterfaceType as T;
        let cases = [
            ("Wi-Fi", "Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC", T::Wireless80211, InterfaceKind::Wifi),
            ("Ethernet 3", "Remote NDIS based Internet Sharing Device", T::Ethernet, InterfaceKind::Mobile),
            ("Ethernet 2", "TAP-Windows Adapter V9", T::Ethernet, InterfaceKind::Vpn),
            ("VMnet8", "VMware Virtual Ethernet Adapter for VMnet8", T::Ethernet, InterfaceKind::Virtual),
            ("Local Area Connection* 1", "Microsoft Wi-Fi Direct Virtual Adapter", T::Wireless80211, InterfaceKind::Virtual),
            ("Cellular", "Generic Mobile Broadband Adapter", T::Wwanpp, InterfaceKind::Mobile),
        ];
        for (name, description, if_type, want) in cases {
            assert_eq!(classify(&named(name, description, if_type)), want, "{description}");
        }
    }
}
