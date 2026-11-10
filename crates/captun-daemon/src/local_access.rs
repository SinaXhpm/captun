//! What devices may reach besides the internet: this computer, each other,
//! and the home network. The system's own rules (`captun_platform::reach`)
//! hold devices back on every network Captun shares; the routing engine
//! refuses the same destinations itself, for flows that reach it anyway.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;
use captun_core::Config;
use captun_platform::{
    iface::Interface,
    reach::{self, LocalReach, MAX_OWN_ADDRESSES, ReachConfig},
};

/// The settings, read the way round the rules need them.
pub(crate) fn local_reach(config: &Config) -> LocalReach {
    LocalReach {
        this_computer: !config.network.block_host,
        each_other: !config.network.isolate_clients,
        home_network: !config.network.block_host_lan,
    }
}

/// A network Captun shares, as the rules need it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedNetwork<K> {
    pub(crate) key: K,
    /// OS name of its interface.
    pub(crate) interface: String,
    pub(crate) subnet: Ipv4Net,
    /// This computer's address on it.
    pub(crate) gateway: Ipv4Addr,
}

/// The rules each shared network needs. The adapter's index always goes in
/// once the adapter is known: router advertisements and redirects from
/// devices are dropped on it whatever the settings. This computer's
/// addresses only go in when a rule uses them, so their changes do not make
/// the rules be put in again for nothing.
pub(crate) fn desired<K: Copy>(networks: &[SharedNetwork<K>], reach: LocalReach, ifaces: &[Interface]) -> Vec<(K, ReachConfig)> {
    let mut own: Vec<Ipv4Addr> = ifaces
        .iter()
        .filter(|i| !i.loopback)
        .flat_map(|i| i.ipv4.iter().copied())
        .filter(|a| !a.is_loopback() && !a.is_unspecified())
        .collect();
    own.sort_unstable();
    own.dedup();
    own.truncate(MAX_OWN_ADDRESSES);
    networks
        .iter()
        .map(|net| {
            // No name yet (Windows makes the hotspot's adapter as it starts):
            // no index, rather than whichever adapter has no name either.
            let named = |i: &&Interface| {
                !net.interface.is_empty()
                    && (i.name.eq_ignore_ascii_case(&net.interface) || i.system_name.eq_ignore_ascii_case(&net.interface))
            };
            let if_index = ifaces.iter().find(named).map(|i| i.index);
            let config = ReachConfig {
                interface: net.interface.clone(),
                if_index,
                subnet: net.subnet,
                gateway: net.gateway,
                own_addresses: if reach.this_computer { Vec::new() } else { own.clone() },
                reach,
            };
            (net.key, config)
        })
        .collect()
}

/// What the routing engine refuses itself: a copy of the settings, the shared
/// networks and this computer's addresses, read for every new flow.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReachView {
    networks: Vec<Ipv4Net>,
    own: Vec<IpAddr>,
    reach: Option<LocalReach>,
}

impl ReachView {
    pub(crate) fn new<K>(networks: &[SharedNetwork<K>], reach: LocalReach, ifaces: &[Interface]) -> Self {
        let mut own: Vec<IpAddr> = ifaces
            .iter()
            .flat_map(|i| i.ipv4.iter().map(|a| IpAddr::V4(*a)).chain(i.ipv6.iter().map(|a| IpAddr::V6(*a))))
            .chain(networks.iter().map(|n| IpAddr::V4(n.gateway)))
            .collect();
        own.sort_unstable();
        own.dedup();
        Self { networks: networks.iter().map(|n| n.subnet).collect(), own, reach: Some(reach) }
    }

    /// Whether a device at `client` may not reach `destination`. Devices
    /// outside every shared network (a phone on USB) follow the same settings.
    pub(crate) fn refuses(&self, client: IpAddr, destination: IpAddr) -> bool {
        // Never this computer's loopback, whatever the settings: services
        // there trust that only this computer can reach them.
        if destination.is_loopback() || destination.is_unspecified() || ipv4_mapped_loopback(destination) {
            return true;
        }
        let Some(reach) = self.reach else { return false };
        if self.own.contains(&destination) {
            return !reach.this_computer;
        }
        if let (IpAddr::V4(client), IpAddr::V4(destination)) = (client, destination)
            && self.networks.iter().any(|net| net.contains(&client) && net.contains(&destination))
        {
            return !reach.each_other;
        }
        reach::is_private(destination) && !reach.home_network
    }
}

fn ipv4_mapped_loopback(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback() || v4.is_unspecified()))
}

#[cfg(test)]
mod tests {
    use captun_core::InterfaceKind;

    use super::*;

    fn iface(name: &str, index: u32, ipv4: &[&str]) -> Interface {
        Interface {
            index,
            name: name.into(),
            system_name: format!("{{{name}}}"),
            description: None,
            kind: InterfaceKind::Other,
            physical: true,
            mac: None,
            ipv4: ipv4.iter().map(|a| a.parse().unwrap()).collect(),
            ipv6: vec!["fe80::1".parse().unwrap()],
            up: true,
            loopback: false,
            has_gateway: false,
            gateway: None,
            default_route: false,
            speed_mbps: None,
        }
    }

    fn hotspot() -> SharedNetwork<u8> {
        SharedNetwork {
            key: 1,
            interface: "Local Area Connection* 2".into(),
            subnet: "192.168.137.0/24".parse().unwrap(),
            gateway: Ipv4Addr::new(192, 168, 137, 1),
        }
    }

    fn ifaces() -> Vec<Interface> {
        let mut lo = iface("Loopback", 1, &["127.0.0.1"]);
        lo.loopback = true;
        vec![lo, iface("Ethernet", 4, &["192.168.1.50"]), iface("Local Area Connection* 2", 17, &["192.168.137.1"])]
    }

    const ALL: LocalReach = LocalReach { this_computer: true, each_other: true, home_network: true };
    const NONE: LocalReach = LocalReach { this_computer: false, each_other: false, home_network: false };

    #[test]
    fn the_defaults_keep_devices_to_the_internet() {
        assert_eq!(local_reach(&Config::default()), NONE);
    }

    #[test]
    fn rules_carry_this_computers_addresses_only_when_they_use_them() {
        let closed = desired(&[hotspot()], NONE, &ifaces());
        let (key, config) = &closed[0];
        assert_eq!(*key, 1);
        assert_eq!(config.own_addresses, [Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(192, 168, 137, 1)], "no loopback");
        assert_eq!(config.if_index, Some(17), "found by the adapter's name");

        let open = desired(&[hotspot()], LocalReach { this_computer: true, ..NONE }, &ifaces());
        assert!(open[0].1.own_addresses.is_empty());
        // Router advertisements and redirects are dropped on the adapter
        // whatever the settings, so its index always goes in.
        assert_eq!(open[0].1.if_index, Some(17));
        assert_eq!(desired(&[hotspot()], ALL, &ifaces())[0].1.if_index, Some(17));
        // So a new address elsewhere changes nothing that needs putting in again.
        let mut more = ifaces();
        more.push(iface("VPN", 30, &["10.8.0.2"]));
        assert_eq!(desired(&[hotspot()], ALL, &more), desired(&[hotspot()], ALL, &ifaces()));
    }

    #[test]
    fn a_network_whose_adapter_has_no_name_yet_gets_no_index() {
        // Before the access point starts, Windows has not made its adapter.
        let starting = SharedNetwork { interface: String::new(), ..hotspot() };
        let mut nameless = ifaces();
        nameless.push(Interface { system_name: String::new(), ..iface("", 9, &[]) });
        let (_, config) = &desired(&[starting], NONE, &nameless)[0];
        assert_eq!(config.if_index, None);
        assert_eq!(config.subnet, hotspot().subnet, "held to the rules by its addresses all the same");
    }

    #[test]
    fn the_engine_refuses_what_the_settings_refuse() {
        let device: IpAddr = "192.168.137.23".parse().unwrap();
        let closed = ReachView::new(&[hotspot()], NONE, &ifaces());
        let open = ReachView::new(&[hotspot()], ALL, &ifaces());
        for (destination, refused_when_closed) in [
            ("192.168.137.1", true),  // this computer on the hotspot
            ("192.168.1.50", true),   // this computer at home
            ("fe80::1", true),        // this computer over IPv6
            ("192.168.137.40", true), // another device
            ("192.168.1.1", true),    // the router
            ("10.0.0.7", true),
            ("8.8.8.8", false),
            ("198.18.0.5", false),
            ("2606:4700::1111", false),
        ] {
            let destination: IpAddr = destination.parse().unwrap();
            assert_eq!(closed.refuses(device, destination), refused_when_closed, "{destination} closed");
            assert!(!open.refuses(device, destination), "{destination} open");
        }
        for loopback in ["127.0.0.1", "127.9.9.9", "::1", "0.0.0.0", "::ffff:127.0.0.1"] {
            assert!(open.refuses(device, loopback.parse().unwrap()), "{loopback} is never reachable");
        }
    }

    #[test]
    fn a_phone_on_usb_follows_the_same_settings() {
        let phone: IpAddr = "192.168.42.129".parse().unwrap();
        let closed = ReachView::new::<u8>(&[], NONE, &ifaces());
        assert!(closed.refuses(phone, "192.168.1.50".parse().unwrap()), "this computer");
        assert!(closed.refuses(phone, "192.168.1.1".parse().unwrap()), "the home network");
        assert!(!closed.refuses(phone, "1.1.1.1".parse().unwrap()));
        assert!(!ReachView::new::<u8>(&[], ALL, &ifaces()).refuses(phone, "192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn before_any_settings_only_loopback_is_refused() {
        let view = ReachView::default();
        assert!(!view.refuses("192.168.137.23".parse().unwrap(), "192.168.1.1".parse().unwrap()));
        assert!(view.refuses("192.168.137.23".parse().unwrap(), "127.0.0.1".parse().unwrap()));
    }
}
