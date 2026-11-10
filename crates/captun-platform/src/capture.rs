//! Taking devices' traffic into the routing engine, so it can decide each
//! flow and send it out through the device's chosen outbound.
//!
//! - **Linux:** a TUN device plus policy routing: traffic arriving on the
//!   device network's interface is looked up in a table whose default route is
//!   the TUN (`ip rule`/`ip route`).
//! - **Windows:** routing cannot select by source, so WinDivert takes the
//!   devices' packets out of Windows' own forwarding instead (see `divert`).
//!
//! [`create`] gives the engine's packet device and a [`Steerer`] that adds and
//! removes networks while the engine runs. Transparent routing is opt-in
//! (`network.transparent_routing`) until it has been proven on more hardware.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("this system cannot route devices one by one yet")]
    Unsupported,
    #[cfg(target_os = "linux")]
    #[error("cannot create the TUN device (are we root?): {0}")]
    Tun(#[from] tun::Error),
    #[error("{0}")]
    Driver(String),
    #[error("cannot steer the network's traffic: {0}")]
    Steering(String),
}

/// What the engine needs to know to take the right traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureConfig {
    /// OS name of the interface the devices are on.
    pub hotspot_interface: String,
    /// The devices' network, e.g. `192.168.137.0/24`.
    pub subnet: IpNet,
    /// This computer's address on that network. Traffic to it is not captured:
    /// the sign-in page and the system's own services live there.
    pub gateway: IpAddr,
    /// Also take the DNS queries devices send to `gateway`, for the hub to
    /// answer through each device's own way out. On Windows another DNS
    /// server (Internet Connection Sharing's) holds that address.
    pub dns: bool,
}

impl CaptureConfig {
    /// Whether steering `other` puts in the very rules steering `self` did,
    /// so a steering of `self` can stand for `other` without being opened
    /// again. Linux steers by the adapter's name and the network alone, and
    /// cannot hold the same rules twice: taking one copy out takes both.
    /// Windows' capture follows the network, this computer's address on it
    /// and whether DNS is taken, never the adapter's name.
    pub fn steers_like(&self, other: &Self) -> bool {
        if cfg!(target_os = "linux") {
            self.hotspot_interface == other.hotspot_interface && self.subnet == other.subnet
        } else if cfg!(windows) {
            self.subnet == other.subnet && self.gateway == other.gateway && self.dns == other.dns
        } else {
            self == other
        }
    }

    /// Whether a steering of `other` must go before `self` is steered. On
    /// Linux every network on one adapter shares the rule that sends that
    /// adapter's traffic to the TUN (it names the adapter alone): steering
    /// `self` puts that rule in afresh, and `other`'s going would then take
    /// it out from under `self`. Windows' captures share nothing.
    pub fn clashes_with(&self, other: &Self) -> bool {
        cfg!(target_os = "linux") && self.hotspot_interface == other.hotspot_interface
    }
}

/// Whether a network can be steered before its adapter is known, by its
/// addresses alone: Windows' capture learns the adapter from the devices'
/// first packets, while Linux steers by the adapter's name.
pub fn steers_by_address() -> bool {
    cfg!(windows)
}

/// The engine's packet device on this system.
#[cfg(target_os = "linux")]
pub type Device = tun::AsyncDevice;
#[cfg(windows)]
pub type Device = crate::divert::DivertDevice;
#[cfg(not(any(target_os = "linux", windows)))]
pub type Device = tokio::io::DuplexStream;

/// Whether this build can route devices through the engine at all. WinDivert
/// ships for x64 Windows only.
pub fn supports_transparent_routing() -> bool {
    cfg!(any(target_os = "linux", all(windows, target_arch = "x86_64")))
}

/// Opens the engine's packet device and the steerer that feeds networks into it.
pub async fn create() -> Result<(Device, Steerer), CaptureError> {
    #[cfg(target_os = "linux")]
    return linux::create_device().map(|device| (device, Steerer {}));
    #[cfg(windows)]
    return crate::divert::open().map(|(device, divert)| (device, Steerer { divert }));
    #[cfg(not(any(target_os = "linux", windows)))]
    Err(CaptureError::Unsupported)
}

/// Adds networks to the engine while it runs.
#[derive(Debug)]
pub struct Steerer {
    #[cfg(windows)]
    divert: crate::divert::DivertSteerer,
}

impl Steerer {
    /// Starts sending one network's traffic into the engine. `adapters` is
    /// the adapter list as read beforehand (`iface::list_async`), where the
    /// capture looks for the network's adapter when it needs it (Windows):
    /// callers hold the engine's lock, and a read can take seconds. Keep the
    /// guard: dropping it gives the network back to the system.
    #[cfg_attr(not(windows), allow(unused_variables))]
    pub fn steer(&self, config: &CaptureConfig, adapters: &[crate::iface::Interface]) -> Result<SteeringGuard, CaptureError> {
        #[cfg(target_os = "linux")]
        return linux::steer(config);
        #[cfg(windows)]
        return self.divert.steer(config, adapters).map(|capture| SteeringGuard { _capture: capture });
        #[cfg(not(any(target_os = "linux", windows)))]
        Err(CaptureError::Unsupported)
    }

    /// Packets taken from devices so far, where the system can tell.
    pub fn captured_packets(&self) -> Option<u64> {
        #[cfg(windows)]
        return Some(self.divert.captured_packets());
        #[cfg(not(windows))]
        None
    }

    /// Of those, the packets dropped because the engine had fallen behind,
    /// where the system can tell.
    pub fn dropped_packets(&self) -> Option<u64> {
        #[cfg(windows)]
        return Some(self.divert.dropped_packets());
        #[cfg(not(windows))]
        None
    }
}

/// Keeps one network steered into the engine; dropping it reverts that.
#[derive(Debug)]
pub struct SteeringGuard {
    #[cfg(target_os = "linux")]
    cleanup: Vec<Argv>,
    #[cfg(windows)]
    _capture: crate::divert::NetworkCapture,
}

#[cfg(target_os = "linux")]
impl Drop for SteeringGuard {
    fn drop(&mut self) {
        for (program, args) in &self.cleanup {
            match std::process::Command::new(program).args(args).output() {
                Ok(out) if !out.status.success() => tracing::warn!(
                    "steering cleanup `{program} {}` failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
                Err(e) => tracing::warn!("steering cleanup `{program}` could not run: {e}"),
                Ok(_) => {}
            }
        }
    }
}

/// The WinDivert filter that matches a device network's traffic to anywhere
/// but that network itself (so the sign-in page and device-to-device traffic
/// stay untouched, multicast and broadcast too), and, with `dns_at`, the DNS
/// queries devices send to that address.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn divert_filter(subnet: Ipv4Net, dns_at: Option<Ipv4Addr>) -> String {
    let (first, last) = (subnet.network(), subnet.broadcast());
    let outside = format!("(ip.DstAddr < {first} or ip.DstAddr > {last}) and ip.DstAddr < {}", Ipv4Addr::new(224, 0, 0, 0));
    let wanted = match dns_at {
        Some(dns) => format!("(({outside}) or (ip.DstAddr == {dns} and (udp.DstPort == 53 or tcp.DstPort == 53)))"),
        None => outside,
    };
    format!("ip and ip.SrcAddr >= {first} and ip.SrcAddr <= {last} and {wanted}")
}

/// One command to run, as a program and its separate arguments (never a shell
/// string, so values with spaces or metacharacters are safe).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
type Argv = (String, Vec<String>);

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn argv(program: &str, args: &[&str]) -> Argv {
    (program.to_owned(), args.iter().map(|s| s.to_string()).collect())
}

/// Linux policy-routing table and rule priorities. The priorities sit above the
/// main table's default rule so our rules are consulted first.
const RT_TABLE: &str = "7777";
const RULE_PRIO_LOCAL: u32 = 10000;
const RULE_PRIO_TUN: u32 = 10001;
// The subnet-local exception must be consulted before the catch-all TUN rule.
const _: () = assert!(RULE_PRIO_LOCAL < RULE_PRIO_TUN);

/// Name of the TUN adapter Captun creates on Linux.
pub const TUN_NAME: &str = "captun";

/// Policy routing that sends traffic arriving on the devices' interface to the
/// TUN, except traffic to their own subnet (device to device, and the gateway,
/// so DNS and the sign-in page keep working). Returns `(apply, cleanup)`.
///
/// Every network shares the table and the two priorities, so the cleanup
/// names this network's rules by everything they were added with: a rule
/// deleted by its priority alone would be whichever network's came first.
/// It leaves the table alone, since the other networks' rules still look it
/// up; its one route goes through the TUN and goes away with it when the
/// engine stops.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_steering(hotspot_if: &str, subnet: &str) -> (Vec<Argv>, Vec<Argv>) {
    let prio_local = RULE_PRIO_LOCAL.to_string();
    let prio_tun = RULE_PRIO_TUN.to_string();
    let local = ["iif", hotspot_if, "to", subnet, "priority", prio_local.as_str(), "lookup", "main"];
    let tun = ["iif", hotspot_if, "priority", prio_tun.as_str(), "lookup", RT_TABLE];
    let rule = |action: &str, selectors: &[&str]| argv("ip", &[&["rule", action][..], selectors].concat());
    let apply = vec![
        argv("ip", &["route", "replace", "default", "dev", TUN_NAME, "table", RT_TABLE]),
        rule("add", &local),
        rule("add", &tun),
    ];
    let cleanup = vec![rule("del", &tun), rule("del", &local)];
    (apply, cleanup)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::Ipv4Addr;

    use tracing::info;

    use super::{Argv, CaptureConfig, CaptureError, SteeringGuard, TUN_NAME, linux_steering};

    /// Link address on the TUN, off common private ranges to avoid clashes;
    /// traffic is sent here by policy routing, not by this address.
    const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 124, 0, 1);
    const TUN_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 252);
    /// Matches the engine's IP stack.
    const MTU: u16 = 1500;

    pub(super) fn create_device() -> Result<tun::AsyncDevice, CaptureError> {
        let mut config = tun::Configuration::default();
        config.tun_name(TUN_NAME).address(TUN_ADDR).netmask(TUN_NETMASK).mtu(MTU).up();
        let device = tun::create_as_async(&config)?;
        info!(tun = TUN_NAME, "packet device up");
        Ok(device)
    }

    pub(super) fn steer(config: &CaptureConfig) -> Result<SteeringGuard, CaptureError> {
        let (apply, cleanup) = linux_steering(&config.hotspot_interface, &config.subnet.to_string());
        // A run that was stopped abruptly may have left this network's rules
        // behind, and adding a rule that is already there fails. The cleanup
        // names only this network's rules, so another network's stay.
        run_quietly(&cleanup);
        if let Err(e) = run_all(apply) {
            // Takes out the rules that did go in.
            run_quietly(&cleanup);
            return Err(e);
        }
        info!(subnet = %config.subnet, interface = %config.hotspot_interface, "traffic steered into the engine");
        Ok(SteeringGuard { cleanup })
    }

    /// Runs commands whose failure only means there was nothing to remove.
    fn run_quietly(commands: &[Argv]) {
        for (program, args) in commands {
            let _ = std::process::Command::new(program).args(args).output();
        }
    }

    fn run_all(commands: Vec<Argv>) -> Result<(), CaptureError> {
        for (program, args) in commands {
            let output = std::process::Command::new(&program)
                .args(&args)
                .output()
                .map_err(|e| CaptureError::Steering(format!("cannot run {program}: {e}")))?;
            if !output.status.success() {
                return Err(CaptureError::Steering(format!(
                    "`{program} {}` failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_apply_and_cleanup_are_inverse() {
        let (apply, cleanup) = linux_steering("wlan0", "192.168.137.0/24");
        assert_eq!(apply.len(), 3);
        // The default route into the TUN lands in our private table, never main.
        assert!(apply[0].1.contains(&"table".to_string()) && apply[0].1.contains(&RT_TABLE.to_string()));
        // Subnet-local traffic (gateway, DNS, peers) stays on the main table.
        assert!(apply[1].1.windows(2).any(|w| w == ["to", "192.168.137.0/24"]));
        // Cleanup deletes exactly the two rules added, last first, by every
        // selector they were added with, and leaves the shared table alone.
        let deleted: Vec<Vec<String>> = apply[1..]
            .iter()
            .rev()
            .map(|(_, args)| args.iter().map(|a| if a == "add" { "del".to_owned() } else { a.clone() }).collect())
            .collect();
        assert_eq!(cleanup.iter().map(|(_, args)| args.clone()).collect::<Vec<_>>(), deleted);
        assert_eq!(
            cleanup[0].1,
            ["rule", "del", "iif", "wlan0", "priority", &RULE_PRIO_TUN.to_string(), "lookup", RT_TABLE]
        );
        assert_eq!(
            cleanup[1].1,
            ["rule", "del", "iif", "wlan0", "to", "192.168.137.0/24", "priority", &RULE_PRIO_LOCAL.to_string(), "lookup", "main"]
        );
        assert!(cleanup.iter().all(|(program, args)| program == "ip" && !args.contains(&"flush".to_owned())));
    }

    /// Stopping cable sharing must never take the hotspot's rules, or empty
    /// the table they look up.
    #[test]
    fn one_networks_cleanup_never_touches_anothers() {
        let (hotspot_apply, hotspot) = linux_steering("wlan0", "192.168.137.0/24");
        let (_, cable) = linux_steering("eth1", "10.73.0.0/24");
        for command in &cable {
            assert!(!hotspot.contains(command), "{command:?}");
            assert!(command.1.windows(2).any(|w| w == ["iif", "eth1"]), "{command:?}");
            // Nothing that would also match one of the hotspot's rules.
            assert!(!hotspot_apply[1..].iter().any(|(_, added)| added[2..] == command.1[2..]), "{command:?}");
        }
    }

    #[test]
    fn linux_rules_are_ordered_local_before_tun() {
        let (apply, _) = linux_steering("wlan0", "10.42.0.0/24");
        let prio = |a: &Argv| a.1.iter().position(|x| x == "priority").map(|i| a.1[i + 1].clone());
        assert_eq!(prio(&apply[1]).unwrap(), RULE_PRIO_LOCAL.to_string());
        assert_eq!(prio(&apply[2]).unwrap(), RULE_PRIO_TUN.to_string());
    }

    #[test]
    fn windows_capture_takes_device_traffic_but_leaves_the_device_network_alone() {
        let filter = divert_filter("192.168.137.0/24".parse().unwrap(), None);
        assert_eq!(
            filter,
            "ip and ip.SrcAddr >= 192.168.137.0 and ip.SrcAddr <= 192.168.137.255 and (ip.DstAddr < 192.168.137.0 or ip.DstAddr > 192.168.137.255) and ip.DstAddr < 224.0.0.0"
        );
    }

    #[test]
    fn windows_capture_can_take_dns_sent_to_this_computer() {
        let filter = divert_filter("192.168.137.0/24".parse().unwrap(), Some(Ipv4Addr::new(192, 168, 137, 1)));
        assert_eq!(
            filter,
            "ip and ip.SrcAddr >= 192.168.137.0 and ip.SrcAddr <= 192.168.137.255 and (((ip.DstAddr < 192.168.137.0 or ip.DstAddr > 192.168.137.255) and ip.DstAddr < 224.0.0.0) or (ip.DstAddr == 192.168.137.1 and (udp.DstPort == 53 or tcp.DstPort == 53)))"
        );
    }

    #[test]
    fn a_steering_stands_for_a_config_that_needs_the_same_rules() {
        let hotspot = CaptureConfig {
            hotspot_interface: String::new(),
            subnet: "192.168.137.0/24".parse().unwrap(),
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 137, 1)),
            dns: true,
        };
        let named = CaptureConfig { hotspot_interface: "Local Area Connection* 2".into(), ..hotspot.clone() };
        let without_dns = CaptureConfig { dns: false, ..hotspot.clone() };
        let elsewhere = CaptureConfig { subnet: "10.74.0.0/24".parse().unwrap(), ..hotspot.clone() };
        assert!(hotspot.steers_like(&hotspot));
        assert!(!hotspot.steers_like(&elsewhere), "another network");
        if cfg!(windows) {
            // Steered before Windows named the adapter: the name changes nothing.
            assert!(hotspot.steers_like(&named));
            assert!(!hotspot.steers_like(&without_dns), "the filter takes DNS or not");
            assert!(steers_by_address());
        }
        if cfg!(target_os = "linux") {
            assert!(!hotspot.steers_like(&named), "rules name the adapter");
            assert!(hotspot.steers_like(&without_dns), "rules leave DNS to the main table");
            assert!(!steers_by_address());
        }
    }

    /// A network that moves to another subnet on the same adapter (a
    /// fallback way, say) shares its old steering's rule into the TUN, so on
    /// Linux the old steering goes before the new one opens.
    #[test]
    fn two_networks_on_one_adapter_clash_on_linux_only() {
        let first = CaptureConfig {
            hotspot_interface: "wlan0".into(),
            subnet: "10.42.0.0/24".parse().unwrap(),
            gateway: IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)),
            dns: false,
        };
        let moved = CaptureConfig {
            subnet: "10.74.0.0/24".parse().unwrap(),
            gateway: IpAddr::V4(Ipv4Addr::new(10, 74, 0, 1)),
            ..first.clone()
        };
        let elsewhere = CaptureConfig { hotspot_interface: "eth1".into(), ..moved.clone() };
        assert_eq!(moved.clashes_with(&first), cfg!(target_os = "linux"));
        assert!(!moved.clashes_with(&elsewhere), "another adapter has rules of its own");
        // The rule they share, word for word.
        let (_, old) = linux_steering("wlan0", "10.42.0.0/24");
        let (_, new) = linux_steering("wlan0", "10.74.0.0/24");
        assert_eq!(old.iter().filter(|rule| new.contains(rule)).count(), 1);
        let (_, other) = linux_steering("eth1", "10.74.0.0/24");
        assert!(!new.iter().any(|rule| other.contains(rule)));
    }

    #[test]
    fn argv_keeps_values_separate() {
        let (program, args) = argv("ip", &["rule", "add", "iif", "wlan 0"]);
        assert_eq!(program, "ip");
        assert_eq!(args, ["rule", "add", "iif", "wlan 0"]);
    }
}
