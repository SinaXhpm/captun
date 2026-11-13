//! What devices on a shared network may reach besides the internet: this
//! computer, one another, and the private networks this computer is on (the
//! home network and its router).
//!
//! - **Windows:** WinDivert drops what the settings refuse before Windows
//!   delivers or forwards it, ahead of the routing engine's capture. Letting
//!   devices reach this computer also opens Windows Firewall to their network,
//!   which Windows otherwise treats as a public one. Whether devices on the
//!   Wi-Fi hotspot reach each other directly is up to the Wi-Fi driver: that
//!   traffic never climbs to Windows' IP layer, so only what passes through
//!   this computer can be held back.
//! - **Linux:** iptables chains on the network's interface (`INPUT` for this
//!   computer, `FORWARD` for the rest). The access point keeps Wi-Fi devices
//!   apart (`ap_isolate`), set when the hotspot starts.
//! - **Elsewhere:** not enforced yet; [`apply`] says so when something would
//!   need to be.
//!
//! Each change is undone when the returned [`ReachGuard`] is dropped. The
//! filters and commands are built by pure functions, tested on any system.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;

/// What devices may reach besides the internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalReach {
    /// This computer itself, beyond what sharing needs (DHCP and DNS).
    pub this_computer: bool,
    /// The other devices on the same network.
    pub each_other: bool,
    /// The private networks this computer is on: the home network, the
    /// router, other networks Captun shares.
    pub home_network: bool,
}

/// The most of this computer's addresses one rule lists; WinDivert filters
/// are kept short (it does not optimise them).
pub const MAX_OWN_ADDRESSES: usize = 32;

/// One shared network and what its devices may reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReachConfig {
    /// OS name of the network's interface: the friendly name on Windows, the
    /// kernel name on Linux.
    pub interface: String,
    /// OS index of the interface, once known.
    pub if_index: Option<u32>,
    /// The devices' network, e.g. `192.168.137.0/24`.
    pub subnet: Ipv4Net,
    /// This computer's address on that network.
    pub gateway: Ipv4Addr,
    /// This computer's IPv4 addresses on every adapter (loopback aside).
    pub own_addresses: Vec<Ipv4Addr>,
    pub reach: LocalReach,
}

#[derive(Debug, thiserror::Error)]
pub enum ReachError {
    #[error("this system cannot limit what devices reach yet")]
    Unsupported,
    #[error("{0}")]
    Failed(String),
}

/// Ranges reachable only from this computer's own networks, never across the
/// internet: "this network", private, shared (carrier NAT), loopback and
/// link-local. Not 198.18.0.0/15: proxy tools hand out "fake" addresses
/// there that must keep working.
const PRIVATE: [(Ipv4Addr, u8); 7] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
];

fn private_nets() -> impl Iterator<Item = Ipv4Net> {
    PRIVATE.iter().filter_map(|&(addr, prefix)| Ipv4Net::new(addr, prefix).ok())
}

/// Whether `ip` lies in a range only this computer's own networks reach (see
/// [`PRIVATE`]); for IPv6: loopback, link-local and unique-local addresses.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => private_nets().any(|net| net.contains(&v4)),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback() || v6.is_unspecified() || first & 0xffc0 == 0xfe80 || first & 0xfe00 == 0xfc00
        }
    }
}

/// Whether this build can hold devices back at all.
pub fn supported() -> bool {
    cfg!(any(target_os = "linux", all(windows, target_arch = "x86_64")))
}

/// Whether Captun decides if devices on its Wi-Fi hotspot reach each other.
/// On Windows the Wi-Fi driver does, out of Captun's reach.
pub fn wifi_isolation_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Keeps one network's rules in force; dropping it lifts them.
pub struct ReachGuard {
    #[cfg(windows)]
    _drops: Vec<crate::divert::DropRule>,
    #[cfg(any(windows, target_os = "linux"))]
    cleanup: Vec<Argv>,
    warning: Option<String>,
}

impl ReachGuard {
    /// What could not be done while the rest was, such as opening the
    /// firewall for devices.
    pub fn warning(&self) -> Option<&str> {
        self.warning.as_deref()
    }
}

impl std::fmt::Debug for ReachGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReachGuard").field("warning", &self.warning).finish_non_exhaustive()
    }
}

#[cfg(any(windows, target_os = "linux"))]
impl Drop for ReachGuard {
    fn drop(&mut self) {
        for (program, args) in &self.cleanup {
            let tool = crate::tools::tool_name(program);
            match command(program, args).output() {
                Ok(out) if !out.status.success() => tracing::warn!(
                    "lifting a device rule (`{tool} {}`) failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
                Err(e) => tracing::warn!("lifting a device rule: cannot run {tool}: {e}"),
                Ok(_) => {}
            }
        }
    }
}

/// Puts `config`'s rules in force. Blocking: on Windows it may run
/// PowerShell to open the firewall.
pub fn apply(config: &ReachConfig) -> Result<ReachGuard, ReachError> {
    #[cfg(windows)]
    return windows::apply(config);
    #[cfg(target_os = "linux")]
    return linux::apply(config);
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let reach = config.reach;
        if reach.this_computer && reach.each_other && reach.home_network {
            Ok(ReachGuard { warning: None })
        } else {
            Err(ReachError::Unsupported)
        }
    }
}

/// Lifts rules a previous run could not lift itself (it was stopped
/// abruptly). Blocking.
pub fn clear_leftovers() {
    #[cfg(windows)]
    {
        let (program, args) = clear_firewall();
        if let Err(e) = command(&program, &args).output() {
            tracing::warn!("cannot check the firewall for old device rules: {e}");
        }
    }
}

/// One command: a program and its separate arguments (never a shell string).
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
type Argv = (String, Vec<String>);

#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
fn argv(program: &str, args: &[&str]) -> Argv {
    (program.to_owned(), args.iter().map(|s| s.to_string()).collect())
}

/// A command that never opens a console window, and on Windows gets only
/// Windows' own environment ([`crate::tools::command`]).
#[cfg(any(windows, target_os = "linux"))]
fn command(program: &str, args: &[String]) -> std::process::Command {
    let mut command = crate::tools::command(program);
    command.args(args);
    command
}

#[cfg(any(windows, target_os = "linux"))]
fn run_all(commands: &[Argv]) -> Result<(), String> {
    for (program, args) in commands {
        let tool = crate::tools::tool_name(program);
        let output = command(program, args).output().map_err(|e| format!("cannot run {tool}: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let why = if stderr.trim().is_empty() { stdout } else { stderr };
            return Err(format!("`{tool} {}` failed: {}", args.join(" "), why.trim()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- Windows

fn range(field: &str, net: Ipv4Net) -> String {
    format!("({field} >= {} and {field} <= {})", net.network(), net.broadcast())
}

fn outside(field: &str, net: Ipv4Net) -> String {
    format!("({field} < {} or {field} > {})", net.network(), net.broadcast())
}

/// `condition` turned around. WinDivert takes `not` before a single test
/// only, and a test on a header the packet lacks is false whichever way it
/// is put (a TCP packet has neither `udp.DstPort == 67` nor `!= 67`), so
/// this goes through its `?:` operator, which is a true "otherwise".
fn unless(condition: &str) -> String {
    format!("({condition} ? false : true)")
}

/// Packets from the network's devices (never this computer's own, which
/// shares their source range through the gateway address).
fn from_devices(config: &ReachConfig) -> String {
    format!("ip and {} and ip.SrcAddr != {}", range("ip.SrcAddr", config.subnet), config.gateway)
}

/// Private destinations outside the devices' own network.
fn private_outside(subnet: Ipv4Net) -> String {
    let ranges: Vec<String> = private_nets().map(|net| range("ip.DstAddr", net)).collect();
    format!("(({}) and {})", ranges.join(" or "), outside("ip.DstAddr", subnet))
}

/// What devices send to this computer that the settings refuse (WinDivert,
/// local layer). `None` when nothing is refused there.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn local_filter(config: &ReachConfig) -> Option<String> {
    let mut refused = Vec::new();
    if !config.reach.this_computer {
        // Each of this computer's addresses, and its share of broadcast and
        // multicast (name lookups, discovery), except what sharing needs:
        // DHCP, and DNS at the gateway.
        let own = config.own_addresses.iter().take(MAX_OWN_ADDRESSES).copied();
        let mut addresses: Vec<Ipv4Addr> = own.chain([config.gateway, config.subnet.broadcast()]).collect();
        addresses.sort_unstable();
        addresses.dedup();
        let mut to: Vec<String> = addresses.iter().map(|a| format!("ip.DstAddr == {a}")).collect();
        to.push(format!("(ip.DstAddr >= {} and ip.DstAddr <= {})", Ipv4Addr::new(127, 0, 0, 0), Ipv4Addr::new(127, 255, 255, 255)));
        to.push(format!("ip.DstAddr >= {}", Ipv4Addr::new(224, 0, 0, 0)));
        let needed = format!("(udp.DstPort == 67 or (ip.DstAddr == {} and (udp.DstPort == 53 or tcp.DstPort == 53)))", config.gateway);
        refused.push(format!("(({}) and {})", to.join(" or "), unless(&needed)));
    }
    if !config.reach.home_network {
        refused.push(private_outside(config.subnet));
    }
    (!refused.is_empty()).then(|| format!("inbound and {} and ({})", from_devices(config), refused.join(" or ")))
}

/// What devices send through this computer that the settings refuse
/// (WinDivert, forward layer). `None` when nothing is refused there.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn forward_filter(config: &ReachConfig) -> Option<String> {
    let mut refused = Vec::new();
    if !config.reach.each_other {
        refused.push(format!(
            "({} and ip.DstAddr != {} and ip.DstAddr != {})",
            range("ip.DstAddr", config.subnet),
            config.gateway,
            config.subnet.broadcast()
        ));
    }
    if !config.reach.home_network {
        refused.push(private_outside(config.subnet));
    }
    (!refused.is_empty()).then(|| format!("{} and ({})", from_devices(config), refused.join(" or ")))
}

/// ICMPv6 router advertisements (134) and redirects (137). A device has no
/// reason to send this computer either one: with them it would make itself
/// this computer's IPv6 router, and with the advertisement's DNS option its
/// DNS server too. They are refused whatever the settings.
const ROUTER_MESSAGES: [u8; 2] = [134, 137];

/// What finding neighbours needs: router solicitations (133), neighbour
/// solicitations (135) and neighbour advertisements (136). Spared when
/// devices are kept off this computer.
const NEIGHBOUR_DISCOVERY: [u8; 3] = [133, 135, 136];

/// `icmpv6.Type == a or icmpv6.Type == b ...`, in brackets.
#[cfg_attr(not(windows), allow(dead_code))]
fn icmpv6_types(types: &[u8]) -> String {
    let tests: Vec<String> = types.iter().map(|t| format!("icmpv6.Type == {t}")).collect();
    format!("({})", tests.join(" or "))
}

/// IPv6 from the network's devices to this computer (link-local addresses
/// reach it too) that is refused: router advertisements and redirects
/// always, and with `this_computer` off everything but what finding
/// neighbours needs. Needs the adapter's index: IPv6 sources do not say
/// which network they are on.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn ipv6_filter(config: &ReachConfig) -> Option<String> {
    let index = config.if_index?;
    // Router messages are not among those spared, so the second refuses
    // them too.
    let refused =
        if config.reach.this_computer { icmpv6_types(&ROUTER_MESSAGES) } else { unless(&icmpv6_types(&NEIGHBOUR_DISCOVERY)) };
    Some(format!("inbound and ipv6 and ifIdx == {index} and {refused}"))
}

/// The firewall rule that lets a network's devices reach this computer.
#[cfg_attr(not(windows), allow(dead_code))]
fn firewall_rule(subnet: Ipv4Net) -> String {
    format!("Captun devices {subnet}")
}

/// Every such rule carries this group, so leftovers can be found.
#[cfg_attr(not(windows), allow(dead_code))]
const FIREWALL_GROUP: &str = "Captun devices";

/// Lifts every such rule a run that stopped abruptly left behind.
#[cfg_attr(not(windows), allow(dead_code))]
fn clear_firewall() -> Argv {
    powershell(format!("Remove-NetFirewallRule -Group '{FIREWALL_GROUP}' -ErrorAction SilentlyContinue"))
}

#[cfg_attr(not(windows), allow(dead_code))]
fn powershell(script: String) -> Argv {
    let program = crate::tools::system_tool(crate::tools::POWERSHELL);
    argv(&program, &["-NoProfile", "-NonInteractive", "-Command", &script])
}

/// Opens Windows Firewall to the devices' network, for this computer's
/// address there only. Returns `(apply, cleanup)`.
#[cfg_attr(not(windows), allow(dead_code))]
fn firewall_steps(config: &ReachConfig) -> (Vec<Argv>, Vec<Argv>) {
    let name = firewall_rule(config.subnet);
    let apply = powershell(format!(
        "Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue; \
         New-NetFirewallRule -DisplayName '{name}' -Group '{FIREWALL_GROUP}' \
         -Description 'Lets devices on a network Captun shares reach this computer. Removed when sharing stops.' \
         -Direction Inbound -Action Allow -Profile Any -LocalAddress {} -RemoteAddress {} -ErrorAction Stop | Out-Null",
        config.gateway, config.subnet
    ));
    let cleanup = powershell(format!("Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue"));
    (vec![apply], vec![cleanup])
}

#[cfg(windows)]
mod windows {
    use super::{
        ReachConfig, ReachError, ReachGuard, firewall_steps, forward_filter, ipv6_filter, local_filter, run_all,
    };
    use crate::divert::{self, Layer};

    pub(super) fn apply(config: &ReachConfig) -> Result<ReachGuard, ReachError> {
        let mut drops = Vec::new();
        let mut warnings = Vec::new();
        let rules = [
            (local_filter(config), Layer::Local, true),
            (forward_filter(config), Layer::Forward, true),
            // With this computer open to devices, the IPv6 rule only refuses
            // router messages: worth saying when it cannot go in, not worth
            // stopping the rest over.
            (ipv6_filter(config), Layer::Local, !config.reach.this_computer),
        ];
        for (filter, layer, required) in rules {
            let Some(filter) = filter else { continue };
            match divert::drop_rule(&filter, layer) {
                Ok(rule) => drops.push(rule),
                Err(e) if !required => {
                    warnings.push(format!("a device could still make itself this computer's IPv6 router ({e})"));
                }
                Err(e) => return Err(ReachError::Failed(format!("cannot hold devices back: {e}"))),
            }
        }
        let mut guard = ReachGuard { _drops: drops, cleanup: Vec::new(), warning: None };
        if config.reach.this_computer {
            let (apply, cleanup) = firewall_steps(config);
            match run_all(&apply) {
                Ok(()) => guard.cleanup = cleanup,
                Err(e) => warnings.push(format!(
                    "Windows Firewall could not be opened for devices, so it decides what they reach on this computer ({e})"
                )),
            }
        }
        guard.warning = (!warnings.is_empty()).then(|| warnings.join("; "));
        tracing::info!(subnet = %config.subnet, reach = ?config.reach, drops = guard._drops.len(), "device rules in force");
        Ok(guard)
    }
}

// ------------------------------------------------------------------ Linux

/// The chains for one network, named after its subnet so a leftover from a
/// run that stopped abruptly is found and replaced.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn chain(kind: &str, subnet: Ipv4Net) -> String {
    format!("CAPTUN-{kind}-{}", subnet.network().to_string().replace('.', "-"))
}

/// Commands that put rules in, and the commands that lift them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
type Plan = (Vec<Argv>, Vec<Argv>);

/// The iptables plan for one network: IPv4, then IPv6, which is best effort
/// (not every system has ip6tables).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_steps(config: &ReachConfig) -> (Plan, Plan) {
    let dev = config.interface.as_str();
    let subnet = config.subnet.to_string();
    let gateway = config.gateway.to_string();
    let reach = config.reach;
    let privates: Vec<String> = private_nets().map(|net| net.to_string()).collect();
    let (mut apply, mut cleanup) = (Vec::new(), Vec::new());

    if !reach.this_computer || !reach.home_network {
        let input = chain("IN", config.subnet);
        let rule = |args: &[&str]| {
            let mut all = vec!["-A", input.as_str()];
            all.extend_from_slice(args);
            argv("iptables", &all)
        };
        apply.push(argv("iptables", &["-N", &input]));
        apply.push(rule(&["-p", "udp", "--dport", "67", "-j", "RETURN"]));
        apply.push(rule(&["-d", &gateway, "-p", "udp", "--dport", "53", "-j", "RETURN"]));
        apply.push(rule(&["-d", &gateway, "-p", "tcp", "--dport", "53", "-j", "RETURN"]));
        if !reach.this_computer {
            apply.push(rule(&["-j", "DROP"]));
        } else {
            apply.push(rule(&["-d", &subnet, "-j", "RETURN"]));
            for net in &privates {
                apply.push(rule(&["-d", net, "-j", "DROP"]));
            }
        }
        apply.push(argv("iptables", &["-I", "INPUT", "-i", dev, "-j", &input]));
        cleanup.push(argv("iptables", &["-D", "INPUT", "-i", dev, "-j", &input]));
        cleanup.push(argv("iptables", &["-F", &input]));
        cleanup.push(argv("iptables", &["-X", &input]));
    }

    if !reach.each_other || !reach.home_network {
        let forward = chain("FWD", config.subnet);
        let rule = |args: &[&str]| {
            let mut all = vec!["-A", forward.as_str()];
            all.extend_from_slice(args);
            argv("iptables", &all)
        };
        apply.push(argv("iptables", &["-N", &forward]));
        if !reach.each_other {
            // Back out the way it came: one device to another through here.
            apply.push(rule(&["-o", dev, "-j", "DROP"]));
        }
        if !reach.home_network {
            apply.push(rule(&["-d", &subnet, "-j", "RETURN"]));
            for net in &privates {
                apply.push(rule(&["-d", net, "-j", "DROP"]));
            }
        }
        apply.push(argv("iptables", &["-I", "FORWARD", "-i", dev, "-j", &forward]));
        cleanup.push(argv("iptables", &["-D", "FORWARD", "-i", dev, "-j", &forward]));
        cleanup.push(argv("iptables", &["-F", &forward]));
        cleanup.push(argv("iptables", &["-X", &forward]));
    }

    // IPv6 to this computer, whatever the settings: no device may send it
    // router advertisements or redirects.
    let (mut apply6, mut cleanup6) = (Vec::new(), Vec::new());
    let input = chain("IN6", config.subnet);
    let rule = |args: &[&str]| {
        let mut all = vec!["-A", input.as_str()];
        all.extend_from_slice(args);
        argv("ip6tables", &all)
    };
    let icmpv6 = |kind: u8, target: &str| {
        rule(&["-p", "ipv6-icmp", "-m", "icmp6", "--icmpv6-type", &kind.to_string(), "-j", target])
    };
    apply6.push(argv("ip6tables", &["-N", &input]));
    apply6.extend(ROUTER_MESSAGES.map(|kind| icmpv6(kind, "DROP")));
    if !reach.this_computer {
        // What finding neighbours needs, and DHCPv6 and DNS where the system
        // serves them.
        apply6.extend(NEIGHBOUR_DISCOVERY.map(|kind| icmpv6(kind, "RETURN")));
        apply6.push(rule(&["-p", "udp", "--dport", "547", "-j", "RETURN"]));
        apply6.push(rule(&["-p", "udp", "--dport", "53", "-j", "RETURN"]));
        apply6.push(rule(&["-p", "tcp", "--dport", "53", "-j", "RETURN"]));
        apply6.push(rule(&["-j", "DROP"]));
    }
    apply6.push(argv("ip6tables", &["-I", "INPUT", "-i", dev, "-j", &input]));
    cleanup6.push(argv("ip6tables", &["-D", "INPUT", "-i", dev, "-j", &input]));
    cleanup6.push(argv("ip6tables", &["-F", &input]));
    cleanup6.push(argv("ip6tables", &["-X", &input]));
    ((apply, cleanup), (apply6, cleanup6))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Argv, ReachConfig, ReachError, ReachGuard, command, linux_steps, run_all};

    /// Runs commands whose failure only means there was nothing to undo.
    fn run_quietly(commands: &[Argv]) {
        for (program, args) in commands {
            let _ = command(program, args).output();
        }
    }

    pub(super) fn apply(config: &ReachConfig) -> Result<ReachGuard, ReachError> {
        let ((apply, cleanup), (apply6, cleanup6)) = linux_steps(config);
        // A run that stopped abruptly may have left the same chains behind.
        run_quietly(&cleanup);
        run_quietly(&cleanup6);
        if let Err(e) = run_all(&apply) {
            run_quietly(&cleanup);
            return Err(ReachError::Failed(format!("cannot hold devices back: {e}")));
        }
        let mut guard = ReachGuard { cleanup, warning: None };
        match run_all(&apply6) {
            Ok(()) => guard.cleanup.extend(cleanup6),
            Err(e) => {
                run_quietly(&cleanup6);
                guard.warning = Some(if config.reach.this_computer {
                    format!("a device could still make itself this computer's IPv6 router ({e})")
                } else {
                    format!("devices may still reach this computer over IPv6 ({e})")
                });
            }
        }
        tracing::info!(subnet = %config.subnet, reach = ?config.reach, "device rules in force");
        Ok(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(this_computer: bool, each_other: bool, home_network: bool) -> ReachConfig {
        ReachConfig {
            interface: "wlan0".into(),
            if_index: Some(17),
            subnet: "192.168.137.0/24".parse().unwrap(),
            gateway: Ipv4Addr::new(192, 168, 137, 1),
            own_addresses: vec![Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(192, 168, 137, 1)],
            reach: LocalReach { this_computer, each_other, home_network },
        }
    }

    #[test]
    fn private_ranges_are_the_ones_only_local_networks_reach() {
        for ip in ["10.1.2.3", "172.31.0.1", "192.168.1.1", "169.254.9.9", "100.100.1.1", "127.0.0.1", "0.1.2.3", "::1", "fe80::1", "fd00::5", "::ffff:192.168.1.1"] {
            assert!(is_private(ip.parse().unwrap()), "{ip} is private");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "198.18.0.1", "2001:4860::8888", "::ffff:1.1.1.1"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip} is public");
        }
    }

    #[test]
    fn everything_allowed_still_refuses_router_messages_on_windows() {
        let open = config(true, true, true);
        assert_eq!((local_filter(&open), forward_filter(&open)), (None, None));
        assert_eq!(
            ipv6_filter(&open).unwrap(),
            "inbound and ipv6 and ifIdx == 17 and (icmpv6.Type == 134 or icmpv6.Type == 137)"
        );
        let mut unknown = open;
        unknown.if_index = None;
        assert_eq!(ipv6_filter(&unknown), None, "IPv6 needs the adapter");
    }

    #[test]
    fn keeping_devices_off_this_computer_spares_dhcp_and_dns() {
        let filter = local_filter(&config(false, true, true)).unwrap();
        assert!(filter.starts_with("inbound and ip and (ip.SrcAddr >= 192.168.137.0 and ip.SrcAddr <= 192.168.137.255) and ip.SrcAddr != 192.168.137.1"), "{filter}");
        for part in [
            "ip.DstAddr == 192.168.1.50",
            "ip.DstAddr == 192.168.137.1",
            "ip.DstAddr == 192.168.137.255",
            "ip.DstAddr >= 224.0.0.0",
            "(ip.DstAddr >= 127.0.0.0 and ip.DstAddr <= 127.255.255.255)",
            "((udp.DstPort == 67 or (ip.DstAddr == 192.168.137.1 and (udp.DstPort == 53 or tcp.DstPort == 53))) ? false : true)",
        ] {
            assert!(filter.contains(part), "{part} missing from {filter}");
        }
        assert!(!filter.contains("not "), "WinDivert takes `not` before single tests only: {filter}");
        assert_eq!(forward_filter(&config(false, true, true)), None);
        assert_eq!(
            ipv6_filter(&config(false, true, true)).unwrap(),
            "inbound and ipv6 and ifIdx == 17 and ((icmpv6.Type == 133 or icmpv6.Type == 135 or icmpv6.Type == 136) ? false : true)"
        );
        let mut unknown = config(false, true, true);
        unknown.if_index = None;
        assert_eq!(ipv6_filter(&unknown), None, "IPv6 needs the adapter");
    }

    #[test]
    fn keeping_devices_off_the_home_network_spares_their_own() {
        let local = local_filter(&config(true, true, false)).unwrap();
        let forward = forward_filter(&config(true, true, false)).unwrap();
        for filter in [&local, &forward] {
            assert!(filter.contains("(ip.DstAddr >= 192.168.0.0 and ip.DstAddr <= 192.168.255.255)"), "{filter}");
            assert!(filter.contains("(ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.255.255.255)"), "{filter}");
            assert!(filter.contains("and (ip.DstAddr < 192.168.137.0 or ip.DstAddr > 192.168.137.255)"), "{filter}");
            assert!(!filter.contains("198.18"), "fake-address ranges stay reachable: {filter}");
        }
        assert!(!local.contains("udp.DstPort"), "this computer itself stays reachable: {local}");
    }

    #[test]
    fn keeping_devices_apart_covers_what_passes_through_this_computer() {
        let filter = forward_filter(&config(true, false, true)).unwrap();
        assert_eq!(
            filter,
            "ip and (ip.SrcAddr >= 192.168.137.0 and ip.SrcAddr <= 192.168.137.255) and ip.SrcAddr != 192.168.137.1 and \
             (((ip.DstAddr >= 192.168.137.0 and ip.DstAddr <= 192.168.137.255) and ip.DstAddr != 192.168.137.1 and ip.DstAddr != 192.168.137.255))"
        );
        assert_eq!(local_filter(&config(true, false, true)), None);
    }

    #[test]
    fn the_firewall_opens_for_this_computers_address_on_that_network_only() {
        let (apply, cleanup) = firewall_steps(&config(true, true, true));
        // By its full path, never a name Windows would look for next to the
        // service first.
        let powershell = crate::tools::system_tool(crate::tools::POWERSHELL);
        assert!(apply.iter().chain(&cleanup).all(|(program, _)| *program == powershell));
        let script = apply[0].1.last().unwrap();
        assert!(script.contains("New-NetFirewallRule -DisplayName 'Captun devices 192.168.137.0/24' -Group 'Captun devices'"), "{script}");
        assert!(script.contains("-LocalAddress 192.168.137.1 -RemoteAddress 192.168.137.0/24"), "{script}");
        assert!(script.starts_with("Remove-NetFirewallRule -DisplayName 'Captun devices 192.168.137.0/24'"), "replaces a leftover: {script}");
        assert!(cleanup[0].1.last().unwrap().contains("Remove-NetFirewallRule -DisplayName 'Captun devices 192.168.137.0/24'"));
    }

    #[test]
    fn leftover_device_rules_are_lifted_by_their_group() {
        let script = clear_firewall().1.last().unwrap().clone();
        assert_eq!(script, "Remove-NetFirewallRule -Group 'Captun devices' -ErrorAction SilentlyContinue");
    }

    #[test]
    fn linux_keeps_devices_off_this_computer_but_serves_dhcp_and_dns() {
        let ((apply, cleanup), (apply6, cleanup6)) = linux_steps(&config(false, true, true));
        let rules: Vec<String> = apply.iter().map(|(p, a)| format!("{p} {}", a.join(" "))).collect();
        assert_eq!(
            rules,
            [
                "iptables -N CAPTUN-IN-192-168-137-0",
                "iptables -A CAPTUN-IN-192-168-137-0 -p udp --dport 67 -j RETURN",
                "iptables -A CAPTUN-IN-192-168-137-0 -d 192.168.137.1 -p udp --dport 53 -j RETURN",
                "iptables -A CAPTUN-IN-192-168-137-0 -d 192.168.137.1 -p tcp --dport 53 -j RETURN",
                "iptables -A CAPTUN-IN-192-168-137-0 -j DROP",
                "iptables -I INPUT -i wlan0 -j CAPTUN-IN-192-168-137-0",
            ]
        );
        assert_eq!(cleanup[0].1, ["-D", "INPUT", "-i", "wlan0", "-j", "CAPTUN-IN-192-168-137-0"], "unhooked first");
        assert_eq!(cleanup.last().unwrap().1, ["-X", "CAPTUN-IN-192-168-137-0"]);
        let rules6: Vec<String> = apply6.iter().map(|(p, a)| format!("{p} {}", a.join(" "))).collect();
        assert_eq!(
            rules6,
            [
                "ip6tables -N CAPTUN-IN6-192-168-137-0",
                "ip6tables -A CAPTUN-IN6-192-168-137-0 -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j DROP",
                "ip6tables -A CAPTUN-IN6-192-168-137-0 -p ipv6-icmp -m icmp6 --icmpv6-type 137 -j DROP",
                "ip6tables -A CAPTUN-IN6-192-168-137-0 -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j RETURN",
                "ip6tables -A CAPTUN-IN6-192-168-137-0 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN",
                "ip6tables -A CAPTUN-IN6-192-168-137-0 -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN",
                "ip6tables -A CAPTUN-IN6-192-168-137-0 -p udp --dport 547 -j RETURN",
                "ip6tables -A CAPTUN-IN6-192-168-137-0 -p udp --dport 53 -j RETURN",
                "ip6tables -A CAPTUN-IN6-192-168-137-0 -p tcp --dport 53 -j RETURN",
                "ip6tables -A CAPTUN-IN6-192-168-137-0 -j DROP",
                "ip6tables -I INPUT -i wlan0 -j CAPTUN-IN6-192-168-137-0",
            ]
        );
        assert_eq!(cleanup6.len(), 3);
    }

    /// Router advertisements and redirects from devices are dropped on every
    /// shared network, whatever the settings, ahead of anything the chain
    /// lets through.
    #[test]
    fn linux_never_lets_a_device_become_this_computers_router() {
        for mask in 0..8u8 {
            let config = config(mask & 1 != 0, mask & 2 != 0, mask & 4 != 0);
            let (_, (apply6, cleanup6)) = linux_steps(&config);
            let rules: Vec<String> = apply6.iter().map(|(_, a)| a.join(" ")).collect();
            for kind in ["134", "137"] {
                let drop = format!("-A CAPTUN-IN6-192-168-137-0 -p ipv6-icmp -m icmp6 --icmpv6-type {kind} -j DROP");
                let at = rules.iter().position(|r| *r == drop).unwrap_or_else(|| panic!("{drop} missing with {:?}", config.reach));
                assert!(rules[..at].iter().all(|r| !r.contains("RETURN")), "{kind} dropped before anything returns: {rules:?}");
            }
            assert!(!rules.iter().any(|r| r.ends_with("-p ipv6-icmp -j RETURN")), "not every ICMPv6 type: {rules:?}");
            assert_eq!(rules.last().map(String::as_str), Some("-I INPUT -i wlan0 -j CAPTUN-IN6-192-168-137-0"));
            assert_eq!(cleanup6.len(), 3, "and lifted with the rest");
        }
    }

    #[test]
    fn linux_holds_back_the_home_network_and_device_to_device_forwarding() {
        let ((apply, cleanup), (apply6, _)) = linux_steps(&config(true, false, false));
        let rules: Vec<String> = apply.iter().map(|(p, a)| format!("{p} {}", a.join(" "))).collect();
        assert!(rules.contains(&"iptables -A CAPTUN-FWD-192-168-137-0 -o wlan0 -j DROP".to_string()), "{rules:?}");
        assert!(rules.contains(&"iptables -A CAPTUN-FWD-192-168-137-0 -d 192.168.0.0/16 -j DROP".to_string()), "{rules:?}");
        // The devices' own network is let through before the private ranges.
        let own = rules.iter().position(|r| r == "iptables -A CAPTUN-FWD-192-168-137-0 -d 192.168.137.0/24 -j RETURN").unwrap();
        let private = rules.iter().position(|r| r == "iptables -A CAPTUN-FWD-192-168-137-0 -d 192.168.0.0/16 -j DROP").unwrap();
        assert!(own < private);
        // This computer stays reachable at its address on the network.
        assert!(rules.contains(&"iptables -A CAPTUN-IN-192-168-137-0 -d 192.168.137.0/24 -j RETURN".to_string()), "{rules:?}");
        assert!(!rules.contains(&"iptables -A CAPTUN-IN-192-168-137-0 -j DROP".to_string()));
        // IPv6 to this computer stays open, router messages aside.
        assert_eq!(apply6.len(), 4, "{apply6:?}");
        assert!(!apply6.iter().any(|(_, a)| a.join(" ") == "-A CAPTUN-IN6-192-168-137-0 -j DROP"));
        assert_eq!(cleanup.len(), 6);
    }

    #[test]
    fn linux_only_refuses_router_messages_when_everything_is_allowed() {
        let ((apply, cleanup), (apply6, cleanup6)) = linux_steps(&config(true, true, true));
        assert!(apply.is_empty() && cleanup.is_empty());
        let rules: Vec<String> = apply6.iter().map(|(_, a)| a.join(" ")).collect();
        assert_eq!(
            rules,
            [
                "-N CAPTUN-IN6-192-168-137-0",
                "-A CAPTUN-IN6-192-168-137-0 -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j DROP",
                "-A CAPTUN-IN6-192-168-137-0 -p ipv6-icmp -m icmp6 --icmpv6-type 137 -j DROP",
                "-I INPUT -i wlan0 -j CAPTUN-IN6-192-168-137-0",
            ]
        );
        assert_eq!(cleanup6.len(), 3);
    }

    /// Hand-made packets for WinDivert's evaluator.
    #[cfg(windows)]
    mod packets {
        use std::net::{Ipv4Addr, Ipv6Addr};

        fn ipv4(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
            let mut p = vec![0u8; 20];
            let len = (20 + payload.len()) as u16;
            p[0] = 0x45;
            p[2..4].copy_from_slice(&len.to_be_bytes());
            p[8] = 64;
            p[9] = protocol;
            p[12..16].copy_from_slice(&src.octets());
            p[16..20].copy_from_slice(&dst.octets());
            p.extend_from_slice(payload);
            p
        }

        fn ports(dport: u16, rest: usize) -> Vec<u8> {
            let mut h = vec![0u8; rest];
            h[0..2].copy_from_slice(&50_000u16.to_be_bytes());
            h[2..4].copy_from_slice(&dport.to_be_bytes());
            h
        }

        pub(super) fn tcp(src: &str, dst: &str, dport: u16) -> Vec<u8> {
            let mut h = ports(dport, 20);
            h[12] = 0x50;
            h[13] = 0x02; // SYN
            ipv4(6, src.parse().unwrap(), dst.parse().unwrap(), &h)
        }

        pub(super) fn udp(src: &str, dst: &str, dport: u16) -> Vec<u8> {
            let mut h = ports(dport, 8);
            h[4..6].copy_from_slice(&8u16.to_be_bytes());
            ipv4(17, src.parse().unwrap(), dst.parse().unwrap(), &h)
        }

        pub(super) fn ping(src: &str, dst: &str) -> Vec<u8> {
            ipv4(1, src.parse().unwrap(), dst.parse().unwrap(), &[8, 0, 0, 0, 0, 0, 0, 0])
        }

        fn ipv6(next: u8, src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
            let mut p = vec![0u8; 40];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            p[6] = next;
            p[7] = 255;
            p[8..24].copy_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
            p[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
            p.extend_from_slice(payload);
            p
        }

        pub(super) fn tcp6(src: &str, dst: &str, dport: u16) -> Vec<u8> {
            let mut h = ports(dport, 20);
            h[12] = 0x50;
            h[13] = 0x02;
            ipv6(6, src, dst, &h)
        }

        pub(super) fn icmp6(src: &str, dst: &str, kind: u8) -> Vec<u8> {
            ipv6(58, src, dst, &[kind, 0, 0, 0, 0, 0, 0, 0])
        }
    }

    /// What each combination of settings does to real packets, decided by
    /// WinDivert's own evaluator: refused ones match the drop rule, the rest
    /// (DHCP, DNS at the gateway, the internet) never do.
    #[cfg(windows)]
    #[test]
    fn windows_rules_drop_exactly_what_the_settings_refuse() {
        use packets::*;

        use crate::divert::{Layer, filter_matches};

        const DEV: &str = "192.168.137.23";
        let dropped = |config: &ReachConfig, packet: &[u8], layer: Layer| -> Option<bool> {
            let filter = match layer {
                Layer::Local if packet[0] >> 4 == 6 => ipv6_filter(config),
                Layer::Local => local_filter(config),
                Layer::Forward => forward_filter(config),
            };
            match filter {
                Some(filter) => filter_matches(&filter, packet, layer, false, 17),
                None => Some(false),
            }
        };

        // (packet, layer, refused when: this computer off, each other off, home network off)
        let cases: Vec<(&str, Vec<u8>, Layer, [bool; 3])> = vec![
            ("file sharing on this computer", tcp(DEV, "192.168.137.1", 445), Layer::Local, [true, false, false]),
            ("ping this computer", ping(DEV, "192.168.137.1"), Layer::Local, [true, false, false]),
            ("discovery (mDNS)", udp(DEV, "224.0.0.251", 5353), Layer::Local, [true, false, false]),
            ("broadcast on the network", udp(DEV, "192.168.137.255", 137), Layer::Local, [true, false, false]),
            ("DHCP request", udp(DEV, "255.255.255.255", 67), Layer::Local, [false, false, false]),
            ("DHCP renewal", udp(DEV, "192.168.137.1", 67), Layer::Local, [false, false, false]),
            ("DNS at the gateway", udp(DEV, "192.168.137.1", 53), Layer::Local, [false, false, false]),
            ("DNS over TCP at the gateway", tcp(DEV, "192.168.137.1", 53), Layer::Local, [false, false, false]),
            ("DNS at another address of this computer", udp(DEV, "192.168.1.50", 53), Layer::Local, [true, false, true]),
            ("this computer's home-network address", tcp(DEV, "192.168.1.50", 445), Layer::Local, [true, false, true]),
            ("the internet, seen locally", tcp(DEV, "8.8.8.8", 443), Layer::Local, [false, false, false]),
            ("another device", tcp(DEV, "192.168.137.40", 8080), Layer::Forward, [false, true, false]),
            ("the router", tcp(DEV, "192.168.1.1", 80), Layer::Forward, [false, false, true]),
            ("a 10.x network", tcp(DEV, "10.0.0.7", 22), Layer::Forward, [false, false, true]),
            ("carrier NAT space", udp(DEV, "100.64.1.1", 53), Layer::Forward, [false, false, true]),
            ("link-local", tcp(DEV, "169.254.1.1", 80), Layer::Forward, [false, false, true]),
            ("the internet", tcp(DEV, "8.8.8.8", 443), Layer::Forward, [false, false, false]),
            ("a proxy's fake address", tcp(DEV, "198.18.0.5", 443), Layer::Forward, [false, false, false]),
            ("IPv6 to this computer", tcp6("fe80::23", "fe80::1", 445), Layer::Local, [true, false, false]),
            ("IPv6 ping to this computer", icmp6("fe80::23", "fe80::1", 128), Layer::Local, [true, false, false]),
            ("IPv6 neighbour discovery", icmp6("fe80::23", "ff02::1:ff00:1", 135), Layer::Local, [false, false, false]),
            ("IPv6 neighbour advertisement", icmp6("fe80::23", "fe80::1", 136), Layer::Local, [false, false, false]),
            ("IPv6 router solicitation", icmp6("fe80::23", "ff02::2", 133), Layer::Local, [false, false, false]),
        ];
        for mask in 0..8u8 {
            let config = config(mask & 1 != 0, mask & 2 != 0, mask & 4 != 0);
            let off = [!config.reach.this_computer, !config.reach.each_other, !config.reach.home_network];
            for (name, packet, layer, refused_when) in &cases {
                let expected = refused_when.iter().zip(off).any(|(&refused, off)| refused && off);
                let Some(actual) = dropped(&config, packet, *layer) else { return };
                assert_eq!(actual, expected, "{name} with {:?}", config.reach);
            }
        }
        // This computer's own packets to devices are never touched.
        let reply = udp("192.168.137.1", DEV, 50_000);
        let blocked = config(false, false, false);
        assert_eq!(filter_matches(&local_filter(&blocked).unwrap(), &reply, Layer::Local, true, 17), Some(false));
        assert_eq!(filter_matches(&forward_filter(&blocked).unwrap(), &reply, Layer::Forward, false, 17), Some(false));
        // IPv6 from another adapter is not the devices'.
        let elsewhere = tcp6("fe80::23", "fe80::1", 445);
        assert_eq!(filter_matches(&ipv6_filter(&blocked).unwrap(), &elsewhere, Layer::Local, false, 5), Some(false));

        // Whatever the settings, no device may make itself this computer's
        // IPv6 router: its advertisements and redirects are dropped.
        for mask in 0..8u8 {
            let config = config(mask & 1 != 0, mask & 2 != 0, mask & 4 != 0);
            let filter = ipv6_filter(&config).unwrap();
            for (name, packet) in [("router advertisement", icmp6("fe80::23", "ff02::1", 134)), ("redirect", icmp6("fe80::23", "fe80::1", 137))] {
                assert_eq!(filter_matches(&filter, &packet, Layer::Local, false, 17), Some(true), "{name} with {:?}", config.reach);
                assert_eq!(filter_matches(&filter, &packet, Layer::Local, false, 5), Some(false), "{name} on another adapter");
            }
        }
    }

    /// Every combination of settings, on a computer with many addresses,
    /// gives filters WinDivert's own compiler accepts.
    #[cfg(windows)]
    #[test]
    fn every_windows_rule_compiles() {
        use crate::divert::{Layer, check_filter};
        for mask in 0..8u8 {
            let mut config = config(mask & 1 != 0, mask & 2 != 0, mask & 4 != 0);
            config.own_addresses = (1..=MAX_OWN_ADDRESSES as u8).map(|i| Ipv4Addr::new(10, 9, 8, i)).collect();
            for (filter, layer) in
                [(local_filter(&config), Layer::Local), (forward_filter(&config), Layer::Forward), (ipv6_filter(&config), Layer::Local)]
            {
                let Some(filter) = filter else { continue };
                let Some(result) = check_filter(&filter, layer) else { return };
                assert_eq!(result, Ok(()), "{filter}");
            }
        }
    }

    #[test]
    fn chain_names_fit_iptables() {
        assert!(chain("FWD", "255.255.255.0/24".parse().unwrap()).len() <= 28);
        assert!(chain("IN6", "255.255.255.0/24".parse().unwrap()).len() <= 28);
    }
}
