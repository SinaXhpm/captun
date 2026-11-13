//! Bringing a wired Ethernet or USB interface up as a client-facing **access
//! network**: give it the gateway address and, for basic internet, OS NAT for its
//! subnet. DHCP on the interface is served by `captun-dhcp`; per-client routing
//! through the engine is handled by `capture` when transparent routing is on.
//!
//! Every change is an OS command with a matching revert, run when the returned
//! [`AccessGuard`] is dropped (mirroring `capture` and `tether_net`), or at once
//! for the changes already made when a later one fails. The command builders
//! are pure and unit-tested on any host.

use std::net::Ipv4Addr;

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
use tracing::warn;

/// One command: a program and its separate arguments (never a shell string).
type Argv = (String, Vec<String>);

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn argv(program: &str, args: &[&str]) -> Argv {
    (program.to_owned(), args.iter().map(|s| s.to_string()).collect())
}

/// One change to the system, and the command that reverts it if it needs
/// reverting.
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
struct Step {
    apply: Argv,
    undo: Option<Argv>,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn step(apply: Argv, undo: Option<Argv>) -> Step {
    Step { apply, undo }
}

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("wired access networks are not supported on this platform")]
    Unsupported,
    #[error("`{command}` failed: {message}")]
    Command { command: String, message: String },
}

/// What is needed to bring an access network up on the PC side.
#[derive(Clone, Debug)]
pub struct AccessSetup {
    /// OS index of the interface to share on.
    pub interface_index: u32,
    /// OS/system name of the interface (kernel name on Linux).
    pub interface_system_name: String,
    /// Friendly interface name. Not put in any Windows command: the DHCP
    /// firewall rule finds the adapter by its index, so a name with a quote
    /// in it can never become part of a script.
    pub interface_alias: String,
    /// Captun's gateway address on the network.
    pub gateway: Ipv4Addr,
    /// Subnet prefix length.
    pub prefix_len: u8,
    /// The network (base) address of the subnet.
    pub network: Ipv4Addr,
    /// Hand clients basic internet with OS NAT. Off when the routing engine will
    /// carry their traffic instead.
    pub nat: bool,
}

/// Reverses the PC-side changes when dropped. Cleanup runs synchronously so it
/// works from `Drop`.
pub struct AccessGuard {
    cleanup: Vec<Argv>,
}

impl std::fmt::Debug for AccessGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessGuard").field("steps", &self.cleanup.len()).finish()
    }
}

impl Drop for AccessGuard {
    fn drop(&mut self) {
        #[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
        for (program, args) in &self.cleanup {
            if let Err(e) = run(program, args) {
                warn!("undoing a network change: {e}");
            }
        }
    }
}

/// Whether this build can bring up a wired access network.
pub fn supported() -> bool {
    cfg!(any(windows, target_os = "linux", target_os = "macos"))
}

/// Brings the access network up and returns a guard that reverses it on drop.
/// When a step fails, the steps before it are reverted before this returns.
#[cfg_attr(not(any(windows, target_os = "linux", target_os = "macos")), allow(unused_variables))]
pub fn bring_up(setup: &AccessSetup) -> Result<AccessGuard, AccessError> {
    #[cfg(windows)]
    {
        let cleanup = run_steps(&windows_steps(setup))?;
        Ok(AccessGuard { cleanup })
    }
    #[cfg(target_os = "linux")]
    {
        let cleanup = run_steps(&linux_steps(setup))?;
        Ok(AccessGuard { cleanup })
    }
    #[cfg(target_os = "macos")]
    {
        // NAT goes out of whichever adapters carry this computer's internet.
        let uplinks: Vec<String> = crate::iface::list()
            .into_iter()
            .filter(|i| i.up && i.default_route && i.system_name != setup.interface_system_name)
            .map(|i| i.system_name)
            .collect();
        let rules = pf_rules(setup, &uplinks);
        let path = pf_rules_path(setup.network);
        if setup.nat {
            write_private(&path, &rules)
                .map_err(|e| AccessError::Command { command: format!("write {path}"), message: e.to_string() })?;
        }
        let mut cleanup = match run_steps(&macos_steps(setup, &path)) {
            Ok(cleanup) => cleanup,
            Err(e) => {
                if setup.nat {
                    let _ = std::fs::remove_file(&path);
                }
                return Err(e);
            }
        };
        if setup.nat {
            cleanup.push(argv("/bin/rm", &["-f", &path]));
        }
        Ok(AccessGuard { cleanup })
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err(AccessError::Unsupported)
    }
}

/// Runs one command; its error names the tool without its folder.
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn run(program: &str, args: &[String]) -> Result<(), AccessError> {
    let tool = crate::tools::tool_name(program);
    let output = crate::tools::command(program)
        .args(args)
        .output()
        .map_err(|e| AccessError::Command { command: tool.to_owned(), message: e.to_string() })?;
    if !output.status.success() {
        return Err(AccessError::Command {
            command: format!("{tool} {}", args.join(" ")),
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(())
}

/// Makes each step's change in turn and returns what reverts them, last
/// first.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn run_steps(steps: &[Step]) -> Result<Vec<Argv>, AccessError> {
    run_steps_with(steps, |(program, args)| run(program, args))
}

/// [`run_steps`] with `run` for running a command. When a step fails, the
/// steps before it are reverted at once, so a failed start leaves nothing
/// behind; the gateway address left on the adapter would make the next start
/// fail too.
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn run_steps_with(steps: &[Step], mut run: impl FnMut(&Argv) -> Result<(), AccessError>) -> Result<Vec<Argv>, AccessError> {
    for (done, step) in steps.iter().enumerate() {
        if let Err(e) = run(&step.apply) {
            for undo in undo_of(&steps[..done]) {
                if let Err(undo_failed) = run(&undo) {
                    warn!("undoing a network change after a failed start: {undo_failed}");
                }
            }
            return Err(e);
        }
    }
    Ok(undo_of(steps))
}

/// What reverts `steps`, last first.
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn undo_of(steps: &[Step]) -> Vec<Argv> {
    steps.iter().rev().filter_map(|s| s.undo.clone()).collect()
}

/// A stable WinNAT instance / pf anchor name per subnet.
#[cfg(any(windows, target_os = "macos", test))]
fn nat_name(network: Ipv4Addr) -> String {
    format!("Captun-{}", network.to_string().replace('.', "-"))
}

/// The id (`-Name`) of the Windows Firewall rule that lets DHCP in on a
/// network's adapter: one per subnet, like the NAT, so a rule a run that was
/// stopped abruptly left behind is found and replaced.
#[cfg(any(windows, test))]
fn dhcp_rule_name(network: Ipv4Addr) -> String {
    format!("Captun-DHCP-{}", network.to_string().replace('.', "-"))
}

/// Windows steps: assign the gateway address with `New-NetIPAddress` and, for
/// basic internet, a WinNAT instance for the subnet. Every value in a script is
/// a number, an address or a name made from those, never the adapter's name.
#[cfg(any(windows, test))]
fn windows_steps(setup: &AccessSetup) -> Vec<Step> {
    let idx = setup.interface_index;
    let gw = setup.gateway;
    let plen = setup.prefix_len;
    let prefix = format!("{}/{}", setup.network, setup.prefix_len);
    let nat = nat_name(setup.network);
    let rule = dhcp_rule_name(setup.network);
    let powershell = crate::tools::system_tool(crate::tools::POWERSHELL);
    let ps = |script: String| argv(&powershell, &["-NoProfile", "-NonInteractive", "-Command", &script]);

    let mut steps = vec![
        step(
            ps(format!("New-NetIPAddress -InterfaceIndex {idx} -IPAddress {gw} -PrefixLength {plen} -ErrorAction Stop | Out-Null")),
            Some(ps(format!(
                "Remove-NetIPAddress -InterfaceIndex {idx} -IPAddress {gw} -Confirm:$false -ErrorAction SilentlyContinue"
            ))),
        ),
        // Allow inbound DHCP (UDP 67) only on this interface. With the default
        // inbound block, that keeps Captun's DHCP from ever answering on
        // another network. The rule names the adapter, which PowerShell looks
        // up from its index; the name is only ever data there, and escaped as
        // a pattern, so `*` or `[` in it cannot widen the rule.
        step(
            ps(format!(
                "Remove-NetFirewallRule -Name '{rule}' -ErrorAction SilentlyContinue; \
                 $adapter = (Get-NetIPInterface -InterfaceIndex {idx} -AddressFamily IPv4 -ErrorAction Stop).InterfaceAlias; \
                 New-NetFirewallRule -Name '{rule}' -DisplayName 'Captun DHCP {prefix}' -Direction Inbound -Action Allow \
                 -Protocol UDP -LocalPort 67 -InterfaceAlias ([WildcardPattern]::Escape($adapter)) -ErrorAction Stop | Out-Null"
            )),
            Some(ps(format!("Remove-NetFirewallRule -Name '{rule}' -ErrorAction SilentlyContinue"))),
        ),
    ];
    if setup.nat {
        steps.push(step(
            ps(format!("New-NetNat -Name '{nat}' -InternalIPInterfaceAddressPrefix {prefix} -ErrorAction Stop | Out-Null")),
            Some(ps(format!("Remove-NetNat -Name '{nat}' -Confirm:$false -ErrorAction SilentlyContinue"))),
        ));
    }
    steps
}

/// Linux steps: assign the gateway address, bring the link up, allow the
/// subnet's traffic to be forwarded and, for NAT, masquerade it. Forwarding
/// is needed either way: the routing engine's policy routing forwards the
/// devices' packets into its TUN and its replies back, and a system with
/// forwarding off, or a firewall that drops it, would leave them no way out.
/// Restored on cleanup.
#[cfg(any(target_os = "linux", test))]
fn linux_steps(setup: &AccessSetup) -> Vec<Step> {
    let dev = setup.interface_system_name.as_str();
    let cidr = format!("{}/{}", setup.gateway, setup.prefix_len);
    let subnet = format!("{}/{}", setup.network, setup.prefix_len);
    // An iptables rule, added with `-A` and removed with `-D`.
    let iptables = |rule: &[&str]| {
        let added = [&["-A"][..], rule].concat();
        let removed = [&["-D"][..], rule].concat();
        step(argv("iptables", &added), Some(argv("iptables", &removed)))
    };
    let nat_rule = |rule: &[&str]| {
        let added = [&["-t", "nat", "-A"][..], rule].concat();
        let removed = [&["-t", "nat", "-D"][..], rule].concat();
        step(argv("iptables", &added), Some(argv("iptables", &removed)))
    };

    let mut steps = vec![
        step(argv("ip", &["addr", "add", &cidr, "dev", dev]), Some(argv("ip", &["addr", "del", &cidr, "dev", dev]))),
        step(argv("ip", &["link", "set", dev, "up"]), None),
        // Accept inbound DHCP on this interface in case INPUT defaults to drop.
        iptables(&["INPUT", "-i", dev, "-p", "udp", "--dport", "67", "-j", "ACCEPT"]),
        step(argv("sysctl", &["-w", "net.ipv4.ip_forward=1"]), None),
    ];
    if setup.nat {
        steps.push(nat_rule(&["POSTROUTING", "-s", &subnet, "-j", "MASQUERADE"]));
    }
    steps.push(iptables(&["FORWARD", "-s", &subnet, "-j", "ACCEPT"]));
    steps.push(iptables(&["FORWARD", "-d", &subnet, "-j", "ACCEPT"]));
    steps
}

/// The pf anchor Captun loads its NAT rules into. macOS's stock pf.conf
/// already evaluates every `com.apple/*` anchor, so no system file changes.
#[cfg(any(target_os = "macos", test))]
fn pf_anchor(network: Ipv4Addr) -> String {
    format!("com.apple/{}", nat_name(network))
}

#[cfg(any(target_os = "macos", test))]
fn pf_rules_path(network: Ipv4Addr) -> String {
    format!("/var/run/{}.pf.conf", nat_name(network))
}

/// NAT for the subnet out of each uplink (pf needs a named interface).
#[cfg(any(target_os = "macos", test))]
fn pf_rules(setup: &AccessSetup, uplinks: &[String]) -> String {
    let subnet = format!("{}/{}", setup.network, setup.prefix_len);
    uplinks.iter().map(|up| format!("nat on {up} inet from {subnet} to any -> ({up})
")).collect()
}

#[cfg(target_os = "macos")]
fn write_private(path: &str, text: &str) -> std::io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    file.write_all(text.as_bytes())
}

/// macOS steps: an alias address on the interface and, for NAT, IP
/// forwarding plus pf rules in Captun's own anchor. pf is enabled with a
/// reference (`-E`), so it stays as the user had it once others let go.
#[cfg(any(target_os = "macos", test))]
fn macos_steps(setup: &AccessSetup, rules_path: &str) -> Vec<Step> {
    let dev = setup.interface_system_name.as_str();
    let gw = setup.gateway.to_string();
    let mask = Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(setup.prefix_len)).unwrap_or(0)).to_string();
    let anchor = pf_anchor(setup.network);

    let mut steps = vec![
        step(
            argv("/sbin/ifconfig", &[dev, "inet", &gw, "netmask", &mask, "alias"]),
            Some(argv("/sbin/ifconfig", &[dev, "inet", &gw, "-alias"])),
        ),
        step(argv("/sbin/ifconfig", &[dev, "up"]), None),
    ];
    if setup.nat {
        steps.push(step(argv("/usr/sbin/sysctl", &["-w", "net.inet.ip.forwarding=1"]), None));
        steps.push(step(
            argv("/sbin/pfctl", &["-a", &anchor, "-f", rules_path]),
            Some(argv("/sbin/pfctl", &["-a", &anchor, "-F", "all"])),
        ));
        steps.push(step(argv("/sbin/pfctl", &["-E"]), None));
    }
    steps
}

/// Binds a UDP socket for serving DHCP on `interface`, isolated to it: bound to
/// `0.0.0.0:67` with broadcast and address reuse, and pinned to the interface
/// (`SO_BINDTODEVICE` on Linux, `IP_BOUND_IF` on macOS) so it never receives another network's DHCP.
/// On Windows the isolation is enforced by the per-interface firewall rule that
/// [`bring_up`] installs. Returns a ready async socket.
pub fn bind_dhcp_socket(interface: &crate::iface::Interface) -> std::io::Result<tokio::net::UdpSocket> {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    socket.bind_device(Some(interface.system_name.as_bytes()))?;
    #[cfg(target_os = "macos")]
    socket.bind_device_by_index_v4(std::num::NonZeroU32::new(interface.index))?;
    let _ = interface;
    // 67 is the DHCP server port.
    socket.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67)).into())?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{POWERSHELL, system_tool};

    fn setup(nat: bool) -> AccessSetup {
        AccessSetup {
            interface_index: 12,
            interface_system_name: "eth0".into(),
            interface_alias: "Ethernet 2".into(),
            gateway: Ipv4Addr::new(10, 73, 0, 1),
            prefix_len: 24,
            network: Ipv4Addr::new(10, 73, 0, 0),
            nat,
        }
    }

    /// The commands that make the changes, and those that revert all of them
    /// (last first), as the guard runs them.
    fn plan(steps: &[Step]) -> (Vec<Argv>, Vec<Argv>) {
        (steps.iter().map(|s| s.apply.clone()).collect(), undo_of(steps))
    }

    fn script(command: &Argv) -> &str {
        command.1.last().map(String::as_str).unwrap_or_default()
    }

    #[test]
    fn windows_assigns_address_firewall_and_nat_with_matching_cleanup() {
        let (apply, cleanup) = plan(&windows_steps(&setup(true)));
        assert_eq!(apply.len(), 3, "address + DHCP firewall + NAT");
        assert!(script(&apply[0]).contains("New-NetIPAddress"));
        assert!(script(&apply[0]).contains("10.73.0.1"));
        // DHCP is allowed in only on our interface, found by its index.
        assert!(script(&apply[1]).contains("New-NetFirewallRule"));
        assert!(script(&apply[1]).contains("LocalPort 67"));
        assert!(script(&apply[1]).contains("Get-NetIPInterface -InterfaceIndex 12 -AddressFamily IPv4"));
        assert!(script(&apply[1]).contains("-InterfaceAlias ([WildcardPattern]::Escape($adapter))"));
        assert!(script(&apply[2]).contains("New-NetNat -Name 'Captun-10-73-0-0'"));
        assert!(script(&apply[2]).contains("10.73.0.0/24"));
        // Cleanup removes the NAT first, then the firewall rule, then the address.
        assert_eq!(cleanup.len(), 3);
        assert!(script(&cleanup[0]).contains("Remove-NetNat"));
        assert!(script(&cleanup[1]).contains("Remove-NetFirewallRule"));
        assert!(script(&cleanup[2]).contains("Remove-NetIPAddress"));
        // PowerShell by its full path, never a name Windows would look for
        // next to the service first.
        assert!(apply.iter().chain(&cleanup).all(|(program, _)| *program == system_tool(POWERSHELL)));
    }

    #[test]
    fn windows_without_nat_still_assigns_address_and_dhcp_firewall() {
        let (apply, cleanup) = plan(&windows_steps(&setup(false)));
        assert_eq!(apply.len(), 2);
        assert_eq!(cleanup.len(), 2);
        assert!(script(&apply[0]).contains("New-NetIPAddress"));
        assert!(script(&apply[1]).contains("New-NetFirewallRule"));
    }

    /// The firewall rule is one per subnet and removed by its id, so a
    /// leftover is replaced and nothing else is touched.
    #[test]
    fn windows_dhcp_rule_is_named_after_the_subnet() {
        let (apply, cleanup) = plan(&windows_steps(&setup(false)));
        assert!(script(&apply[1]).starts_with("Remove-NetFirewallRule -Name 'Captun-DHCP-10-73-0-0' -ErrorAction SilentlyContinue;"));
        assert!(script(&apply[1]).contains("New-NetFirewallRule -Name 'Captun-DHCP-10-73-0-0' -DisplayName 'Captun DHCP 10.73.0.0/24'"));
        assert_eq!(script(&cleanup[0]), "Remove-NetFirewallRule -Name 'Captun-DHCP-10-73-0-0' -ErrorAction SilentlyContinue");
        assert_ne!(dhcp_rule_name(Ipv4Addr::new(10, 73, 0, 0)), dhcp_rule_name(Ipv4Addr::new(10, 74, 0, 0)));
    }

    /// PowerShell takes ’ and ‘ as quotes as well as ', so an adapter named
    /// `x’; calc; #` would end a quoted string and run `calc`. No script
    /// carries the name at all.
    #[test]
    fn an_adapter_name_never_becomes_part_of_a_script() {
        for name in ["O'Brien LAN", "Sina’s dock", "x’; calc; #", "Ethernet [2]*"] {
            let mut setup = setup(true);
            setup.interface_alias = name.into();
            setup.interface_system_name = name.into();
            let steps = windows_steps(&setup);
            let commands = steps.iter().flat_map(|s| std::iter::once(&s.apply).chain(&s.undo));
            for (_, args) in commands {
                for arg in args {
                    for part in [name, "Brien", "Sina", "calc", "’", "[2]"] {
                        assert!(!arg.contains(part), "{part:?} from {name:?} in {arg}");
                    }
                }
            }
        }
    }

    /// A step that fails takes back what the steps before it did, last first,
    /// and nothing after it runs.
    #[test]
    fn a_failed_start_undoes_what_it_did() {
        let steps = windows_steps(&setup(true));
        let mut ran = Vec::new();
        let result = run_steps_with(&steps, |command| {
            ran.push(script(command).to_owned());
            if script(command).contains("New-NetFirewallRule") {
                Err(AccessError::Command { command: "powershell".into(), message: "refused".into() })
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert_eq!(ran.len(), 3, "{ran:#?}");
        assert!(ran[0].starts_with("New-NetIPAddress"));
        assert!(ran[1].contains("New-NetFirewallRule"));
        assert!(ran[2].starts_with("Remove-NetIPAddress"), "the gateway address comes off again");
        assert!(!ran.iter().any(|s| s.contains("NetNat")), "nothing after the failed step");

        // All of it, when everything went in.
        let mut ran = 0;
        let cleanup = run_steps_with(&steps, |_| {
            ran += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!((ran, cleanup.len()), (3, 3));
        assert!(script(&cleanup[0]).contains("Remove-NetNat"));
    }

    #[test]
    fn a_failed_first_step_has_nothing_to_undo() {
        let steps = linux_steps(&setup(true));
        let mut ran = 0;
        let result = run_steps_with(&steps, |_| {
            ran += 1;
            Err(AccessError::Command { command: "ip".into(), message: "File exists".into() })
        });
        assert!(result.is_err());
        assert_eq!(ran, 1);
    }

    #[test]
    fn linux_assigns_address_brings_up_and_masquerades() {
        let (apply, cleanup) = plan(&linux_steps(&setup(true)));
        assert_eq!(apply[0].1, ["addr", "add", "10.73.0.1/24", "dev", "eth0"]);
        assert_eq!(apply[1].1, ["link", "set", "eth0", "up"]);
        assert!(apply.iter().any(|(_, a)| a.contains(&"MASQUERADE".to_string())));
        // Address removal is the final cleanup step; the rules come off before
        // it, each removed with the same match it was added with.
        assert_eq!(cleanup.last().unwrap().1, ["addr", "del", "10.73.0.1/24", "dev", "eth0"]);
        assert_eq!(cleanup[0].1, ["-D", "FORWARD", "-d", "10.73.0.0/24", "-j", "ACCEPT"]);
        assert!(cleanup.iter().any(|(_, a)| *a == ["-t", "nat", "-D", "POSTROUTING", "-s", "10.73.0.0/24", "-j", "MASQUERADE"]));
        assert!(cleanup.iter().any(|(_, a)| *a == ["-D", "INPUT", "-i", "eth0", "-p", "udp", "--dport", "67", "-j", "ACCEPT"]));
        assert_eq!(cleanup.len(), 5, "nothing to undo for bringing the link up or turning forwarding on");
    }

    /// While the routing engine carries the devices' traffic there is no
    /// NAT, but its policy routing forwards their packets all the same.
    #[test]
    fn linux_without_nat_still_lets_the_subnet_be_forwarded() {
        let (apply, cleanup) = plan(&linux_steps(&setup(false)));
        assert!(apply.iter().any(|(program, a)| program == "sysctl" && *a == ["-w", "net.ipv4.ip_forward=1"]));
        assert!(apply.iter().any(|(_, a)| *a == ["-A", "FORWARD", "-s", "10.73.0.0/24", "-j", "ACCEPT"]));
        assert!(apply.iter().any(|(_, a)| *a == ["-A", "FORWARD", "-d", "10.73.0.0/24", "-j", "ACCEPT"]));
        assert!(!apply.iter().any(|(_, a)| a.contains(&"MASQUERADE".to_owned())), "the engine's own way out, never NAT");
        assert_eq!(cleanup[0].1, ["-D", "FORWARD", "-d", "10.73.0.0/24", "-j", "ACCEPT"]);
        assert_eq!(cleanup.len(), 4, "the two forwarding rules, DHCP and the address");
    }

    #[test]
    fn macos_aliases_the_address_and_nats_through_its_own_pf_anchor() {
        assert_eq!(pf_rules_path(Ipv4Addr::new(10, 73, 0, 0)), "/var/run/Captun-10-73-0-0.pf.conf");
        let (apply, cleanup) = plan(&macos_steps(&setup(true), "/var/run/x.pf.conf"));
        assert_eq!(apply[0].1, ["eth0", "inet", "10.73.0.1", "netmask", "255.255.255.0", "alias"]);
        assert!(apply.iter().any(|(p, a)| p == "/sbin/pfctl" && a.contains(&"com.apple/Captun-10-73-0-0".to_owned())));
        assert_eq!(cleanup[0].1, ["-a", "com.apple/Captun-10-73-0-0", "-F", "all"]);
        assert_eq!(cleanup.last().unwrap().1, ["eth0", "inet", "10.73.0.1", "-alias"]);
        let rules = pf_rules(&setup(true), &["en0".into()]);
        assert_eq!(rules, "nat on en0 inet from 10.73.0.0/24 to any -> (en0)
");

        let (apply, cleanup) = plan(&macos_steps(&setup(false), "/var/run/x.pf.conf"));
        assert!(apply.iter().all(|(p, _)| p != "/sbin/pfctl"));
        assert_eq!(cleanup.len(), 1);
    }

    #[test]
    fn nat_name_is_subnet_specific() {
        assert_eq!(nat_name(Ipv4Addr::new(10, 73, 0, 0)), "Captun-10-73-0-0");
        assert_ne!(nat_name(Ipv4Addr::new(10, 73, 0, 0)), nat_name(Ipv4Addr::new(192, 168, 8, 0)));
    }
}
