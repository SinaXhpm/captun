//! PC-side network set-up for reverse tethering ("USB to phone").
//!
//! Captun only ever gives internet; it never takes it. When the phone's USB
//! network link comes up, the phone's tethering offers itself to this
//! computer as a gateway and a DNS server. Left alone, the computer could send
//! its own traffic, and the phone's traffic in a loop, out over the phone's
//! mobile data. So, on the link:
//!
//! 1. **It never carries this computer's traffic.** Its default routes are
//!    removed, the OS is told not to use it as a default where it can be, and
//!    the DNS servers the phone offers are not used. A DHCP renewal can bring a
//!    route back, so [`enforce`] repeats the removal for as long as the session
//!    runs, and the daemon checks the outcome: the link must never be the
//!    computer's default route.
//! 2. **The phone can reach the proxy.** A firewall rule allows the proxy's
//!    port inbound.
//!
//! Each change is an OS command with a matching revert, run when the returned
//! [`ReverseNetGuard`] is dropped. Removing something that is not there fails
//! harmlessly, so only the steps the feature cannot work without must succeed.
//! The command builders are pure and unit-tested on any host.

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
use tracing::warn;

/// One command: a program and its separate arguments (never a shell string).
type Argv = (String, Vec<String>);

#[cfg_attr(not(any(windows, target_os = "linux", target_os = "macos", test)), allow(dead_code))]
fn argv(program: &str, args: &[&str]) -> Argv {
    (program.to_owned(), args.iter().map(|s| s.to_string()).collect())
}

/// A command and whether the set-up fails without it.
#[cfg_attr(not(any(windows, target_os = "linux", target_os = "macos", test)), allow(dead_code))]
struct Step {
    command: Argv,
    required: bool,
}

/// Only Windows has a step the feature cannot work without (its firewall).
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn must(command: Argv) -> Step {
    Step { command, required: true }
}

#[cfg_attr(not(any(windows, target_os = "linux", target_os = "macos", test)), allow(dead_code))]
fn try_(command: Argv) -> Step {
    Step { command, required: false }
}

#[derive(Debug, thiserror::Error)]
pub enum TetherNetError {
    #[error("reverse-tethering network set-up is not supported on this platform")]
    Unsupported,
    #[error("`{command}` failed: {message}")]
    Command { command: String, message: String },
}

/// The USB link on the PC and the proxy port the phone must reach.
#[derive(Clone, Debug)]
pub struct ReverseNet {
    /// OS index of the USB-link interface.
    pub interface_index: u32,
    /// Its OS name (the kernel name on Linux and macOS).
    pub interface_name: String,
    /// The TCP port Captun's proxy inbound listens on.
    pub proxy_port: u16,
}

/// Reverses the PC-side changes when dropped. Cleanup runs synchronously so it
/// works from `Drop` (and from the daemon's blocking shutdown path).
pub struct ReverseNetGuard {
    cleanup: Vec<Argv>,
}

impl std::fmt::Debug for ReverseNetGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReverseNetGuard").field("steps", &self.cleanup.len()).finish()
    }
}

impl Drop for ReverseNetGuard {
    fn drop(&mut self) {
        #[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
        for (program, args) in &self.cleanup {
            if let Err(message) = run(program, args) {
                warn!("reverse-net cleanup `{} {}` failed: {message}", crate::tools::tool_name(program), args.join(" "));
            }
        }
    }
}

/// Applies the PC-side set-up and returns a guard that reverses it on drop.
#[cfg_attr(not(any(windows, target_os = "linux", target_os = "macos")), allow(unused_variables))]
pub fn protect(net: &ReverseNet) -> Result<ReverseNetGuard, TetherNetError> {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    {
        let (apply, cleanup) = steps(net);
        run_steps(apply)?;
        Ok(ReverseNetGuard { cleanup })
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    Err(TetherNetError::Unsupported)
}

/// Removes any default route over the link again. Run while the session
/// lasts: a DHCP renewal from the phone can put one back.
#[cfg_attr(not(any(windows, target_os = "linux", target_os = "macos")), allow(unused_variables))]
pub fn enforce(net: &ReverseNet) {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    if let Err(e) = run_steps(drop_default_routes(net)) {
        warn!("could not keep the phone link off this computer's routes: {e}");
    }
}

/// Whether this build can set up reverse-tethering networking.
pub fn supported() -> bool {
    cfg!(any(windows, target_os = "linux", target_os = "macos"))
}

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn run(program: &str, args: &[String]) -> Result<(), String> {
    // On Windows: no console window, and only Windows' own environment.
    match crate::tools::command(program).args(args).output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(String::from_utf8_lossy(&out.stderr).trim().to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn run_steps(steps: Vec<Step>) -> Result<(), TetherNetError> {
    for Step { command: (program, args), required } in steps {
        let tool = crate::tools::tool_name(&program);
        match run(&program, &args) {
            Ok(()) => {}
            Err(message) if required => {
                return Err(TetherNetError::Command { command: format!("{tool} {}", args.join(" ")), message });
            }
            // Usually "nothing to remove".
            Err(message) => tracing::debug!("`{tool} {}`: {message}", args.join(" ")),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn steps(net: &ReverseNet) -> (Vec<Step>, Vec<Argv>) {
    windows_steps(net)
}
#[cfg(target_os = "linux")]
fn steps(net: &ReverseNet) -> (Vec<Step>, Vec<Argv>) {
    linux_steps(net)
}
#[cfg(target_os = "macos")]
fn steps(net: &ReverseNet) -> (Vec<Step>, Vec<Argv>) {
    (macos_drop_default_routes(net), Vec::new())
}

#[cfg(windows)]
fn drop_default_routes(net: &ReverseNet) -> Vec<Step> {
    vec![windows_drop_default_routes(net)]
}
#[cfg(target_os = "linux")]
fn drop_default_routes(net: &ReverseNet) -> Vec<Step> {
    linux_drop_default_routes(net)
}
#[cfg(target_os = "macos")]
fn drop_default_routes(net: &ReverseNet) -> Vec<Step> {
    macos_drop_default_routes(net)
}

/// The firewall rule name, unique per port so parallel sessions don't clash.
#[cfg(any(windows, test))]
fn rule_name(port: u16) -> String {
    format!("Captun Reverse Tether {port}")
}

/// A PowerShell script, run by PowerShell's full path.
#[cfg(any(windows, test))]
fn ps(script: String) -> Argv {
    let program = crate::tools::system_tool(crate::tools::POWERSHELL);
    argv(&program, &["-NoProfile", "-NonInteractive", "-Command", &script])
}

#[cfg(any(windows, test))]
fn windows_drop_default_routes(net: &ReverseNet) -> Step {
    let idx = net.interface_index;
    try_(ps(format!(
        "Get-NetRoute -InterfaceIndex {idx} -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
    )))
}

/// Windows: remove the link's default routes and push its metric to the back
/// (should one return before the next [`enforce`]), drop the DNS servers the
/// phone hands out, and open the proxy port. All built-in tools, all restorable.
#[cfg(any(windows, test))]
fn windows_steps(net: &ReverseNet) -> (Vec<Step>, Vec<Argv>) {
    let idx = net.interface_index.to_string();
    let port = net.proxy_port.to_string();
    let name = rule_name(net.proxy_port);
    let netsh = crate::tools::system_tool(crate::tools::NETSH);
    let dns = |family: &str, source: &str| {
        let mut args = vec!["interface", family, "set", "dnsservers", idx.as_str(), source];
        if source == "source=static" {
            args.extend(["address=none", "register=none", "validate=no"]);
        }
        argv(&netsh, &args)
    };

    let apply = vec![
        try_(ps(format!("Set-NetIPInterface -InterfaceIndex {idx} -InterfaceMetric 9999 -ErrorAction Stop"))),
        windows_drop_default_routes(net),
        try_(dns("ipv4", "source=static")),
        try_(dns("ipv6", "source=static")),
        // New-NetFirewallRule takes the adapter by name only, which PowerShell
        // looks up from its index, so the name is never part of the script
        // (and is escaped as the pattern it is taken as).
        must(ps(format!(
            "$adapter = (Get-NetIPInterface -InterfaceIndex {idx} -AddressFamily IPv4 -ErrorAction Stop).InterfaceAlias; \
             New-NetFirewallRule -DisplayName '{name}' -Direction Inbound -Action Allow -Protocol TCP -LocalPort {port} \
             -InterfaceAlias ([WildcardPattern]::Escape($adapter)) -ErrorAction Stop | Out-Null"
        ))),
    ];
    let cleanup = vec![
        ps(format!("Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue")),
        dns("ipv4", "source=dhcp"),
        dns("ipv6", "source=dhcp"),
        ps(format!("Set-NetIPInterface -InterfaceIndex {idx} -AutomaticMetric Enabled -ErrorAction SilentlyContinue")),
    ];
    (apply, cleanup)
}

#[cfg(any(target_os = "linux", test))]
fn linux_drop_default_routes(net: &ReverseNet) -> Vec<Step> {
    let dev = net.interface_name.as_str();
    vec![
        try_(argv("ip", &["-4", "route", "del", "default", "dev", dev])),
        try_(argv("ip", &["-6", "route", "del", "default", "dev", dev])),
    ]
}

/// Linux: tell NetworkManager (for this connection only, not saved) never to
/// make the link a default route or use its DNS, remove any default route it
/// already has, and accept the proxy port on it.
#[cfg(any(target_os = "linux", test))]
fn linux_steps(net: &ReverseNet) -> (Vec<Step>, Vec<Argv>) {
    let dev = net.interface_name.as_str();
    let port = net.proxy_port.to_string();
    let accept = ["INPUT", "-i", dev, "-p", "tcp", "--dport", port.as_str(), "-j", "ACCEPT"];
    let mut apply = vec![try_(argv(
        "nmcli",
        &[
            "device",
            "modify",
            dev,
            "ipv4.never-default",
            "yes",
            "ipv6.never-default",
            "yes",
            "ipv4.ignore-auto-dns",
            "yes",
            "ipv6.ignore-auto-dns",
            "yes",
        ],
    ))];
    apply.extend(linux_drop_default_routes(net));
    // An INPUT policy that drops would hide the proxy; most desktops accept anyway.
    apply.push(try_(argv("iptables", &[&["-I"][..], &accept[..]].concat())));
    let cleanup = vec![argv("iptables", &[&["-D"][..], &accept[..]].concat())];
    (apply, cleanup)
}

/// macOS only gives the primary network service a global default route, and
/// the phone's link is not normally that; any it does get is removed.
#[cfg(any(target_os = "macos", test))]
fn macos_drop_default_routes(net: &ReverseNet) -> Vec<Step> {
    let dev = net.interface_name.as_str();
    vec![
        try_(argv("/sbin/route", &["-n", "delete", "-inet", "default", "-interface", dev])),
        try_(argv("/sbin/route", &["-n", "delete", "-inet", "default", "-ifscope", dev])),
        try_(argv("/sbin/route", &["-n", "delete", "-inet6", "default", "-ifscope", dev])),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> ReverseNet {
        ReverseNet { interface_index: 23, interface_name: "usb0".into(), proxy_port: 8080 }
    }

    fn script(step: &Step) -> &str {
        step.command.1.last().map(String::as_str).unwrap_or_default()
    }

    #[test]
    fn windows_never_routes_through_the_phone_and_opens_only_the_proxy() {
        let (apply, cleanup) = windows_steps(&net());
        assert!(script(&apply[0]).contains("InterfaceMetric 9999"));
        assert!(script(&apply[1]).contains("Remove-NetRoute") && script(&apply[1]).contains("'0.0.0.0/0','::/0'"));
        assert_eq!(apply[2].command.0, crate::tools::system_tool(crate::tools::NETSH));
        assert!(apply[2].command.1.contains(&"address=none".to_owned()), "the phone's DNS is not used");
        // Only the firewall rule must succeed; there may be no route to remove.
        assert_eq!(apply.iter().filter(|s| s.required).count(), 1);
        let rule = apply.iter().find(|s| s.required).unwrap();
        assert!(script(rule).contains("LocalPort 8080"));
        // New-NetFirewallRule has no -InterfaceIndex: the adapter goes in by
        // name, looked up from its index by PowerShell itself.
        assert!(script(rule).contains("Get-NetIPInterface -InterfaceIndex 23 -AddressFamily IPv4"));
        assert!(script(rule).contains("-InterfaceAlias ([WildcardPattern]::Escape($adapter))"));
        // Windows' own tools by their full path, never a name Windows would
        // look for next to the service first.
        let tools = [crate::tools::system_tool(crate::tools::POWERSHELL), crate::tools::system_tool(crate::tools::NETSH)];
        assert!(apply.iter().map(|s| &s.command).chain(&cleanup).all(|(program, _)| tools.contains(program)));

        let name = rule_name(8080);
        assert!(cleanup[0].1.last().unwrap().contains(&format!("Remove-NetFirewallRule -DisplayName '{name}'")));
        assert!(cleanup.iter().any(|c| c.1.contains(&"source=dhcp".to_owned())));
        assert!(cleanup.last().unwrap().1.last().unwrap().contains("AutomaticMetric Enabled"));
    }

    #[test]
    fn linux_keeps_networkmanager_from_using_the_phone() {
        let (apply, cleanup) = linux_steps(&net());
        assert_eq!(apply[0].command.0, "nmcli");
        assert!(apply[0].command.1.windows(2).any(|w| w == ["ipv4.never-default", "yes"]));
        assert!(apply[0].command.1.windows(2).any(|w| w == ["ipv4.ignore-auto-dns", "yes"]));
        assert!(apply.iter().any(|s| s.command.1 == ["-4", "route", "del", "default", "dev", "usb0"]));
        assert!(apply.iter().all(|s| !s.required));
        assert_eq!(cleanup[0].1[0], "-D");
        assert!(cleanup[0].1.contains(&"8080".to_owned()));
    }

    #[test]
    fn macos_removes_default_routes_over_the_link() {
        let steps = macos_drop_default_routes(&net());
        assert!(steps.iter().all(|s| s.command.0 == "/sbin/route" && s.command.1.contains(&"usb0".to_owned())));
    }

    #[test]
    fn rule_name_is_port_specific() {
        assert_ne!(rule_name(8080), rule_name(9090));
    }
}
