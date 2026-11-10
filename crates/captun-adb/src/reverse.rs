//! Reverse tethering: let the phone use *this PC's* internet over USB.
//!
//! Both methods are free of any app store and work with Captun's built-in adb —
//! no external `adb` and nothing on the phone for the default path.
//!
//! - [`ReverseMethod::SystemProxy`] (default): nothing is installed on the
//!   phone. Captun brings up the USB network link (RNDIS/NCM) so the phone can
//!   reach this PC by IP, runs a proxy inbound on the PC, and points the phone's
//!   system HTTP proxy at the PC's address on that link. The inbound feeds the
//!   phone's traffic into the policy engine. Carries proxy-aware TCP/HTTPS only —
//!   no UDP, and apps that ignore the system proxy are not covered. Chosen by
//!   default to keep the phone untouched.
//! - [`ReverseMethod::Helper`]: a small helper pushed over adb provides a
//!   VPN/TUN on the phone, so all traffic including UDP is carried. The helper is
//!   not from an app store and is removed on revert.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    command::{clear_global_proxy_cmd, force_stop_cmd, set_global_proxy_cmd, start_component_cmd},
    plan::{AdbOp, ReversiblePlan},
};

/// How the phone's traffic is captured for reverse tethering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReverseMethod {
    /// No app, no root: the phone's system HTTP proxy, pointed at the PC over the
    /// USB network link.
    #[default]
    SystemProxy,
    /// A pushed helper's VPN, covering all traffic including UDP.
    Helper,
}

impl ReverseMethod {
    /// Whether this method carries UDP and non-proxy-aware traffic.
    pub fn is_full_coverage(self) -> bool {
        matches!(self, Self::Helper)
    }
}

/// The helper app to drive for [`ReverseMethod::Helper`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperApp {
    /// Path on the PC to the helper `.apk`.
    pub apk_path: PathBuf,
    /// The helper's Android package name, for stopping and removing it on revert.
    pub package: String,
    /// The component to launch, e.g. `com.example.helper/.ControlActivity`.
    pub component: String,
}

/// Where the phone should send its proxied traffic: this PC's address on the USB
/// network link, and the port Captun's proxy inbound listens on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseParams {
    /// This PC's IPv4 address on the USB link, reachable from the phone.
    pub proxy_host: String,
    /// The PC-side port the Captun proxy inbound listens on.
    pub proxy_port: u16,
    /// Required for [`ReverseMethod::Helper`]; ignored by `SystemProxy`.
    pub helper: Option<HelperApp>,
}

impl ReverseParams {
    /// The no-app case: the phone's system proxy points at `host:port` on the PC.
    pub fn system_proxy(host: impl Into<String>, port: u16) -> Self {
        Self { proxy_host: host.into(), proxy_port: port, helper: None }
    }
}

/// Builds the reverse-tethering plan and the plan to undo it. The USB network
/// link itself is brought up and down by the daemon; a plan here only covers
/// the phone-side proxy or helper changes.
///
/// `revert` is ordered to stop the phone sending traffic *before* the path it
/// relies on is removed: the proxy is cleared (or the helper stopped) first.
pub fn reverse_plan(method: ReverseMethod, params: &ReverseParams) -> ReversiblePlan {
    match method {
        ReverseMethod::SystemProxy => ReversiblePlan {
            apply: vec![AdbOp::shell(set_global_proxy_cmd(&params.proxy_host, params.proxy_port))],
            revert: vec![AdbOp::shell(clear_global_proxy_cmd())],
        },
        ReverseMethod::Helper => {
            let mut apply = Vec::new();
            let mut revert = Vec::new();
            if let Some(helper) = &params.helper {
                apply.push(AdbOp::Install(helper.apk_path.clone()));
                apply.push(AdbOp::shell(start_component_cmd(&helper.component)));
                // Stop the helper, then remove it.
                revert.push(AdbOp::shell(force_stop_cmd(&helper.package)));
                revert.push(AdbOp::Uninstall(helper.package.clone()));
            }
            ReversiblePlan { apply, revert }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_method_is_the_no_app_one() {
        assert_eq!(ReverseMethod::default(), ReverseMethod::SystemProxy);
        assert!(!ReverseMethod::SystemProxy.is_full_coverage());
        assert!(ReverseMethod::Helper.is_full_coverage());
    }

    #[test]
    fn system_proxy_sets_then_clears_the_proxy() {
        let plan = reverse_plan(ReverseMethod::SystemProxy, &ReverseParams::system_proxy("192.168.42.238", 9090));
        assert_eq!(plan.apply, vec![AdbOp::shell("settings put global http_proxy 192.168.42.238:9090")]);
        assert_eq!(plan.revert, vec![AdbOp::shell("settings put global http_proxy :0")]);
    }

    #[test]
    fn helper_installs_and_launches_then_stops_and_removes() {
        let params = ReverseParams {
            proxy_host: String::new(),
            proxy_port: 0,
            helper: Some(HelperApp {
                apk_path: PathBuf::from("/opt/captun/helper.apk"),
                package: "org.captun.helper".into(),
                component: "org.captun.helper/.VpnControl".into(),
            }),
        };
        let plan = reverse_plan(ReverseMethod::Helper, &params);
        assert_eq!(plan.apply[0], AdbOp::Install(PathBuf::from("/opt/captun/helper.apk")));
        assert_eq!(plan.apply[1], AdbOp::shell("am start -n org.captun.helper/.VpnControl"));
        assert_eq!(plan.revert[0], AdbOp::shell("am force-stop org.captun.helper"));
        assert_eq!(plan.revert[1], AdbOp::Uninstall("org.captun.helper".into()));
    }
}
