//! VPN-link outbounds (VLESS, VMess, Trojan, Shadowsocks, Hysteria2) through
//! a bundled Xray-core program run as a supervised sidecar. Captun's own
//! data plane reaches each one as a loopback SOCKS5 proxy, so per-device
//! routing, UDP, limits and stats work the same as for any other outbound.

mod config;
mod process;
mod sidecar;

use std::{
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use captun_core::{
    Secret,
    link::{VpnLink, VpnProtocol},
};

pub use config::{Route, full_config, outbound_for_link, outbound_from_file};
pub use sidecar::{Sidecar, SidecarState, SidecarStatus};

#[cfg(windows)]
const PROGRAM: &str = "xray.exe";
#[cfg(not(windows))]
const PROGRAM: &str = "xray";

/// What the user is told when the service's check refuses the Xray program.
pub(crate) const REFUSED: &str =
    "VPN links are off because other programs on this computer can change Captun's files. Reinstall Captun for all users.";

/// The check registered with [`set_program_check`].
static PROGRAM_CHECK: OnceLock<fn(&Path) -> io::Result<()>> = OnceLock::new();

/// Registers the check the Xray program must pass before it is trusted and
/// again right before every start, so a file swapped after start-up is caught
/// too. On Windows the service registers one that refuses a program in a
/// folder other accounts can change: an all-users install in Program Files
/// passes, a copy in the user's own folders does not. Without one (tests,
/// development builds) only the built-in checks apply. The first registration
/// stays.
pub fn set_program_check(check: fn(&Path) -> io::Result<()>) {
    if PROGRAM_CHECK.set(check).is_err() {
        tracing::debug!("an Xray program check was already registered; keeping it");
    }
}

/// Runs the registered check, if any.
pub(crate) fn check_program(path: &Path) -> io::Result<()> {
    PROGRAM_CHECK.get().map_or(Ok(()), |check| check(path))
}

/// [`check_program`] for the moment before the program runs: logs why a
/// refused one is refused, and gives the user's sentence.
pub(crate) fn allow_run(path: &Path) -> Result<(), String> {
    check_program(path).map_err(|e| {
        tracing::warn!(path = %path.display(), "not running the VPN link engine (Xray): {e}");
        REFUSED.to_owned()
    })
}

/// Where the Xray program is looked for: next to the service first (where
/// Captun's installers put it), then where Linux packages install it.
fn candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().and_then(|exe| exe.parent().map(PathBuf::from)) {
        candidates.push(dir.join(PROGRAM));
    }
    #[cfg(target_os = "linux")]
    candidates.extend(["/usr/lib/captun/xray", "/usr/bin/xray", "/usr/local/bin/xray"].map(PathBuf::from));
    candidates
}

/// Finds the Xray program (see [`candidates`]). Places other users could
/// write to are never used.
pub fn find_program() -> Option<PathBuf> {
    candidates().into_iter().find(|path| {
        let ok = process::trusted(path);
        if !ok && path.exists() {
            tracing::warn!(path = %path.display(), "ignoring an Xray program that other users could have changed");
        }
        ok
    })
}

/// Whether an Xray program is in place but the registered check refuses it,
/// so that "not installed" would be the wrong thing to tell the user.
pub(crate) fn program_refused() -> bool {
    PROGRAM_CHECK.get().is_some() && candidates().iter().any(|path| path.is_file() && check_program(path).is_err())
}

/// Every secret in a link, so Xray's log lines can be scrubbed of them.
pub(crate) fn link_secrets(link: &VpnLink) -> Vec<Secret> {
    match &link.protocol {
        VpnProtocol::Vless { id, .. } | VpnProtocol::Vmess { id, .. } => vec![id.clone()],
        VpnProtocol::Trojan { password } | VpnProtocol::Shadowsocks { password, .. } => vec![password.clone()],
        VpnProtocol::Hysteria2 { auth, obfs_password } => {
            let mut secrets = vec![auth.clone()];
            secrets.extend(obfs_password.clone());
            secrets
        }
    }
}
