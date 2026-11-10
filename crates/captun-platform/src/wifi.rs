//! The Wi-Fi hardware itself: which adapters exist (even switched off) and
//! switching them on before hosting, so a disabled adapter or a radio left off
//! never stands between the user and a hotspot. Only used where Captun
//! hosts the hotspot itself (Windows, Linux).
#![cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]

use captun_core::InterfaceKind;

/// A Wi-Fi adapter, enabled or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WifiAdapter {
    pub(crate) name: String,
    /// Switched off in the OS (Windows "Disabled"); the radio may still be off
    /// when this is true.
    pub(crate) enabled: bool,
}

/// Every Wi-Fi adapter of this computer. Disabled ones vanish from the normal
/// interface list on Windows, so they are looked up separately.
pub(crate) fn adapters() -> Vec<WifiAdapter> {
    let mut found: Vec<WifiAdapter> = crate::iface::list()
        .into_iter()
        .filter(|i| i.kind == InterfaceKind::Wifi)
        .map(|i| WifiAdapter { name: i.name, enabled: true })
        .collect();
    if found.is_empty() {
        found.extend(disabled_adapters().into_iter().map(|name| WifiAdapter { name, enabled: false }));
    }
    found
}

/// Why the OS's own hotspot feature will not run here, when it says so up
/// front. Captun can still host by itself then.
pub(crate) fn os_hotspot_blocker() -> Option<&'static str> {
    #[cfg(windows)]
    return crate::windows::hotspot_blocker();
    #[cfg(not(windows))]
    None
}

/// A tool hosting depends on that is missing, as a sentence for the user.
pub(crate) fn missing_tools() -> Option<String> {
    #[cfg(target_os = "linux")]
    if !on_path("nmcli") && !on_path("hostapd") {
        return Some("Install NetworkManager or hostapd to host a hotspot on this computer.".into());
    }
    None
}

#[cfg(target_os = "linux")]
pub(crate) fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

/// Switches Wi-Fi on: enables disabled adapters and turns the radio on.
/// Best effort; returns what it changed, for the log. Needs the privileges
/// only the service has.
pub(crate) async fn prepare() -> Vec<String> {
    #[cfg(windows)]
    return windows::prepare().await;
    #[cfg(target_os = "linux")]
    return linux::prepare().await;
    #[cfg(not(any(windows, target_os = "linux")))]
    Vec::new()
}

#[cfg(windows)]
fn disabled_adapters() -> Vec<String> {
    windows::disabled_adapters()
}

#[cfg(not(windows))]
fn disabled_adapters() -> Vec<String> {
    Vec::new()
}

#[cfg(windows)]
mod windows {
    use std::time::Duration;

    use captun_core::InterfaceKind;
    use tracing::warn;
    use windows::Devices::Radios::{Radio, RadioKind, RadioState};

    /// Physical 802.11 adapters (NdisPhysicalMedium 9) that are disabled (State 3).
    const DISABLED_WIFI: &str = "Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter -Filter 'NdisPhysicalMedium=9 AND State=3'";

    /// Runs `script` in PowerShell, started by its full path, with Windows'
    /// own environment and without flashing a console window when the GUI
    /// asks.
    fn powershell(script: &str) -> std::io::Result<std::process::Output> {
        crate::tools::command(&crate::tools::system_tool(crate::tools::POWERSHELL))
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!("[Console]::OutputEncoding = [Text.Encoding]::UTF8; {script}"))
            .output()
    }

    pub(super) fn disabled_adapters() -> Vec<String> {
        match powershell(&format!("{DISABLED_WIFI} | ForEach-Object {{ $_.Name }}")) {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn wifi_present() -> bool {
        crate::iface::list().iter().any(|i| i.kind == InterfaceKind::Wifi)
    }

    pub(super) async fn prepare() -> Vec<String> {
        let mut done = Vec::new();
        let disabled = tokio::task::spawn_blocking(disabled_adapters).await.unwrap_or_default();
        if !disabled.is_empty() {
            let enabled = tokio::task::spawn_blocking(|| powershell(&format!("{DISABLED_WIFI} | Invoke-CimMethod -MethodName Enable | Out-Null")))
                .await;
            match enabled {
                Ok(Ok(out)) if out.status.success() => {
                    done.push(format!("turned on Wi-Fi adapter {}", disabled.join(", ")));
                    // The adapter takes a moment to come back as an interface.
                    for _ in 0..20 {
                        if wifi_present() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
                Ok(Ok(out)) => warn!("could not turn on Wi-Fi: {}", String::from_utf8_lossy(&out.stderr).trim()),
                Ok(Err(e)) => warn!("could not turn on Wi-Fi: {e}"),
                Err(e) => warn!("could not turn on Wi-Fi: {e}"),
            }
        }
        match tokio::task::spawn_blocking(radio_on).await {
            Ok(Ok(true)) => done.push("switched the Wi-Fi radio on".into()),
            Ok(Ok(false)) => {}
            Ok(Err(e)) => warn!("could not switch the Wi-Fi radio on: {e}"),
            Err(e) => warn!("could not switch the Wi-Fi radio on: {e}"),
        }
        done
    }

    /// Turns software-switched-off Wi-Fi radios on (the Wi-Fi quick toggle or
    /// airplane mode). Returns whether one was switched.
    fn radio_on() -> windows::core::Result<bool> {
        Radio::RequestAccessAsync()?.get()?;
        let mut switched = false;
        for radio in &Radio::GetRadiosAsync()?.get()? {
            if radio.Kind()? == RadioKind::WiFi && radio.State()? == RadioState::Off {
                radio.SetStateAsync(RadioState::On)?.get()?;
                switched = true;
            }
        }
        Ok(switched)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use tokio::process::Command;

    async fn quietly(program: &str, args: &[&str]) -> bool {
        Command::new(program).args(args).output().await.is_ok_and(|out| out.status.success())
    }

    pub(super) async fn prepare() -> Vec<String> {
        let mut done = Vec::new();
        if super::on_path("rfkill") && quietly("rfkill", &["unblock", "wifi"]).await {
            done.push("unblocked Wi-Fi (rfkill)".into());
        }
        if super::on_path("nmcli") && quietly("nmcli", &["radio", "wifi", "on"]).await {
            done.push("switched the Wi-Fi radio on (NetworkManager)".into());
        }
        done
    }
}
