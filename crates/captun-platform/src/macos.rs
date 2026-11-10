//! macOS has no public API for an app to create a Wi-Fi hotspot, so Captun
//! works alongside the system's own Internet Sharing instead of replacing it:
//! once the user turns it on, its bridge interface and the leases its DHCP
//! server writes tell Captun that the hotspot is up and who is on it, and
//! the rest of Captun (device list, outbounds, DNS) applies to them.

use std::net::IpAddr;

use async_trait::async_trait;
use captun_core::{ObservedClient, config::HotspotConfig};

use crate::{BackendState, HotspotBackend, HotspotError, PlatformNotes, StartOptions};

/// Where macOS turns Internet Sharing on, in the words of System Settings.
pub(crate) const HOW_TO_SHARE: &str = "macOS only lets its own Internet Sharing create a Wi-Fi hotspot. Turn it on in System Settings → General → Sharing → Internet Sharing (share to Wi-Fi); Captun then lists and manages the devices on it.";

/// The lease file of bootpd, the DHCP server Internet Sharing runs.
const LEASES: &str = "/var/db/dhcpd_leases";

#[derive(Debug, Default)]
pub(crate) struct InternetSharing;

/// Internet Sharing's bridge (`bridge100`, …) while it is on.
fn sharing_bridge() -> Option<crate::iface::Interface> {
    crate::iface::list()
        .into_iter()
        .find(|i| i.name.starts_with("bridge1") && i.up && !i.ipv4.is_empty())
}

#[async_trait]
impl HotspotBackend for InternetSharing {
    fn notes(&self) -> PlatformNotes {
        PlatformNotes { hotspot: false, band_selection: false, notes: vec![HOW_TO_SHARE.into()] }
    }

    async fn start(&self, _config: &HotspotConfig, _options: StartOptions) -> Result<BackendState, HotspotError> {
        Err(HotspotError::Unsupported(HOW_TO_SHARE.into()))
    }

    async fn stop(&self) -> Result<(), HotspotError> {
        if sharing_bridge().is_some() {
            return Err(HotspotError::Unsupported(
                "Turn Internet Sharing off in System Settings → General → Sharing.".into(),
            ));
        }
        Ok(())
    }

    async fn state(&self) -> Result<BackendState, HotspotError> {
        Ok(match sharing_bridge() {
            Some(bridge) => BackendState {
                running: true,
                transitioning: false,
                ssid: None,
                gateway: bridge.ipv4.first().map(|ip| IpAddr::V4(*ip)),
                interface: Some(bridge.name),
                max_clients: None,
            },
            None => BackendState::default(),
        })
    }

    async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError> {
        let Some(bridge) = sharing_bridge() else { return Ok(Vec::new()) };
        let text = tokio::fs::read_to_string(LEASES).await.unwrap_or_default();
        // Leases outlive connections; keep the ones on the bridge's /24 that
        // the neighbour table still knows.
        let on_bridge = |ip: &IpAddr| match (ip, bridge.ipv4.first()) {
            (IpAddr::V4(ip), Some(gw)) => ip.octets()[..3] == gw.octets()[..3],
            _ => false,
        };
        let neighbours = arp_table(&bridge.name).await;
        Ok(crate::parse::bootpd_leases(&text)
            .into_iter()
            .filter(|(mac, ip, _)| on_bridge(ip) && (neighbours.is_empty() || neighbours.contains(mac)))
            .map(|(mac, ip, hostname)| ObservedClient { mac, addrs: vec![ip], hostname })
            .collect())
    }
}

/// MAC addresses `arp` currently sees on `interface`.
async fn arp_table(interface: &str) -> Vec<captun_core::MacAddr> {
    let Ok(out) = tokio::process::Command::new("/usr/sbin/arp").args(["-an", "-i", interface]).output().await else {
        return Vec::new();
    };
    // "? (192.168.2.2) at a:b:c:1:2:3 on bridge100 ifscope [bridge]"
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.split(" at ").nth(1)?.split_whitespace().next().map(str::to_owned))
        .filter_map(|mac| {
            let parts: Vec<u8> = mac.split(':').map(|p| u8::from_str_radix(p, 16)).collect::<Result<_, _>>().ok()?;
            Some(captun_core::MacAddr(parts.try_into().ok()?))
        })
        .collect()
}
