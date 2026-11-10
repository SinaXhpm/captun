//! OS integration: bringing the hotspot up and down, listing its stations,
//! and discovering network interfaces for interface-pinned egresses.

pub mod access;
pub mod capture;
#[cfg(windows)]
pub mod divert;
#[cfg(windows)]
mod hosted;
#[cfg(any(target_os = "linux", test))]
mod hostapd;
mod hotspot;
pub mod iface;
pub mod neighbors;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(windows, target_os = "linux"))]
mod own_net;
mod parse;
pub mod reach;
mod refresh;
pub mod tether_net;
mod tools;
pub mod trust;
mod wifi;
#[cfg(windows)]
mod windows;

pub use hotspot::{
    BackendState, HotspotBackend, HotspotError, HotspotSupport, PlatformNotes, StartOptions, Unsupported, hotspot_support,
};

/// The hotspot backend for the platform this binary was built for: the OS's
/// own hotspot first, then a way Captun runs the network for itself, so any
/// Wi-Fi adapter that can act as an access point is used.
pub fn default_backend() -> Box<dyn HotspotBackend> {
    #[cfg(windows)]
    return Box::new(hotspot::FallbackHotspot::new(
        Box::new(windows::MobileHotspot::new()),
        Box::new(hosted::HostedNetwork::default()),
        ("Windows Mobile hotspot", "the Wi-Fi hosted network"),
    ));
    #[cfg(target_os = "linux")]
    return Box::new(hotspot::FallbackHotspot::new(
        Box::new(linux::NetworkManagerHotspot::new()),
        Box::new(hostapd::HostapdHotspot::default()),
        ("NetworkManager", "hostapd"),
    ));
    #[cfg(target_os = "macos")]
    return Box::new(macos::InternetSharing);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    return Box::new(Unsupported);
}
