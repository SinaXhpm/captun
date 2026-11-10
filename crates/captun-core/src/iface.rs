use serde::{Deserialize, Serialize};

/// What a network adapter is, so it can be listed in words people know and
/// software-only adapters can be tucked away.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Ethernet,
    Wifi,
    /// A phone sharing its data over USB (RNDIS/NCM) or a mobile broadband modem.
    Mobile,
    /// A VPN or tunnel adapter.
    Vpn,
    /// Virtual machines, containers, Wi-Fi Direct and other software adapters.
    Virtual,
    Loopback,
    #[default]
    Other,
}
