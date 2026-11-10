use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Secret, TargetAddr};

/// Stable identifier of an egress, referenced by clients, groups and rules.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EgressId(String);

impl EgressId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Ids are written into firewall object names and file names, so they are
    /// limited to a conservative character set.
    pub fn is_well_formed(&self) -> bool {
        !self.0.is_empty()
            && self.0.len() <= 32
            && self.0.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }
}

impl From<&str> for EgressId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl fmt::Display for EgressId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for EgressId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/// A way out to the internet that client traffic can be steered through.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EgressConfig {
    pub id: EgressId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub kind: EgressKind,
    #[serde(default, skip_serializing_if = "UdpPolicy::is_native")]
    pub udp: UdpPolicy,
    /// A turned-off egress stays listed, but nothing may route through it.
    #[serde(default = "yes", skip_serializing_if = "is_yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

fn is_yes(value: &bool) -> bool {
    *value
}

fn is_no(value: &bool) -> bool {
    !*value
}

impl EgressConfig {
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(self.id.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EgressKind {
    /// Straight out of the host, optionally pinned to one interface: a second
    /// Wi-Fi adapter, Ethernet, a USB modem or an OS-level VPN adapter.
    Direct {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
    },
    Socks5 {
        server: TargetAddr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<Secret>,
        /// Reach the proxy through another egress (proxy chaining).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<EgressId>,
    },
    /// HTTP CONNECT proxy. Carries TCP only.
    Http {
        server: TargetAddr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<Secret>,
        /// An HTTPS proxy: the connection to the proxy itself is TLS, checked
        /// against the public certificate authorities.
        #[serde(default, skip_serializing_if = "is_no")]
        tls: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<EgressId>,
    },
    /// An Xray-core outbound run by the managed sidecar: either a share link
    /// (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`) or a
    /// JSON outbound file.
    Xray {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        link: Option<Secret>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config_file: Option<PathBuf>,
    },
    /// Drops everything; useful as a rule target or a kill-switch egress.
    Block,
}

impl EgressKind {
    pub fn via(&self) -> Option<&EgressId> {
        match self {
            Self::Socks5 { via, .. } | Self::Http { via, .. } => via.as_ref(),
            _ => None,
        }
    }

    pub fn supports_native_udp(&self) -> bool {
        !matches!(self, Self::Http { .. })
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Direct { .. } => "direct",
            Self::Socks5 { .. } => "socks5",
            Self::Http { .. } => "http",
            Self::Xray { .. } => "xray",
            Self::Block => "block",
        }
    }
}

/// What happens to a client's UDP when its egress is selected.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpPolicy {
    /// Carry UDP through the egress itself (SOCKS5 UDP ASSOCIATE, Xray, direct).
    #[default]
    Native,
    Block,
    /// Send UDP through a different egress, e.g. for an HTTP proxy.
    Via(EgressId),
}

impl UdpPolicy {
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }
}
