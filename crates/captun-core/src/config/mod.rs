//! The configuration. The GUI keeps it (encrypted, next to the app) and hands
//! it to the service over IPC, which runs every change through
//! [`Config::validate`]; a service run on its own keeps it in `captun.toml`.

mod rule;
mod schedule;
mod validate;

use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use serde::{Deserialize, Serialize};

pub use rule::{PortRange, Protocol, RuleAction, RuleConfig};
pub use schedule::{ClockTime, Schedule, Weekday};
pub use validate::{MAX_QUOTA_MB, is_list_link, validate_passphrase, validate_ssid};

use crate::{ClientState, DomainPattern, EgressConfig, EgressId, EgressKind, MacAddr, Secret, TargetAddr};

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot access config file: {0}")]
    Io(#[from] io::Error),
    #[error("cannot parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("cannot serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("invalid config:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub hotspot: HotspotConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub access_network: AccessNetworkConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub tls_inspection: TlsInspectionConfig,
    #[serde(default)]
    pub portal: PortalConfig,
    #[serde(default = "default_egresses", rename = "egress")]
    pub egresses: Vec<EgressConfig>,
    #[serde(default, rename = "group", skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupConfig>,
    #[serde(default, rename = "client", skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<ClientProfile>,
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RuleConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            hotspot: HotspotConfig::default(),
            network: NetworkConfig::default(),
            access_network: AccessNetworkConfig::default(),
            dns: DnsConfig::default(),
            tls_inspection: TlsInspectionConfig::default(),
            portal: PortalConfig::default(),
            egresses: default_egresses(),
            groups: Vec::new(),
            clients: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Loads the file, or returns defaults when it does not exist yet.
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Validates, then writes atomically (temp file + rename) so a crash never
    /// leaves a truncated config. The file holds secrets, so on Unix it is
    /// created owner-only.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        let text = self.to_toml()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("toml.tmp");
        {
            use std::io::Write;
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn egress(&self, id: &EgressId) -> Option<&EgressConfig> {
        self.egresses.iter().find(|e| &e.id == id)
    }

    pub fn group(&self, id: &str) -> Option<&GroupConfig> {
        self.groups.iter().find(|g| g.id == id)
    }

    pub fn client(&self, mac: &MacAddr) -> Option<&ClientProfile> {
        self.clients.iter().find(|c| &c.mac == mac)
    }

    /// The data allowance `mac` has: its own, else its group's, else the one
    /// every device has; none when none of them sets one.
    pub fn quota_for(&self, mac: &MacAddr) -> Option<Quota> {
        let profile = self.client(mac);
        profile
            .and_then(|p| p.quota)
            .or_else(|| profile.and_then(|p| p.group.as_deref()).and_then(|g| self.group(g)).and_then(|g| g.quota))
            .or(self.network.device_quota)
    }

    /// Returns the profile for `mac`, creating an empty one if needed.
    pub fn client_mut(&mut self, mac: MacAddr) -> &mut ClientProfile {
        let index = match self.clients.iter().position(|c| c.mac == mac) {
            Some(i) => i,
            None => {
                self.clients.push(ClientProfile::new(mac));
                self.clients.len() - 1
            }
        };
        &mut self.clients[index]
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotspotConfig {
    pub ssid: String,
    /// WPA2/WPA3 passphrase. Empty means "not configured yet"; the hotspot
    /// refuses to start until it is set.
    #[serde(default, skip_serializing_if = "Secret::is_empty")]
    pub passphrase: Secret,
    #[serde(default)]
    pub band: WifiBand,
    /// The Wi-Fi adapter that hosts the access point: its name as the adapter
    /// list shows it ("Wi-Fi 2" on Windows, "wlan1" on Linux). `None` lets the
    /// system choose. Windows hosts one Mobile hotspot at a time and is asked
    /// to put it on this adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Bring the hotspot up as soon as the service starts.
    #[serde(default = "yes")]
    pub autostart: bool,
    /// Most stations Captun admits at once; later arrivals are held until one
    /// leaves. `None` leaves only the OS's own cap (Windows: usually 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_clients: Option<u32>,
}

/// Upper bound for `hotspot.max_clients`; no consumer access point gets close.
pub const MAX_CLIENT_LIMIT: u32 = 255;

impl HotspotConfig {
    /// Whether `other` brings up the same access point. Autostart and the device
    /// limit are Captun's own and never need the radio restarted.
    pub fn same_access_point(&self, other: &Self) -> bool {
        self.ssid == other.ssid
            && self.passphrase == other.passphrase
            && self.band == other.band
            && self.interface == other.interface
    }
}

impl Default for HotspotConfig {
    fn default() -> Self {
        Self {
            ssid: "Captun".into(),
            passphrase: Secret::default(),
            band: WifiBand::default(),
            interface: None,
            autostart: true,
            max_clients: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiBand {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "2.4ghz")]
    Ghz2_4,
    #[serde(rename = "5ghz")]
    Ghz5,
    #[serde(rename = "6ghz")]
    Ghz6,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// New stations get no internet until approved in the UI.
    #[serde(default)]
    pub quarantine_new_clients: bool,
    /// Stations on the hotspot cannot reach each other.
    #[serde(default = "yes")]
    pub isolate_clients: bool,
    /// Stations cannot reach this computer itself, beyond what sharing needs
    /// (DHCP and DNS). Off, they reach it at its address on their network, and
    /// on Windows the firewall is opened for them.
    #[serde(default = "yes")]
    pub block_host: bool,
    /// Stations cannot reach the host's other networks (home LAN, router UI).
    #[serde(default = "yes")]
    pub block_host_lan: bool,
    /// Drop a client's traffic when its egress is down instead of leaking it
    /// through another route.
    #[serde(default = "yes")]
    pub kill_switch: bool,
    /// The speed limit on all devices together, shared by every flow of every
    /// device; a device's own limit (or its group's) still applies within it.
    /// Like those, it takes effect while traffic goes through the routing
    /// engine (`transparent_routing`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<RateLimit>,
    /// The data allowance of each device that has none of its own and none
    /// from its group. Each device counts its own use against it. Like the
    /// speed limits, it is kept while traffic goes through the routing engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_quota: Option<Quota>,
    /// The day a weekly data allowance starts over on.
    #[serde(default = "default_week_start")]
    pub week_starts: Weekday,
    /// Steer hotspot traffic through the routing engine so per-client egress,
    /// bandwidth limits and live statistics take effect. Experimental and off
    /// by default: it sets up a TUN device and OS routing and needs validation
    /// on real hotspot hardware.
    #[serde(default)]
    pub transparent_routing: bool,
    #[serde(default = "default_egress_id")]
    pub default_egress: EgressId,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            quarantine_new_clients: false,
            isolate_clients: true,
            block_host: true,
            block_host_lan: true,
            kill_switch: true,
            limit: None,
            device_quota: None,
            week_starts: default_week_start(),
            transparent_routing: false,
            default_egress: default_egress_id(),
        }
    }
}

/// A wired Ethernet or USB interface brought up as a shared network that clients
/// connect to, instead of (or alongside) the Wi-Fi hotspot. Captun gives it a
/// gateway address, serves DHCP on it, and routes and monitors the devices on it
/// like any hotspot client.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessNetworkConfig {
    /// Off by default; the Wi-Fi hotspot is the usual access network.
    #[serde(default)]
    pub enabled: bool,
    /// The wired/USB interface to share on (friendly or system name). Required
    /// when enabled; `None` means "not chosen yet".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Captun's address on this network — the clients' gateway and DNS server.
    #[serde(default = "default_access_gateway")]
    pub gateway: Ipv4Addr,
    /// Subnet prefix length (e.g. 24 for a /24).
    #[serde(default = "default_access_prefix")]
    pub prefix_len: u8,
    /// First address handed out by DHCP (inclusive).
    #[serde(default = "default_access_dhcp_start")]
    pub dhcp_start: Ipv4Addr,
    /// Last address handed out by DHCP (inclusive).
    #[serde(default = "default_access_dhcp_end")]
    pub dhcp_end: Ipv4Addr,
    /// DHCP lease time, in seconds.
    #[serde(default = "default_lease_secs")]
    pub lease_secs: u32,
    /// Provide basic internet with OS NAT. Turn this off to route clients through
    /// the engine instead (per-client egress, limits), via `transparent_routing`.
    #[serde(default = "yes")]
    pub nat: bool,
    /// Bring the access network up as soon as the service starts.
    #[serde(default)]
    pub autostart: bool,
}

impl Default for AccessNetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            gateway: default_access_gateway(),
            prefix_len: default_access_prefix(),
            dhcp_start: default_access_dhcp_start(),
            dhcp_end: default_access_dhcp_end(),
            lease_secs: default_lease_secs(),
            nat: true,
            autostart: false,
        }
    }
}

impl AccessNetworkConfig {
    /// The subnet mask derived from the prefix length.
    pub fn netmask(&self) -> Ipv4Addr {
        let prefix = self.prefix_len.min(32);
        Ipv4Addr::from(if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) })
    }

    /// The network (base) address: the gateway masked by the prefix.
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.gateway) & u32::from(self.netmask()))
    }

    /// The subnet's broadcast address.
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network()) | !u32::from(self.netmask()))
    }
}

/// Bandwidth cap in kilobits per second; `None` means unlimited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_kbps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_kbps: Option<u64>,
}

/// A data allowance: how much a device may use in each period, download and
/// upload together, and what happens once that is used up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quota {
    /// Megabytes in each period, as the app shows sizes: 1 MB is
    /// [`MB`] bytes (1,048,576), 1 GB 1,024 MB.
    pub mb: u64,
    pub every: QuotaPeriod,
    /// Once it is used up, the device is slowed to this speed (kbit/s, both
    /// ways) until the period ends; without one it gets no internet then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub then_kbps: Option<u64>,
}

impl Quota {
    /// The allowance in bytes.
    pub fn bytes(&self) -> u64 {
        self.mb.saturating_mul(MB)
    }
}

/// Bytes in a megabyte of a data allowance.
pub const MB: u64 = 1 << 20;

/// How often a data allowance starts over: each day at midnight, each week
/// on `network.week_starts`, each month on its first day (all local time),
/// or never, until it is reset by hand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaPeriod {
    #[default]
    Day,
    Week,
    Month,
    Total,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_upstream: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<RateLimit>,
    /// Each device of the group gets this data allowance, unless it has one
    /// of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quota>,
}

/// Persistent per-station settings, keyed by MAC.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientProfile {
    pub mac: MacAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default)]
    pub state: ClientState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Overrides the group and global egress for this station.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_upstream: Option<String>,
    /// Overrides the group and global data allowance for this station.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quota>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<RateLimit>,
    /// The admin allows TLS inspection for this station. It only takes effect
    /// once the station's user has accepted the terms as well (`tls_consent`).
    #[serde(default)]
    pub inspect_tls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_consent: Option<TlsConsent>,
}

impl ClientProfile {
    pub fn new(mac: MacAddr) -> Self {
        Self {
            mac,
            alias: None,
            state: ClientState::Pending,
            group: None,
            egress: None,
            dns_upstream: None,
            quota: None,
            limit: None,
            inspect_tls: false,
            tls_consent: None,
        }
    }
}

/// Record of a station's user accepting the inspection terms on the portal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConsent {
    pub accepted_at_ms: u64,
    pub terms_version: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    #[serde(default = "default_dns_upstream_id")]
    pub default_upstream: String,
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
    #[serde(default)]
    pub min_ttl: u32,
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u32,
    #[serde(default)]
    pub block_response: BlockResponse,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocklist: Vec<DomainPattern>,
    /// Redirect every DNS query on the hotspot to this server and block DoT,
    /// so clients cannot bypass filtering with their own resolver.
    #[serde(default = "yes")]
    pub enforce: bool,
    #[serde(default = "yes")]
    pub log_queries: bool,
    #[serde(default = "default_dns_upstreams", rename = "upstream")]
    pub upstreams: Vec<DnsUpstreamConfig>,
    #[serde(default, rename = "override", skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<DnsOverride>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_dns_port(),
            default_upstream: default_dns_upstream_id(),
            cache_size: default_cache_size(),
            min_ttl: 0,
            max_ttl: default_max_ttl(),
            block_response: BlockResponse::default(),
            blocklist: Vec::new(),
            enforce: true,
            log_queries: true,
            upstreams: default_dns_upstreams(),
            overrides: Vec::new(),
        }
    }
}

impl DnsConfig {
    pub fn upstream(&self, id: &str) -> Option<&DnsUpstreamConfig> {
        self.upstreams.iter().find(|u| u.id == id)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponse {
    #[default]
    NxDomain,
    /// Answer `0.0.0.0` / `::`, which some apps handle more gracefully.
    NullIp,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    Udp,
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
}

impl DnsProtocol {
    pub fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 53,
            Self::Tls => 853,
            Self::Https => 443,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsUpstreamConfig {
    pub id: String,
    pub protocol: DnsProtocol,
    /// `ip`, `ip:port` or `host:port`; the port defaults by protocol.
    pub address: String,
    /// TLS server name for DoT/DoH; defaults to the address host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// DoH request path, `/dns-query` by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl DnsUpstreamConfig {
    pub fn target(&self) -> Result<TargetAddr, crate::addr::ParseTargetError> {
        TargetAddr::parse_with_default_port(&self.address, self.protocol.default_port())
    }

    pub fn tls_server_name(&self) -> Result<String, crate::addr::ParseTargetError> {
        match &self.server_name {
            Some(name) => Ok(name.clone()),
            None => self.target().map(|t| t.host()),
        }
    }

    pub fn doh_path(&self) -> &str {
        self.path.as_deref().unwrap_or("/dns-query")
    }
}

/// Local answer for a name, like a hosts file entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsOverride {
    pub domain: DomainPattern,
    pub addrs: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsInspectionConfig {
    /// Master switch. Inspection additionally needs the admin toggle and the
    /// station's own consent per client.
    #[serde(default)]
    pub enabled: bool,
    /// Bumped when the terms text changes; older consents stop counting.
    #[serde(default = "one")]
    pub terms_version: u32,
    /// Names that are never intercepted (banking, pinned apps).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bypass: Vec<DomainPattern>,
    /// Stop intercepting a name after repeated handshake failures, which is
    /// how certificate-pinning apps show up.
    #[serde(default = "yes")]
    pub auto_bypass_pinned: bool,
    /// Block QUIC (UDP 443) for inspected stations so browsers fall back to TCP.
    #[serde(default = "yes")]
    pub block_quic: bool,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    #[serde(default = "default_retention_hours")]
    pub retention_hours: u32,
}

impl Default for TlsInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            terms_version: 1,
            bypass: Vec::new(),
            auto_bypass_pinned: true,
            block_quic: true,
            max_body_bytes: default_max_body(),
            retention_hours: default_retention_hours(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Stations must type this before getting online.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Stations must accept the usage terms before getting online.
    #[serde(default = "yes")]
    pub show_terms: bool,
    #[serde(default = "default_session_hours")]
    pub session_hours: u32,
}

impl Default for PortalConfig {
    fn default() -> Self {
        Self { enabled: false, password: None, show_terms: true, session_hours: default_session_hours() }
    }
}

fn yes() -> bool {
    true
}

fn one() -> u32 {
    1
}

fn default_access_gateway() -> Ipv4Addr {
    Ipv4Addr::new(10, 73, 0, 1)
}

fn default_access_prefix() -> u8 {
    24
}

fn default_access_dhcp_start() -> Ipv4Addr {
    Ipv4Addr::new(10, 73, 0, 10)
}

fn default_access_dhcp_end() -> Ipv4Addr {
    Ipv4Addr::new(10, 73, 0, 200)
}

fn default_lease_secs() -> u32 {
    3600
}

fn default_version() -> u32 {
    CONFIG_VERSION
}

fn default_egress_id() -> EgressId {
    EgressId::new("direct")
}

fn default_egresses() -> Vec<EgressConfig> {
    vec![EgressConfig {
        id: default_egress_id(),
        name: Some("System default".into()),
        kind: EgressKind::Direct { interface: None },
        udp: Default::default(),
        enabled: true,
    }]
}

fn default_dns_port() -> u16 {
    53
}

fn default_dns_upstream_id() -> String {
    "cloudflare".into()
}

fn default_dns_upstreams() -> Vec<DnsUpstreamConfig> {
    vec![
        DnsUpstreamConfig {
            id: "cloudflare".into(),
            protocol: DnsProtocol::Https,
            address: "1.1.1.1".into(),
            server_name: Some("cloudflare-dns.com".into()),
            path: None,
        },
        DnsUpstreamConfig {
            id: "cloudflare-udp".into(),
            protocol: DnsProtocol::Udp,
            address: "1.1.1.1".into(),
            server_name: None,
            path: None,
        },
    ]
}

fn default_cache_size() -> usize {
    // Many devices ask for many names. This limits answers, not memory: the
    // DNS cache also stops at 32 MiB and keeps no answer over 4 KiB.
    32_768
}

fn default_max_ttl() -> u32 {
    86_400
}

fn default_max_body() -> usize {
    1 << 20
}

fn default_retention_hours() -> u32 {
    24
}

fn default_week_start() -> Weekday {
    Weekday::Mon
}

fn default_session_hours() -> u32 {
    24
}

#[cfg(test)]
mod tests;
