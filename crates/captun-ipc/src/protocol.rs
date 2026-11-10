use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use captun_core::{
    ClientState, Config, EgressId, InterfaceKind, MacAddr, TargetAddr,
    config::{ClientProfile, Protocol, RateLimit},
};
use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change to the frames below. 2: the token is
/// proved both ways and never sent (see [`crate::handshake`]).
pub const PROTOCOL_VERSION: u32 = 2;

/// Upper bound for one frame; a full config with hundreds of rules fits easily.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    /// Opens a connection with 32 random bytes (hex). It carries no secret:
    /// whatever answers must prove it holds the token first. An app from
    /// before version 2 sends its token here instead and no nonce, which
    /// reads as an empty one.
    Hello {
        version: u32,
        #[serde(default)]
        nonce: String,
    },
    /// The client's proof, sent only once the service proved itself.
    Auth { proof: String },
    Request { id: u64, request: Request },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    /// The answer to `Hello`: the service's own 32 random bytes and its proof,
    /// both hex.
    Challenge { version: u32, nonce: String, proof: String },
    Welcome { version: u32, service_version: String },
    Response { id: u64, result: Result<Response, IpcError> },
    Event { event: Event },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    GetStatus,
    StartHotspot,
    StopHotspot,
    ListClients,
    /// Replaces the stored profile for one station (alias, state, egress …).
    SetClientProfile(ClientProfile),
    /// Forgets an offline station and deletes its profile.
    ForgetClient { mac: MacAddr },
    GetConfig,
    /// Validates, persists and applies a whole new config.
    SetConfig(Box<Config>),
    ListInterfaces,
    /// Opens a TCP connection through the egress to measure reachability.
    TestEgress { id: EgressId, target: Option<TargetAddr> },
    /// Lists Android devices adb can see (`adb devices -l`).
    ListAdbDevices,
    /// Turns reverse tethering (the phone using the PC's internet) on or off.
    /// Captun only gives internet; it never uses a phone's.
    SetReverseTether {
        serial: String,
        enable: bool,
        #[serde(default)]
        method: ReverseTetherMethod,
    },
    /// Brings the wired/USB access network up (shares internet over Ethernet/USB
    /// to devices that plug in), using the `access_network` config.
    StartAccessNetwork,
    StopAccessNetwork,
    /// Stops the service cleanly (sharing off, changes reverted), so a newer
    /// copy can start in its place.
    Shutdown,
    /// How each online list the rules use stands, and whether an update is
    /// under way.
    GetLists,
    /// Starts downloading every online list the rules use, through the
    /// outbound `through` (the default outbound when `None`), and answers at
    /// once, as GetLists does; [`Event::Lists`] tells how it goes. While an
    /// update is under way nothing new starts. Lists are never fetched
    /// unless asked.
    UpdateLists { through: Option<EgressId> },
    /// How often each rule decided since the rules last changed, one entry
    /// per rule in order.
    GetRuleHits,
    /// What the rules do with a website or an address: a device's lookup of
    /// it and a connection to it, by the rules alone (whether the device may
    /// use the network at all aside). Nothing is counted, looked up or sent.
    TestRules {
        /// A website name or an IP address; a pasted link is cut down to its
        /// host. A port written on it (`example.com:8080`) is the one tested;
        /// a different `port` as well is refused, as which was meant is unclear.
        target: String,
        /// Any device when `None`: the default outbound, and only the rules
        /// for every device.
        device: Option<MacAddr>,
        /// When `None`: the port written on `target`, else 80 for an
        /// `http://` link, else 443.
        port: Option<u16>,
        /// TCP when `None`.
        protocol: Option<Protocol>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Status(Box<ServiceStatus>),
    Clients(Vec<ClientView>),
    Config(Box<Config>),
    Interfaces(Vec<InterfaceInfo>),
    EgressTest(EgressTestResult),
    AdbDevices(Vec<AdbDeviceInfo>),
    Tether(TetherOutcome),
    Lists(ListsProgress),
    RuleHits(Vec<RuleHits>),
    RuleTest(Box<RuleTestResult>),
}

/// How often one rule decided since the rules last changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleHits {
    /// New connections it decided.
    pub connections: u64,
    /// Name lookups it decided.
    pub lookups: u64,
    /// When it last decided either (ms since the epoch); `None` until it does.
    pub last_ms: Option<u64>,
}

/// What the rules do with a website or an address. Rules are named by their
/// index into `config.rules`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTestResult {
    /// The website tested, when it was a name.
    pub name: Option<String>,
    /// The address tested, when it was one.
    pub address: Option<IpAddr>,
    /// What a device's lookup of the name does; `None` for an address.
    pub lookup: Option<LookupOutcome>,
    /// What a connection does, decided with the name or the address.
    pub connection: ConnectionOutcome,
    /// For an address: the name devices last looked it up by, if any did lately.
    pub learned_name: Option<String>,
    /// What a connection to the address that does not say its name (QUIC,
    /// apps' own protocols) does: it goes by `learned_name`.
    pub by_learned_name: Option<ConnectionOutcome>,
    /// The port the connection was tested on.
    pub port: u16,
    /// TCP or UDP, as tested.
    pub protocol: Protocol,
}

/// What a device's lookup of a name does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupOutcome {
    /// Answered as blocked.
    pub blocked: bool,
    /// The outbound it is looked up through, unless blocked.
    pub egress: Option<EgressId>,
    /// The rule that decided; `None` for the device's usual way.
    pub rule: Option<usize>,
}

/// What a connection does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionOutcome {
    /// What happens to it in the end, its outbound's say included.
    pub verdict: RuleVerdict,
    /// The outbound the rules send it to; `None` when they stop it
    /// themselves.
    pub egress: Option<EgressId>,
    /// The outbound that really carries it: `egress` itself, or the one
    /// `egress` sends UDP through. `None` when none does (UDP blocked on
    /// `egress`), so it is stopped although the rules let it through.
    pub carried_by: Option<EgressId>,
    /// The rule that decided; `None` when no rule fits and it goes the
    /// device's usual way.
    pub rule: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerdict {
    Allow,
    /// Dropped silently.
    Deny,
    /// Refused out loud, so the app stops waiting.
    Reject,
}

/// One online list the rules use, as the service holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListStatus {
    pub url: String,
    /// Names and address ranges in the copy in use; both zero until the list
    /// has been downloaded.
    pub names: usize,
    pub addresses: usize,
    /// When the copy in use was downloaded (ms since the epoch).
    pub updated_ms: Option<u64>,
    /// Why the last download failed; the copy from before stays in use.
    pub error: Option<String>,
}

/// The online lists the rules use, and how far an update of them is.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListsProgress {
    /// An update is under way: the lists are being downloaded one after
    /// another, each put in use as it comes.
    pub updating: bool,
    /// How many of the update's `total` lists it is through with,
    /// downloaded or not. Once it is over, how it ended (`done` = `total`);
    /// both zero before the first.
    pub done: usize,
    pub total: usize,
    pub lists: Vec<ListStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct IpcError {
    pub code: ErrorCode,
    pub message: String,
}

impl IpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    BadRequest,
    InvalidConfig,
    NotFound,
    Unsupported,
    HotspotFailed,
    Internal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub service_version: String,
    pub platform: String,
    pub uptime_secs: u64,
    pub hotspot: HotspotStatus,
    #[serde(default)]
    pub access_network: AccessNetworkStatus,
    pub clients_online: usize,
    pub dns_running: bool,
    pub capabilities: Capabilities,
    #[serde(default)]
    pub tether: TetherStatus,
    /// The engine that runs VPN-link outbounds.
    #[serde(default)]
    pub xray: XrayStatus,
    /// Whether devices' traffic is going through Captun (and so through
    /// their outbounds) right now.
    #[serde(default)]
    pub routing: RoutingStatus,
    /// Whether what devices may reach besides the internet (this computer,
    /// each other, the home network) is held to the settings right now.
    #[serde(default)]
    pub local_access: LocalAccessStatus,
}

/// Whether the "what devices can reach" settings are in force.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccessStatus {
    pub state: LocalAccessState,
    /// Why they are not in force, or what was left undone while the rest is.
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAccessState {
    /// Nothing is being shared.
    #[default]
    Idle,
    /// In force on every network Captun shares.
    Active,
    /// Could not be put in force: devices reach what the system lets them.
    Failed,
    /// This system cannot do it yet.
    Unsupported,
}

/// Whether Captun is carrying devices' traffic itself, which is what makes
/// outbounds, the kill switch, limits and traffic figures apply.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingStatus {
    pub state: RoutingState,
    pub error: Option<String>,
    /// Packets taken from devices so far, where the system can tell: a number
    /// that grows while devices browse shows capture is working.
    pub captured_packets: Option<u64>,
    /// Of those, the packets dropped because the routing engine had fallen
    /// behind, where the system can tell.
    #[serde(default)]
    pub dropped_packets: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingState {
    /// Turned off: devices use this computer's internet directly.
    #[default]
    Off,
    /// Turned on; starts with the hotspot, USB or cable sharing.
    Waiting,
    Active,
    Failed,
    /// This system cannot do it yet.
    Unsupported,
}

/// The Xray sidecar that runs VPN-link outbounds (VLESS, VMess, …).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrayStatus {
    pub state: XrayState,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XrayState {
    /// No outbound needs it.
    #[default]
    Idle,
    /// Outbounds need it but the program is not installed.
    Missing,
    Starting,
    Running,
    Failed,
}

/// The phone the service shares this PC's internet with over USB, if any.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TetherStatus {
    /// A phone using this PC's internet.
    pub reverse: Option<TetherSession>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TetherSession {
    pub serial: String,
    /// The PC-side network adapter of the USB link.
    pub interface: Option<String>,
}

/// State of the wired/USB access network.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessNetworkStatus {
    pub running: bool,
    /// The interface being shared on.
    pub interface: Option<String>,
    /// Captun's gateway address on the access network.
    pub gateway: Option<IpAddr>,
    /// Devices currently holding a DHCP lease.
    pub leases: usize,
    /// Whether basic OS NAT is providing internet.
    pub nat: bool,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotspotState {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotspotStatus {
    pub state: HotspotState,
    pub ssid: Option<String>,
    /// OS name of the interface the stations are attached to.
    pub interface: Option<String>,
    /// The hub's own address on the hotspot network.
    pub gateway: Option<IpAddr>,
    pub max_clients: Option<u32>,
    pub error: Option<String>,
}

/// What this platform build can actually do, so the GUI can grey out the rest
/// and explain why.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub hotspot: bool,
    pub band_selection: bool,
    pub per_client_routing: bool,
    pub tls_inspection: bool,
    /// Captun decides whether devices on its Wi-Fi hotspot reach each other
    /// (on Windows the Wi-Fi driver does).
    #[serde(default)]
    pub wifi_isolation: bool,
    pub notes: Vec<String>,
}

/// One station as the GUI shows it: live presence merged with its profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientView {
    pub mac: MacAddr,
    pub online: bool,
    pub addrs: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub alias: Option<String>,
    pub state: ClientState,
    /// Connected while the hotspot is at its device limit: held until a slot frees up.
    pub over_limit: bool,
    pub group: Option<String>,
    /// Egress pinned on the profile, if any.
    pub egress: Option<EgressId>,
    /// Egress the station's traffic actually uses after group/global fallback.
    pub effective_egress: EgressId,
    pub limit: Option<RateLimit>,
    pub inspect_tls: bool,
    pub tls_consented: bool,
    /// Locally administered MAC, i.e. a phone's per-network random address.
    pub randomized_mac: bool,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub traffic: TrafficStats,
}

/// A device's traffic when its entry was put together. The speeds are those
/// of the last [`Event::Traffic`]; that event keeps them current.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficStats {
    /// Bytes the device received (downloaded) through Captun.
    pub rx_bytes: u64,
    /// Bytes it sent (uploaded).
    pub tx_bytes: u64,
    /// Download speed, in bits per second.
    pub rx_bps: u64,
    /// Upload speed, in bits per second.
    pub tx_bps: u64,
    /// Connections and flows open now.
    pub active_flows: u32,
}

/// One device's traffic, as [`Event::Traffic`] reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTraffic {
    pub mac: MacAddr,
    /// Bytes the device received (downloaded) through Captun.
    pub rx_bytes: u64,
    /// Bytes it sent (uploaded).
    pub tx_bytes: u64,
    /// Download speed over the last second, in bits per second.
    pub rx_bps: u64,
    /// Upload speed over the last second, in bits per second.
    pub tx_bps: u64,
    /// Connections and flows open now.
    pub active_flows: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub index: u32,
    /// Name to put in an egress `interface` field.
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub kind: InterfaceKind,
    /// Backed by hardware rather than software (best effort).
    #[serde(default)]
    pub physical: bool,
    pub mac: Option<MacAddr>,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub up: bool,
    pub has_gateway: bool,
    #[serde(default)]
    pub gateway: Option<IpAddr>,
    /// Carries the OS's default route, i.e. this computer's own internet.
    #[serde(default)]
    pub default_route: bool,
    #[serde(default)]
    pub speed_mbps: Option<u64>,
    /// Faces devices Captun shares with (the hotspot, or the USB link to a
    /// phone), so it is never offered as a way out.
    pub is_hotspot: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressTestResult {
    pub ok: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
    /// Whether devices' UDP (calls, games, QUIC) gets through it; `None` when
    /// that could not be told. Many local SOCKS5 proxies carry only TCP.
    #[serde(default)]
    pub udp: Option<bool>,
}

/// How reverse tethering captures the phone's traffic. The default installs
/// nothing on the phone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReverseTetherMethod {
    /// No app, no root: the phone's system HTTP proxy, tunnelled to the PC.
    #[default]
    SystemProxy,
    /// A pushed helper's VPN, covering all traffic including UDP.
    Helper,
}

/// One Android device as the GUI shows it, flattened from `adb devices -l`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdbDeviceInfo {
    pub serial: String,
    /// Friendly name (model if known, else the serial).
    pub label: String,
    /// `device`, `unauthorized`, `offline`, `no_permissions`, …
    pub state: String,
    pub model: Option<String>,
    /// Whether commands can be sent (state is `device`).
    pub ready: bool,
}

/// The result of a tethering action, with any follow-up the user should see.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TetherOutcome {
    pub ok: bool,
    pub message: String,
    /// The post-session safety notice (shown after turning a feature off).
    pub caution: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Event {
    /// The whole device list, sent when a device joins, leaves, is forgotten
    /// or held back, or the settings change; never on a timer. Speeds come in
    /// [`Event::Traffic`].
    Clients(Vec<ClientView>),
    /// The traffic of every device online that has had any, once a second
    /// while a GUI is connected and it changes: a report the same as the
    /// last one is not sent again.
    Traffic(Vec<DeviceTraffic>),
    Hotspot(HotspotStatus),
    Xray(XrayStatus),
    ConfigChanged,
    /// One name lookup.
    DnsQuery(DnsQueryLog),
    /// Name lookups gathered over a short while, so a busy network costs one
    /// message a few times a second rather than one per lookup.
    DnsQueries(DnsQueryBatch),
    Log(LogLine),
    /// How an update of the online lists goes: when it starts, after each
    /// list, and once more when it is over (`updating` false).
    Lists(ListsProgress),
}

/// Name lookups, oldest first, and how many more were left out to keep the
/// batch small (the oldest go first).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryBatch {
    pub entries: Vec<DnsQueryLog>,
    #[serde(default)]
    pub dropped: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryLog {
    pub at_ms: u64,
    pub client: Option<MacAddr>,
    pub client_ip: IpAddr,
    pub name: String,
    pub qtype: String,
    /// `NOERROR`, `NXDOMAIN`, `BLOCKED`, `OVERRIDE`, `CACHED`, `FAILED` …
    pub outcome: String,
    pub answers: Vec<String>,
    pub upstream: Option<String>,
    pub latency_ms: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    pub at_ms: u64,
    pub level: LogLevel,
    pub target: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_have_stable_json_shape() {
        let req = ClientFrame::Request { id: 7, request: Request::TestEgress { id: "socks".into(), target: None } };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"type":"request","id":7,"request":{"method":"test_egress","params":{"id":"socks","target":null}}}"#
        );

        let ok = ServerFrame::Response { id: 7, result: Ok(Response::Ok) };
        assert_eq!(serde_json::to_string(&ok).unwrap(), r#"{"type":"response","id":7,"result":{"Ok":{"kind":"ok"}}}"#);

        let unit = serde_json::to_string(&Request::GetStatus).unwrap();
        assert_eq!(unit, r#"{"method":"get_status"}"#);
    }

    #[test]
    fn the_greeting_keeps_its_json_shape() {
        let hello = ClientFrame::Hello { version: 2, nonce: "ab".into() };
        assert_eq!(serde_json::to_string(&hello).unwrap(), r#"{"type":"hello","version":2,"nonce":"ab"}"#);
        let auth = ClientFrame::Auth { proof: "cd".into() };
        assert_eq!(serde_json::to_string(&auth).unwrap(), r#"{"type":"auth","proof":"cd"}"#);
        let challenge = ServerFrame::Challenge { version: 2, nonce: "ef".into(), proof: "01".into() };
        assert_eq!(
            serde_json::to_string(&challenge).unwrap(),
            r#"{"type":"challenge","version":2,"nonce":"ef","proof":"01"}"#
        );

        // An app from before version 2 sends its token; it reads as a hello
        // with no nonce, and the token is not kept.
        let old = r#"{"type":"hello","version":1,"token":"00ff"}"#;
        let ClientFrame::Hello { version, nonce } = serde_json::from_str(old).unwrap() else { panic!("wrong frame") };
        assert_eq!((version, nonce.as_str()), (1, ""));
    }

    #[test]
    fn the_rules_tools_keep_their_json_shape() {
        assert_eq!(serde_json::to_string(&Request::GetRuleHits).unwrap(), r#"{"method":"get_rule_hits"}"#);
        let test = Request::TestRules { target: "example.com".into(), device: None, port: Some(53), protocol: Some(Protocol::Udp) };
        assert_eq!(
            serde_json::to_string(&test).unwrap(),
            r#"{"method":"test_rules","params":{"target":"example.com","device":null,"port":53,"protocol":"udp"}}"#
        );
        // Everything but the target may be left out.
        let Request::TestRules { target, device, port, protocol } =
            serde_json::from_str(r#"{"method":"test_rules","params":{"target":"1.2.3.4"}}"#).unwrap()
        else {
            panic!("wrong request");
        };
        assert_eq!((target.as_str(), device, port, protocol), ("1.2.3.4", None, None, None));

        let hits = Response::RuleHits(vec![RuleHits { connections: 3, lookups: 1, last_ms: Some(7) }]);
        assert_eq!(
            serde_json::to_string(&hits).unwrap(),
            r#"{"kind":"rule_hits","data":[{"connections":3,"lookups":1,"last_ms":7}]}"#
        );

        // As the GUI's types read it.
        let call = ConnectionOutcome {
            verdict: RuleVerdict::Allow,
            egress: Some("proxy".into()),
            carried_by: Some("direct".into()),
            rule: Some(1),
        };
        let tested = Response::RuleTest(Box::new(RuleTestResult {
            name: Some("telegram.org".into()),
            address: None,
            lookup: Some(LookupOutcome { blocked: false, egress: Some("proxy".into()), rule: Some(1) }),
            connection: call,
            learned_name: None,
            by_learned_name: None,
            port: 443,
            protocol: Protocol::Udp,
        }));
        assert_eq!(
            serde_json::to_string(&tested).unwrap(),
            concat!(
                r#"{"kind":"rule_test","data":{"name":"telegram.org","address":null,"#,
                r#""lookup":{"blocked":false,"egress":"proxy","rule":1},"#,
                r#""connection":{"verdict":"allow","egress":"proxy","carried_by":"direct","rule":1},"#,
                r#""learned_name":null,"by_learned_name":null,"port":443,"protocol":"udp"}}"#
            )
        );
    }

    #[test]
    fn lookups_in_a_batch_keep_their_json_shape() {
        let lookup = DnsQueryLog {
            at_ms: 5,
            client: None,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 137, 2)),
            name: "example.com".into(),
            qtype: "A".into(),
            outcome: "NOERROR".into(),
            answers: vec!["93.184.215.14".into()],
            upstream: None,
            latency_ms: 12,
        };
        let one = serde_json::to_string(&lookup).unwrap();
        let batch = Event::DnsQueries(DnsQueryBatch { entries: vec![lookup], dropped: 3 });
        let text = serde_json::to_string(&batch).unwrap();
        assert_eq!(text, format!(r#"{{"kind":"dns_queries","data":{{"entries":[{one}],"dropped":3}}}}"#));

        let Event::DnsQueries(back) = serde_json::from_str(&text).unwrap() else { panic!("wrong event") };
        assert_eq!((back.entries.len(), back.dropped), (1, 3));
        // `dropped` may be left out.
        let Event::DnsQueries(bare) = serde_json::from_str(r#"{"kind":"dns_queries","data":{"entries":[]}}"#).unwrap()
        else {
            panic!("wrong event");
        };
        assert_eq!(bare, DnsQueryBatch::default());
    }

    #[test]
    fn the_routing_status_keeps_its_json_shape() {
        let active = RoutingStatus {
            state: RoutingState::Active,
            error: None,
            captured_packets: Some(1200),
            dropped_packets: Some(3),
        };
        // As the GUI's types read it.
        assert_eq!(
            serde_json::to_string(&active).unwrap(),
            r#"{"state":"active","error":null,"captured_packets":1200,"dropped_packets":3}"#
        );
        // A status without the drop count still reads.
        let older: RoutingStatus =
            serde_json::from_str(r#"{"state":"active","error":null,"captured_packets":5}"#).unwrap();
        assert_eq!(older.dropped_packets, None);
    }

    #[test]
    fn device_speeds_keep_their_json_shape() {
        let speeds = Event::Traffic(vec![DeviceTraffic {
            mac: "02:00:00:00:00:07".parse().unwrap(),
            rx_bytes: 1500,
            tx_bytes: 300,
            rx_bps: 12_000,
            tx_bps: 2_400,
            active_flows: 2,
        }]);
        let text = serde_json::to_string(&speeds).unwrap();
        // As the GUI's types read it.
        assert_eq!(
            text,
            concat!(
                r#"{"kind":"traffic","data":[{"mac":"02:00:00:00:00:07","rx_bytes":1500,"tx_bytes":300,"#,
                r#""rx_bps":12000,"tx_bps":2400,"active_flows":2}]}"#
            )
        );
        let Event::Traffic(back) = serde_json::from_str(&text).unwrap() else { panic!("wrong event") };
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].rx_bps, 12_000);
    }

    #[test]
    fn list_progress_keeps_its_json_shape() {
        let progress = ListsProgress {
            updating: true,
            done: 3,
            total: 8,
            lists: vec![ListStatus {
                url: "https://lists.example/ads.txt".into(),
                names: 2,
                addresses: 1,
                updated_ms: Some(9),
                error: None,
            }],
        };
        let data = concat!(
            r#"{"updating":true,"done":3,"total":8,"lists":[{"url":"https://lists.example/ads.txt","#,
            r#""names":2,"addresses":1,"updated_ms":9,"error":null}]}"#
        );
        // The answer to GetLists and UpdateLists, and the event, carry the same.
        let answer = serde_json::to_string(&Response::Lists(progress.clone())).unwrap();
        assert_eq!(answer, format!(r#"{{"kind":"lists","data":{data}}}"#));
        let event = serde_json::to_string(&Event::Lists(progress.clone())).unwrap();
        assert_eq!(event, answer);
        let Event::Lists(back) = serde_json::from_str(&event).unwrap() else { panic!("wrong event") };
        assert_eq!(back, progress);
    }

    #[test]
    fn config_survives_the_wire() {
        let config = Config::default();
        let frame = ClientFrame::Request { id: 1, request: Request::SetConfig(Box::new(config.clone())) };
        let text = serde_json::to_string(&frame).unwrap();
        let ClientFrame::Request { request: Request::SetConfig(back), .. } = serde_json::from_str(&text).unwrap() else {
            panic!("wrong frame");
        };
        assert_eq!(*back, config);
    }
}
