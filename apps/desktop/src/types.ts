// Mirrors the serde JSON of captun-core (config) and captun-ipc (protocol).
//
// Rules of thumb that keep the service's parser happy:
// - Config structs use `deny_unknown_fields`: never add UI-only keys.
// - Optional scalars (`Option<T>`) may be omitted or null.
// - Lists, `passphrase` and `udp` have serde defaults but reject null:
//   omit them instead (JSON.stringify drops `undefined`).

export type MacAddr = string;
export type EgressId = string;
/** `host:port`, `1.2.3.4:80` or `[::1]:443`. */
export type TargetAddr = string;
/** `example.com`, `full:a.example.com`, `keyword:ads`. */
export type DomainPattern = string;
/** `HH:MM`. */
export type ClockTime = string;
/** `443` or `"8000-8999"`. */
export type PortRange = number | string;
export type IpNet = string;
export type IpAddr = string;

// ---- captun-core config -------------------------------------------------

export type ClientState = "pending" | "approved" | "blocked";
export type WifiBand = "auto" | "2.4ghz" | "5ghz" | "6ghz";

export interface HotspotConfig {
  ssid: string;
  passphrase?: string;
  band: WifiBand;
  interface?: string | null;
  autostart: boolean;
  /** Most devices admitted at once; omitted means only the OS limit applies. */
  max_clients?: number | null;
}

export interface NetworkConfig {
  quarantine_new_clients: boolean;
  /** Devices cannot reach one another. */
  isolate_clients: boolean;
  /** Devices cannot reach this computer (DHCP and DNS still work). */
  block_host: boolean;
  /** Devices cannot reach this computer's home network or router. */
  block_host_lan: boolean;
  kill_switch: boolean;
  /** The speed limit on all devices together; omitted means unlimited. */
  limit?: RateLimit | null;
  /** The data allowance of each device that has none of its own or from its group. */
  device_quota?: Quota | null;
  /** The day weekly allowances start over on. */
  week_starts?: Weekday;
  transparent_routing: boolean;
  default_egress: EgressId;
}

export interface AccessNetworkConfig {
  enabled: boolean;
  interface?: string | null;
  gateway: IpAddr;
  prefix_len: number;
  dhcp_start: IpAddr;
  dhcp_end: IpAddr;
  lease_secs: number;
  nat: boolean;
  autostart: boolean;
}

export interface RateLimit {
  down_kbps?: number | null;
  up_kbps?: number | null;
}

export type QuotaPeriod = "day" | "week" | "month" | "total";

/** A data allowance: download and upload together, per period. */
export interface Quota {
  /** Megabytes of 1,048,576 bytes (1 GB is 1,024 MB). */
  mb: number;
  every: QuotaPeriod;
  /** Once used up: slowed to this speed (kbit/s); omitted means no internet until it starts over. */
  then_kbps?: number | null;
}

/** A device's data allowance as it stands. */
export interface QuotaUse {
  quota: Quota;
  /** Bytes used in this period. */
  used: number;
  /** Bytes allowed in this period, with any extra given. */
  allowed: number;
  over: boolean;
  /** When it starts over (ms); null for one that only a reset starts over. */
  resets_at_ms: number | null;
}

export interface UsageBytes {
  down: number;
  up: number;
}

export interface DeviceUsage extends UsageBytes {
  mac: MacAddr;
}

/** Data use between each two neighbouring times asked about, and per device. */
export interface UsageReport {
  buckets: UsageBytes[];
  devices: DeviceUsage[];
  /** The oldest use kept (ms), if any is. */
  kept_since_ms: number | null;
}

export interface GroupConfig {
  id: string;
  name?: string | null;
  egress?: EgressId | null;
  dns_upstream?: string | null;
  quota?: Quota | null;
  limit?: RateLimit | null;
}

export interface TlsConsent {
  accepted_at_ms: number;
  terms_version: number;
}

export interface ClientProfile {
  mac: MacAddr;
  alias?: string | null;
  state: ClientState;
  group?: string | null;
  egress?: EgressId | null;
  dns_upstream?: string | null;
  quota?: Quota | null;
  limit?: RateLimit | null;
  inspect_tls: boolean;
  tls_consent?: TlsConsent | null;
}

export type BlockResponse = "nx_domain" | "null_ip" | "refused";
export type DnsProtocol = "udp" | "tcp" | "tls" | "https";

export interface DnsUpstreamConfig {
  id: string;
  protocol: DnsProtocol;
  address: string;
  server_name?: string | null;
  path?: string | null;
}

export interface DnsOverride {
  domain: DomainPattern;
  addrs: IpAddr[];
}

export interface DnsConfig {
  enabled: boolean;
  port: number;
  default_upstream: string;
  cache_size: number;
  min_ttl: number;
  max_ttl: number;
  block_response: BlockResponse;
  blocklist?: DomainPattern[];
  enforce: boolean;
  log_queries: boolean;
  upstream: DnsUpstreamConfig[];
  override?: DnsOverride[];
}

export interface TlsInspectionConfig {
  enabled: boolean;
  terms_version: number;
  bypass?: DomainPattern[];
  auto_bypass_pinned: boolean;
  block_quic: boolean;
  max_body_bytes: number;
  retention_hours: number;
}

export interface PortalConfig {
  enabled: boolean;
  password?: string | null;
  show_terms: boolean;
  session_hours: number;
}

export type UdpPolicy = "native" | "block" | { via: EgressId };

export type EgressType = "direct" | "socks5" | "http" | "xray" | "block";

export interface ProxyFields {
  server: TargetAddr;
  username?: string | null;
  password?: string | null;
  via?: EgressId | null;
}

export interface HttpProxyFields extends ProxyFields {
  /** An HTTPS proxy: the connection to the proxy itself is encrypted. */
  tls?: boolean;
}

export type EgressKind =
  | { type: "direct"; interface?: string | null }
  | ({ type: "socks5" } & ProxyFields)
  | ({ type: "http" } & HttpProxyFields)
  | { type: "xray"; link?: string | null; config_file?: string | null }
  | { type: "block" };

export type EgressConfig = {
  id: EgressId;
  name?: string | null;
  udp?: UdpPolicy;
  /** Omitted means on. A turned-off egress stays listed but nothing may use it. */
  enabled?: boolean;
} & EgressKind;

export type Protocol = "tcp" | "udp";
export type Weekday = "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun";
export const WEEKDAYS: Weekday[] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

export interface Schedule {
  days?: Weekday[];
  start: ClockTime;
  end: ClockTime;
}

export type RuleAction = "allow" | "deny" | "reject" | { route: EgressId };

export interface RuleConfig {
  name?: string | null;
  enabled: boolean;
  clients?: MacAddr[];
  groups?: string[];
  domains?: DomainPattern[];
  cidrs?: IpNet[];
  /** Links to online lists of websites and addresses, downloaded only when asked. */
  lists?: string[];
  ports?: PortRange[];
  protocol?: Protocol | null;
  schedule?: Schedule | null;
  action: RuleAction;
}

export interface Config {
  version: number;
  hotspot: HotspotConfig;
  network: NetworkConfig;
  access_network: AccessNetworkConfig;
  dns: DnsConfig;
  tls_inspection: TlsInspectionConfig;
  portal: PortalConfig;
  egress: EgressConfig[];
  group?: GroupConfig[];
  client?: ClientProfile[];
  rule?: RuleConfig[];
}

// ---- captun-ipc protocol ------------------------------------------------

export type HotspotState = "stopped" | "starting" | "running" | "stopping" | "failed";

export interface HotspotStatus {
  state: HotspotState;
  ssid: string | null;
  interface: string | null;
  gateway: IpAddr | null;
  max_clients: number | null;
  error: string | null;
}

export interface Capabilities {
  hotspot: boolean;
  band_selection: boolean;
  per_client_routing: boolean;
  tls_inspection: boolean;
  /** Captun decides whether Wi-Fi devices reach each other (on Windows the Wi-Fi driver does). */
  wifi_isolation: boolean;
  notes: string[];
}

export interface AccessNetworkStatus {
  running: boolean;
  interface: string | null;
  gateway: IpAddr | null;
  leases: number;
  nat: boolean;
  error: string | null;
}

export interface TetherSession {
  serial: string;
  /** The PC-side network adapter of the USB link. */
  interface: string | null;
}

/** Captun only gives internet: the phone uses this PC's, never the reverse. */
export interface TetherStatus {
  /** A phone using this PC's internet. */
  reverse: TetherSession | null;
}

export interface ServiceStatus {
  service_version: string;
  platform: string;
  uptime_secs: number;
  hotspot: HotspotStatus;
  access_network: AccessNetworkStatus;
  clients_online: number;
  dns_running: boolean;
  capabilities: Capabilities;
  tether: TetherStatus;
  xray: XrayStatus;
  routing: RoutingStatus;
  local_access: LocalAccessStatus;
}

export type LocalAccessState = "idle" | "active" | "failed" | "unsupported";

/** Whether the "what devices can reach" settings are in force. */
export interface LocalAccessStatus {
  state: LocalAccessState;
  error: string | null;
}

export type RoutingState = "off" | "waiting" | "active" | "failed" | "unsupported";

/** Whether Captun carries devices' traffic itself, which makes outbounds apply. */
export interface RoutingStatus {
  state: RoutingState;
  error: string | null;
  /** Packets taken from devices so far, where the system can tell. */
  captured_packets: number | null;
  /**
   * Of those, the packets dropped because Captun's routing could not keep
   * up, where the system can tell. Missing from services before it was added.
   */
  dropped_packets?: number | null;
}

export type XrayState = "idle" | "missing" | "starting" | "running" | "failed";

/** The engine (Xray) that runs VPN-link outbounds. */
export interface XrayStatus {
  state: XrayState;
  version: string | null;
  error: string | null;
}

/**
 * A device's traffic when the device list was put together. Its speeds are
 * those of the last `traffic` event, which keeps them current.
 */
export interface TrafficStats {
  /** Bytes the device downloaded through Captun. */
  rx_bytes: number;
  tx_bytes: number;
  /** Download speed, in bits per second. */
  rx_bps: number;
  tx_bps: number;
  active_flows: number;
}

/** One device's traffic, as the service sends it every second while it changes. */
export interface DeviceTraffic {
  mac: MacAddr;
  /** Bytes the device downloaded through Captun. */
  rx_bytes: number;
  tx_bytes: number;
  /** Download speed over the last second, in bits per second. */
  rx_bps: number;
  tx_bps: number;
  active_flows: number;
}

export interface ClientView {
  mac: MacAddr;
  online: boolean;
  addrs: IpAddr[];
  hostname: string | null;
  alias: string | null;
  state: ClientState;
  /** Connected while the hotspot is full: held until a slot frees up. */
  over_limit: boolean;
  /** Its data allowance and how much of it is used, when it has one. */
  quota: QuotaUse | null;
  group: string | null;
  egress: EgressId | null;
  effective_egress: EgressId;
  limit: RateLimit | null;
  inspect_tls: boolean;
  tls_consented: boolean;
  randomized_mac: boolean;
  first_seen_ms: number;
  last_seen_ms: number;
  traffic: TrafficStats;
}

export type InterfaceKind = "ethernet" | "wifi" | "mobile" | "vpn" | "virtual" | "loopback" | "other";

export interface InterfaceInfo {
  index: number;
  name: string;
  description: string | null;
  kind: InterfaceKind;
  /** Backed by hardware rather than software (best effort). */
  physical: boolean;
  mac: MacAddr | null;
  ipv4: string[];
  ipv6: string[];
  up: boolean;
  has_gateway: boolean;
  gateway: IpAddr | null;
  /** Carries this computer's own internet (the OS default route). */
  default_route: boolean;
  speed_mbps: number | null;
  /** Faces devices Captun shares with (the hotspot or a phone's USB link); never a way out. */
  is_hotspot: boolean;
}

export interface EgressTestResult {
  ok: boolean;
  latency_ms: number | null;
  error: string | null;
  /** Whether UDP (calls, games) gets through; null when it could not be told. */
  udp?: boolean | null;
}

/** One online list the rules use, as the service holds it. */
export interface ListStatus {
  url: string;
  /** Websites and address ranges in the copy in use; both 0 until downloaded. */
  names: number;
  addresses: number;
  updated_ms: number | null;
  /** Why the last download failed; the copy from before stays in use. */
  error: string | null;
}

/** The online lists the rules use, and how far an update of them is. */
export interface ListsProgress {
  /** An update is under way: the lists are downloaded one after another, each put in use as it comes. */
  updating: boolean;
  /**
   * How many of the update's `total` lists it is through with, downloaded or
   * not. Once it is over, how it ended (`done` = `total`); both 0 before the first.
   */
  done: number;
  total: number;
  lists: ListStatus[];
}

/** How often one rule decided since the rules last changed. */
export interface RuleHits {
  connections: number;
  lookups: number;
  /** When it last decided either (ms since the epoch); null until it does. */
  last_ms: number | null;
}

/** "allow", or blocked silently ("deny") or refused out loud ("reject"). */
export type RuleVerdict = "allow" | "deny" | "reject";

/** What a device's lookup of a website does. */
export interface LookupOutcome {
  blocked: boolean;
  /** The outbound it is looked up through, unless blocked. */
  egress: EgressId | null;
  /** Index into `rule` of the rule that decided; null for the device's usual way. */
  rule: number | null;
}

/** What a connection does. */
export interface ConnectionOutcome {
  /** What happens to it in the end, its outbound's say included. */
  verdict: RuleVerdict;
  /** The outbound the rules send it to; null when they stop it themselves. */
  egress: EgressId | null;
  /**
   * The outbound that really carries it: `egress`, or the one `egress` sends
   * UDP through. Null when none does (UDP blocked on `egress`), so it is
   * stopped although the rules let it through.
   */
  carried_by: EgressId | null;
  /** Index into `rule` of the rule that decided; null when no rule fits. */
  rule: number | null;
}

/** What the rules do with a website or an address. */
export interface RuleTestResult {
  /** The website tested, when it was a name. */
  name: string | null;
  /** The address tested, when it was one. */
  address: IpAddr | null;
  /** What a lookup of the website does; null for an address. */
  lookup: LookupOutcome | null;
  /** What a connection does, decided with the website or the address. */
  connection: ConnectionOutcome;
  /**
   * For an address: the website this device last looked it up as, or, when
   * testing for any device, the one a device last looked it up as; null if none.
   */
  learned_name: string | null;
  /** What a connection that does not say its name does, going by `learned_name`. */
  by_learned_name: ConnectionOutcome | null;
  /** The port the connection was tested on. */
  port: number;
  /** TCP or UDP, as tested. */
  protocol: Protocol;
}

export type ReverseTetherMethod = "system_proxy" | "helper";

export interface AdbDeviceInfo {
  serial: string;
  label: string;
  /** `device`, `unauthorized`, `offline`, `no_permissions`, … */
  state: string;
  model: string | null;
  ready: boolean;
}

export interface TetherOutcome {
  ok: boolean;
  message: string;
  caution: string | null;
}

export interface DnsQueryLog {
  at_ms: number;
  client: MacAddr | null;
  client_ip: IpAddr;
  name: string;
  qtype: string;
  outcome: string;
  answers: string[];
  upstream: string | null;
  latency_ms: number;
}

/** Lookups the GUI shell hands over together, a few times a second at most. */
export interface DnsQueryBatch {
  /** Oldest first. */
  entries: DnsQueryLog[];
  /**
   * Lookups left out since the previous batch because too many came at once:
   * a count for this batch only, not a running total (the log adds them up).
   */
  dropped: number;
}

/**
 * What the GUI shell (src-tauri) passes on as `ipc-event`: the service's
 * events, except that DNS lookups come in batches and the service's log
 * lines stay out (nothing here shows them).
 */
export type IpcEvent =
  | { kind: "clients"; data: ClientView[] }
  /** Every online device that has had traffic; one missing has had none. */
  | { kind: "traffic"; data: DeviceTraffic[] }
  | { kind: "hotspot"; data: HotspotStatus }
  | { kind: "xray"; data: XrayStatus }
  | { kind: "config_changed" }
  | { kind: "dns_queries"; data: DnsQueryBatch }
  /** How an update of the online lists goes: when it starts, after each list, and when it is over. */
  | { kind: "lists"; data: ListsProgress };

// ---- GUI shell (src-tauri) -----------------------------------------------

/** This copy of Captun and where the project lives. */
export interface AppInfo {
  version: string;
  website: string;
  repository: string;
}

/** What "Check for updates" found on GitHub. */
export interface UpdateInfo {
  current: string;
  /** The newest published release; null when none is published yet. */
  latest: string | null;
  newer: boolean;
  /** The release page to download from. */
  url: string | null;
  notes: string | null;
}

/** What a pasted proxy or VPN link is, read without saving it. */
export interface LinkSummary {
  /** The outbound type it becomes. */
  type: "socks5" | "http" | "xray";
  /** In plain words, e.g. "VLESS" or "HTTPS proxy". */
  protocol: string;
  server: string;
  name?: string;
  transport?: string;
  security?: string;
  username?: string;
  password?: string;
  tls?: boolean;
}

/** Whether this computer can host a Wi-Fi hotspot, asked without the service. */
export interface HotspotSupport {
  supported: boolean;
  /** Why not, when not supported. */
  reason: string | null;
  /** Something Start takes care of first, such as switching Wi-Fi on. */
  notice: string | null;
}

export interface ConnectionStatus {
  connected: boolean;
  service_version: string | null;
  error: string | null;
  token_path: string;
  endpoint: string;
  /** Where the settings are saved (encrypted, next to the app when possible). */
  settings_path: string;
  /** Settings changed while the service was off and not handed over yet. */
  config_pending: boolean;
  /** Why the service refused the saved settings, if it did. */
  config_sync_error: string | null;
  /** Why saved settings could not be opened when Captun started, if so. */
  settings_notice: string | null;
  /**
   * Something about the service to show while not connected: an older service
   * is being or was stopped, or another program answered in its place.
   */
  service_notice: string | null;
}

export type CommandErrorCode =
  | "unauthorized"
  | "bad_request"
  | "invalid_config"
  | "not_found"
  | "unsupported"
  | "hotspot_failed"
  | "internal"
  | "not_connected"
  | "transport"
  | "timeout"
  | "launch_failed";

export interface CommandError {
  code: CommandErrorCode;
  message: string;
}
