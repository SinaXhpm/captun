import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AdbDeviceInfo,
  AppInfo,
  ClientProfile,
  ClientView,
  CommandError,
  Config,
  ConnectionStatus,
  EgressTestResult,
  HotspotSupport,
  LinkSummary,
  InterfaceInfo,
  IpcEvent,
  ListsProgress,
  MacAddr,
  Protocol,
  ReverseTetherMethod,
  RuleHits,
  RuleTestResult,
  ServiceStatus,
  TargetAddr,
  TetherOutcome,
  UpdateInfo,
  UsageReport,
} from "./types";

/** Error thrown by every API call; `message` is the service's text verbatim. */
export class ApiError extends Error {
  readonly code: CommandError["code"];

  constructor(err: CommandError) {
    super(err.message);
    this.name = "ApiError";
    this.code = err.code;
  }
}

function isCommandError(value: unknown): value is CommandError {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { code?: unknown }).code === "string" &&
    typeof (value as { message?: unknown }).message === "string"
  );
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (e) {
    if (isCommandError(e)) throw new ApiError(e);
    throw new ApiError({ code: "internal", message: e instanceof Error ? e.message : String(e) });
  }
}

export function errorMessage(e: unknown): string {
  const message = e instanceof Error ? e.message : String(e);
  // Settings the service could not even read (a typo in a list, say).
  const unreadable = /^invalid args `\w+` for command `\w+`: (.*)$/s.exec(message);
  return unreadable ? `Some settings are not valid: ${unreadable[1]}` : message;
}

export const api = {
  connectionStatus: () => call<ConnectionStatus>("connection_status"),
  startService: () => call<void>("start_service"),
  getStatus: () => call<ServiceStatus>("get_status"),
  startHotspot: () => call<void>("start_hotspot"),
  stopHotspot: () => call<void>("stop_hotspot"),
  hotspotSupport: () => call<HotspotSupport>("hotspot_support"),
  describeLink: (link: string) => call<LinkSummary>("describe_link", { link }),
  appInfo: () => call<AppInfo>("app_info"),
  openLink: (url: string) => call<void>("open_link", { url }),
  checkUpdate: () => call<UpdateInfo>("check_update"),
  startAccessNetwork: () => call<void>("start_access_network"),
  stopAccessNetwork: () => call<void>("stop_access_network"),
  stopService: () => call<void>("stop_service"),
  listClients: () => call<ClientView[]>("list_clients"),
  setClientProfile: (profile: ClientProfile) => call<void>("set_client_profile", { profile }),
  forgetClient: (mac: MacAddr) => call<void>("forget_client", { mac }),
  getConfig: () => call<Config>("get_config"),
  setConfig: (config: Config) => call<void>("set_config", { config }),
  listInterfaces: () => call<InterfaceInfo[]>("list_interfaces"),
  testEgress: (id: string, target?: TargetAddr) =>
    call<EgressTestResult>("test_egress", { id, target: target ?? null }),
  listAdbDevices: () => call<AdbDeviceInfo[]>("list_adb_devices"),
  setReverseTether: (serial: string, enable: boolean, method: ReverseTetherMethod = "system_proxy") =>
    call<TetherOutcome>("set_reverse_tether", { serial, enable, method }),
  /** How each list the rules use stands, and whether an update is under way. */
  getLists: () => call<ListsProgress>("get_lists"),
  /**
   * Starts downloading every list the rules use, through `through` or the default outbound.
   * The service answers at once, as getLists does; "lists" events tell how the update goes.
   */
  updateLists: (through?: string) => call<ListsProgress>("update_lists", { through: through ?? null }),
  /** How often each rule decided since the rules last changed; empty while the service is not running. */
  getRuleHits: () => call<RuleHits[]>("get_rule_hits"),
  /**
   * What the rules do with a website or an address, for `device` or any device (null). With no
   * `port`, the one typed with the website is tested, else 443 (80 for an http:// link).
   */
  testRules: (target: string, device: MacAddr | null, port: number | null, protocol: Protocol) =>
    call<RuleTestResult>("test_rules", { target, device, port, protocol }),
  /** Data use between each two neighbouring `bounds` (ms), by `device` or all, and per device. */
  getUsage: (bounds: number[], device: MacAddr | null) => call<UsageReport>("get_usage", { bounds, device }),
  /** Starts a device's data allowance over now. */
  resetQuota: (mac: MacAddr) => call<void>("reset_quota", { mac }),
  /** Gives a device `mb` more megabytes in this period of its allowance. */
  addQuota: (mac: MacAddr, mb: number) => call<void>("add_quota", { mac, mb }),
};

export function onConnection(handler: (status: ConnectionStatus) => void): Promise<UnlistenFn> {
  return listen<ConnectionStatus>("connection", (e) => handler(e.payload));
}

export function onIpcEvent(handler: (event: IpcEvent) => void): Promise<UnlistenFn> {
  return listen<IpcEvent>("ipc-event", (e) => handler(e.payload));
}
