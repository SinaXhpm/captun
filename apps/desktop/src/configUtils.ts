import type { ClientProfile, ClientView, Config, EgressConfig, EgressType, InterfaceInfo, InterfaceKind, RuleAction, UdpPolicy } from "./types";

// The config calls a way out to the internet an "egress"; the GUI says
// "outbound", a client is a "device" and the access network "cable sharing".

export const EGRESS_TYPE_LABEL: Record<EgressType, string> = {
  direct: "Network adapter",
  socks5: "SOCKS5 proxy",
  http: "HTTP proxy",
  xray: "VPN link (V2Ray)",
  block: "Block (no internet)",
};

/** The editor's choices: an HTTPS proxy is an HTTP proxy reached over TLS. */
export type EditorType = EgressType | "https";

export const EDITOR_TYPE_LABEL: Record<EditorType, string> = {
  direct: "Network adapter",
  socks5: "SOCKS5 proxy",
  http: "HTTP proxy",
  https: "HTTPS proxy",
  xray: "VPN link (V2Ray)",
  block: "Block (no internet)",
};

export function editorType(e: EgressConfig): EditorType {
  return e.type === "http" && e.tls ? "https" : e.type;
}

const VPN_PROTOCOL: Record<string, string> = {
  vless: "VLESS",
  vmess: "VMess",
  trojan: "Trojan",
  ss: "Shadowsocks",
  hysteria2: "Hysteria2",
  hy2: "Hysteria2",
};

/** "VLESS · host:443" from a share link, best effort and without secrets. */
export function vpnLinkBrief(link: string): string {
  const text = link.trim();
  const cut = text.indexOf("://");
  const scheme = cut >= 0 ? text.slice(0, cut) : "";
  const rest = cut >= 0 ? text.slice(cut + 3) : "";
  const protocol = VPN_PROTOCOL[scheme.toLowerCase()] ?? "VPN link";
  let server = "";
  try {
    if (scheme.toLowerCase() === "vmess") {
      const json = JSON.parse(atob(rest.split("#")[0] ?? "")) as { add?: string; port?: string | number };
      if (json.add) server = `${json.add}:${json.port ?? ""}`;
    } else {
      const body = (rest.split("#")[0] ?? "").split("?")[0] ?? "";
      const at = body.lastIndexOf("@");
      if (at >= 0) server = body.slice(at + 1).replace(/\/+$/, "");
    }
  } catch {
    // An unreadable link still gets its protocol name.
  }
  return server ? `${protocol} · ${server}` : protocol;
}

/** Human-readable places that point at an egress, for safe deletion or turning off. */
export function egressReferences(config: Config, id: string): string[] {
  const refs: string[] = [];
  if (config.network.default_egress === id) refs.push("Settings → default outbound");
  for (const g of config.group ?? []) {
    if (g.egress === id) refs.push(`Group "${g.name ?? g.id}"`);
  }
  for (const c of config.client ?? []) {
    if (c.egress === id) refs.push(`Device ${c.alias ?? c.mac}`);
  }
  (config.rule ?? []).forEach((r, i) => {
    if (typeof r.action === "object" && r.action.route === id) refs.push(`Rule ${i + 1}${r.name ? ` (${r.name})` : ""}`);
  });
  for (const e of config.egress) {
    if (e.id === id) continue;
    if ((e.type === "socks5" || e.type === "http") && e.via === id) refs.push(`Outbound "${egressName(e)}" (reaches its proxy through it)`);
    if (typeof e.udp === "object" && e.udp.via === id) refs.push(`Outbound "${egressName(e)}" (sends UDP through it)`);
  }
  return refs;
}

export function upstreamReferences(config: Config, id: string): string[] {
  const refs: string[] = [];
  if (config.dns.default_upstream === id) refs.push("DNS → default DNS server");
  for (const g of config.group ?? []) {
    if (g.dns_upstream === id) refs.push(`Group "${g.name ?? g.id}"`);
  }
  for (const c of config.client ?? []) {
    if (c.dns_upstream === id) refs.push(`Device ${c.alias ?? c.mac}`);
  }
  return refs;
}

export function groupReferences(config: Config, id: string): string[] {
  const refs: string[] = [];
  for (const c of config.client ?? []) {
    if (c.group === id) refs.push(`Device ${c.alias ?? c.mac}`);
  }
  (config.rule ?? []).forEach((r, i) => {
    if (r.groups?.includes(id)) refs.push(`Rule ${i + 1}${r.name ? ` (${r.name})` : ""}`);
  });
  return refs;
}

export function egressName(e: EgressConfig): string {
  return e.name ?? e.id;
}

export function egressLabel(config: Config | null, id: string | null | undefined): string {
  if (!id) return "—";
  const e = config?.egress.find((x) => x.id === id);
  return e ? egressName(e) : id;
}

export function isEnabled(e: EgressConfig): boolean {
  return e.enabled !== false;
}

/** Outbounds that devices, groups and rules may pick. */
export function usableEgresses(config: Config): EgressConfig[] {
  return config.egress.filter(isEnabled);
}

export function egressSummary(e: EgressConfig): string {
  switch (e.type) {
    case "direct":
      return e.interface ? `through adapter ${e.interface}` : "follows this computer's own internet";
    case "socks5":
    case "http":
      return `${e.server}${e.username ? ` as ${e.username}` : ""}${e.via ? ` through ${e.via}` : ""}`;
    case "xray":
      if (e.config_file) return `config file ${e.config_file}`;
      return e.link ? vpnLinkBrief(e.link) : "no link yet";
    case "block":
      return "no internet";
  }
}

// ---- Devices --------------------------------------------------------------

export function deviceName(c: ClientView): string {
  return c.alias ?? c.hostname ?? "Unknown device";
}

/** The address others reach a device at: its IPv4 one, which every app takes. */
export function deviceAddress(c: ClientView): string | undefined {
  return c.addrs.find((a) => !a.includes(":")) ?? c.addrs[0];
}

/** The stored profile, or one rebuilt from the live view for new devices. */
export function profileFor(config: Config, c: ClientView): ClientProfile {
  const stored = config.client?.find((p) => p.mac === c.mac);
  if (stored) return structuredClone(stored);
  return {
    mac: c.mac,
    alias: c.alias ?? undefined,
    state: c.state,
    group: c.group ?? undefined,
    egress: c.egress ?? undefined,
    limit: c.limit ?? undefined,
    inspect_tls: c.inspect_tls,
  };
}

export function udpLabel(policy: UdpPolicy | undefined): string {
  if (policy === undefined || policy === "native") return "through it";
  if (policy === "block") return "blocked";
  return `through ${policy.via}`;
}

/** A rule's action in a word or two, as its row shows it. */
export function actionLabel(action: RuleAction, config: Config | null): string {
  if (typeof action === "object") return `Via ${egressLabel(config, action.route)}`;
  return { allow: "Allow", deny: "Block", reject: "Refuse" }[action];
}

// ---- Network adapters ----------------------------------------------------

export const KIND_LABEL: Record<InterfaceKind, string> = {
  ethernet: "Ethernet",
  wifi: "Wi-Fi",
  mobile: "Phone / mobile",
  vpn: "VPN",
  virtual: "Virtual",
  loopback: "Loopback",
  other: "Network",
};

const KIND_ORDER: InterfaceKind[] = ["ethernet", "wifi", "mobile", "vpn", "other", "virtual", "loopback"];

/** Adapters worth offering by default; virtual ones hide behind "show all". */
export function isUsualAdapter(i: InterfaceInfo): boolean {
  return !i.is_hotspot && i.kind !== "virtual" && i.kind !== "loopback";
}

/** This computer's internet first, then connected ones, then by kind and name. */
export function sortAdapters(list: InterfaceInfo[]): InterfaceInfo[] {
  return [...list].sort(
    (a, b) =>
      Number(b.default_route) - Number(a.default_route) ||
      Number(b.up) - Number(a.up) ||
      KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) ||
      a.name.localeCompare(b.name),
  );
}

export function formatSpeed(mbps: number | null): string | null {
  if (mbps == null) return null;
  return mbps >= 1000 ? `${Number((mbps / 1000).toFixed(1))} Gbps` : `${mbps} Mbps`;
}

export function adapterStatus(i: InterfaceInfo): string {
  if (!i.up) return "not connected";
  return i.has_gateway || i.default_route ? "has internet" : "connected";
}

/** One line of what an adapter is and how it is doing. */
export function adapterDetails(i: InterfaceInfo): string {
  return [KIND_LABEL[i.kind], i.ipv4[0], i.up ? formatSpeed(i.speed_mbps) : null, adapterStatus(i)]
    .filter((part): part is string => !!part)
    .join(" · ");
}

export function sameAdapter(a: string | null | undefined, b: string | null | undefined): boolean {
  return !!a && !!b && a.toLowerCase() === b.toLowerCase();
}

/** The outbound pinned to this adapter, if one exists. */
export function adapterEgress(config: Config, adapter: string): EgressConfig | undefined {
  return config.egress.find((e) => e.type === "direct" && sameAdapter(e.interface, adapter));
}

/** An unused ID made from a name: lowercase letters, digits, '-' and '_'. */
export function newEgressId(config: Config, name: string): string {
  const base =
    name
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 28) || "outbound";
  const taken = new Set(config.egress.map((e) => e.id));
  if (!taken.has(base)) return base;
  for (let n = 2; ; n++) {
    const id = `${base}-${n}`;
    if (!taken.has(id)) return id;
  }
}

/**
 * Turns the outbound for an adapter on, creating it if needed, inside a
 * `saveConfig` mutation. Returns its ID.
 */
export function enableAdapterEgress(draft: Config, adapter: string): string {
  const existing = adapterEgress(draft, adapter);
  if (existing) {
    delete existing.enabled;
    return existing.id;
  }
  const id = newEgressId(draft, adapter);
  draft.egress.push({ id, name: adapter, type: "direct", interface: adapter });
  return id;
}
