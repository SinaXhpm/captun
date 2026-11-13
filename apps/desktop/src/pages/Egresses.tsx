import { useEffect, useRef, useState, type ComponentType } from "react";
import {
  Activity,
  Ban,
  CircleCheck,
  Boxes,
  EthernetPort,
  Globe,
  Lock,
  Network,
  Pencil,
  Plus,
  Server,
  Shield,
  Smartphone,
  Star,
  Trash2,
  Wifi,
  type LucideProps,
} from "lucide-react";
import { api, errorMessage } from "../api";
import {
  EDITOR_TYPE_LABEL,
  type EditorType,
  adapterDetails,
  adapterEgress,
  egressName,
  egressReferences,
  editorType,
  egressSummary,
  enableAdapterEgress,
  isEnabled,
  isUsualAdapter,
  newEgressId,
  sameAdapter,
  sortAdapters,
  udpLabel,
} from "../configUtils";
import { Empty, Field, Pill, Switch, Toggle } from "../components/Form";
import { ConfirmDialog, Modal } from "../components/Modal";
import { useService } from "../service";
import { PLATFORM, useAdapters } from "../system";
import type { Config, EgressConfig, EgressTestResult, InterfaceInfo, InterfaceKind, LinkSummary, UdpPolicy, XrayStatus } from "../types";
import { opt, validateEgressId, validateTarget } from "../validation";

const KIND_ICON: Record<InterfaceKind, ComponentType<LucideProps>> = {
  ethernet: EthernetPort,
  wifi: Wifi,
  mobile: Smartphone,
  vpn: Shield,
  virtual: Boxes,
  loopback: Network,
  other: Network,
};

function egressIcon(e: EgressConfig, adapter: InterfaceInfo | undefined): ComponentType<LucideProps> {
  switch (e.type) {
    case "direct":
      return e.interface ? KIND_ICON[adapter?.kind ?? "other"] : Globe;
    case "socks5":
    case "http":
      return Server;
    case "xray":
      return Lock;
    case "block":
      return Ban;
  }
}

/**
 * How the service's sentence starts when it refuses to run the VPN engine
 * from a folder other programs can change (captun-xray's REFUSED).
 */
const ENGINE_REFUSED = "VPN links are off because";

/** Why VPN links cannot run right now, if they cannot. */
function engineProblem(xray: XrayStatus | undefined): string | null {
  switch (xray?.state) {
    case "missing":
      return "The VPN engine (Xray) is missing from this installation, so VPN links cannot connect. Reinstall Captun.";
    case "failed":
      // A refusal needs a reinstall, not a retry, and already says so.
      if (xray.error?.startsWith(ENGINE_REFUSED)) return xray.error;
      return `The VPN engine stopped: ${xray.error ?? "unknown error"}. Captun keeps retrying.`;
    default:
      return null;
  }
}

/**
 * Mirrors captun-core: the service opens this file with full rights, so on
 * Windows it must be on one of this computer's own drives (C:\…), never a
 * network folder (\\server\share) or a device path (\\?\, \\.\).
 */
function configFileError(path: string): string | null {
  const t = path.trim();
  if (t === "") return null;
  if (PLATFORM === "windows") {
    if (/^[\\/]{2}/.test(t)) return "Use a file on this computer's own drive, not a network folder.";
    if (!/^[A-Za-z]:[\\/]/.test(t)) return "Use the full path, starting with the drive letter (for example C:\\VPN\\outbound.json).";
  } else if (!t.startsWith("/")) {
    return "Use the full path, starting with /.";
  }
  return null;
}

type TestState = EgressTestResult | "running";

/** What the editor opens on: an outbound, a new one, or a new one for an adapter. */
type EditTarget = { egress: EgressConfig | null; adapter?: string };

/**
 * Outbounds: the ways devices' traffic can leave this computer. Every network
 * adapter is listed, off until turned on; proxies and VPN links are added by
 * hand. Only outbounds that are on can be picked for devices, groups and rules.
 */
export function Egresses() {
  const { connected, config, status, saveConfig } = useService();
  const { adapters } = useAdapters();
  const [showAll, setShowAll] = useState(false);
  const [editing, setEditing] = useState<EditTarget | null>(null);
  const [deleting, setDeleting] = useState<EgressConfig | null>(null);
  const [inUse, setInUse] = useState<{ egress: EgressConfig; action: "turn off" | "delete" } | null>(null);
  const [tests, setTests] = useState<Record<string, TestState>>({});

  if (!config) return <Empty>Loading…</Empty>;

  const adapterFor = (e: EgressConfig) =>
    e.type === "direct" && e.interface ? adapters?.find((a) => sameAdapter(a.name, e.interface)) : undefined;
  // The adapter cable sharing hands out addresses on faces devices, not the internet.
  const sharedOn = config.access_network.enabled ? config.access_network.interface : null;
  const detected = sortAdapters(
    (adapters ?? []).filter(
      (a) => a.kind !== "loopback" && !a.is_hotspot && !adapterEgress(config, a.name) && !sameAdapter(a.name, sharedOn),
    ),
  );
  const usual = detected.filter(isUsualAdapter);
  const hidden = detected.length - usual.length;
  const listed = showAll ? detected : usual;

  const test = async (id: string) => {
    setTests((t) => ({ ...t, [id]: "running" }));
    let result: EgressTestResult;
    try {
      result = await api.testEgress(id);
    } catch (e) {
      result = { ok: false, latency_ms: null, error: errorMessage(e) };
    }
    setTests((t) => ({ ...t, [id]: result }));
  };

  const setOn = (e: EgressConfig, on: boolean) => {
    if (!on && egressReferences(config, e.id).length > 0) {
      setInUse({ egress: e, action: "turn off" });
      return;
    }
    void saveConfig(
      (c) => {
        const target = c.egress.find((x) => x.id === e.id);
        if (!target) return;
        if (on) delete target.enabled;
        else target.enabled = false;
      },
      on ? `${egressName(e)} is on` : `${egressName(e)} is off`,
    );
  };

  const hasVpnLinks = config.egress.some((e) => e.type === "xray");
  const engine = hasVpnLinks ? engineProblem(status?.xray) : null;

  const turnOnAdapter = (a: InterfaceInfo) => void saveConfig((c) => void enableAdapterEgress(c, a.name), `${a.name} is on`);

  return (
    <div className="page">
      <div className="toolbar">
        <p className="muted">Where your devices' internet goes out. Turn on the adapters or proxies you want to use.</p>
        <button className="button button-primary" onClick={() => setEditing({ egress: null })}>
          <Plus size={14} aria-hidden="true" /> Add
        </button>
      </div>
      {engine && (
        <div className="inline-alert inline-alert-warn" role="alert">
          {engine}
        </div>
      )}

      <ul className="outbound-list">
        {config.egress.map((e) => {
          const adapter = adapterFor(e);
          const Icon = egressIcon(e, adapter);
          const on = isEnabled(e);
          const t = tests[e.id];
          const isDefault = config.network.default_egress === e.id;
          const details =
            e.type === "xray"
              ? `${egressSummary(e)}${status?.xray.state === "starting" && on ? " · connecting…" : ""}`
              : e.type !== "direct"
                ? `${EDITOR_TYPE_LABEL[editorType(e)]} · ${egressSummary(e)}`
              : !e.interface
                ? "Follows this computer's own internet"
                : adapter
                  ? adapterDetails(adapter)
                  : "Adapter not plugged in";
          return (
            <li key={e.id} className={on ? "outbound" : "outbound outbound-off"}>
              <Switch checked={on} label={on ? `Turn ${egressName(e)} off` : `Turn ${egressName(e)} on`} onChange={(v) => setOn(e, v)} />
              <Icon size={16} className="outbound-icon" aria-hidden="true" />
              <div className="outbound-body">
                <div className="cell-main">
                  {egressName(e)}
                  {isDefault && <span className="tag tag-accent">default</span>}
                </div>
                <div className="cell-sub" title={adapter?.description ?? undefined}>
                  {details}
                  {e.udp !== undefined && e.udp !== "native" && ` · UDP ${udpLabel(e.udp)}`}
                </div>
                {t && t !== "running" && !t.ok && <div className="field-error">{t.error}</div>}
                {t && t !== "running" && t.ok && t.udp === false && e.udp !== "block" && (
                  <div className="field-warn">
                    No UDP: calls and games won't work through it, but web pages still open.
                    {e.type === "socks5" && udpMode(e.udp) === "native" && " Turn on UDP in the proxy to fix that."}
                  </div>
                )}
              </div>
              {t === "running" ? (
                <span className="muted">testing…</span>
              ) : t?.ok ? (
                <Pill tone="ok">{t.latency_ms != null ? `${t.latency_ms} ms` : "works"}</Pill>
              ) : t ? (
                <Pill tone="danger">failed</Pill>
              ) : null}
              <div className="row-actions">
                <button
                  className="icon-button"
                  aria-label={`Test ${egressName(e)}`}
                  title={connected ? "Test" : "Start the service to test"}
                  disabled={t === "running" || !connected}
                  onClick={() => void test(e.id)}
                >
                  <Activity size={14} />
                </button>
                {!isDefault && on ? (
                  <button
                    className="icon-button"
                    aria-label={`Make ${egressName(e)} the default`}
                    title="Make default"
                    onClick={() => void saveConfig((c) => (c.network.default_egress = e.id), `${egressName(e)} is now the default`)}
                  >
                    <Star size={14} />
                  </button>
                ) : (
                  // Its place kept, so every row's buttons line up.
                  <span className="icon-button-spacer" aria-hidden="true" />
                )}
                <button className="icon-button" aria-label={`Edit ${egressName(e)}`} title="Edit" onClick={() => setEditing({ egress: e })}>
                  <Pencil size={14} />
                </button>
                <button
                  className="icon-button"
                  aria-label={`Delete ${egressName(e)}`}
                  title="Delete"
                  onClick={() => (egressReferences(config, e.id).length > 0 ? setInUse({ egress: e, action: "delete" }) : setDeleting(e))}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </li>
          );
        })}

        {listed.map((a) => {
          const Icon = KIND_ICON[a.kind];
          return (
            <li key={`adapter-${a.index}`} className="outbound outbound-off">
              <Switch checked={false} label={`Turn ${a.name} on`} onChange={() => turnOnAdapter(a)} />
              <Icon size={16} className="outbound-icon" aria-hidden="true" />
              <div className="outbound-body">
                <div className="cell-main">{a.name}</div>
                <div className="cell-sub" title={a.description ?? undefined}>
                  {adapterDetails(a)}
                </div>
              </div>
              <div className="row-actions">
                <button className="icon-button" aria-label={`Set up ${a.name}`} title="Edit before turning on" onClick={() => setEditing({ egress: null, adapter: a.name })}>
                  <Pencil size={14} />
                </button>
              </div>
            </li>
          );
        })}
      </ul>
      {hidden > 0 && (
        <button className="link-button" onClick={() => setShowAll((s) => !s)}>
          {showAll ? "Hide virtual adapters" : `Show ${hidden} virtual adapter${hidden === 1 ? "" : "s"}`}
        </button>
      )}

      {editing && (
        <EgressEditor
          initial={editing.egress}
          adapterName={editing.adapter}
          config={config}
          adapters={adapters}
          onClose={() => setEditing(null)}
        />
      )}

      {inUse && (
        <Modal
          title={`Cannot ${inUse.action} ${egressName(inUse.egress)}`}
          onClose={() => setInUse(null)}
          footer={
            <button className="button" onClick={() => setInUse(null)}>
              Close
            </button>
          }
        >
          <p>This outbound is still in use. Point these at another outbound first:</p>
          <ul className="notes">
            {egressReferences(config, inUse.egress.id).map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        </Modal>
      )}

      {deleting && (
        <ConfirmDialog
          title="Delete outbound"
          confirmLabel="Delete"
          danger
          onCancel={() => setDeleting(null)}
          onConfirm={() => {
            const id = deleting.id;
            setDeleting(null);
            void saveConfig((c) => (c.egress = c.egress.filter((e) => e.id !== id)), "Outbound deleted");
          }}
        >
          Delete <strong>{egressName(deleting)}</strong>?
          {deleting.type === "direct" && deleting.interface ? " The adapter stays listed, turned off." : " Nothing uses it."}
        </ConfirmDialog>
      )}
    </div>
  );
}

type UdpMode = "native" | "block" | "via";

function udpMode(policy: UdpPolicy | undefined): UdpMode {
  if (policy === undefined || policy === "native") return "native";
  return policy === "block" ? "block" : "via";
}

interface EditorProps {
  initial: EgressConfig | null;
  /** Opens a new outbound on this adapter. */
  adapterName?: string;
  config: Config;
  adapters: InterfaceInfo[] | null;
  onClose: () => void;
}

function EgressEditor({ initial, adapterName, config, adapters, onClose }: EditorProps) {
  const { saveConfig, status } = useService();
  const proxy = initial && (initial.type === "socks5" || initial.type === "http") ? initial : null;
  const [name, setName] = useState(initial?.name ?? adapterName ?? "");
  const [type, setType] = useState<EditorType>(initial ? editorType(initial) : adapterName ? "direct" : "direct");
  const [iface, setIface] = useState(initial?.type === "direct" ? (initial.interface ?? "") : (adapterName ?? ""));
  const [server, setServer] = useState(proxy?.server ?? "");
  const [username, setUsername] = useState(proxy?.username ?? "");
  const [password, setPassword] = useState(proxy?.password ?? "");
  const [via, setVia] = useState(proxy?.via ?? "");
  const [link, setLink] = useState(initial?.type === "xray" ? (initial.link ?? "") : "");
  const [linkInfo, setLinkInfo] = useState<LinkSummary | null>(null);
  const [linkError, setLinkError] = useState<string | null>(null);
  const [configFile, setConfigFile] = useState(initial?.type === "xray" ? (initial.config_file ?? "") : "");
  // An outbound that uses a config file opens with Advanced shown, so a
  // problem with the file is in sight. Fixed at opening: the user may close it.
  const [advancedOpen] = useState(configFile !== "");
  const [udp, setUdp] = useState<UdpMode>(udpMode(initial?.udp));
  const [udpVia, setUdpVia] = useState(typeof initial?.udp === "object" ? initial.udp.via : "");
  const [enabled, setEnabled] = useState(initial ? isEnabled(initial) : true);
  const [id, setId] = useState("");
  const [showVirtual, setShowVirtual] = useState(false);
  const [saving, setSaving] = useState(false);
  // The link whose details were last copied into the form, so it happens once.
  const applied = useRef(link.trim());
  // A name that came from a link, which the next link may replace.
  const linkName = useRef<string | null>(null);

  const isHttp = type === "http" || type === "https";
  const isProxy = type === "socks5" || isHttp;
  // New outbounds can start from a pasted link; VPN links are their link.
  const showLink = !initial || type === "xray";

  // HTTP(S) proxies cannot carry UDP; never leave them on "native".
  useEffect(() => {
    if (isHttp && udp === "native") setUdp("block");
  }, [isHttp, udp]);

  // Read the link as it is typed or pasted, and fill the form from it.
  useEffect(() => {
    const text = link.trim();
    if (text === "") {
      setLinkInfo(null);
      setLinkError(null);
      return;
    }
    let current = true;
    const timer = window.setTimeout(() => {
      api.describeLink(text).then(
        (info) => {
          if (!current) return;
          setLinkInfo(info);
          setLinkError(null);
          if (applied.current === text) return;
          applied.current = text;
          if (info.name && (name.trim() === "" || name === linkName.current)) {
            setName(info.name);
            linkName.current = info.name;
          }
          if (info.type === "xray") {
            setType("xray");
            if (udp === "block" && !initial) setUdp("native");
          } else {
            setType(info.type === "socks5" ? "socks5" : info.tls ? "https" : "http");
            setServer(info.server);
            setUsername(info.username ?? "");
            setPassword(info.password ?? "");
          }
        },
        (e: unknown) => {
          if (!current) return;
          setLinkInfo(null);
          setLinkError(errorMessage(e));
        },
      );
    }, 250);
    return () => {
      current = false;
      window.clearTimeout(timer);
    };
    // Only the link drives this; the other fields are read at the moment it parses.
  }, [link]);

  const others = config.egress.filter((e) => e.id !== initial?.id && isEnabled(e));
  const udpTargets = others.filter((e) => e.type !== "http");
  // A new outbound gets an ID made from its name unless one is typed.
  const autoId = newEgressId(config, opt(name) ?? (type === "direct" ? iface || "system" : type));
  const finalId = initial?.id ?? (opt(id) ?? autoId);
  const refs = initial && !enabled ? egressReferences(config, initial.id) : [];
  const vpnLink = type === "xray" && linkInfo?.type === "xray" ? linkInfo : null;

  const errors: Record<string, string | null> = {
    id: initial ? null : (validateEgressId(finalId) ?? (config.egress.some((e) => e.id === finalId) ? "This ID is already used." : null)),
    server: isProxy ? validateTarget(server) : null,
    password: isProxy && password !== "" && username.trim() === "" ? "A password needs a username." : null,
    link:
      type === "xray"
        ? link.trim() !== "" && configFile.trim() !== ""
          ? "Use either the link or a config file, not both."
          : link.trim() === "" && configFile.trim() === ""
            ? "Paste the link from your provider."
            : linkError
        : linkError, // a pasted link that cannot be read must be fixed or cleared first
    configFile: type === "xray" ? configFileError(configFile) : null,
    udp: udp === "via" && udpVia === "" ? "Pick the outbound that carries UDP." : null,
    enabled: refs.length > 0 ? `Still used by ${refs.join(", ")}.` : null,
  };
  const invalid = Object.values(errors).some((e) => e !== null);

  const build = (): EgressConfig => {
    const policy: UdpPolicy | undefined = udp === "native" ? undefined : udp === "block" ? "block" : { via: udpVia };
    const common = { id: finalId, name: opt(name), udp: policy, enabled: enabled ? undefined : false };
    const credentials = { server: server.trim(), username: opt(username), password: password === "" ? undefined : password, via: opt(via) };
    switch (type) {
      case "direct":
        return { ...common, type, interface: opt(iface) };
      case "socks5":
        return { ...common, type, ...credentials };
      case "http":
        return { ...common, type, ...credentials };
      case "https":
        return { ...common, type: "http", ...credentials, tls: true };
      case "xray":
        return { ...common, type, link: opt(link), config_file: opt(configFile) };
      case "block":
        return { ...common, type };
    }
  };

  const save = async () => {
    setSaving(true);
    const egress = build();
    const ok = await saveConfig((c) => {
      const index = c.egress.findIndex((e) => e.id === egress.id);
      if (index >= 0) c.egress[index] = egress;
      else c.egress.push(egress);
    }, initial ? "Outbound updated" : "Outbound added");
    setSaving(false);
    if (ok) onClose();
  };

  const shared = config.access_network.enabled ? config.access_network.interface : null;
  const choices = sortAdapters((adapters ?? []).filter((a) => a.kind !== "loopback" && !a.is_hotspot && !sameAdapter(a.name, shared)));
  const visibleChoices = choices.filter((a) => showVirtual || isUsualAdapter(a) || sameAdapter(a.name, iface));
  const hiddenCount = choices.length - choices.filter(isUsualAdapter).length;
  const missing = iface !== "" && adapters !== null && !choices.some((a) => sameAdapter(a.name, iface));
  const engine = type === "xray" ? engineProblem(status?.xray) : null;

  return (
    <Modal
      title={initial ? `Edit ${egressName(initial)}` : "Add outbound"}
      onClose={onClose}
      wide
      footer={
        <>
          <button className="button" onClick={onClose}>
            Cancel
          </button>
          <button className="button button-primary" disabled={invalid || saving} onClick={() => void save()}>
            Save
          </button>
        </>
      }
    >
      <div className="form-grid">
        {showLink && (
          <Field
            label={type === "xray" ? "VPN link" : "Paste a link (optional)"}
            error={errors.link}
            wide
            hint={
              type === "xray"
                ? "The vless://, vmess://, trojan://, ss:// or hysteria2:// link from your provider."
                : "A socks5://, http://, https:// or VPN link (vless://, vmess://, trojan://, ss://, hysteria2://) fills in everything below."
            }
          >
            <input
              value={link}
              onChange={(e) => setLink(e.target.value)}
              placeholder="vless://… or socks5://…"
              spellCheck={false}
              autoComplete="off"
              data-autofocus={initial ? undefined : true}
            />
          </Field>
        )}
        {showLink && linkInfo && (
          <p className="link-info field-wide">
            <CircleCheck size={14} aria-hidden="true" />
            <span>
              <strong>{linkInfo.protocol}</strong> · {linkInfo.server}
              {linkInfo.transport && ` · ${linkInfo.transport}`}
              {linkInfo.security && ` + ${linkInfo.security}`}
              {linkInfo.name && <span className="muted"> · “{linkInfo.name}”</span>}
            </span>
          </p>
        )}

        <Field label="Type">
          <select value={type} onChange={(e) => setType(e.target.value as EditorType)}>
            {(Object.keys(EDITOR_TYPE_LABEL) as EditorType[]).map((t) => (
              <option key={t} value={t}>
                {EDITOR_TYPE_LABEL[t]}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder={type === "direct" ? iface || "System default" : "e.g. Office VPN"} />
        </Field>

        {type === "direct" && (
          <fieldset className="field field-wide">
            <legend className="field-label">Network adapter</legend>
            <div className="adapter-list" role="radiogroup" aria-label="Network adapter">
              <label className={iface === "" ? "adapter adapter-selected" : "adapter"}>
                <input type="radio" name="adapter" checked={iface === ""} onChange={() => setIface("")} />
                <Globe size={16} aria-hidden="true" />
                <span className="adapter-text">
                  <span className="cell-main">System default</span>
                  <span className="cell-sub">Follows this computer's own internet, whichever adapter that is.</span>
                </span>
              </label>
              {missing && (
                <label className="adapter adapter-selected">
                  <input type="radio" name="adapter" checked onChange={() => undefined} />
                  <Network size={16} aria-hidden="true" />
                  <span className="adapter-text">
                    <span className="cell-main">{iface}</span>
                    <span className="cell-sub">Not plugged in right now.</span>
                  </span>
                </label>
              )}
              {adapters === null && <span className="muted">Looking for adapters…</span>}
              {visibleChoices.map((a) => {
                const Icon = KIND_ICON[a.kind];
                const selected = sameAdapter(a.name, iface);
                return (
                  <label key={a.index} className={selected ? "adapter adapter-selected" : "adapter"}>
                    <input type="radio" name="adapter" checked={selected} onChange={() => setIface(a.name)} />
                    <Icon size={16} aria-hidden="true" />
                    <span className="adapter-text">
                      <span className="cell-main">
                        {a.name}
                        {a.default_route && <span className="tag tag-accent">this computer's internet</span>}
                      </span>
                      <span className="cell-sub">{adapterDetails(a)}</span>
                      {selected && (
                        <span className="cell-sub adapter-facts">
                          {[a.description, a.mac && `MAC ${a.mac}`, a.gateway && `gateway ${a.gateway}`, a.ipv6.length > 0 && `IPv6 ${a.ipv6.length}`]
                            .filter(Boolean)
                            .join(" · ")}
                        </span>
                      )}
                    </span>
                  </label>
                );
              })}
            </div>
            {hiddenCount > 0 && (
              <button type="button" className="link-button" onClick={() => setShowVirtual((s) => !s)}>
                {showVirtual ? "Hide virtual adapters" : `Show ${hiddenCount} virtual adapter${hiddenCount === 1 ? "" : "s"}`}
              </button>
            )}
          </fieldset>
        )}

        {isProxy && (
          <>
            <Field label="Server" error={errors.server} hint={type === "https" ? "The proxy's certificate is checked." : undefined}>
              <input
                value={server}
                onChange={(e) => setServer(e.target.value)}
                placeholder={type === "https" ? "proxy.example.com:443" : type === "http" ? "127.0.0.1:8080" : "127.0.0.1:1080"}
                spellCheck={false}
              />
            </Field>
            <Field label="Reach the proxy through" hint="Chain this proxy behind another outbound.">
              <select value={via} onChange={(e) => setVia(e.target.value)}>
                <option value="">Directly</option>
                {others.map((e) => (
                  <option key={e.id} value={e.id}>
                    {egressName(e)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Username">
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" spellCheck={false} />
            </Field>
            <Field label="Password" error={errors.password}>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
            </Field>
          </>
        )}

        {type === "xray" && engine && (
          <div className="inline-alert inline-alert-warn field-wide" role="alert">
            {engine}
          </div>
        )}
        {vpnLink && status?.xray.state === "running" && (
          <p className="muted small field-wide">Runs on the built-in VPN engine (Xray {status.xray.version ?? ""}).</p>
        )}

        {type !== "block" && (
          <>
            <Field label="Games and calls (UDP)" error={errors.udp} hint={isHttp ? "HTTP proxies cannot carry UDP." : undefined}>
              <select value={udp} onChange={(e) => setUdp(e.target.value as UdpMode)}>
                <option value="native" disabled={isHttp}>
                  Through this outbound
                </option>
                <option value="block">Block</option>
                <option value="via">Through another outbound</option>
              </select>
            </Field>
            {udp === "via" ? (
              <Field label="UDP outbound">
                <select value={udpVia} onChange={(e) => setUdpVia(e.target.value)}>
                  <option value="">Choose…</option>
                  {udpTargets.map((e) => (
                    <option key={e.id} value={e.id}>
                      {egressName(e)}
                    </option>
                  ))}
                </select>
              </Field>
            ) : (
              <div />
            )}
          </>
        )}

        <div className="field field-wide">
          <Toggle label="Turned on" description="Only outbounds that are on can be picked for devices, groups and rules." checked={enabled} onChange={setEnabled} />
          {errors.enabled && <span className="field-error">{errors.enabled}</span>}
        </div>

        <details className="field field-wide advanced" open={advancedOpen}>
          <summary>Advanced</summary>
          <div className="form-grid">
            <Field label="ID" error={errors.id} hint={initial ? "IDs cannot change because other settings refer to them." : "Used in rules and logs; made from the name if left empty."}>
              <input value={initial?.id ?? id} placeholder={initial ? undefined : autoId} onChange={(e) => setId(e.target.value)} disabled={!!initial} spellCheck={false} />
            </Field>
            {type === "xray" && (
              <Field
                label="Xray config file (instead of a link)"
                error={errors.configFile}
                hint="Full path to an Xray JSON outbound on this computer's own drive, not a network folder."
              >
                <input value={configFile} onChange={(e) => setConfigFile(e.target.value)} spellCheck={false} />
              </Field>
            )}
          </div>
        </details>
      </div>
    </Modal>
  );
}
