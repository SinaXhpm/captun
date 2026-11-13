import { useState, type ReactNode } from "react";
import { Cable, CircleAlert, CircleCheck, Info, Pencil, Plus, ShieldAlert, Trash2 } from "lucide-react";
import { adapterDetails, egressLabel, egressName, groupReferences, sameAdapter, sortAdapters, usableEgresses } from "../configUtils";
import { api, errorMessage } from "../api";
import { AddressChip } from "../components/AddressChip";
import { QuotaFields, describeQuota, formToQuota, quotaToForm } from "../components/QuotaFields";
import { Card, Empty, Field, Pill, SubTabs, Toggle } from "../components/Form";
import { ConfirmDialog, Modal } from "../components/Modal";
import { useToast } from "../components/Toast";
import { formatDuration, formatKbps } from "../format";
import { useServiceCore, useServiceStatus } from "../service";
import { ADMIN_PROMPT, PLATFORM, restartServiceAndWait, useAdapters } from "../system";
import type {
  AccessNetworkConfig,
  Config,
  GroupConfig,
  NetworkConfig,
  PortalConfig,
  ServiceStatus,
  TlsInspectionConfig,
  Weekday,
} from "../types";
import { lines, opt, optList, optNumber } from "../validation";

type Section = "general" | "access" | "cable" | "groups" | "https" | "signin" | "about";

const SECTIONS: { id: Section; label: string }[] = [
  { id: "general", label: "General" },
  { id: "access", label: "Local access" },
  { id: "cable", label: "Cable sharing" },
  { id: "groups", label: "Groups" },
  { id: "https", label: "HTTPS" },
  { id: "signin", label: "Sign-in page" },
  { id: "about", label: "About" },
];

// The last section opened, kept while the app runs.
let lastSection: Section = "general";

/** Makes Settings open at `section` next time, for links from other pages. */
export function openSettingsAt(section: Section) {
  lastSection = section;
}

export function Settings() {
  const { config } = useServiceCore();
  const [section, setSection] = useState<Section>(lastSection);
  if (!config) return <Empty>Loading…</Empty>;

  const open = (id: Section) => {
    lastSection = id;
    setSection(id);
  };

  return (
    <div className="page">
      <SubTabs label="Settings sections" tabs={SECTIONS} value={section} onChange={open} />
      {section === "general" && <NetworkSection key={JSON.stringify(config.network)} config={config} />}
      {section === "general" && <SpeedLimitSection key={JSON.stringify(config.network.limit ?? null)} config={config} />}
      {section === "general" && (
        <AllowanceSection key={JSON.stringify([config.network.device_quota ?? null, config.network.week_starts ?? "mon"])} config={config} />
      )}
      {section === "access" && <LocalAccessSection key={JSON.stringify(config.network)} config={config} />}
      {section === "cable" && <AccessNetworkSection key={JSON.stringify(config.access_network)} config={config} />}
      {section === "groups" && <GroupsSection config={config} />}
      {section === "https" && <TlsSection key={JSON.stringify(config.tls_inspection)} current={config.tls_inspection} />}
      {section === "signin" && <PortalSection key={JSON.stringify(config.portal)} current={config.portal} />}
      {section === "about" && <AboutSection />}
    </div>
  );
}

/** Service facts and what this platform can do; needs the running service. */
/** Restarts the service so a newer copy of Captun takes over. */
function RestartButton() {
  const { refreshStatus } = useServiceCore();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  return (
    <button
      className="button"
      disabled={busy}
      title="Stops the service and starts it again"
      onClick={async () => {
        setBusy(true);
        try {
          await restartServiceAndWait();
          toast.success("The Captun service restarted");
        } catch (e) {
          toast.error("Could not restart the service", errorMessage(e));
        } finally {
          setBusy(false);
          await refreshStatus();
        }
      }}
    >
      {busy ? `Restarting… ${ADMIN_PROMPT.during}` : "Restart service"}
    </button>
  );
}

/** Where the settings live, said plainly: they are kept next to the app. */
function SettingsFile() {
  const { connection } = useServiceCore();
  if (!connection) return null;
  return (
    <>
      <dt>Settings</dt>
      <dd>
        <span className="facts-path">{connection.settings_path}</span>
        <span className="field-hint">Encrypted: only your account on this computer can open it.</span>
      </dd>
    </>
  );
}

function AboutSection() {
  const status = useServiceStatus();
  if (!status) {
    return (
      <Card title="About">
        <p className="muted">Captun shares this computer's internet over Wi-Fi or USB. Details about this system appear here once sharing has started.</p>
        <dl className="facts">
          <SettingsFile />
        </dl>
      </Card>
    );
  }
  const { capabilities } = status;
  return (
    <Card title="About" actions={<RestartButton />}>
      <dl className="facts">
        <dt>Service</dt>
        <dd>
          v{status.service_version} on {status.platform}
        </dd>
        <dt>Uptime</dt>
        <dd>{formatDuration(status.uptime_secs)}</dd>
        <SettingsFile />
      </dl>
      <div className="chips">
        <Pill tone={capabilities.hotspot ? "ok" : "muted"}>Hotspot</Pill>
        <Pill tone={capabilities.band_selection ? "ok" : "muted"}>Wi-Fi band choice</Pill>
        <Pill tone={capabilities.per_client_routing ? "ok" : "muted"}>Per-device routing</Pill>
        <Pill tone={capabilities.tls_inspection ? "ok" : "muted"}>HTTPS inspection</Pill>
      </div>
      {capabilities.notes.length > 0 && (
        <ul className="notes">
          {capabilities.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function SaveButton({ dirty, disabled, onSave }: { dirty: boolean; disabled?: boolean; onSave: () => Promise<unknown> }) {
  const [saving, setSaving] = useState(false);
  return (
    <button
      className="button button-primary"
      disabled={!dirty || disabled || saving}
      onClick={async () => {
        setSaving(true);
        await onSave();
        setSaving(false);
      }}
    >
      Save
    </button>
  );
}

/** The switches this section owns; the default outbound is set on Home and
 *  what devices can reach under Local access. */
const NETWORK_SWITCHES = ["quarantine_new_clients", "kill_switch", "transparent_routing"] as const;

function NetworkSection({ config }: { config: Config }) {
  const { saveConfig } = useServiceCore();
  const [net, setNet] = useState<NetworkConfig>(config.network);
  const set = <K extends keyof NetworkConfig>(key: K, value: NetworkConfig[K]) => setNet((n) => ({ ...n, [key]: value }));
  const dirty = NETWORK_SWITCHES.some((key) => net[key] !== config.network[key]);
  // Only this section's switches are written, so a change made elsewhere
  // meanwhile (such as the default outbound on Home) is never undone.
  const save = () =>
    saveConfig((c) => {
      for (const key of NETWORK_SWITCHES) c.network[key] = net[key];
    }, "Settings saved");

  return (
    <Card title="Devices and safety" actions={<SaveButton dirty={dirty} onSave={save} />}>
      <div className="toggle-list">
        <Toggle
          label="Ask before new devices get internet"
          description="New devices wait on the Devices page until you allow them."
          checked={net.quarantine_new_clients}
          onChange={(v) => set("quarantine_new_clients", v)}
        />
        <Toggle
          label="Cut the internet if an outbound stops working"
          description="Rather than sending traffic out another way."
          checked={net.kill_switch}
          onChange={(v) => set("kill_switch", v)}
        />
        <Toggle
          label="Route devices through Captun (experimental)"
          description="Needed for per-device outbounds, speed limits and live stats."
          checked={net.transparent_routing}
          onChange={(v) => set("transparent_routing", v)}
        />
      </div>
    </Card>
  );
}

/**
 * The speed limit on all devices together, shared by all of them; a device's
 * own limit is set where the device is edited, on the Devices page.
 */
function SpeedLimitSection({ config }: { config: Config }) {
  const { saveConfig } = useServiceCore();
  const saved = config.network.limit ?? null;
  const [down, setDown] = useState(saved?.down_kbps?.toString() ?? "");
  const [up, setUp] = useState(saved?.up_kbps?.toString() ?? "");
  const error = [down, up].some((v) => v.trim() !== "" && !(Number(v) > 0 && Number.isInteger(Number(v))))
    ? "Limits must be whole numbers above 0 (leave empty for unlimited)."
    : undefined;
  const downKbps = optNumber(down);
  const upKbps = optNumber(up);
  const dirty = downKbps !== (saved?.down_kbps ?? undefined) || upKbps !== (saved?.up_kbps ?? undefined);
  // Only the limit is written, so other settings changed meanwhile stay.
  const save = () =>
    saveConfig((c) => {
      if (downKbps === undefined && upKbps === undefined) delete c.network.limit;
      else c.network.limit = { down_kbps: downKbps, up_kbps: upKbps };
    }, downKbps === undefined && upKbps === undefined ? "Speed limit removed" : "Speed limit saved");

  return (
    <Card title="Speed limit for all devices" actions={<SaveButton dirty={dirty} disabled={!!error} onSave={save} />}>
      <p className="muted card-intro">
        Shared by every device together. A device can also have a limit of its own: edit it on the Devices page.
      </p>
      <div className="form-grid">
        <Field label="Download (kbit/s)" error={error} hint={formatKbps(downKbps)}>
          <input inputMode="numeric" value={down} onChange={(e) => setDown(e.target.value)} placeholder="Unlimited" />
        </Field>
        <Field label="Upload (kbit/s)" hint={formatKbps(upKbps)}>
          <input inputMode="numeric" value={up} onChange={(e) => setUp(e.target.value)} placeholder="Unlimited" />
        </Field>
      </div>
      {!config.network.transparent_routing && (
        <p className="muted small">Speed limits work while devices are routed through Captun (the switch above).</p>
      )}
    </Card>
  );
}

const WEEKDAY_NAME: Record<Weekday, string> = {
  mon: "Monday",
  tue: "Tuesday",
  wed: "Wednesday",
  thu: "Thursday",
  fri: "Friday",
  sat: "Saturday",
  sun: "Sunday",
};

/**
 * The data allowance every device gets unless it has its own or its group's,
 * and the day weekly allowances start over on. Each device counts its own use.
 */
function AllowanceSection({ config }: { config: Config }) {
  const { saveConfig } = useServiceCore();
  const savedWeek = config.network.week_starts ?? "mon";
  const [form, setForm] = useState(() => quotaToForm(config.network.device_quota));
  const [week, setWeek] = useState<Weekday>(savedWeek);
  const quota = formToQuota(form);
  const dirty = JSON.stringify(quota.quota ?? null) !== JSON.stringify(config.network.device_quota ?? null) || week !== savedWeek;
  // Only these two are written, so other settings changed meanwhile stay.
  const save = () =>
    saveConfig((c) => {
      if (quota.quota) c.network.device_quota = quota.quota;
      else delete c.network.device_quota;
      c.network.week_starts = week;
    }, quota.quota ? `Each device now gets ${describeQuota(quota.quota)}` : "Devices have no data allowance now");

  return (
    <Card title="Data allowance for each device" actions={<SaveButton dirty={dirty} disabled={!!quota.error} onSave={save} />}>
      <p className="muted card-intro">
        How much each device may use, counted for each device on its own. A device or a group can have an allowance of its own: edit
        it on the Devices page or under Groups. Its use is on the Usage page.
      </p>
      <div className="form-grid">
        <QuotaFields form={form} onChange={setForm} error={quota.error} />
        <Field label="Weeks start on" hint="For allowances that start over each week.">
          <select value={week} onChange={(e) => setWeek(e.target.value as Weekday)}>
            {(Object.keys(WEEKDAY_NAME) as Weekday[]).map((d) => (
              <option key={d} value={d}>
                {WEEKDAY_NAME[d]}
              </option>
            ))}
          </select>
        </Field>
      </div>
      {!config.network.transparent_routing && (
        <p className="muted small">Data allowances work while devices are routed through Captun (Devices and safety, above).</p>
      )}
    </Card>
  );
}

/** The switches Local access owns, stored the "keep out" way round. */
const REACH_SWITCHES = ["block_host", "isolate_clients", "block_host_lan"] as const;
type ReachSwitch = (typeof REACH_SWITCHES)[number];

/** This computer's address on the hotspot while it runs; Windows' hotspot always has the same one. */
function hotspotAddress(status: ServiceStatus | null): { address: string; live: boolean } | null {
  const gateway = status?.hotspot.state === "running" ? status.hotspot.gateway : null;
  if (gateway) return { address: gateway, live: true };
  return PLATFORM === "windows" ? { address: "192.168.137.1", live: false } : null;
}

/**
 * What devices can reach besides the internet: this computer, each other and
 * the home network, said the allowing way round ("can reach"), with a plain
 * guide to using the hotspot as a local network.
 */
function LocalAccessSection({ config }: { config: Config }) {
  const { saveConfig } = useServiceCore();
  const status = useServiceStatus();
  const [net, setNet] = useState<NetworkConfig>(config.network);
  const dirty = REACH_SWITCHES.some((key) => net[key] !== config.network[key]);
  const allow = (key: ReachSwitch, on: boolean) => setNet((n) => ({ ...n, [key]: !on }));
  const save = () =>
    saveConfig((c) => {
      for (const key of REACH_SWITCHES) c.network[key] = net[key];
    }, "Settings saved");
  // Whether Captun, rather than the Wi-Fi driver, decides if devices see each other.
  const wifiIsolation = status ? status.capabilities.wifi_isolation : PLATFORM === "linux";
  const here = hotspotAddress(status);
  const addr = here?.address ?? "this computer's address";

  return (
    <>
      <Card title="What devices can reach" actions={<SaveButton dirty={dirty} onSave={save} />}>
        <p className="muted card-intro">Devices always get the internet. Choose what else they can reach.</p>
        <div className="toggle-list">
          <Toggle
            label="This computer"
            checked={!net.block_host}
            onChange={(v) => allow("block_host", v)}
            description={
              <>
                Open what runs here from a device: shared folders, a local website, a game server.
                {PLATFORM === "windows" && " Windows Firewall lets devices on your hotspot in while this is on."}
              </>
            }
          />
          {wifiIsolation ? (
            <Toggle
              label="Each other"
              checked={!net.isolate_clients}
              onChange={(v) => allow("isolate_clients", v)}
              description="Devices talk to one another directly: local games, sending files, casting. The hotspot restarts to apply this."
            />
          ) : (
            <div className="toggle toggle-static">
              <Info size={15} className="toggle-icon" aria-hidden="true" />
              <span className="toggle-text">
                <span className="toggle-label">Each other</span>
                <span className="toggle-description">
                  {PLATFORM === "windows"
                    ? "On Windows your Wi-Fi adapter decides this, not Captun. To check, open one device's address from another."
                    : "This system's hotspot decides this, not Captun."}
                </span>
              </span>
            </div>
          )}
          <Toggle
            label="Your home network"
            checked={!net.block_host_lan}
            onChange={(v) => allow("block_host_lan", v)}
            description="Your router's page and the other devices at home: printers, TVs, storage."
          />
        </div>
        {dirty ? <p className="reach-state">Save to apply your changes.</p> : <ReachState status={status} />}
      </Card>

      <Card title="How to connect">
        <ol className="guide">
          <li>
            <strong>Addresses.</strong> This computer is {here ? <AddressChip address={here.address} /> : "shown here"} on your hotspot
            {here && !here.live && " (while it is on)"}. Each device's address is next to it on the Devices page.
          </li>
          <Step needs={net.block_host ? "This computer" : null}>
            <strong>A website or app running here:</strong> on the device, open <span className="mono">http://{addr}:port</span>, with the
            port the program uses.
          </Step>
          <Step needs={net.block_host ? "This computer" : null}>
            <strong>Shared folders here:</strong> from another computer, open <span className="mono">\\{addr}</span> (Windows) or{" "}
            <span className="mono">smb://{addr}</span> (Mac).
          </Step>
          <Step needs={net.isolate_clients && wifiIsolation ? "Each other" : null}>
            <strong>Between devices:</strong> apps made for a local network work as on home Wi-Fi, such as LocalSend for files, local
            games and casting. Use the address shown on the Devices page.
          </Step>
          <li>
            <strong>Still no luck?</strong>{" "}
            {PLATFORM === "windows" && "A program can carry its own block in Windows Firewall; allow it in Windows Security. "}A device that
            joins again usually gets its address back.
          </li>
        </ol>
      </Card>
    </>
  );
}

/** One step of the guide, greyed out until the switch it needs is on. */
function Step({ needs, children }: { needs: string | null; children: ReactNode }) {
  return (
    <li className={needs ? "guide-off" : undefined}>
      {children}
      {needs && <span className="guide-needs"> Turn on “{needs}” first.</span>}
    </li>
  );
}

/** Whether the settings above are in force right now, said plainly. */
function ReachState({ status }: { status: ServiceStatus | null }) {
  const local = status?.local_access;
  if (!local || local.state === "idle") {
    return <p className="reach-state">These apply while you share.</p>;
  }
  if (local.state === "unsupported") {
    return (
      <p className="reach-state reach-state-warn">
        <CircleAlert size={13} aria-hidden="true" /> This system cannot hold devices back yet; the choices are saved for later.
      </p>
    );
  }
  if (local.state === "failed") {
    return (
      <p className="reach-state reach-state-warn" role="alert">
        <CircleAlert size={13} aria-hidden="true" /> Not in force: {local.error ?? "unknown error"}
      </p>
    );
  }
  return (
    <p className={local.error ? "reach-state reach-state-warn" : "reach-state reach-state-ok"}>
      {local.error ? <CircleAlert size={13} aria-hidden="true" /> : <CircleCheck size={13} aria-hidden="true" />}
      {local.error ? ` In force, except: ${local.error}` : " In force now."}
    </p>
  );
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function AccessNetworkSection({ config }: { config: Config }) {
  const { connected, saveConfig, refreshStatus } = useServiceCore();
  const status = useServiceStatus();
  const toast = useToast();
  const current = config.access_network;
  const [enabled, setEnabled] = useState(current.enabled);
  const [iface, setIface] = useState(current.interface ?? "");
  const [nat, setNat] = useState(current.nat);
  const [autostart, setAutostart] = useState(current.autostart);
  const [gateway, setGateway] = useState(current.gateway);
  const [prefix, setPrefix] = useState(String(current.prefix_len));
  const [dhcpStart, setDhcpStart] = useState(current.dhcp_start);
  const [dhcpEnd, setDhcpEnd] = useState(current.dhcp_end);
  const [lease, setLease] = useState(String(current.lease_secs));
  const { adapters } = useAdapters();
  const [busy, setBusy] = useState(false);

  // Never offer the adapter this computer's own internet comes in on.
  const candidates = sortAdapters(
    (adapters ?? []).filter((a) => !a.is_hotspot && !a.default_route && a.kind !== "loopback" && a.kind !== "virtual"),
  );
  const prefixNum = optNumber(prefix);
  const leaseNum = optNumber(lease);
  const error = !isIpv4(gateway)
    ? "This computer's address must be a valid IPv4 address."
    : !isIpv4(dhcpStart) || !isIpv4(dhcpEnd)
      ? "The addresses to give out must be valid IPv4 addresses."
      : prefixNum === undefined || !Number.isInteger(prefixNum) || prefixNum < 8 || prefixNum > 30
        ? "The subnet prefix must be a whole number between 8 and 30."
        : leaseNum === undefined || !Number.isInteger(leaseNum) || leaseNum < 60
          ? "The lease time must be at least 60 seconds."
          : null;

  const next: AccessNetworkConfig = {
    ...current,
    enabled,
    interface: iface === "" ? null : iface,
    nat,
    autostart,
    gateway,
    prefix_len: prefixNum ?? current.prefix_len,
    dhcp_start: dhcpStart,
    dhcp_end: dhcpEnd,
    lease_secs: leaseNum ?? current.lease_secs,
  };
  // Field by field: an unset adapter is missing from the stored config but null here.
  const keys = Object.keys({ ...current, ...next }) as (keyof AccessNetworkConfig)[];
  const dirty = keys.some((key) => (next[key] ?? null) !== (current[key] ?? null));
  const an = status?.access_network;

  const run = async (action: () => Promise<void>, failure: string) => {
    setBusy(true);
    try {
      await action();
      await refreshStatus();
    } catch (e) {
      toast.error(failure, errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title={
        <span className="title-with-icon">
          <Cable size={16} aria-hidden="true" /> Cable sharing
        </span>
      }
      actions={
        <>
          {an?.running ? (
            <button className="button" disabled={busy} onClick={() => void run(api.stopAccessNetwork, "Could not stop cable sharing")}>
              Stop
            </button>
          ) : (
            <button
              className="button"
              disabled={busy || dirty || !connected || !current.enabled || !current.interface}
              title={dirty ? "Save your changes first" : connected ? undefined : "Start sharing from Home first"}
              onClick={() => void run(api.startAccessNetwork, "Could not start cable sharing")}
            >
              Start
            </button>
          )}
          <SaveButton dirty={dirty} disabled={!!error} onSave={() => saveConfig((c) => (c.access_network = next), "Cable sharing settings saved")} />
        </>
      }
    >
      <p className="muted">Share the internet with devices plugged into an Ethernet or USB adapter; they show up on the Devices page.</p>
      <div className="toggle-list">
        <Toggle label="Turn on cable sharing" checked={enabled} onChange={setEnabled} />
        <Toggle
          label="Share the internet directly (NAT)"
          description="Simple sharing. Turn off to send cable devices through Captun's routing instead (experimental)."
          checked={nat}
          onChange={setNat}
        />
        <Toggle label="Start it with the service" checked={autostart} onChange={setAutostart} />
      </div>
      {error && <div className="inline-alert inline-alert-danger">{error}</div>}
      <div className="form-grid">
        <Field label="Network adapter">
          <select value={iface} onChange={(e) => setIface(e.target.value)}>
            <option value="">Choose an adapter…</option>
            {iface !== "" && !candidates.some((a) => sameAdapter(a.name, iface)) && <option value={iface}>{iface} (not found)</option>}
            {candidates.map((a) => (
              <option key={a.index} value={a.name}>
                {a.name} — {adapterDetails(a)}
              </option>
            ))}
          </select>
        </Field>
      </div>
      {/* Addresses have working defaults; most people never open this. */}
      <details className="advanced">
        <summary>
          Addresses: devices get {current.dhcp_start}–{current.dhcp_end}, this computer is {current.gateway}
        </summary>
        <div className="form-grid">
          <Field label="This computer's address" hint="Must not be in your home network's range.">
            <input value={gateway} onChange={(e) => setGateway(e.target.value)} spellCheck={false} />
          </Field>
          <Field label="Subnet prefix">
            <input inputMode="numeric" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
          </Field>
          <Field label="First address to give out">
            <input value={dhcpStart} onChange={(e) => setDhcpStart(e.target.value)} spellCheck={false} />
          </Field>
          <Field label="Last address to give out">
            <input value={dhcpEnd} onChange={(e) => setDhcpEnd(e.target.value)} spellCheck={false} />
          </Field>
          <Field label="Lease time (seconds)">
            <input inputMode="numeric" value={lease} onChange={(e) => setLease(e.target.value)} />
          </Field>
        </div>
      </details>
      {an?.running && (
        <p className="muted small">
          On · {an.interface ?? "?"} · {an.leases} device{an.leases === 1 ? "" : "s"}
          {an.nat ? " · shared directly" : ""}
        </p>
      )}
      {an?.error && <div className="inline-alert inline-alert-danger">{an.error}</div>}
    </Card>
  );
}

function TlsSection({ current }: { current: TlsInspectionConfig }) {
  const { saveConfig } = useServiceCore();
  const [confirming, setConfirming] = useState(false);
  const [termsVersion, setTermsVersion] = useState(String(current.terms_version));
  const [bypass, setBypass] = useState((current.bypass ?? []).join("\n"));
  const [autoBypass, setAutoBypass] = useState(current.auto_bypass_pinned);
  const [blockQuic, setBlockQuic] = useState(current.block_quic);
  const [maxBodyKb, setMaxBodyKb] = useState(String(Math.round(current.max_body_bytes / 1024)));
  const [retention, setRetention] = useState(String(current.retention_hours));

  const terms = optNumber(termsVersion);
  const body = optNumber(maxBodyKb);
  const hours = optNumber(retention);
  const error =
    terms === undefined || terms < 1 || !Number.isInteger(terms)
      ? "Terms version must be a whole number of at least 1."
      : body === undefined || body < 0 || !Number.isInteger(body)
        ? "Body limit must be a whole number of KiB."
        : hours === undefined || hours < 0 || !Number.isInteger(hours)
          ? "Retention must be a whole number of hours."
          : null;

  const next: TlsInspectionConfig = {
    ...current,
    terms_version: terms ?? current.terms_version,
    bypass: optList(lines(bypass)),
    auto_bypass_pinned: autoBypass,
    block_quic: blockQuic,
    max_body_bytes: (body ?? 0) * 1024,
    retention_hours: hours ?? current.retention_hours,
  };
  const dirty = JSON.stringify(next) !== JSON.stringify({ ...current, bypass: optList(current.bypass ?? []) });

  const setEnabled = (enabled: boolean) =>
    saveConfig((c) => (c.tls_inspection.enabled = enabled), enabled ? "HTTPS inspection turned on" : "HTTPS inspection turned off");

  return (
    <Card
      title={
        <span className="title-with-icon">
          <ShieldAlert size={16} aria-hidden="true" /> HTTPS inspection
        </span>
      }
      actions={<SaveButton dirty={dirty} disabled={!!error} onSave={() => saveConfig((c) => (c.tls_inspection = { ...next, enabled: c.tls_inspection.enabled }), "HTTPS inspection settings saved")} />}
    >
      <Toggle
        label="Allow HTTPS inspection"
        description="Main switch. A device is inspected only if you also allow it on the Devices page and its user accepts the terms and installs the Captun certificate."
        checked={current.enabled}
        onChange={(v) => (v ? setConfirming(true) : void setEnabled(false))}
      />
      {error && <div className="inline-alert inline-alert-danger">{error}</div>}
      <div className="form-grid">
        <Field label="Terms version" hint="Raise it after changing the terms; earlier consents stop counting.">
          <input inputMode="numeric" value={termsVersion} onChange={(e) => setTermsVersion(e.target.value)} />
        </Field>
        <Field label="Most content kept per request (KiB)">
          <input inputMode="numeric" value={maxBodyKb} onChange={(e) => setMaxBodyKb(e.target.value)} />
        </Field>
        <Field label="Keep what was captured for (hours)">
          <input inputMode="numeric" value={retention} onChange={(e) => setRetention(e.target.value)} />
        </Field>
        <Field label="Never inspect these websites (one per line)" wide hint="e.g. bank.com, full:accounts.google.com, keyword:pay">
          <textarea rows={4} value={bypass} onChange={(e) => setBypass(e.target.value)} spellCheck={false} />
        </Field>
      </div>
      <div className="toggle-list">
        <Toggle
          label="Skip apps that refuse inspection"
          description="Stop inspecting a website after its app keeps rejecting the connection (certificate pinning)."
          checked={autoBypass}
          onChange={setAutoBypass}
        />
        <Toggle
          label="Block QUIC for inspected devices"
          description="Browsers then fall back to a connection type that can be inspected."
          checked={blockQuic}
          onChange={setBlockQuic}
        />
      </div>

      {confirming && (
        <ConfirmDialog
          title="Turn on HTTPS inspection?"
          confirmLabel="Turn on inspection"
          danger
          acknowledge="I understand and will only inspect devices whose users have given informed consent."
          onCancel={() => setConfirming(false)}
          onConfirm={() => {
            setConfirming(false);
            void setEnabled(true);
          }}
        >
          <p>
            HTTPS inspection decrypts the secure web traffic of devices on your hotspot, including passwords, messages and
            other private data.
          </p>
          <ul className="notes">
            <li>
              Intercepting other people's communications without their consent is illegal in many countries. Use it only
              on your own devices or with the informed consent of each device's user.
            </li>
            <li>
              Each device must still be allowed one by one, and its user must accept the terms on the sign-in page and
              install the Captun certificate before anything is inspected.
            </li>
            <li>Banking and certificate-pinned apps stop working while inspected unless they are bypassed.</li>
            <li>Captured content is stored encrypted on this computer and deleted after the retention period.</li>
          </ul>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function PortalSection({ current }: { current: PortalConfig }) {
  const { saveConfig } = useServiceCore();
  const [enabled, setEnabled] = useState(current.enabled);
  const [showTerms, setShowTerms] = useState(current.show_terms);
  const [password, setPassword] = useState(current.password ?? "");
  const [hours, setHours] = useState(String(current.session_hours));

  const sessionHours = optNumber(hours);
  const error = sessionHours === undefined || sessionHours < 1 || !Number.isInteger(sessionHours) ? "Session length must be at least 1 hour." : null;
  const next: PortalConfig = {
    enabled,
    show_terms: showTerms,
    password: password === "" ? undefined : password,
    session_hours: sessionHours ?? current.session_hours,
  };
  const dirty =
    enabled !== current.enabled ||
    showTerms !== current.show_terms ||
    password !== (current.password ?? "") ||
    next.session_hours !== current.session_hours;

  return (
    <Card title="Sign-in page" actions={<SaveButton dirty={dirty} disabled={!!error} onSave={() => saveConfig((c) => (c.portal = next), "Sign-in page settings saved")} />}>
      <div className="toggle-list">
        <Toggle
          label="Show a sign-in page to new devices"
          description="Devices see it before they get internet access."
          checked={enabled}
          onChange={setEnabled}
        />
        <Toggle label="Require accepting the usage terms" checked={showTerms} disabled={!enabled} onChange={setShowTerms} />
      </div>
      {error && <div className="inline-alert inline-alert-danger">{error}</div>}
      <div className="form-grid">
        <Field label="Sign-in password" hint="Leave empty for no password.">
          <input type="password" value={password} disabled={!enabled} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
        </Field>
        <Field label="Session length (hours)">
          <input inputMode="numeric" value={hours} disabled={!enabled} onChange={(e) => setHours(e.target.value)} />
        </Field>
      </div>
    </Card>
  );
}

function GroupsSection({ config }: { config: Config }) {
  const { saveConfig } = useServiceCore();
  const [editing, setEditing] = useState<GroupConfig | "new" | null>(null);
  const [deleting, setDeleting] = useState<GroupConfig | null>(null);
  const groups = config.group ?? [];
  const refs = deleting ? groupReferences(config, deleting.id) : [];

  return (
    <Card
      title="Device groups"
      actions={
        <button className="button" onClick={() => setEditing("new")}>
          <Plus size={14} aria-hidden="true" /> Add group
        </button>
      }
    >
      {groups.length === 0 ? (
        <p className="muted">A group gives several devices the same outbound, DNS server, speed limit and data allowance.</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Group</th>
              <th>Outbound</th>
              <th>DNS server</th>
              <th>Speed limit down / up</th>
              <th>Data allowance</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr key={g.id}>
                <td>
                  <div className="cell-main">{g.name ?? g.id}</div>
                  <div className="cell-sub mono">{g.id}</div>
                </td>
                <td>{g.egress ? egressLabel(config, g.egress) : "default"}</td>
                <td>{g.dns_upstream ?? "default"}</td>
                <td>
                  {formatKbps(g.limit?.down_kbps)} / {formatKbps(g.limit?.up_kbps)}
                </td>
                <td>{g.quota ? describeQuota(g.quota) : "—"}</td>
                <td className="row-actions">
                  <button className="icon-button" aria-label={`Edit group ${g.id}`} onClick={() => setEditing(g)}>
                    <Pencil size={14} />
                  </button>
                  <button className="icon-button" aria-label={`Delete group ${g.id}`} onClick={() => setDeleting(g)}>
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {editing && <GroupEditor initial={editing === "new" ? null : editing} config={config} onClose={() => setEditing(null)} />}
      {deleting &&
        (refs.length > 0 ? (
          <Modal
            title={`Cannot delete group ${deleting.name ?? deleting.id}`}
            onClose={() => setDeleting(null)}
            footer={
              <button className="button" onClick={() => setDeleting(null)}>
                Close
              </button>
            }
          >
            <p>The group is still in use by:</p>
            <ul className="notes">
              {refs.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </Modal>
        ) : (
          <ConfirmDialog
            title="Delete group"
            confirmLabel="Delete"
            danger
            onCancel={() => setDeleting(null)}
            onConfirm={() => {
              const id = deleting.id;
              setDeleting(null);
              void saveConfig((c) => (c.group = optList((c.group ?? []).filter((g) => g.id !== id))), "Group deleted");
            }}
          >
            Delete group <strong>{deleting.name ?? deleting.id}</strong>?
          </ConfirmDialog>
        ))}
    </Card>
  );
}

function GroupEditor({ initial, config, onClose }: { initial: GroupConfig | null; config: Config; onClose: () => void }) {
  const { saveConfig } = useServiceCore();
  const [id, setId] = useState(initial?.id ?? "");
  const [name, setName] = useState(initial?.name ?? "");
  const [egress, setEgress] = useState(initial?.egress ?? "");
  const [dns, setDns] = useState(initial?.dns_upstream ?? "");
  const [down, setDown] = useState(initial?.limit?.down_kbps?.toString() ?? "");
  const [up, setUp] = useState(initial?.limit?.up_kbps?.toString() ?? "");
  const [quotaForm, setQuotaForm] = useState(() => quotaToForm(initial?.quota));
  const quota = formToQuota(quotaForm);

  const idError = initial
    ? null
    : id.trim() === ""
      ? "ID is required."
      : (config.group ?? []).some((g) => g.id === id.trim())
        ? "This ID is already used."
        : null;
  const limitError = [down, up].some((v) => v.trim() !== "" && !(Number(v) > 0 && Number.isInteger(Number(v))))
    ? "Limits must be whole numbers above 0."
    : null;
  const choices = usableEgresses(config);
  const egressOff = egress !== "" && !choices.some((e) => e.id === egress);

  const save = async () => {
    const downKbps = optNumber(down);
    const upKbps = optNumber(up);
    const group: GroupConfig = {
      id: initial?.id ?? id.trim(),
      name: opt(name),
      egress: opt(egress),
      dns_upstream: opt(dns),
      quota: quota.quota,
      limit: downKbps !== undefined || upKbps !== undefined ? { down_kbps: downKbps, up_kbps: upKbps } : undefined,
    };
    const ok = await saveConfig((c) => {
      const list = c.group ?? [];
      const index = list.findIndex((g) => g.id === group.id);
      if (index >= 0) list[index] = group;
      else list.push(group);
      c.group = list;
    }, initial ? "Group updated" : "Group added");
    if (ok) onClose();
  };

  return (
    <Modal
      title={initial ? `Edit group ${initial.name ?? initial.id}` : "Add group"}
      onClose={onClose}
      footer={
        <>
          <button className="button" onClick={onClose}>
            Cancel
          </button>
          <button className="button button-primary" disabled={!!idError || !!limitError || egressOff || !!quota.error} onClick={() => void save()}>
            Save
          </button>
        </>
      }
    >
      <div className="form-grid">
        <Field label="ID" error={idError}>
          <input value={initial?.id ?? id} disabled={!!initial} onChange={(e) => setId(e.target.value)} spellCheck={false} />
        </Field>
        <Field label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Outbound" error={egressOff ? "This outbound is turned off; pick another or turn it on under Outbound." : null}>
          <select value={egress} onChange={(e) => setEgress(e.target.value)}>
            <option value="">Default ({egressLabel(config, config.network.default_egress)})</option>
            {egressOff && <option value={egress}>{egressLabel(config, egress)} (off)</option>}
            {choices.map((e) => (
              <option key={e.id} value={e.id}>
                {egressName(e)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="DNS server">
          <select value={dns} onChange={(e) => setDns(e.target.value)}>
            <option value="">Default ({config.dns.default_upstream})</option>
            {config.dns.upstream.map((u) => (
              <option key={u.id} value={u.id}>
                {u.id}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Download speed limit (kbit/s)" error={limitError}>
          <input inputMode="numeric" value={down} onChange={(e) => setDown(e.target.value)} placeholder="Unlimited" />
        </Field>
        <Field label="Upload speed limit (kbit/s)">
          <input inputMode="numeric" value={up} onChange={(e) => setUp(e.target.value)} placeholder="Unlimited" />
        </Field>
        <QuotaFields
          form={quotaForm}
          onChange={setQuotaForm}
          error={quota.error}
          inherited={config.network.device_quota ? `Empty: ${describeQuota(config.network.device_quota)}, as every device has.` : "Empty: unlimited."}
        />
      </div>
    </Modal>
  );
}
