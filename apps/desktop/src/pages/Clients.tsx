import { useMemo, useState } from "react";
import { Ban, Check, Laptop, Pencil, Search, Trash2, Users } from "lucide-react";
import { api } from "../api";
import { deviceAddress, deviceName, egressLabel, egressName, profileFor, usableEgresses } from "../configUtils";
import { AddressChip } from "../components/AddressChip";
import { Empty, EmptyState, Field, Pill, Toggle } from "../components/Form";
import { ConfirmDialog, Modal } from "../components/Modal";
import { formatAgo, formatBytes, formatKbps, formatRate } from "../format";
import { useNav } from "../nav";
import { useClients, useDeviceTraffic, useServiceCore, useServiceStatus } from "../service";
import type { ClientProfile, ClientState, ClientView, Config, MacAddr, TrafficStats } from "../types";
import { openSettingsAt } from "./Settings";
import { opt, optNumber } from "../validation";

type Filter = "all" | "online" | "pending" | "blocked";

const FILTER_LABEL: Record<Filter, string> = { all: "All", online: "Online", pending: "Waiting", blocked: "Blocked" };

const STATE_TONE: Record<ClientState, "ok" | "warn" | "danger"> = { approved: "ok", pending: "warn", blocked: "danger" };
const STATE_LABEL: Record<ClientState, string> = { approved: "allowed", pending: "waiting", blocked: "blocked" };

export function Clients() {
  const { connected, config, run, saveClient } = useServiceCore();
  const clients = useClients();
  const nav = useNav();
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [editing, setEditing] = useState<ClientView | null>(null);
  const [forgetting, setForgetting] = useState<ClientView | null>(null);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return clients
      .filter((c) => {
        if (filter === "online" && !c.online) return false;
        if (filter === "pending" && c.state !== "pending") return false;
        if (filter === "blocked" && c.state !== "blocked") return false;
        if (!q) return true;
        return [deviceName(c), c.hostname ?? "", c.mac, ...c.addrs].some((s) => s.toLowerCase().includes(q));
      })
      .sort(
        (a, b) =>
          Number(b.online) - Number(a.online) ||
          Number(b.state === "pending") - Number(a.state === "pending") ||
          deviceName(a).localeCompare(deviceName(b)),
      );
  }, [clients, filter, query]);

  if (!connected) {
    return (
      <EmptyState icon={Users} title="No devices yet" action={<button className="button button-primary" onClick={() => nav("home")}>Start sharing</button>}>
        Devices show up here when they join your hotspot or a USB phone goes online.
      </EmptyState>
    );
  }
  if (!config) return <Empty>Loading…</Empty>;

  const setState = (c: ClientView, state: ClientState) =>
    void saveClient({ ...profileFor(config, c), state }, state === "approved" ? `${deviceName(c)} allowed` : `${deviceName(c)} blocked`);

  return (
    <div className="page">
      <div className="toolbar">
        <div className="segmented" role="group" aria-label="Filter devices">
          {(["all", "online", "pending", "blocked"] as Filter[]).map((f) => (
            <button key={f} aria-pressed={filter === f} onClick={() => setFilter(f)}>
              {FILTER_LABEL[f]}
            </button>
          ))}
        </div>
        <label className="search">
          <Search size={14} aria-hidden="true" />
          <input placeholder="Search name or address" aria-label="Search devices" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
      </div>

      <ThisComputer />

      {visible.length === 0 ? (
        clients.length === 0 ? (
          <EmptyState icon={Users} title="No devices yet">
            Devices show up here as soon as they join.
          </EmptyState>
        ) : (
          <Empty>No device matches.</Empty>
        )
      ) : (
        <ul className="device-list">
          {visible.map((c) => {
            const address = c.online ? deviceAddress(c) : undefined;
            const detail = c.online ? `via ${egressLabel(config, c.effective_egress)}` : `seen ${formatAgo(c.last_seen_ms)}`;
            return (
              <li key={c.mac} className={c.online ? "device" : "device device-offline"}>
                <span className={c.online ? "device-icon device-icon-on" : "device-icon"} aria-hidden="true">
                  <Laptop size={16} />
                </span>
                <div className="device-body">
                  <div className="cell-main">
                    {deviceName(c)}
                    {c.state !== "approved" && <Pill tone={STATE_TONE[c.state]}>{STATE_LABEL[c.state]}</Pill>}
                    {c.online && c.over_limit && (
                      <span className="tag tag-warn" title="The hotspot is at its device limit; this device waits for a free slot.">
                        hotspot full
                      </span>
                    )}
                    {c.inspect_tls && c.tls_consented && <span className="tag tag-warn">HTTPS inspected</span>}
                  </div>
                  <div className="cell-sub">
                    {address && (
                      <>
                        <AddressChip address={address} small />
                        {" · "}
                      </>
                    )}
                    {detail}
                  </div>
                </div>
                {c.online && <DeviceRate mac={c.mac} listed={c.traffic} />}
                <div className="row-actions">
                  {c.state === "pending" && (
                    <button className="button button-primary" onClick={() => setState(c, "approved")}>
                      <Check size={14} aria-hidden="true" /> Allow
                    </button>
                  )}
                  {c.state === "blocked" && (
                    <button className="button" onClick={() => setState(c, "approved")}>
                      Unblock
                    </button>
                  )}
                  {c.state !== "blocked" && (
                    <button className="icon-button" aria-label={`Block ${deviceName(c)}`} title="Block" onClick={() => setState(c, "blocked")}>
                      <Ban size={14} />
                    </button>
                  )}
                  <button className="icon-button" aria-label={`Edit ${deviceName(c)}`} title="Details and settings" onClick={() => setEditing(c)}>
                    <Pencil size={14} />
                  </button>
                  {!c.online && (
                    <button className="icon-button" aria-label={`Forget ${deviceName(c)}`} title="Forget" onClick={() => setForgetting(c)}>
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}

      {editing && <ClientEditor view={editing} config={config} onClose={() => setEditing(null)} />}
      {forgetting && (
        <ConfirmDialog
          title="Forget device"
          confirmLabel="Forget"
          danger
          onCancel={() => setForgetting(null)}
          onConfirm={() => {
            const mac = forgetting.mac;
            setForgetting(null);
            void run(() => api.forgetClient(mac), "Could not forget the device", "Device forgotten");
          }}
        >
          Remove <strong>{deviceName(forgetting)}</strong> ({forgetting.mac}) and all its settings? If it reconnects it is treated
          as a new device.
        </ConfirmDialog>
      )}
    </div>
  );
}

/**
 * A device's speeds right now. It redraws by itself every second as they
 * come; the list around it does not. `listed` is what the device list said,
 * until the service sends the device's speeds.
 */
function DeviceRate({ mac, listed }: { mac: MacAddr; listed: TrafficStats }) {
  const traffic = useDeviceTraffic(mac) ?? listed;
  return (
    <div className="device-rate mono" title="Download / upload right now">
      <span>↓ {formatRate(traffic.rx_bps)}</span>
      <span>↑ {formatRate(traffic.tx_bps)}</span>
    </div>
  );
}

/** What a device has downloaded and uploaded so far, kept current. */
function DataUsed({ mac, listed }: { mac: MacAddr; listed: TrafficStats }) {
  const traffic = useDeviceTraffic(mac) ?? listed;
  return (
    <>
      ↓ {formatBytes(traffic.rx_bytes)} · ↑ {formatBytes(traffic.tx_bytes)}
    </>
  );
}

/**
 * This computer's address on the hotspot and what devices may reach, with a
 * way to change it: the addresses here are what devices use to find each
 * other and this computer.
 */
function ThisComputer() {
  const { config } = useServiceCore();
  const status = useServiceStatus();
  const nav = useNav();
  const gateway = status?.hotspot.state === "running" ? status.hotspot.gateway : status?.access_network.gateway;
  if (!gateway || !config) return null;
  const { block_host, isolate_clients, block_host_lan } = config.network;
  const reach = [
    !block_host && "this computer",
    !isolate_clients && status?.capabilities.wifi_isolation && "each other",
    !block_host_lan && "your home network",
  ].filter(Boolean);
  return (
    <p className="this-computer">
      <span>This computer:</span>
      <AddressChip address={gateway} />
      <span className="this-computer-reach">Devices reach {reach.length > 0 ? `the internet, ${reach.join(", ")}` : "the internet only"}.</span>
      <button
        className="link-button"
        onClick={() => {
          openSettingsAt("access");
          nav("settings");
        }}
      >
        Change
      </button>
    </p>
  );
}

function ClientEditor({ view, config, onClose }: { view: ClientView; config: Config; onClose: () => void }) {
  const { saveClient } = useServiceCore();
  const base = profileFor(config, view);
  const [alias, setAlias] = useState(base.alias ?? "");
  const [group, setGroup] = useState(base.group ?? "");
  const [egress, setEgress] = useState(base.egress ?? "");
  const [dns, setDns] = useState(base.dns_upstream ?? "");
  const [down, setDown] = useState(base.limit?.down_kbps?.toString() ?? "");
  const [up, setUp] = useState(base.limit?.up_kbps?.toString() ?? "");
  const [inspect, setInspect] = useState(base.inspect_tls);
  const [saving, setSaving] = useState(false);

  const groupConfig = config.group?.find((g) => g.id === group);
  const inheritedEgress = groupConfig?.egress ?? config.network.default_egress;
  const inheritedDns = groupConfig?.dns_upstream ?? config.dns.default_upstream;
  const limitError = [down, up].some((v) => v.trim() !== "" && !(Number(v) > 0 && Number.isInteger(Number(v))))
    ? "Limits must be whole numbers above 0 (leave empty for unlimited)."
    : null;
  const aliasError = [...alias].length > 64 ? "The name must be at most 64 characters." : null;
  const egressChoices = usableEgresses(config);
  const egressOff = egress !== "" && !egressChoices.some((e) => e.id === egress);
  const consent = base.tls_consent;
  const consentCurrent = consent != null && consent.terms_version >= config.tls_inspection.terms_version;

  const save = async () => {
    setSaving(true);
    const downKbps = optNumber(down);
    const upKbps = optNumber(up);
    const profile: ClientProfile = {
      ...base,
      alias: opt(alias),
      group: opt(group),
      egress: opt(egress),
      dns_upstream: opt(dns),
      limit: downKbps !== undefined || upKbps !== undefined ? { down_kbps: downKbps, up_kbps: upKbps } : undefined,
      inspect_tls: inspect,
    };
    const ok = await saveClient(profile, "Device updated");
    setSaving(false);
    if (ok) onClose();
  };

  return (
    <Modal
      title={`Edit ${deviceName(view)}`}
      onClose={onClose}
      footer={
        <>
          <button className="button" onClick={onClose}>
            Cancel
          </button>
          <button className="button button-primary" disabled={saving || !!limitError || !!aliasError || egressOff} onClick={() => void save()}>
            Save
          </button>
        </>
      }
    >
      <dl className="facts facts-compact">
        <dt>Hardware address</dt>
        <dd>
          <span className="mono">{view.mac}</span>
          {view.randomized_mac && (
            <span className="tag" title="The device may use a different address on each network">
              private
            </span>
          )}
        </dd>
        <dt>IP address</dt>
        <dd className="address-list">{view.addrs.length > 0 ? view.addrs.map((a) => <AddressChip key={a} address={a} />) : "—"}</dd>
        <dt>Data used</dt>
        <dd>
          <DataUsed mac={view.mac} listed={view.traffic} />
        </dd>
        <dt>Seen</dt>
        <dd>{view.online ? "online now" : formatAgo(view.last_seen_ms)}</dd>
      </dl>
      <div className="form-grid">
        <Field label="Name" error={aliasError} hint={view.hostname ? `It calls itself ${view.hostname}` : undefined}>
          <input value={alias} onChange={(e) => setAlias(e.target.value)} placeholder={view.hostname ?? "e.g. Living room TV"} />
        </Field>
        <Field label="Group">
          <select value={group} onChange={(e) => setGroup(e.target.value)}>
            <option value="">No group</option>
            {(config.group ?? []).map((g) => (
              <option key={g.id} value={g.id}>
                {g.name ?? g.id}
              </option>
            ))}
          </select>
        </Field>
        <Field
          label="Outbound"
          error={egressOff ? "This outbound is turned off; pick another or turn it on under Outbound." : null}
          hint="Where this device's internet goes out."
        >
          <select value={egress} onChange={(e) => setEgress(e.target.value)}>
            <option value="">Default ({egressLabel(config, inheritedEgress)})</option>
            {egressOff && <option value={egress}>{egressLabel(config, egress)} (off)</option>}
            {egressChoices.map((e) => (
              <option key={e.id} value={e.id}>
                {egressName(e)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="DNS server">
          <select value={dns} onChange={(e) => setDns(e.target.value)}>
            <option value="">Default ({inheritedDns})</option>
            {config.dns.upstream.map((u) => (
              <option key={u.id} value={u.id}>
                {u.id}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Download speed limit (kbit/s)" error={limitError} hint={formatKbps(optNumber(down))}>
          <input inputMode="numeric" value={down} onChange={(e) => setDown(e.target.value)} placeholder="Unlimited" />
        </Field>
        <Field label="Upload speed limit (kbit/s)" hint={formatKbps(optNumber(up))}>
          <input inputMode="numeric" value={up} onChange={(e) => setUp(e.target.value)} placeholder="Unlimited" />
        </Field>
      </div>
      <Toggle
        label="Allow HTTPS inspection for this device"
        checked={inspect}
        disabled={!config.tls_inspection.enabled}
        onChange={setInspect}
        description={
          !config.tls_inspection.enabled
            ? "HTTPS inspection is turned off for everyone (Settings)."
            : consentCurrent
              ? "The device's user accepted the current terms. Inspection is active while this is on."
              : "Takes effect only after the device's user accepts the terms on the sign-in page and installs the Captun certificate."
        }
      />
    </Modal>
  );
}
