import { memo, useMemo, useState } from "react";
import { Pause, Pencil, Play, Plus, Search, Trash2, X } from "lucide-react";
import { upstreamReferences } from "../configUtils";
import { Card, Empty, Field, Pill, SubTabs, Toggle } from "../components/Form";
import { ConfirmDialog, Modal } from "../components/Modal";
import { formatTime, timeZoneOffset } from "../format";
import { useDnsLog, useServiceCore } from "../service";
import type { BlockResponse, Config, DnsConfig, DnsOverride, DnsProtocol, DnsQueryLog, DnsUpstreamConfig } from "../types";
import { lines, opt, optList, optNumber, tokens } from "../validation";

type Section = "general" | "blocked" | "answers" | "servers" | "log";

const SECTIONS: { id: Section; label: string }[] = [
  { id: "general", label: "General" },
  { id: "blocked", label: "Blocked sites" },
  { id: "answers", label: "Custom answers" },
  { id: "servers", label: "DNS servers" },
  { id: "log", label: "Log" },
];

// The last section opened, kept while the app runs.
let lastSection: Section = "general";

export function Dns() {
  const { config } = useServiceCore();
  const [section, setSection] = useState<Section>(lastSection);
  if (!config) return <Empty>Loading…</Empty>;

  const open = (id: Section) => {
    lastSection = id;
    setSection(id);
  };
  // The general section re-initialises only when its own fields change.
  const { upstream: _upstream, override, blocklist, ...general } = config.dns;
  return (
    <div className="page">
      <SubTabs label="DNS sections" tabs={SECTIONS} value={section} onChange={open} />
      {section === "general" && <GeneralSection key={JSON.stringify(general)} config={config} />}
      {section === "blocked" && <BlocklistSection key={JSON.stringify(blocklist ?? [])} current={blocklist ?? []} />}
      {section === "answers" && <OverridesSection key={JSON.stringify(override ?? [])} current={override ?? []} />}
      {section === "servers" && <UpstreamsSection config={config} />}
      {section === "log" && <QueryLog config={config} />}
    </div>
  );
}

function GeneralSection({ config }: { config: Config }) {
  const { saveConfig } = useServiceCore();
  const dns = config.dns;
  const [enabled, setEnabled] = useState(dns.enabled);
  const [enforce, setEnforce] = useState(dns.enforce);
  const [logQueries, setLogQueries] = useState(dns.log_queries);
  const [defaultUpstream, setDefaultUpstream] = useState(dns.default_upstream);
  const [blockResponse, setBlockResponse] = useState<BlockResponse>(dns.block_response);
  const [port, setPort] = useState(String(dns.port));
  const [cacheSize, setCacheSize] = useState(String(dns.cache_size));
  const [minTtl, setMinTtl] = useState(String(dns.min_ttl));
  const [maxTtl, setMaxTtl] = useState(String(dns.max_ttl));

  const num = (v: string) => optNumber(v);
  const whole = (v: string) => {
    const n = num(v);
    return n !== undefined && Number.isInteger(n) && n >= 0 ? n : undefined;
  };
  const p = whole(port);
  const cache = whole(cacheSize);
  const lo = whole(minTtl);
  const hi = whole(maxTtl);
  const error =
    p === undefined || p < 1 || p > 65535
      ? "The port must be 1–65535."
      : cache === undefined || cache > 1_000_000
        ? "The cache size must be 0–1000000 entries."
        : lo === undefined || hi === undefined
          ? "Cache times must be whole seconds."
          : lo > hi
            ? "The shortest cache time must not exceed the longest."
            : null;

  const next: Partial<DnsConfig> = {
    enabled,
    enforce,
    log_queries: logQueries,
    default_upstream: defaultUpstream,
    block_response: blockResponse,
    port: p,
    cache_size: cache,
    min_ttl: lo,
    max_ttl: hi,
  };
  const dirty = (Object.keys(next) as (keyof DnsConfig)[]).some((k) => next[k] !== dns[k]);

  return (
    <Card
      title="Website lookups (DNS)"
      actions={
        <button
          className="button button-primary"
          disabled={!dirty || !!error}
          onClick={() => void saveConfig((c) => (c.dns = { ...c.dns, ...next }), "DNS settings saved")}
        >
          Save
        </button>
      }
    >
      <div className="toggle-list">
        <Toggle
          label="Answer website lookups for devices"
          description="Captun finds websites' addresses for connected devices, so blocking and custom answers work."
          checked={enabled}
          onChange={setEnabled}
        />
        <Toggle
          label="Make devices use it"
          description="Catch lookups sent anywhere else, so devices cannot get around blocked sites."
          checked={enforce}
          onChange={setEnforce}
        />
        <Toggle label="Keep a lookup log" description="Fills the live log below." checked={logQueries} onChange={setLogQueries} />
      </div>
      {error && <div className="inline-alert inline-alert-danger">{error}</div>}
      <div className="form-grid form-grid-3">
        <Field label="Default DNS server">
          <select value={defaultUpstream} onChange={(e) => setDefaultUpstream(e.target.value)}>
            {dns.upstream.map((u) => (
              <option key={u.id} value={u.id}>
                {u.id}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Blocked sites look like">
          <select value={blockResponse} onChange={(e) => setBlockResponse(e.target.value as BlockResponse)}>
            <option value="nx_domain">They don't exist</option>
            <option value="null_ip">An empty address (0.0.0.0)</option>
            <option value="refused">A refused lookup</option>
          </select>
        </Field>
        <Field label="Port">
          <input inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
        </Field>
        <Field label="Remembered answers">
          <input inputMode="numeric" value={cacheSize} onChange={(e) => setCacheSize(e.target.value)} />
        </Field>
        <Field label="Shortest cache time (s)">
          <input inputMode="numeric" value={minTtl} onChange={(e) => setMinTtl(e.target.value)} />
        </Field>
        <Field label="Longest cache time (s)">
          <input inputMode="numeric" value={maxTtl} onChange={(e) => setMaxTtl(e.target.value)} />
        </Field>
      </div>
    </Card>
  );
}

const PROTOCOL_LABEL: Record<DnsProtocol, string> = { udp: "UDP", tcp: "TCP", tls: "DNS over TLS", https: "DNS over HTTPS" };

function UpstreamsSection({ config }: { config: Config }) {
  const { saveConfig } = useServiceCore();
  const [editing, setEditing] = useState<DnsUpstreamConfig | "new" | null>(null);
  const [deleting, setDeleting] = useState<DnsUpstreamConfig | null>(null);
  const refs = deleting ? upstreamReferences(config, deleting.id) : [];

  return (
    <Card
      title="DNS servers"
      actions={
        <button className="button" onClick={() => setEditing("new")}>
          <Plus size={14} aria-hidden="true" /> Add
        </button>
      }
    >
      <p className="muted">Lookups go out through each device's own outbound, so they never leak around a proxy or VPN.</p>
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Address</th>
            <th>Certificate name / path</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {config.dns.upstream.map((u) => (
            <tr key={u.id}>
              <td>
                {u.id}
                {u.id === config.dns.default_upstream && <span className="tag tag-accent">default</span>}
              </td>
              <td>{PROTOCOL_LABEL[u.protocol]}</td>
              <td className="mono">{u.address}</td>
              <td className="mono">{[u.server_name, u.path].filter(Boolean).join(" ") || "—"}</td>
              <td className="row-actions">
                <button className="icon-button" aria-label={`Edit DNS server ${u.id}`} onClick={() => setEditing(u)}>
                  <Pencil size={14} />
                </button>
                <button className="icon-button" aria-label={`Delete DNS server ${u.id}`} onClick={() => setDeleting(u)}>
                  <Trash2 size={14} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {editing && <UpstreamEditor initial={editing === "new" ? null : editing} config={config} onClose={() => setEditing(null)} />}
      {deleting &&
        (refs.length > 0 ? (
          <Modal
            title={`Cannot delete ${deleting.id}`}
            onClose={() => setDeleting(null)}
            footer={
              <button className="button" onClick={() => setDeleting(null)}>
                Close
              </button>
            }
          >
            <p>This DNS server is still in use by:</p>
            <ul className="notes">
              {refs.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </Modal>
        ) : (
          <ConfirmDialog
            title="Delete DNS server"
            confirmLabel="Delete"
            danger
            onCancel={() => setDeleting(null)}
            onConfirm={() => {
              const id = deleting.id;
              setDeleting(null);
              void saveConfig((c) => (c.dns.upstream = c.dns.upstream.filter((u) => u.id !== id)), "DNS server deleted");
            }}
          >
            Delete DNS server <strong>{deleting.id}</strong>?
          </ConfirmDialog>
        ))}
    </Card>
  );
}

function UpstreamEditor({ initial, config, onClose }: { initial: DnsUpstreamConfig | null; config: Config; onClose: () => void }) {
  const { saveConfig } = useServiceCore();
  const [id, setId] = useState(initial?.id ?? "");
  const [protocol, setProtocol] = useState<DnsProtocol>(initial?.protocol ?? "https");
  const [address, setAddress] = useState(initial?.address ?? "");
  const [serverName, setServerName] = useState(initial?.server_name ?? "");
  const [path, setPath] = useState(initial?.path ?? "");

  const encrypted = protocol === "tls" || protocol === "https";
  const errors = {
    id: initial ? null : id.trim() === "" ? "A name is required." : config.dns.upstream.some((u) => u.id === id.trim()) ? "This name is already used." : null,
    address: address.trim() === "" ? "Address is required." : null,
    path: protocol === "https" && path.trim() !== "" && !path.trim().startsWith("/") ? "Path must start with '/'." : null,
  };
  const invalid = Object.values(errors).some((e) => e !== null);

  const save = async () => {
    const upstream: DnsUpstreamConfig = {
      id: initial?.id ?? id.trim(),
      protocol,
      address: address.trim(),
      server_name: encrypted ? opt(serverName) : undefined,
      path: protocol === "https" ? opt(path) : undefined,
    };
    const ok = await saveConfig((c) => {
      const index = c.dns.upstream.findIndex((u) => u.id === upstream.id);
      if (index >= 0) c.dns.upstream[index] = upstream;
      else c.dns.upstream.push(upstream);
    }, initial ? "DNS server updated" : "DNS server added");
    if (ok) onClose();
  };

  return (
    <Modal
      title={initial ? `Edit DNS server ${initial.id}` : "Add DNS server"}
      onClose={onClose}
      footer={
        <>
          <button className="button" onClick={onClose}>
            Cancel
          </button>
          <button className="button button-primary" disabled={invalid} onClick={() => void save()}>
            Save
          </button>
        </>
      }
    >
      <div className="form-grid">
        <Field label="Name" error={errors.id}>
          <input value={initial?.id ?? id} disabled={!!initial} onChange={(e) => setId(e.target.value)} spellCheck={false} />
        </Field>
        <Field label="Type">
          <select value={protocol} onChange={(e) => setProtocol(e.target.value as DnsProtocol)}>
            {(Object.keys(PROTOCOL_LABEL) as DnsProtocol[]).map((p) => (
              <option key={p} value={p}>
                {PROTOCOL_LABEL[p]}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Address" error={errors.address} hint="IP, IP:port or host:port; the usual port is used if left out.">
          <input value={address} onChange={(e) => setAddress(e.target.value)} placeholder="1.1.1.1" spellCheck={false} />
        </Field>
        {encrypted && (
          <Field label="Certificate name" hint="The name its certificate must show; defaults to the address.">
            <input value={serverName} onChange={(e) => setServerName(e.target.value)} placeholder="cloudflare-dns.com" spellCheck={false} />
          </Field>
        )}
        {protocol === "https" && (
          <Field label="Path" error={errors.path}>
            <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/dns-query" spellCheck={false} />
          </Field>
        )}
      </div>
    </Modal>
  );
}

function BlocklistSection({ current }: { current: string[] }) {
  const { saveConfig } = useServiceCore();
  const [text, setText] = useState(current.join("\n"));
  const dirty = JSON.stringify(lines(text)) !== JSON.stringify(current);
  return (
    <Card
      title="Blocked sites"
      actions={
        <button
          className="button button-primary"
          disabled={!dirty}
          onClick={() => void saveConfig((c) => (c.dns.blocklist = optList(lines(text))), "Blocked sites saved")}
        >
          Save
        </button>
      }
    >
      <Field label="One per line" wide hint={`${lines(text).length} entries · example.com, full:x.example.com, keyword:ads`}>
        <textarea rows={10} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
      </Field>
    </Card>
  );
}

interface OverrideRow {
  domain: string;
  addrs: string;
}

function OverridesSection({ current }: { current: DnsOverride[] }) {
  const { saveConfig } = useServiceCore();
  const [rows, setRows] = useState<OverrideRow[]>(current.map((o) => ({ domain: o.domain, addrs: o.addrs.join(", ") })));
  const toOverrides = (): DnsOverride[] =>
    rows.filter((r) => r.domain.trim() !== "").map((r) => ({ domain: r.domain.trim(), addrs: tokens(r.addrs) }));
  const dirty = JSON.stringify(toOverrides()) !== JSON.stringify(current);
  const missing = rows.some((r) => r.domain.trim() !== "" && tokens(r.addrs).length === 0);
  const setRow = (i: number, patch: Partial<OverrideRow>) => setRows((list) => list.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <Card
      title="Custom answers"
      actions={
        <>
          <button className="button" onClick={() => setRows((list) => [...list, { domain: "", addrs: "" }])}>
            <Plus size={14} aria-hidden="true" /> Add
          </button>
          <button
            className="button button-primary"
            disabled={!dirty || missing}
            onClick={() => void saveConfig((c) => (c.dns.override = optList(toOverrides())), "Custom answers saved")}
          >
            Save
          </button>
        </>
      }
    >
      {missing && <div className="inline-alert inline-alert-danger">Every custom answer needs at least one address.</div>}
      {rows.length === 0 ? (
        <p className="muted">Give a name your own address, like a hosts file. Example: full:hub.lan → 192.168.137.1</p>
      ) : (
        <div className="override-rows">
          {rows.map((r, i) => (
            <div key={i} className="override-row">
              <input aria-label={`Override ${i + 1} name`} placeholder="full:hub.lan" value={r.domain} onChange={(e) => setRow(i, { domain: e.target.value })} spellCheck={false} />
              <input aria-label={`Override ${i + 1} addresses`} placeholder="192.168.137.1, fd00::1" value={r.addrs} onChange={(e) => setRow(i, { addrs: e.target.value })} spellCheck={false} />
              <button className="icon-button" aria-label={`Remove override ${i + 1}`} onClick={() => setRows((list) => list.filter((_, j) => j !== i))}>
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

const OUTCOME_TONE: Record<string, "ok" | "warn" | "danger" | "muted" | "accent"> = {
  NOERROR: "ok",
  CACHED: "muted",
  OVERRIDE: "accent",
  SYSTEM: "ok",
  BLOCKED: "danger",
  NXDOMAIN: "warn",
  REFUSED: "danger",
  SERVFAIL: "danger",
  FAILED: "danger",
};

/** The service's result codes, in words. */
const OUTCOME_LABEL: Record<string, string> = {
  NOERROR: "found",
  CACHED: "remembered",
  OVERRIDE: "your answer",
  SYSTEM: "this computer's DNS",
  BLOCKED: "blocked",
  NXDOMAIN: "no such site",
  REFUSED: "refused",
  SERVFAIL: "server failed",
  FAILED: "failed",
};

/** Row keys that stay with each query as new ones arrive on top. */
function queryKeys(rows: DnsQueryLog[]): string[] {
  const seen = new Map<string, number>();
  return rows.map((e) => {
    const base = `${e.at_ms}-${e.client_ip}-${e.name}-${e.qtype}`;
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    return `${base}#${n}`;
  });
}

interface QueryRowProps {
  entry: DnsQueryLog;
  device: string;
  /** Not shown: when it changes, every row redraws its time in the new time zone. */
  zone: number;
}

/** One lookup. Rows already drawn keep still as new lookups arrive on top. */
const QueryRow = memo(function QueryRow({ entry, device }: QueryRowProps) {
  const answers = entry.answers.join(", ");
  return (
    <tr>
      <td className="mono">{formatTime(entry.at_ms)}</td>
      <td>{device}</td>
      <td className="mono">{entry.name}</td>
      <td>{entry.qtype}</td>
      <td>
        <Pill tone={OUTCOME_TONE[entry.outcome] ?? "muted"}>{OUTCOME_LABEL[entry.outcome] ?? entry.outcome.toLowerCase()}</Pill>
      </td>
      <td className="mono cell-truncate" title={answers}>
        {answers || "—"}
      </td>
      <td>{entry.upstream ?? "—"}</td>
      <td className="num mono">{entry.latency_ms}</td>
    </tr>
  );
});

/**
 * The live lookup log. It redraws for new lookups and its own buttons only,
 * not each time the rest of the page does (the device list alone refreshes
 * every second).
 */
const QueryLog = memo(function QueryLog({ config }: { config: Config }) {
  const { entries, dropped, clear } = useDnsLog();
  const [filter, setFilter] = useState("");
  const [frozen, setFrozen] = useState<DnsQueryLog[] | null>(null);
  const source = frozen ?? entries;

  const names = useMemo(() => new Map((config.client ?? []).map((c) => [c.mac, c.alias ?? c.mac])), [config.client]);
  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return source;
    return source.filter((e) =>
      [e.name, e.qtype, e.outcome, e.client_ip, e.client ?? "", names.get(e.client ?? "") ?? "", e.upstream ?? ""].some((s) =>
        s.toLowerCase().includes(q),
      ),
    );
  }, [source, filter, names]);
  const rowKeys = useMemo(() => queryKeys(rows), [rows]);
  const zone = timeZoneOffset();

  return (
    <Card
      title={`Lookup log (${source.length})`}
      actions={
        <>
          <label className="search">
            <Search size={14} aria-hidden="true" />
            <input placeholder="Filter" aria-label="Filter lookups" value={filter} onChange={(e) => setFilter(e.target.value)} />
          </label>
          <button className="button" onClick={() => setFrozen(frozen ? null : entries)}>
            {frozen ? <Play size={14} aria-hidden="true" /> : <Pause size={14} aria-hidden="true" />} {frozen ? "Resume" : "Pause"}
          </button>
          <button
            className="button"
            onClick={() => {
              clear();
              setFrozen(frozen ? [] : null);
            }}
          >
            Clear
          </button>
        </>
      }
    >
      {!config.dns.log_queries && <div className="inline-alert">The log is off; turn on “Keep a lookup log” above.</div>}
      {dropped > 0 && (
        <div className="inline-alert">
          {dropped === 1 ? "1 lookup was" : `${dropped.toLocaleString()} lookups were`} not shown because too many came at once.
        </div>
      )}
      {rows.length === 0 ? (
        <p className="muted">No lookups yet.</p>
      ) : (
        <div className="table-wrap table-scroll">
          <table className="table table-compact">
            <thead>
              <tr>
                <th>Time</th>
                <th>Device</th>
                <th>Website</th>
                <th>Type</th>
                <th>Result</th>
                <th>Answers</th>
                <th>DNS server</th>
                <th className="num">ms</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e, i) => (
                <QueryRow key={rowKeys[i]} entry={e} device={e.client ? (names.get(e.client) ?? e.client) : e.client_ip} zone={zone} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
});
