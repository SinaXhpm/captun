import { memo, useCallback, useEffect, useId, useMemo, useRef, useState, type ComponentType, type FormEvent, type ReactNode } from "react";
import type { LucideProps } from "lucide-react";
import {
  ArrowDown,
  ArrowUp,
  Ban,
  Check,
  ChevronRight,
  CircleSlash,
  Clock,
  FlaskConical,
  Globe,
  Hash,
  LayoutGrid,
  ListChecks,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Route,
  Smartphone,
  Trash2,
  Users,
  X,
} from "lucide-react";
import { api, errorMessage } from "../api";
import { actionLabel, deviceName, egressLabel, egressName, usableEgresses } from "../configUtils";
import { Empty, Pill, Switch, Toggle } from "../components/Form";
import { ConfirmDialog, Modal } from "../components/Modal";
import { formatAgo } from "../format";
import { useInterval } from "../hooks";
import { RULE_TEMPLATES, TEMPLATE_GROUPS, ruleFromTemplate, type RuleTemplate } from "../ruleTemplates";
import { useClients, useLists, useServiceCore } from "../service";
import {
  WEEKDAYS,
  type ClientProfile,
  type ClientView,
  type Config,
  type ConnectionOutcome,
  type GroupConfig,
  type ListStatus,
  type ListsProgress,
  type LookupOutcome,
  type PortRange,
  type Protocol,
  type RuleAction,
  type RuleConfig,
  type RuleHits,
  type RuleTestResult,
  type Schedule,
  type Weekday,
} from "../types";
import { checkDomains, checkLinks, checkRanges, opt, optList, tokens, validateClock, validateMac, validatePort, type Checked } from "../validation";

const DAY_SHORT: Record<Weekday, string> = { mon: "Mon", tue: "Tue", wed: "Wed", thu: "Thu", fri: "Fri", sat: "Sat", sun: "Sun" };

/** "every day", "Mon–Fri", or "Mon, Wed, Sat". */
function daysLabel(days: Weekday[] | undefined): string {
  const picked = WEEKDAYS.filter((d) => days?.includes(d));
  if (picked.length === 0 || picked.length === WEEKDAYS.length) return "every day";
  const at = picked.map((d) => WEEKDAYS.indexOf(d));
  const run = at.every((v, i) => i === 0 || v === (at[i - 1] ?? -2) + 1);
  const first = picked[0];
  const last = picked[picked.length - 1];
  if (run && picked.length >= 3 && first && last) return `${DAY_SHORT[first]}–${DAY_SHORT[last]}`;
  return picked.map((d) => DAY_SHORT[d]).join(", ");
}

const normalizeMac = (mac: string) => mac.trim().toLowerCase().replace(/-/g, ":");

// Sorts device names in the user's language, as localeCompare does, with one
// collator made once for every sort.
const collator = new Intl.Collator();

interface KnownDevice {
  mac: string;
  name: string;
}

/** Every device Captun knows by name, sorted by it: saved ones and those online now. */
function knownDevices(profiles: ClientProfile[] | undefined, clients: ClientView[]): KnownDevice[] {
  const known = new Map<string, string>();
  for (const c of clients) known.set(c.mac, deviceName(c));
  for (const p of profiles ?? []) if (p.alias || !known.has(p.mac)) known.set(p.mac, p.alias ?? known.get(p.mac) ?? p.mac);
  return [...known].map(([mac, name]) => ({ mac, name })).sort((a, b) => collator.compare(a.name, b.name));
}

type Part = { icon: ComponentType<LucideProps>; text: string };

/** "176,107 websites · 2,103 ranges", or what is known instead. */
function listContents(links: string[], lists: ListStatus[]): string {
  const known = links.map((link) => lists.find((l) => l.url === link)).filter((l): l is ListStatus => l !== undefined);
  const names = known.reduce((n, l) => n + l.names, 0);
  const addresses = known.reduce((n, l) => n + l.addresses, 0);
  if (names === 0 && addresses === 0) return known.some((l) => l.error) ? "download failed" : "not downloaded yet";
  return [names > 0 ? `${names.toLocaleString()} websites` : "", addresses > 0 ? `${addresses.toLocaleString()} ranges` : ""].filter(Boolean).join(" · ");
}

/** What a rule matches, as short labelled pieces for its row; `names` maps devices' MACs to their names. */
function summarize(rule: RuleConfig, names: Map<string, string>, groups: GroupConfig[] | undefined, lists: ListStatus[]): Part[] {
  const list = (items: string[], max = 2) => (items.length > max ? `${items.slice(0, max).join(", ")} +${items.length - max}` : items.join(", "));
  const parts: Part[] = [];
  if (rule.clients?.length) parts.push({ icon: Smartphone, text: list(rule.clients.map((m) => names.get(m) ?? m)) });
  if (rule.groups?.length) parts.push({ icon: Users, text: list(rule.groups.map((g) => groups?.find((x) => x.id === g)?.name ?? g)) });
  if (rule.domains?.length) parts.push({ icon: Globe, text: list(rule.domains) });
  if (rule.cidrs?.length) parts.push({ icon: Network, text: list(rule.cidrs) });
  if (rule.lists?.length) {
    const count = rule.lists.length === 1 ? "1 online list" : `${rule.lists.length} online lists`;
    parts.push({ icon: ListChecks, text: `${count}: ${listContents(rule.lists, lists)}` });
  }
  if (rule.ports?.length || rule.protocol) {
    const ports = rule.ports?.length ? `port ${list(rule.ports.map(String), 3)}` : "";
    const proto = rule.protocol ? rule.protocol.toUpperCase() : "";
    parts.push({ icon: Hash, text: [ports, proto].filter(Boolean).join(" · ") });
  }
  if (rule.schedule) parts.push({ icon: Clock, text: `${daysLabel(rule.schedule.days)} ${rule.schedule.start}–${rule.schedule.end}` });
  return parts;
}

function actionTone(action: RuleAction): "ok" | "danger" | "accent" {
  if (typeof action === "object") return "accent";
  return action === "allow" ? "ok" : "danger";
}

/** How often the rules' counts are asked for while the page is open. */
const HITS_POLL_MS = 5000;

/** "1,234 connections · 56 lookups · 2m 5s ago", or "not used yet". */
function hitsLabel(hits: RuleHits): string {
  const count = (n: number, one: string, many: string) => (n > 0 ? `${n.toLocaleString()} ${n === 1 ? one : many}` : "");
  const parts = [count(hits.connections, "connection", "connections"), count(hits.lookups, "lookup", "lookups")].filter(Boolean);
  if (parts.length === 0 || hits.last_ms === null) return "not used yet";
  return [...parts, formatAgo(hits.last_ms)].join(" · ");
}

// The same empty list every time, so what is worked out from the rules keeps.
const NO_RULES: RuleConfig[] = [];

/**
 * Keys that follow each rule when the list is reordered, so focus stays on the
 * rule that moved. Whether a rule is on is left out: toggling it keeps its row.
 */
function ruleKeys(rules: RuleConfig[]): string[] {
  const seen = new Map<string, number>();
  return rules.map((rule) => {
    const base = JSON.stringify({ ...rule, enabled: undefined });
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    return `${base}#${n}`;
  });
}

interface RuleRowProps {
  rule: RuleConfig;
  index: number;
  last: boolean;
  parts: Part[];
  /** Its action in a word or two. */
  action: string;
  /** How often it decided, in words; null while it is off or not counted. */
  hits: string | null;
  busy: boolean;
  onToggle: (index: number, enabled: boolean) => void;
  onMove: (index: number, delta: number) => void;
  onEdit: (index: number, rule: RuleConfig) => void;
  onDelete: (index: number) => void;
}

/**
 * One rule in the list. The page redraws for every refresh of the device list
 * and of the counts; a row redraws only when something it shows has changed.
 */
const RuleRow = memo(function RuleRow({ rule, index, last, parts, action, hits, busy, onToggle, onMove, onEdit, onDelete }: RuleRowProps) {
  const name = rule.name ?? `Rule ${index + 1}`;
  return (
    <li className={rule.enabled ? "rule" : "rule rule-off"}>
      <span className="rule-index">{index + 1}</span>
      <Switch
        checked={rule.enabled}
        disabled={busy}
        label={rule.enabled ? `Turn ${name} off` : `Turn ${name} on`}
        onChange={(enabled) => onToggle(index, enabled)}
      />
      <button className="rule-body" onClick={() => onEdit(index, rule)} title="Edit this rule">
        <span className="rule-title">
          <span className="rule-name">{name}</span>
          <Pill tone={actionTone(rule.action)}>{action}</Pill>
        </span>
        <span className="rule-chips">
          {parts.length === 0 ? (
            <span className="rule-chip">All traffic from every device</span>
          ) : (
            parts.map((p) => (
              <span key={p.text} className="rule-chip">
                <p.icon size={11} aria-hidden="true" />
                {p.text}
              </span>
            ))
          )}
          {hits !== null && (
            <span className="rule-hits" title="Since the rules last changed: the connections and website lookups this rule decided, and when it last did">
              {hits}
            </span>
          )}
        </span>
      </button>
      <div className="row-actions">
        <button className="icon-button" aria-label={`Move ${name} up`} title="Move up" disabled={busy || index === 0} onClick={() => onMove(index, -1)}>
          <ArrowUp size={14} />
        </button>
        <button className="icon-button" aria-label={`Move ${name} down`} title="Move down" disabled={busy || last} onClick={() => onMove(index, 1)}>
          <ArrowDown size={14} />
        </button>
        <button className="icon-button" aria-label={`Edit ${name}`} title="Edit" onClick={() => onEdit(index, rule)}>
          <Pencil size={14} />
        </button>
        <button className="icon-button" aria-label={`Delete ${name}`} title="Delete" disabled={busy} onClick={() => onDelete(index)}>
          <Trash2 size={14} />
        </button>
      </div>
    </li>
  );
});

export function Rules() {
  const { config, connected, saveConfig } = useServiceCore();
  const clients = useClients();
  const [editing, setEditing] = useState<{ index: number | null; rule: RuleConfig; title?: string } | null>(null);
  const [deleting, setDeleting] = useState<number | null>(null);
  const [gallery, setGallery] = useState(false);
  // One change at a time: a second click before the first is saved would
  // apply to a list that is about to change.
  const [busy, setBusy] = useState(false);
  // Kept above the pages: an update goes on in the background when this one is left.
  const { progress: listsProgress, update: updateLists } = useLists();
  const lists = listsProgress.lists;
  const listLinks = (config?.rule ?? []).flatMap((r) => r.lists ?? []).join("\n");

  // How often each rule decided, by its place in the list. Any change to the
  // rules shifts the places, so the service starts the counts over, and the
  // page drops what it holds and any answer still on its way.
  const [hits, setHits] = useState<RuleHits[]>([]);
  const rulesKey = useMemo(() => JSON.stringify(config?.rule ?? []), [config?.rule]);
  const hitsFor = useRef(rulesKey);
  const refreshHits = useCallback(() => {
    const asked = hitsFor.current;
    api.getRuleHits().then(
      (next) => {
        if (hitsFor.current === asked) setHits(next);
      },
      () => undefined,
    );
  }, []);
  useEffect(() => {
    hitsFor.current = rulesKey;
    setHits([]);
    if (connected) refreshHits();
  }, [rulesKey, connected, refreshHits]);
  useInterval(refreshHits, HITS_POLL_MS, connected);

  // Worked out again only when what they come from changes, not for every rule
  // on every redraw: the page also redraws for each refresh of the device list.
  const rules = config?.rule ?? NO_RULES;
  const keys = useMemo(() => ruleKeys(rules), [rules]);
  // The device list arrives every second with new speeds; the devices are
  // sorted again only when one comes, goes or is renamed.
  const namesKey = JSON.stringify(clients.map((c) => [c.mac, deviceName(c)]));
  const devices = useMemo(() => knownDevices(config?.client, clients), [config?.client, namesKey]);
  const deviceNames = useMemo(() => new Map(devices.map((d) => [d.mac, d.name])), [devices]);
  const groups = config?.group;
  const summaries = useMemo(() => rules.map((rule) => summarize(rule, deviceNames, groups, lists)), [rules, deviceNames, groups, lists]);

  const update = useCallback(
    async (mutate: (list: RuleConfig[]) => void, success: string) => {
      setBusy(true);
      try {
        return await saveConfig((c) => {
          const list = c.rule ?? [];
          mutate(list);
          c.rule = optList(list);
        }, success);
      } finally {
        setBusy(false);
      }
    },
    [saveConfig],
  );
  // The rows' handlers stay the same from one redraw to the next, so rows
  // that did not change keep still.
  const move = useCallback(
    (index: number, delta: number) =>
      void update((list) => {
        const [item] = list.splice(index, 1);
        if (item) list.splice(index + delta, 0, item);
      }, "Rule order saved"),
    [update],
  );
  const toggle = useCallback(
    (index: number, enabled: boolean) =>
      void update((list) => {
        const r = list[index];
        if (r) r.enabled = enabled;
      }, enabled ? "Rule turned on" : "Rule turned off"),
    [update],
  );
  const edit = useCallback((index: number, rule: RuleConfig) => setEditing({ index, rule }), []);

  if (!config) return <Empty>Loading…</Empty>;

  return (
    <div className="page">
      <div className="toolbar">
        <p className="muted">Rules are checked from the top and the first one that fits decides. Traffic no rule fits goes out the device's usual way.</p>
        <div className="toolbar-actions">
          <button className="button" onClick={() => setGallery(true)}>
            <LayoutGrid size={14} aria-hidden="true" /> Ready-made
          </button>
          <button className="button button-primary" onClick={() => setEditing({ index: null, rule: { enabled: true, action: { route: "" } } })}>
            <Plus size={14} aria-hidden="true" /> Add rule
          </button>
        </div>
      </div>

      {listLinks !== "" && <ListsBar config={config} progress={listsProgress} connected={connected} onUpdate={updateLists} />}

      {!config.network.transparent_routing && (
        <div className="inline-alert inline-alert-warn" role="alert">
          Rules only work while Outbounds are on. Right now devices use this computer's internet directly and no rule applies.{" "}
          <button
            className="link-button"
            disabled={busy}
            onClick={() =>
              void saveConfig((c) => {
                c.network.transparent_routing = true;
              }, "Outbounds turned on")
            }
          >
            Turn on
          </button>
        </div>
      )}

      {rules.length > 0 && <RuleTester config={config} clients={clients} devices={devices} lists={lists} connected={connected} rulesKey={rulesKey} />}

      {rules.length === 0 ? (
        <Empty>No rules yet. All traffic goes out through each device's outbound.</Empty>
      ) : (
        <ol className="rule-list">
          {rules.map((rule, i) => {
            // A rule that is off decides nothing, so it shows no count.
            const used = rule.enabled ? hits[i] : undefined;
            return (
              <RuleRow
                key={keys[i]}
                rule={rule}
                index={i}
                last={i === rules.length - 1}
                parts={summaries[i] ?? []}
                action={actionLabel(rule.action, config)}
                hits={used ? hitsLabel(used) : null}
                busy={busy}
                onToggle={toggle}
                onMove={move}
                onEdit={edit}
                onDelete={setDeleting}
              />
            );
          })}
        </ol>
      )}

      {gallery && (
        <TemplateGallery
          rules={rules}
          onClose={() => setGallery(false)}
          onPick={(template) => {
            setGallery(false);
            setEditing({ index: null, rule: ruleFromTemplate(template, config), title: `Add ${template.name}` });
          }}
        />
      )}
      {editing && (
        <RuleEditor
          initial={editing.rule}
          title={editing.title ?? (editing.index === null ? "Add rule" : `Edit rule ${editing.index + 1}`)}
          config={config}
          devices={devices}
          lists={lists}
          onClose={() => setEditing(null)}
          onSave={async (rule) => {
            const index = editing.index;
            const ok = await update((list) => {
              if (index === null) list.push(rule);
              else list[index] = rule;
            }, index === null ? "Rule added" : "Rule updated");
            if (ok) setEditing(null);
          }}
        />
      )}
      {deleting !== null && (
        <ConfirmDialog
          title="Delete rule"
          confirmLabel="Delete"
          danger
          onCancel={() => setDeleting(null)}
          onConfirm={() => {
            const index = deleting;
            setDeleting(null);
            void update((list) => void list.splice(index, 1), "Rule deleted");
          }}
        >
          Delete rule {deleting + 1}
          {rules[deleting]?.name ? ` (${rules[deleting]?.name})` : ""}?
        </ConfirmDialog>
      )}
    </div>
  );
}

/**
 * Online lists: how many there are and what they hold, and the button that
 * downloads them all again, through an outbound of the user's choosing (a
 * source may be filtered on the direct way out). Nothing is ever downloaded
 * without that button. The service downloads them in the background, one
 * after another, and the bar shows how far it is until the last is through;
 * what the update came to is told in a toast (see ListsProvider).
 */
function ListsBar({
  config,
  progress,
  connected,
  onUpdate,
}: {
  config: Config;
  progress: ListsProgress;
  connected: boolean;
  onUpdate: (through: string) => Promise<void>;
}) {
  const id = useId();
  const choices = usableEgresses(config).filter((e) => e.type !== "block");
  const [through, setThrough] = useState(config.network.default_egress);
  // From the press until the service answers; from then on, the service says.
  const [starting, setStarting] = useState(false);
  const updating = starting || progress.updating;
  const howFar = progress.updating && progress.total > 0 ? `Updating… ${progress.done} of ${progress.total} lists done` : "Updating…";
  const { lists } = progress;
  const failed = lists.filter((l) => l.error);
  const downloaded = lists.filter((l) => l.updated_ms !== null);
  const oldest = downloaded.reduce<number | null>((min, l) => (min === null || (l.updated_ms ?? 0) < min ? l.updated_ms : min), null);
  const names = lists.reduce((n, l) => n + l.names, 0);
  const addresses = lists.reduce((n, l) => n + l.addresses, 0);

  const update = async () => {
    setStarting(true);
    try {
      await onUpdate(through);
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="lists-bar">
      <div className="lists-bar-text">
        <ListChecks size={16} aria-hidden="true" />
        <span>
          <strong>
            {lists.length} online {lists.length === 1 ? "list" : "lists"}
          </strong>
          {names + addresses > 0
            ? [names > 0 ? `${names.toLocaleString()} websites` : "", addresses > 0 ? `${addresses.toLocaleString()} address ranges` : ""]
                .filter(Boolean)
                .map((part) => ` · ${part}`)
                .join("")
            : " · not downloaded yet"}
          {oldest !== null && ` · updated ${formatAgo(oldest)}`}
          {failed.length > 0 && <span className="field-error"> · {failed.length} failed</span>}
        </span>
      </div>
      <div className="lists-bar-actions">
        <label className="muted" htmlFor={`${id}-through`}>
          Download through
        </label>
        <select id={`${id}-through`} value={through} disabled={updating} onChange={(e) => setThrough(e.target.value)}>
          {!choices.some((e) => e.id === through) && <option value={through}>{egressLabel(config, through)}</option>}
          {choices.map((e) => (
            <option key={e.id} value={e.id}>
              {egressName(e)}
            </option>
          ))}
        </select>
        <button
          className="button"
          disabled={updating || !connected}
          title={connected ? "Download every list again now" : "Lists are downloaded by the service; start it first"}
          onClick={() => void update()}
        >
          <RefreshCw size={14} aria-hidden="true" className={updating ? "spin" : undefined} /> {updating ? howFar : "Update lists"}
        </button>
        {/* The button is off while updating, so screen readers hear how far it is from here. */}
        <span className="visually-hidden" role="status">
          {progress.updating ? howFar : ""}
        </span>
      </div>
    </div>
  );
}

/** A rule as the tester's answer names it: its own name, else "Rule N". */
function ruleName(config: Config, index: number): string {
  return config.rule?.[index]?.name ?? `Rule ${index + 1}`;
}

/** What a lookup does, in words: "through Office proxy, by Telegram". */
function lookupWords(outcome: LookupOutcome, config: Config, usual: string): ReactNode {
  const rule = outcome.rule === null ? null : <strong>{ruleName(config, outcome.rule)}</strong>;
  if (outcome.blocked) return <>blocked{rule && <> by {rule}</>}</>;
  const through = <strong>{egressLabel(config, outcome.egress)}</strong>;
  return rule ? (
    <>
      through {through}, by {rule}
    </>
  ) : (
    <>
      through {through}, {usual} (no rule fits)
    </>
  );
}

/**
 * What a connection does, in words: "refused by No ads". When the rules'
 * outbound sends games and calls another way, or carries none, the answer
 * says so: "refused: Telegram sends it to Office proxy, which does not carry
 * games and calls".
 */
function connectionWords(outcome: ConnectionOutcome, config: Config, usual: string): ReactNode {
  const rule = outcome.rule === null ? null : <strong>{ruleName(config, outcome.rule)}</strong>;
  // Stopped by the rules themselves.
  if (outcome.egress === null) {
    if (outcome.verdict === "deny") return <>blocked silently{rule && <> by {rule}</>}</>;
    if (outcome.verdict === "reject") return <>refused{rule && <> by {rule}</>}</>;
  }
  if (outcome.carried_by === outcome.egress) {
    return lookupWords({ blocked: false, egress: outcome.egress, rule: outcome.rule }, config, usual);
  }
  const chosen = <strong>{egressLabel(config, outcome.egress)}</strong>;
  const sent = rule ? (
    <>
      {rule} sends it to {chosen}
    </>
  ) : (
    <>
      {usual} is {chosen}
    </>
  );
  const noRule = rule ? null : " (no rule fits)";
  if (outcome.carried_by !== null) {
    const carrier = <strong>{egressLabel(config, outcome.carried_by)}</strong>;
    return (
      <>
        through {carrier}: {sent}, which uses {carrier} for games and calls{noRule}
      </>
    );
  }
  return outcome.verdict === "reject" ? (
    <>
      refused: {sent}, which does not carry games and calls{noRule}
    </>
  ) : (
    <>
      blocked silently: {sent}, which is not available{noRule}
    </>
  );
}

function sameOutcome(a: ConnectionOutcome, b: ConnectionOutcome): boolean {
  return a.verdict === b.verdict && a.egress === b.egress && a.carried_by === b.carried_by && a.rule === b.rule;
}

/** Why none of a device's traffic gets through whatever the rules say, if so. */
function heldBack(config: Config, clients: ClientView[], mac: string): string | null {
  const live = clients.find((c) => c.mac === mac);
  const state = config.client?.find((p) => p.mac === mac)?.state ?? live?.state ?? "pending";
  if (state === "blocked") return "This device is blocked, so none of its traffic gets through, whatever the rules say.";
  if (live?.over_limit) return "The hotspot is full, so this device waits for a free place before any of this applies.";
  if (state === "pending" && config.network.quarantine_new_clients) return "This device waits for your approval, so none of its traffic gets through yet.";
  return null;
}

/**
 * "Which rule applies?": what the rules do with a website or an address, for
 * one device or any, as they stand right now. The service answers by the
 * rules alone; nothing is looked up, sent or counted.
 */
function RuleTester({
  config,
  clients,
  devices,
  lists,
  connected,
  rulesKey,
}: {
  config: Config;
  clients: ClientView[];
  /** The devices to pick from, by name. */
  devices: KnownDevice[];
  lists: ListStatus[];
  connected: boolean;
  rulesKey: string;
}) {
  const id = useId();
  const [target, setTarget] = useState("");
  const [device, setDevice] = useState("");
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState<Protocol>("tcp");
  const [testing, setTesting] = useState(false);
  const [answer, setAnswer] = useState<{ result: RuleTestResult; device: string } | { error: string } | null>(null);
  // An answer names rules by their place, which a change to the rules shifts.
  useEffect(() => setAnswer(null), [rulesKey]);

  const chosen = devices.some((d) => d.mac === device) ? device : "";
  // The same elements while the devices stay the same, so redraws skip them.
  const deviceOptions = useMemo(
    () =>
      devices.map((d) => (
        <option key={d.mac} value={d.mac}>
          {d.name}
        </option>
      )),
    [devices],
  );
  const portText = port.trim();
  const portNumber = /^\d{1,5}$/.test(portText) ? Number(portText) : NaN;
  const portError = portText === "" || (portNumber >= 1 && portNumber <= 65535) ? null : "A port is a number from 1 to 65535.";
  const ready = connected && !testing && target.trim() !== "" && portError === null;

  const test = async (event: FormEvent) => {
    event.preventDefault();
    if (!ready) return;
    setTesting(true);
    try {
      const result = await api.testRules(target.trim(), chosen || null, portText === "" ? null : portNumber, protocol);
      setAnswer({ result, device: chosen });
    } catch (e) {
      setAnswer({ error: errorMessage(e) });
    } finally {
      setTesting(false);
    }
  };

  let outcome: ReactNode = null;
  if (!connected) {
    outcome = <span className="field-hint">The service answers this; start it to test the rules.</span>;
  } else if (portError) {
    outcome = <span className="field-error">{portError}</span>;
  } else if (answer && "error" in answer) {
    outcome = <span className="field-error">{answer.error}</span>;
  } else if (answer) {
    const { result } = answer;
    const usual = answer.device ? "the device's usual way" : "the default outbound";
    const note = answer.device ? heldBack(config, clients, answer.device) : null;
    // Each device's connections go by the websites its own lookups named; for
    // any device, the service answers with the name a device looked up.
    const asker = answer.device ? "this device" : "a device";
    const whose = answer.device ? "this device" : "their own device";
    const learnedHint = `Connections that do not say which website they are for (such as QUIC) go by the website ${whose} last looked this address up as.`;
    const learned = result.learned_name && result.by_learned_name && !sameOutcome(result.connection, result.by_learned_name) ? result.by_learned_name : null;
    // A website is tested by its name alone: nothing is looked up for it.
    const byAddress =
      result.name !== null &&
      (config.rule ?? []).some(
        (r) => r.enabled && ((r.cidrs?.length ?? 0) > 0 || (r.lists ?? []).some((link) => (lists.find((l) => l.url === link)?.addresses ?? 0) > 0)),
      );
    outcome = (
      <ul className="rule-test-result" aria-live="polite">
        {result.lookup && (
          <li>
            <span className="muted">Looking it up:</span> {lookupWords(result.lookup, config, usual)}
          </li>
        )}
        <li>
          <span className="muted">
            Connecting on port {result.port} ({result.protocol === "udp" ? "UDP" : "TCP"}):
          </span>{" "}
          {connectionWords(result.connection, config, usual)}
        </li>
        {learned && (
          <li title={learnedHint}>
            <span className="muted">
              As <strong>{result.learned_name}</strong>, the website {asker} last looked it up as:
            </span>{" "}
            {connectionWords(learned, config, usual)}
          </li>
        )}
        {byAddress && <li className="field-hint">Rules about addresses are checked only when you test an address.</li>}
        {note && <li className="field-hint">{note}</li>}
      </ul>
    );
  }

  return (
    <form className="rule-test" onSubmit={(e) => void test(e)}>
      <div className="rule-test-form">
        <label className="rule-test-label" htmlFor={`${id}-target`}>
          <FlaskConical size={14} aria-hidden="true" /> Which rule applies?
        </label>
        <input
          id={`${id}-target`}
          className="rule-test-target"
          value={target}
          disabled={!connected}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="Website or address, e.g. instagram.com or 1.2.3.4"
          spellCheck={false}
          autoComplete="off"
        />
        <select value={chosen} disabled={!connected} aria-label="Device" onChange={(e) => setDevice(e.target.value)}>
          <option value="">Any device</option>
          {deviceOptions}
        </select>
        <input
          className="rule-test-port"
          value={port}
          disabled={!connected}
          onChange={(e) => setPort(e.target.value)}
          placeholder="Port"
          aria-label="Port"
          title="Port: when left empty, the one typed with the website (as in example.com:8080), else 443 (secure websites)"
          inputMode="numeric"
        />
        <select value={protocol} disabled={!connected} aria-label="Protocol" onChange={(e) => setProtocol(e.target.value as Protocol)}>
          <option value="tcp">TCP (web and apps)</option>
          <option value="udp">UDP (games and calls)</option>
        </select>
        <button type="submit" className="button" disabled={!ready} title={connected ? "Show what the rules do with it right now" : "Start the service to test the rules"}>
          {testing ? "Testing…" : "Test"}
        </button>
      </div>
      {outcome}
    </form>
  );
}

/** Ready-made rules by kind; picking one opens it in the editor, to adjust before it is added. */
function TemplateGallery({ rules, onPick, onClose }: { rules: RuleConfig[]; onPick: (template: RuleTemplate) => void; onClose: () => void }) {
  const added = new Set(rules.map((r) => r.name));
  return (
    <Modal title="Ready-made rules" onClose={onClose} wide>
      <div className="templates">
        {TEMPLATE_GROUPS.map(({ group, hint }) => (
          <section key={group} className="templates-group">
            <h3>{group}</h3>
            <p className="field-hint">{hint}</p>
            <div className="templates-grid">
              {RULE_TEMPLATES.filter((t) => t.group === group).map((t) => (
                <button key={t.id} type="button" className="template" onClick={() => onPick(t)}>
                  <span className="template-name">
                    {t.name}
                    {added.has(t.name) && <Pill tone="muted">added</Pill>}
                  </span>
                  <span className="template-about">{t.about}</span>
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>
    </Modal>
  );
}

/** Under a pasted list: how many entries it holds, or the first few that are wrong. */
function EntriesStatus({ check, one, many, hint }: { check: Checked; one: string; many: string; hint: string }) {
  if (check.errors.length > 0) {
    const more = check.errors.length > 3 ? ` (and ${check.errors.length - 3} more)` : "";
    return <span className="field-error">{check.errors.slice(0, 3).join(" ") + more}</span>;
  }
  const n = check.values.length;
  return (
    <span className="field-hint">
      {n > 0 ? `${n} ${n === 1 ? one : many} · ` : ""}
      {hint}
    </span>
  );
}

type ActionKind = "allow" | "deny" | "reject" | "route";

const ACTIONS: { kind: ActionKind; label: string; icon: ComponentType<LucideProps>; hint: string }[] = [
  { kind: "allow", label: "Allow", icon: Check, hint: "Lets it through the device's usual outbound." },
  { kind: "deny", label: "Block", icon: Ban, hint: "Drops it quietly; the app keeps waiting until it gives up." },
  { kind: "reject", label: "Refuse", icon: CircleSlash, hint: "Blocks it and tells the app right away, so it stops waiting." },
  { kind: "route", label: "Send another way", icon: Route, hint: "Sends it through the outbound picked below." },
];

/** Chosen devices as removable chips, plus ways to add more. */
function DevicePicker({
  macs,
  known,
  onChange,
  labelledBy,
}: {
  macs: string[];
  known: KnownDevice[];
  onChange: (macs: string[]) => void;
  labelledBy: string;
}) {
  const [typed, setTyped] = useState("");
  const typedError = typed.trim() === "" ? null : validateMac(typed);
  const nameOf = (mac: string) => known.find((k) => k.mac === mac)?.name ?? mac;
  const add = (mac: string) => {
    const m = normalizeMac(mac);
    if (!macs.includes(m)) onChange([...macs, m]);
  };
  const addTyped = () => {
    if (typed.trim() === "" || typedError) return;
    add(typed);
    setTyped("");
  };
  const choices = known.filter((k) => !macs.includes(k.mac));

  return (
    <div className="picker-cell">
      <div className="picker" role="group" aria-labelledby={labelledBy}>
        {macs.length === 0 && <span className="picker-any">Any device</span>}
        {macs.map((mac) => (
          <span key={mac} className="chip" title={mac}>
            {nameOf(mac)}
            <button type="button" className="chip-remove" aria-label={`Remove ${nameOf(mac)}`} onClick={() => onChange(macs.filter((m) => m !== mac))}>
              <X size={11} />
            </button>
          </span>
        ))}
        {choices.length > 0 && (
          <select
            className="picker-add"
            value=""
            aria-label="Add a device"
            onChange={(e) => {
              if (e.target.value) add(e.target.value);
            }}
          >
            <option value="">{macs.length ? "Add another…" : "Pick a device…"}</option>
            {choices.map((c) => (
              <option key={c.mac} value={c.mac}>
                {c.name === c.mac ? c.mac : `${c.name} (${c.mac})`}
              </option>
            ))}
          </select>
        )}
        <span className="picker-type">
          <input
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addTyped();
              }
            }}
            placeholder="or type a hardware address"
            aria-label="Hardware address to add"
            spellCheck={false}
          />
          <button type="button" className="icon-button" aria-label="Add this address" disabled={typed.trim() === "" || !!typedError} onClick={addTyped}>
            <Plus size={14} />
          </button>
        </span>
      </div>
      {typedError && <span className="field-error">{typedError}</span>}
    </div>
  );
}

interface EditorProps {
  initial: RuleConfig;
  title: string;
  config: Config;
  /** The devices to pick from, by name. */
  devices: KnownDevice[];
  /** How the online lists stand, for the lines under their links. */
  lists: ListStatus[];
  onClose: () => void;
  onSave: (rule: RuleConfig) => Promise<void>;
}

/** One line per link: what its copy holds, or why there is none. */
function LinkStatuses({ links, lists }: { links: string[]; lists: ListStatus[] }) {
  if (links.length === 0) {
    return <span className="field-hint">Links to lists of websites or addresses (hosts files, adblock lists, plain lists). Downloaded only with Update lists.</span>;
  }
  return (
    <ul className="link-statuses">
      {links.map((link) => {
        const status = lists.find((l) => l.url === link);
        const held = status && status.names + status.addresses > 0;
        return (
          <li key={link} className={status?.error ? "field-error" : "field-hint"} title={link}>
            <span className="link-host">{link.replace(/^https?:\/\//, "").split("/")[0]}</span>
            {" · "}
            {held
              ? [status.names > 0 ? `${status.names.toLocaleString()} websites` : "", status.addresses > 0 ? `${status.addresses.toLocaleString()} ranges` : ""]
                  .filter(Boolean)
                  .join(" · ")
              : "not downloaded yet"}
            {held && status.updated_ms !== null && ` · ${formatAgo(status.updated_ms)}`}
            {status?.error && ` · ${status.error}`}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * One rule in three plain steps: what to do, which traffic it is about, and
 * when. Less common conditions (IP ranges, ports, groups) stay folded until
 * needed, so the usual rule fits without scrolling.
 */
function RuleEditor({ initial, title, config, devices, lists, onClose, onSave }: EditorProps) {
  const id = useId();
  const [name, setName] = useState(initial.name ?? "");
  const [enabled, setEnabled] = useState(initial.enabled);
  const [macs, setMacs] = useState<string[]>((initial.clients ?? []).map(normalizeMac));
  const [groups, setGroups] = useState<string[]>(initial.groups ?? []);
  const [domains, setDomains] = useState((initial.domains ?? []).join("\n"));
  const [cidrs, setCidrs] = useState((initial.cidrs ?? []).join("\n"));
  const [links, setLinks] = useState((initial.lists ?? []).join("\n"));
  const [ports, setPorts] = useState((initial.ports ?? []).map(String).join(", "));
  const [protocol, setProtocol] = useState<Protocol | "">(initial.protocol ?? "");
  const [more, setMore] = useState(
    Boolean(
      initial.cidrs?.length || initial.lists?.length || initial.ports?.length || initial.protocol || initial.groups?.length || typeof initial.action === "object",
    ),
  );
  const [scheduled, setScheduled] = useState(initial.schedule != null);
  const [days, setDays] = useState<Weekday[]>(initial.schedule?.days ?? []);
  const [start, setStart] = useState(initial.schedule?.start ?? "22:00");
  const [end, setEnd] = useState(initial.schedule?.end ?? "07:00");
  const [actionKind, setActionKind] = useState<ActionKind>(typeof initial.action === "object" ? "route" : initial.action);
  const egressChoices = usableEgresses(config);
  const [route, setRoute] = useState(typeof initial.action === "object" && initial.action.route ? initial.action.route : (egressChoices[0]?.id ?? ""));
  const [saving, setSaving] = useState(false);

  const domainCheck = checkDomains(domains);
  const rangeCheck = checkRanges(cidrs);
  const linkCheck = checkLinks(links);
  const portErrors = tokens(ports).map(validatePort).filter((e): e is string => e !== null);
  const scheduleError = scheduled ? (validateClock(start) ?? validateClock(end)) : null;
  const routeOff = route !== "" && !egressChoices.some((e) => e.id === route);
  const routeError =
    actionKind !== "route"
      ? null
      : route === ""
        ? "Choose an outbound."
        : routeOff
          ? "This outbound is turned off; pick another or turn it on under Outbound."
          : null;
  const conditions =
    macs.length +
    groups.length +
    domainCheck.values.length +
    rangeCheck.values.length +
    linkCheck.values.length +
    tokens(ports).length +
    (protocol === "" ? 0 : 1) +
    (scheduled ? 1 : 0);
  const blocksEverything = conditions === 0 && (actionKind === "deny" || actionKind === "reject");
  const invalid =
    portErrors.length > 0 ||
    !!scheduleError ||
    !!routeError ||
    domainCheck.errors.length > 0 ||
    rangeCheck.errors.length > 0 ||
    linkCheck.errors.length > 0 ||
    blocksEverything;
  const groupList = config.group ?? [];
  const action = ACTIONS.find((a) => a.kind === actionKind);

  const build = (): RuleConfig => {
    const portList: PortRange[] = tokens(ports).map((p) => (/^\d+$/.test(p) ? Number(p) : p.replace(/\s+/g, "")));
    const schedule: Schedule | undefined = scheduled ? { days: optList(days), start, end } : undefined;
    const ruleAction: RuleAction = actionKind === "route" ? { route } : actionKind;
    return {
      name: opt(name),
      enabled,
      clients: optList(macs),
      groups: optList(groups),
      domains: optList(domainCheck.values),
      cidrs: optList(rangeCheck.values),
      lists: optList(linkCheck.values),
      ports: optList(portList),
      protocol: protocol === "" ? undefined : protocol,
      schedule,
      action: ruleAction,
    };
  };

  return (
    <Modal
      title={title}
      onClose={onClose}
      wide
      footer={
        <>
          <button className="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button button-primary"
            disabled={invalid || saving}
            onClick={async () => {
              setSaving(true);
              await onSave(build());
              setSaving(false);
            }}
          >
            Save
          </button>
        </>
      }
    >
      <div className="rule-rows">
        <label className="rule-label" htmlFor={`${id}-name`}>
          Name
        </label>
        <div className="rule-inline">
          <input id={`${id}-name`} data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. No social media at night" />
          <Toggle label="On" checked={enabled} onChange={setEnabled} />
        </div>

        <span className="rule-label" id={`${id}-do`}>
          What to do
        </span>
        <div className="rule-cell">
          <div className="choices" role="radiogroup" aria-labelledby={`${id}-do`}>
            {ACTIONS.map((a) => (
              <label key={a.kind} className={`choice choice-${a.kind}`}>
                <input
                  type="radio"
                  name={`${id}-action`}
                  value={a.kind}
                  checked={actionKind === a.kind}
                  onChange={() => {
                    setActionKind(a.kind);
                    // Sending addresses another way is what the folded fields are for.
                    if (a.kind === "route") setMore(true);
                  }}
                />
                <a.icon size={14} aria-hidden="true" />
                {a.label}
              </label>
            ))}
          </div>
          {actionKind === "route" ? (
            <div className="rule-inline rule-route">
              <label className="muted" htmlFor={`${id}-route`}>
                Through
              </label>
              <select id={`${id}-route`} value={route} onChange={(e) => setRoute(e.target.value)}>
                {routeOff && <option value={route}>{egressLabel(config, route)} (off)</option>}
                {egressChoices.map((e) => (
                  <option key={e.id} value={e.id}>
                    {egressName(e)}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <span className="field-hint">{action?.hint}</span>
          )}
          {routeError && <span className="field-error">{routeError}</span>}
          {blocksEverything && (
            <span className="field-error">Add at least one condition below: as it is, this would cut off all traffic of every device.</span>
          )}
        </div>

        <p className="rule-divider">
          <span>Applies to</span> empty fields match everything; every filled-in field must match, but websites, addresses and lists count as
          one: going to any of them is enough
        </p>

        <span className="rule-label" id={`${id}-devices`}>
          Devices
        </span>
        <DevicePicker macs={macs} known={devices} onChange={setMacs} labelledBy={`${id}-devices`} />

        <label className="rule-label" htmlFor={`${id}-domains`}>
          Websites
        </label>
        <div className="rule-cell">
          <textarea id={`${id}-domains`} rows={3} value={domains} onChange={(e) => setDomains(e.target.value)} spellCheck={false} placeholder="e.g. instagram.com, youtube.com" />
          <EntriesStatus check={domainCheck} one="website" many="websites" hint="Subdomains included · full:a.example.com exact name only · keyword:ads names with it" />
        </div>

        {more ? (
          <>
            {groupList.length > 0 && (
              <>
                <span className="rule-label" id={`${id}-groups`}>
                  Groups
                </span>
                <div className="chip-toggles" role="group" aria-labelledby={`${id}-groups`}>
                  {groupList.map((g) => (
                    <label key={g.id} className="chip-toggle">
                      <input
                        type="checkbox"
                        checked={groups.includes(g.id)}
                        onChange={(e) => setGroups((list) => (e.target.checked ? [...list, g.id] : list.filter((x) => x !== g.id)))}
                      />
                      {g.name ?? g.id}
                    </label>
                  ))}
                </div>
              </>
            )}
            <label className="rule-label" htmlFor={`${id}-cidrs`}>
              Going to
            </label>
            <div className="rule-cell">
              <textarea
                id={`${id}-cidrs`}
                rows={4}
                value={cidrs}
                onChange={(e) => setCidrs(e.target.value)}
                spellCheck={false}
                placeholder="Addresses or IP ranges, e.g. 1.2.3.4, 10.0.0.0/8, 2001:db8::/32"
              />
              <EntriesStatus check={rangeCheck} one="address or range" many="addresses and ranges" hint="Where the traffic goes, not which device sends it. Separate with new lines, commas or spaces." />
            </div>

            <label className="rule-label" htmlFor={`${id}-lists`}>
              Online lists
            </label>
            <div className="rule-cell">
              <textarea
                id={`${id}-lists`}
                rows={2}
                value={links}
                onChange={(e) => setLinks(e.target.value)}
                spellCheck={false}
                placeholder="https://… one link per line"
              />
              {linkCheck.errors.length > 0 ? <span className="field-error">{linkCheck.errors[0]}</span> : <LinkStatuses links={linkCheck.values} lists={lists} />}
            </div>

            <label className="rule-label" htmlFor={`${id}-ports`}>
              Ports
            </label>
            <div className="rule-cell">
              <div className="rule-inline">
                <input id={`${id}-ports`} value={ports} onChange={(e) => setPorts(e.target.value)} spellCheck={false} placeholder="e.g. 443, 8000-8999" />
                <select className="rule-protocol" value={protocol} aria-label="Protocol" onChange={(e) => setProtocol(e.target.value as Protocol | "")}>
                  <option value="">TCP and UDP</option>
                  <option value="tcp">TCP only (web and apps)</option>
                  <option value="udp">UDP only (games and calls)</option>
                </select>
              </div>
              {portErrors[0] && <span className="field-error">{portErrors[0]}</span>}
            </div>
          </>
        ) : (
          <>
            <span />
            <button type="button" className="link-button rule-more" onClick={() => setMore(true)}>
              <ChevronRight size={13} aria-hidden="true" />
              More: addresses and IP ranges, online lists, ports{groupList.length > 0 ? ", groups" : ""}
            </button>
          </>
        )}

        <span className="rule-label rule-label-when" id={`${id}-when`}>
          When
        </span>
        <div className="rule-cell" role="group" aria-labelledby={`${id}-when`}>
          <Toggle label="Only at certain times" checked={scheduled} onChange={setScheduled} />
          {scheduled && (
            <>
              <div className="chip-toggles" role="group" aria-label="Days">
                {WEEKDAYS.map((d) => (
                  <label key={d} className="chip-toggle">
                    <input
                      type="checkbox"
                      checked={days.includes(d)}
                      onChange={(e) => setDays((list) => (e.target.checked ? WEEKDAYS.filter((x) => x === d || list.includes(x)) : list.filter((x) => x !== d)))}
                    />
                    {DAY_SHORT[d]}
                  </label>
                ))}
                {days.length === 0 && <span className="field-hint">none picked: every day</span>}
              </div>
              <div className="rule-inline rule-times">
                <span className="muted">From</span>
                <input type="time" value={start} onChange={(e) => setStart(e.target.value)} aria-label="From" />
                <span className="muted">until</span>
                <input type="time" value={end} onChange={(e) => setEnd(e.target.value)} aria-label="Until" />
              </div>
              {scheduleError ? (
                <span className="field-error">{scheduleError}</span>
              ) : (
                <span className="field-hint">An end earlier than the start runs past midnight.</span>
              )}
            </>
          )}
        </div>
      </div>
    </Modal>
  );
}
