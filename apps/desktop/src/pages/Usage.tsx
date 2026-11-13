import { type RefObject, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { BarChart3, CircleAlert } from "lucide-react";
import { api, errorMessage } from "../api";
import { deviceName } from "../configUtils";
import { Card, EmptyState } from "../components/Form";
import { describeUse } from "../components/QuotaFields";
import { formatBytes } from "../format";
import { useNav } from "../nav";
import { useClients, useServiceCore } from "../service";
import type { ClientView, MacAddr, UsageReport } from "../types";

type Period = "today" | "7d" | "30d" | "month" | "custom";

const PERIOD_LABEL: Record<Period, string> = {
  today: "Today",
  "7d": "7 days",
  "30d": "30 days",
  month: "This month",
  custom: "Pick days",
};

/** The span asked about: its bounds (local midnights, or hours for one day) and how each stretch is named. */
interface Span {
  bounds: number[];
  hourly: boolean;
}

/** The choices last made, kept while the app runs. */
let remembered: { period: Period; device: MacAddr | ""; from: string; to: string } | null = null;

function midnight(d: Date, plusDays = 0): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + plusDays);
}

/** "2026-11-13" for a date input. */
function dateValue(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function parseDate(value: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : null;
}

/** Each local hour of `day`; an hour the clocks skip comes out once. */
function hoursOf(day: Date): number[] {
  const out: number[] = [];
  for (let h = 0; h <= 24; h++) {
    const t = new Date(day.getFullYear(), day.getMonth(), day.getDate(), h).getTime();
    if (out.length === 0 || t > out[out.length - 1]!) out.push(t);
  }
  return out;
}

function daysFrom(first: Date, count: number): number[] {
  return Array.from({ length: count + 1 }, (_, i) => midnight(first, i).getTime());
}

/** Most days one question may cover; the service keeps a little over a year. */
const MAX_DAYS = 400;

function spanOf(period: Period, from: string, to: string, now = new Date()): Span | null {
  const today = midnight(now);
  switch (period) {
    case "today":
      return { bounds: hoursOf(today), hourly: true };
    case "7d":
      return { bounds: daysFrom(midnight(today, -6), 7), hourly: false };
    case "30d":
      return { bounds: daysFrom(midnight(today, -29), 30), hourly: false };
    case "month": {
      const first = new Date(today.getFullYear(), today.getMonth(), 1);
      const days = new Date(today.getFullYear(), today.getMonth() + 1, 0).getDate();
      return { bounds: daysFrom(first, days), hourly: false };
    }
    case "custom": {
      const a = parseDate(from);
      const b = parseDate(to);
      if (!a || !b || b < a) return null;
      const days = Math.round((midnight(b, 1).getTime() - a.getTime()) / 86_400_000);
      if (days > MAX_DAYS) return null;
      return days === 1 ? { bounds: hoursOf(a), hourly: true } : { bounds: daysFrom(a, days), hourly: false };
    }
  }
}

const HOUR = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
const DAY = new Intl.DateTimeFormat(undefined, { weekday: "short", day: "numeric", month: "short" });
const DAY_SHORT = new Intl.DateTimeFormat(undefined, { day: "numeric" });

function stretchName(span: Span, i: number): string {
  const start = span.bounds[i] ?? 0;
  if (!span.hourly) return DAY.format(start);
  return `${HOUR.format(start)}–${HOUR.format(span.bounds[i + 1] ?? start)}`;
}

/**
 * How much the devices used over a stretch of time: per hour for a day, per
 * day for longer, for every device together or one of them, and what each
 * device used. Counted while devices are routed through Captun, and kept for
 * a little over a year.
 */
export function Usage() {
  const { connected, config, saveConfig } = useServiceCore();
  const clients = useClients();
  const nav = useNav();
  const [period, setPeriod] = useState<Period>(remembered?.period ?? "today");
  const [device, setDevice] = useState<MacAddr | "">(remembered?.device ?? "");
  const [from, setFrom] = useState(remembered?.from ?? dateValue(midnight(new Date(), -6)));
  const [to, setTo] = useState(remembered?.to ?? dateValue(new Date()));
  const [report, setReport] = useState<UsageReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [table, setTable] = useState(false);
  // The day changes at midnight: the spans are worked out again then.
  const [day, setDay] = useState(() => dateValue(new Date()));

  useEffect(() => {
    remembered = { period, device, from, to };
  }, [period, device, from, to]);

  // `day` is there to work the spans out again after midnight.
  const span = useMemo(() => spanOf(period, from, to, new Date(day + "T12:00")), [period, from, to, day]);

  const load = useCallback(async () => {
    setDay(dateValue(new Date()));
    if (!span) return;
    try {
      setReport(await api.getUsage(span.bounds, device === "" ? null : device));
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, [span, device]);

  useEffect(() => {
    if (!connected) return;
    void load();
    // Fresh numbers twice a minute while the page is open.
    const timer = window.setInterval(() => void load(), 30_000);
    return () => window.clearInterval(timer);
  }, [connected, load]);

  const byMac = useMemo(() => new Map(clients.map((c) => [c.mac, c])), [clients]);
  const name = (mac: MacAddr) => {
    const c = byMac.get(mac);
    return c ? deviceName(c) : mac;
  };

  if (!connected) {
    return (
      <EmptyState icon={BarChart3} title="No usage to show yet" action={<button className="button button-primary" onClick={() => nav("home")}>Start sharing</button>}>
        Captun counts what each device uses while it shares this computer's internet.
      </EmptyState>
    );
  }

  const totals = report?.buckets.reduce((sum, b) => ({ down: sum.down + b.down, up: sum.up + b.up }), { down: 0, up: 0 }) ?? { down: 0, up: 0 };
  const deviceChoices = [...clients].sort((a, b) => deviceName(a).localeCompare(deviceName(b)));
  const customError = period === "custom" && !span ? `Pick a first day on or before the last, at most ${MAX_DAYS} days apart.` : null;

  return (
    <div className="page">
      <div className="toolbar usage-toolbar">
        <div className="segmented" role="group" aria-label="Time">
          {(Object.keys(PERIOD_LABEL) as Period[]).map((p) => (
            <button key={p} aria-pressed={period === p} onClick={() => setPeriod(p)}>
              {PERIOD_LABEL[p]}
            </button>
          ))}
        </div>
        <select aria-label="Device" value={device} onChange={(e) => setDevice(e.target.value)} className="usage-device">
          <option value="">All devices</option>
          {device !== "" && !byMac.has(device) && <option value={device}>{device}</option>}
          {deviceChoices.map((c) => (
            <option key={c.mac} value={c.mac}>
              {deviceName(c)}
            </option>
          ))}
        </select>
      </div>
      {period === "custom" && (
        <div className="usage-range">
          <label>
            From <input type="date" value={from} max={to} onChange={(e) => setFrom(e.target.value)} />
          </label>
          <label>
            to <input type="date" value={to} min={from} onChange={(e) => setTo(e.target.value)} />
          </label>
          {customError && <span className="field-error">{customError}</span>}
        </div>
      )}

      {config && !config.network.transparent_routing && (
        <div className="inline-alert inline-alert-warn" role="alert">
          <CircleAlert size={14} aria-hidden="true" /> Use is counted only while devices are routed through Captun; right now they use this
          computer's internet directly.{" "}
          <button className="link-button" onClick={() => void saveConfig((c) => void (c.network.transparent_routing = true), "Outbounds turned on")}>
            Turn on
          </button>
        </div>
      )}
      {error && (
        <div className="inline-alert inline-alert-danger" role="alert">
          Could not read the data use: {error}
        </div>
      )}

      <div className="usage-tiles">
        <Tile label="Downloaded" value={totals.down} swatch="down" />
        <Tile label="Uploaded" value={totals.up} swatch="up" />
        <Tile label="Together" value={totals.down + totals.up} />
      </div>

      <Card
        title={span?.hourly ? "Use per hour" : "Use per day"}
        actions={
          <button className="link-button" onClick={() => setTable((t) => !t)} aria-pressed={table}>
            {table ? "Show chart" : "Show as table"}
          </button>
        }
      >
        {span && report && report.buckets.length === span.bounds.length - 1 ? (
          table ? (
            <StretchTable span={span} report={report} />
          ) : (
            <UsageChart span={span} report={report} />
          )
        ) : (
          <p className="muted">{customError ?? "Loading…"}</p>
        )}
        {report?.kept_since_ms != null && span && span.bounds[0]! < report.kept_since_ms && (
          <p className="muted small">Nothing is kept from before {DAY.format(report.kept_since_ms)}.</p>
        )}
      </Card>

      {device === "" && report && (
        <Card title="By device">
          {report.devices.length === 0 ? (
            <p className="muted">No device used anything in this time.</p>
          ) : (
            <DeviceTable rows={report.devices} name={name} clients={byMac} onPick={(mac) => setDevice(mac)} />
          )}
        </Card>
      )}
    </div>
  );
}

function Tile({ label, value, swatch }: { label: string; value: number; swatch?: "down" | "up" }) {
  return (
    <div className="usage-tile">
      <span className="usage-tile-label">
        {swatch && <span className={`swatch swatch-${swatch}`} aria-hidden="true" />}
        {label}
      </span>
      <span className="usage-tile-value">{formatBytes(value)}</span>
    </div>
  );
}

/** A tidy step for an axis reaching `max` bytes: 1, 2 or 5 of a power of ten, in the unit the labels use. */
function axisStep(max: number): number {
  if (max <= 0) return 1024;
  let unit = 1;
  while (max / unit >= 1024 && unit < 1024 ** 4) unit *= 1024;
  const rough = max / unit / 4;
  const power = 10 ** Math.floor(Math.log10(Math.max(rough, 1e-9)));
  const step = [1, 2, 5, 10].map((m) => m * power).find((s) => s >= rough) ?? 10 * power;
  return Math.max(step * unit, 1);
}

/** The width of an element as it is laid out, kept current. */
function useWidth<T extends HTMLElement>(): [RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setWidth(el.clientWidth);
    const observer = new ResizeObserver(() => setWidth(el.clientWidth));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}

const CHART_HEIGHT = 200;
const PAD = { top: 10, right: 8, bottom: 22, left: 56 };

/**
 * Use per hour or day as columns, download at the bottom and upload on top,
 * with a hairline grid, the axis in tidy steps, and each column's numbers on
 * hover.
 */
function UsageChart({ span, report }: { span: Span; report: UsageReport }) {
  const [box, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const n = report.buckets.length;
  const max = Math.max(0, ...report.buckets.map((b) => b.down + b.up));
  const step = axisStep(max);
  const top = Math.max(step, Math.ceil(max / step) * step);
  const plotW = Math.max(0, width - PAD.left - PAD.right);
  const plotH = CHART_HEIGHT - PAD.top - PAD.bottom;
  const band = n > 0 ? plotW / n : 0;
  const barW = Math.max(2, Math.min(24, band - 2));
  const y = (bytes: number) => PAD.top + plotH - (bytes / top) * plotH;
  const ticks = Array.from({ length: Math.round(top / step) + 1 }, (_, i) => i * step);
  // Labels along the bottom at least 44 px apart.
  const labelEvery = Math.max(1, Math.ceil(44 / Math.max(band, 1)));
  const now = Date.now();

  /** A column part from `y0` (bottom) up to `y1`, its top corners rounded when it ends the column. */
  const part = (x: number, y0: number, y1: number, rounded: boolean) => {
    const h = y0 - y1;
    if (h <= 0) return "";
    const r = rounded ? Math.min(4, h, barW / 2) : 0;
    return `M${x} ${y0}V${y1 + r}${r ? `Q${x} ${y1} ${x + r} ${y1}` : ""}H${x + barW - r}${r ? `Q${x + barW} ${y1} ${x + barW} ${y1 + r}` : ""}V${y0}Z`;
  };

  const shown = hover != null ? report.buckets[hover] : null;
  return (
    <div className="usage-chart" ref={box}>
      <div className="usage-legend" aria-hidden="true">
        <span>
          <span className="swatch swatch-down" /> Download
        </span>
        <span>
          <span className="swatch swatch-up" /> Upload
        </span>
      </div>
      {width > 0 && (
        <svg width={width} height={CHART_HEIGHT} role="img" aria-label={`Data used, ${formatBytes(max)} at most in one ${span.hourly ? "hour" : "day"}`} onMouseLeave={() => setHover(null)}>
          {ticks.map((t) => (
            <g key={t}>
              <line className="usage-grid" x1={PAD.left} x2={PAD.left + plotW} y1={y(t)} y2={y(t)} />
              <text className="usage-axis" x={PAD.left - 8} y={y(t)} dy="0.32em" textAnchor="end">
                {t === 0 ? "0" : formatBytes(t)}
              </text>
            </g>
          ))}
          {report.buckets.map((b, i) => {
            const x = PAD.left + i * band + (band - barW) / 2;
            const base = y(0);
            const downTop = y(b.down);
            // The 2 px gap between the parts comes out of the upper one.
            const upTop = y(b.down + b.up);
            const future = (span.bounds[i] ?? 0) > now;
            return (
              <g key={i}>
                {b.down > 0 && <path className="usage-bar usage-bar-down" d={part(x, base, Math.min(downTop, base - 1), b.up === 0)} />}
                {b.up > 0 && <path className="usage-bar usage-bar-up" d={part(x, b.down > 0 ? downTop - 2 : base, Math.min(upTop, downTop - 2 - 1), true)} />}
                {i % labelEvery === 0 && (
                  <text className={future ? "usage-axis usage-axis-future" : "usage-axis"} x={PAD.left + i * band + band / 2} y={CHART_HEIGHT - 6} textAnchor="middle">
                    {span.hourly ? HOUR.format(span.bounds[i] ?? 0).slice(0, 2) : DAY_SHORT.format(span.bounds[i] ?? 0)}
                  </text>
                )}
                {/* The whole column's height answers the pointer, not just the bars. */}
                <rect
                  className="usage-hit"
                  x={PAD.left + i * band}
                  y={PAD.top}
                  width={band}
                  height={plotH}
                  onMouseEnter={() => setHover(i)}
                />
              </g>
            );
          })}
          <line className="usage-baseline" x1={PAD.left} x2={PAD.left + plotW} y1={y(0)} y2={y(0)} />
          {hover != null && <rect className="usage-hover" x={PAD.left + hover * band} y={PAD.top} width={band} height={plotH} />}
        </svg>
      )}
      {shown && hover != null && (
        <div
          className="usage-tip"
          style={{ left: Math.min(Math.max(PAD.left + hover * band + band / 2, 90), Math.max(width - 90, 90)) }}
          role="status"
        >
          <strong>{stretchName(span, hover)}</strong>
          <span>
            <span className="swatch swatch-down" aria-hidden="true" /> Download {formatBytes(shown.down)}
          </span>
          <span>
            <span className="swatch swatch-up" aria-hidden="true" /> Upload {formatBytes(shown.up)}
          </span>
          <span className="muted">Together {formatBytes(shown.down + shown.up)}</span>
        </div>
      )}
    </div>
  );
}

/** The chart's numbers as rows, for reading out and copying. */
function StretchTable({ span, report }: { span: Span; report: UsageReport }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>{span.hourly ? "Hour" : "Day"}</th>
            <th className="num">Download</th>
            <th className="num">Upload</th>
            <th className="num">Together</th>
          </tr>
        </thead>
        <tbody>
          {report.buckets.map((b, i) => (
            <tr key={i}>
              <td>{stretchName(span, i)}</td>
              <td className="num">{formatBytes(b.down)}</td>
              <td className="num">{formatBytes(b.up)}</td>
              <td className="num">{formatBytes(b.down + b.up)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** What each device used, the most first, with its share as a thin bar and its allowance. */
function DeviceTable({
  rows,
  name,
  clients,
  onPick,
}: {
  rows: UsageReport["devices"];
  name: (mac: MacAddr) => string;
  clients: Map<MacAddr, ClientView>;
  onPick: (mac: MacAddr) => void;
}) {
  const most = Math.max(1, ...rows.map((r) => r.down + r.up));
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Device</th>
            <th className="num">Download</th>
            <th className="num">Upload</th>
            <th className="num">Together</th>
            <th>Allowance</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const quota = clients.get(r.mac)?.quota;
            return (
              <tr key={r.mac}>
                <td>
                  <button className="link-button usage-device-name" onClick={() => onPick(r.mac)} title="Show this device only">
                    {name(r.mac)}
                  </button>
                  <div className="usage-share" aria-hidden="true">
                    <span style={{ width: `${((r.down + r.up) / most) * 100}%` }} />
                  </div>
                </td>
                <td className="num">{formatBytes(r.down)}</td>
                <td className="num">{formatBytes(r.up)}</td>
                <td className="num">{formatBytes(r.down + r.up)}</td>
                <td className={quota?.over ? "usage-over" : "muted"}>{quota ? describeUse(quota).split(" · ")[0] : "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
