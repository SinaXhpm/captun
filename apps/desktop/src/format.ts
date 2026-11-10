const UNITS = ["B", "KB", "MB", "GB", "TB"];

export function formatBytes(bytes: number): string {
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${UNITS[unit]}`;
}

/** Rates arrive in bits per second, as network tools show them. */
export function formatRate(bps: number): string {
  if (bps < 1000) return `${Math.round(bps)} bit/s`;
  if (bps < 1_000_000) return `${(bps / 1000).toFixed(bps < 10_000 ? 1 : 0)} kbit/s`;
  if (bps < 1_000_000_000) return `${(bps / 1_000_000).toFixed(bps < 10_000_000 ? 1 : 0)} Mbit/s`;
  return `${(bps / 1_000_000_000).toFixed(2)} Gbit/s`;
}

export function formatKbps(kbps: number | null | undefined): string {
  if (kbps == null) return "unlimited";
  return formatRate(kbps * 1000);
}

export function formatDuration(totalSecs: number): string {
  const s = Math.floor(totalSecs);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

export function formatAgo(ms: number, now = Date.now()): string {
  const secs = Math.max(0, (now - ms) / 1000);
  if (secs < 5) return "just now";
  return `${formatDuration(secs)} ago`;
}

// One formatter serves every row of the lookup log: making one per call is
// slow. The fields must be named, or it prints the date instead of the time.
function timeFormat(): Intl.DateTimeFormat {
  return new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "numeric", second: "numeric", hour12: false });
}

/**
 * This computer's offset from UTC right now. It changes when the time zone is
 * changed while the app runs (or summer time starts or ends), which a
 * formatter made earlier would not notice.
 */
export function timeZoneOffset(): number {
  return new Date().getTimezoneOffset();
}

let timeZone = timeZoneOffset();
let TIME = timeFormat();

export function formatTime(ms: number): string {
  const zone = timeZoneOffset();
  if (zone !== timeZone) {
    timeZone = zone;
    TIME = timeFormat();
  }
  return TIME.format(ms);
}
