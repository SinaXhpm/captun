// Client-side checks that mirror captun-core validation, so obvious mistakes
// are caught before a round trip. The service remains the authority and its
// messages are always shown verbatim.

const encoder = new TextEncoder();

export function validateSsid(ssid: string): string | null {
  const bytes = encoder.encode(ssid).length;
  if (bytes < 1 || bytes > 32) return "The network name must be 1–32 bytes.";
  if (/[\u0000-\u001f\u007f-\u009f]/.test(ssid)) return "The network name must not contain control characters.";
  return null;
}

/** Empty is allowed: it means "not configured yet". */
export function validatePassphrase(passphrase: string): string | null {
  if (passphrase === "") return null;
  const rawPsk = passphrase.length === 64 && /^[0-9a-fA-F]+$/.test(passphrase);
  const ascii = passphrase.length >= 8 && passphrase.length <= 63 && /^[\x20-\x7e]+$/.test(passphrase);
  return rawPsk || ascii ? null : "The password must be 8–63 printable ASCII characters or a 64-digit hex key.";
}

/** Mirrors captun-core's MAX_CLIENT_LIMIT. */
export const MAX_CLIENT_LIMIT = 255;

/** Empty is allowed: it means "only the system limit". */
export function validateMaxClients(text: string): string | null {
  const t = text.trim();
  if (t === "") return null;
  const n = Number(t);
  return Number.isInteger(n) && n >= 1 && n <= MAX_CLIENT_LIMIT ? null : `Enter a whole number from 1 to ${MAX_CLIENT_LIMIT}, or leave empty.`;
}

export function validateEgressId(id: string): string | null {
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(id)) return "ID must be 1–32 letters, digits, '-' or '_'.";
  return null;
}

export function validateMac(mac: string): string | null {
  return /^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$/.test(mac.trim()) ? null : `"${mac}" is not a MAC address.`;
}

export function validateTarget(target: string): string | null {
  const t = target.trim();
  if (/^\[[0-9a-fA-F:.]+\]:\d{1,5}$/.test(t)) return null;
  const m = /^([^:\s]+):(\d{1,5})$/.exec(t);
  if (!m || Number(m[2]) > 65535) return "Use host:port, e.g. 127.0.0.1:1080 or proxy.example.com:3128.";
  return null;
}

export function validatePort(text: string): string | null {
  const parts = text.split("-").map((p) => p.trim());
  const nums = parts.map(Number);
  if (parts.length > 2 || parts.some((p) => !/^\d+$/.test(p)) || nums.some((n) => n > 65535)) {
    return `"${text}" is not a port or range.`;
  }
  if (nums.length === 2 && (nums[0] ?? 0) > (nums[1] ?? 0)) return `Range "${text}" is reversed.`;
  return null;
}

export function validateClock(text: string): string | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(text);
  if (!m || Number(m[1]) > 23 || Number(m[2]) > 59) return `"${text}" is not a time (HH:MM).`;
  return null;
}

/** Trimmed value, or `undefined` so the key is dropped from the JSON. */
export function opt(value: string | null | undefined): string | undefined {
  const t = (value ?? "").trim();
  return t === "" ? undefined : t;
}

export function optNumber(value: string): number | undefined {
  const t = value.trim();
  if (t === "") return undefined;
  const n = Number(t);
  return Number.isFinite(n) ? n : undefined;
}

/** Splits a textarea into trimmed, non-empty lines. */
export function lines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

/** Splits comma- or whitespace-separated input. */
export function tokens(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter((t) => t !== "");
}

/** Returns the list, or `undefined` when empty so serde's default applies. */
export function optList<T>(list: T[]): T[] | undefined {
  return list.length > 0 ? list : undefined;
}

/** Each entry of a pasted list, checked: the values to save, and what is wrong. */
export interface Checked {
  values: string[];
  errors: string[];
}

function isIpv4(text: string): boolean {
  const parts = text.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function isIpv6(text: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(text) || !text.includes(":")) return false;
  try {
    // The URL parser knows every legal way to write an IPv6 address.
    new URL(`http://[${text}]/`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Addresses and ranges as the service takes them: `1.2.3.4` becomes
 * `1.2.3.4/32` (and an IPv6 address `/128`). Entries may be separated by new
 * lines, commas or spaces.
 */
export function checkRanges(text: string): Checked {
  const values: string[] = [];
  const errors: string[] = [];
  for (const entry of tokens(text)) {
    const [address = "", prefix, ...rest] = entry.split("/");
    const v4 = isIpv4(address);
    const v6 = !v4 && isIpv6(address);
    const max = v4 ? 32 : 128;
    if ((!v4 && !v6) || rest.length > 0) {
      errors.push(`"${entry}" is not an IP address or range.`);
    } else if (prefix !== undefined && (!/^\d{1,3}$/.test(prefix) || Number(prefix) > max)) {
      errors.push(`"${entry}": the part after / must be 0–${max}.`);
    } else {
      values.push(prefix === undefined ? `${address}/${max}` : `${address}/${Number(prefix)}`);
    }
  }
  return { values: [...new Set(values)], errors };
}

/** Links to online lists: http(s) with a host, as the service takes them. */
export function checkLinks(text: string): Checked {
  const values: string[] = [];
  const errors: string[] = [];
  for (const link of tokens(text)) {
    if (/^https?:\/\/[^\s/?#@]+/i.test(link) && link.length <= 2048) values.push(link);
    else errors.push(`"${link}" is not a web link (http:// or https://).`);
  }
  return { values: [...new Set(values)], errors };
}

const LABEL = "[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?";
const HOSTNAME = new RegExp(`^${LABEL}(?:\\.${LABEL})*\\.?$`, "i");

/**
 * Website names in the notation rules use (`example.com`, `full:a.example.com`,
 * `keyword:ads`). A pasted link keeps only its name: `https://www.x.com/p` is
 * `www.x.com`.
 */
export function checkDomains(text: string): Checked {
  const values: string[] = [];
  const errors: string[] = [];
  for (const raw of tokens(text)) {
    if (raw.startsWith("keyword:")) {
      if (raw.length > "keyword:".length) values.push(raw.toLowerCase());
      else errors.push(`"${raw}" needs a word after keyword:.`);
      continue;
    }
    const prefix = /^(full:|domain:)/.exec(raw)?.[0] ?? "";
    let name = raw.slice(prefix.length);
    // A link: keep the host.
    name = name.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/[/?#].*$/, "").replace(/^\*\./, "");
    name = name.replace(/:\d+$/, "").toLowerCase();
    if (name.length > 253 || !HOSTNAME.test(name)) {
      errors.push(`"${raw}" is not a website name.`);
    } else {
      values.push(`${prefix === "domain:" ? "" : prefix}${name.replace(/\.$/, "")}`);
    }
  }
  return { values: [...new Set(values)], errors };
}
