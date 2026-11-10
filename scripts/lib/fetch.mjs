// Shared by the scripts that fetch pinned third-party binaries: download once
// into a cache, refuse anything whose SHA-256 differs from the lock file, and
// pull single files out of the zip. Nothing downloaded is ever run here.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { crc32, inflateRawSync } from "node:zlib";

export const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export function hostTarget() {
  try {
    const out = execFileSync("rustc", ["-vV"], { encoding: "utf8" });
    const host = out.match(/^host: (\S+)$/m);
    if (host) return host[1];
  } catch {
    // Fall back to Node's view of the platform.
  }
  const arch = { x64: "x86_64", arm64: "aarch64" }[process.arch];
  const os = { win32: "pc-windows-msvc", linux: "unknown-linux-gnu", darwin: "apple-darwin" }[process.platform];
  if (!arch || !os) throw new Error(`unsupported platform ${process.platform}/${process.arch}`);
  return `${arch}-${os}`;
}

export function argValue(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

/** The archive at `url`, from the cache when it is there and still matches. */
export async function fetchVerified(url, expected, cacheDir, file) {
  const cached = join(cacheDir, file);
  if (existsSync(cached)) {
    const zip = readFileSync(cached);
    if (sha256(zip) === expected) return zip;
  }
  console.log(`Downloading ${url}`);
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
  const zip = Buffer.from(await res.arrayBuffer());
  const got = sha256(zip);
  if (got !== expected) {
    console.error(`SHA-256 mismatch for ${file}\n  expected ${expected}\n  got      ${got}\nRefusing to use it.`);
    process.exit(1);
  }
  mkdirSync(cacheDir, { recursive: true });
  writeFileSync(cached, zip);
  return zip;
}

/** Pulls one file out of a zip archive (stored or deflated, no ZIP64). */
export function extract(zip, wanted) {
  const EOCD = 0x06054b50;
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) {
    if (zip.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a zip archive");
  const count = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (zip.readUInt32LE(p) !== 0x02014b50) throw new Error("corrupt zip central directory");
    const method = zip.readUInt16LE(p + 10);
    const crc = zip.readUInt32LE(p + 16);
    const size = zip.readUInt32LE(p + 20);
    const plain = zip.readUInt32LE(p + 24);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const local = zip.readUInt32LE(p + 42);
    const name = zip.toString("utf8", p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;
    if (name !== wanted) continue;

    if (zip.readUInt32LE(local) !== 0x04034b50) throw new Error("corrupt zip entry");
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    const data = zip.subarray(start, start + size);
    const out = method === 0 ? Buffer.from(data) : method === 8 ? inflateRawSync(data) : null;
    if (!out) throw new Error(`unsupported zip compression ${method}`);
    if (out.length !== plain || crc32(out) >>> 0 !== crc) throw new Error(`${wanted} is damaged inside the archive`);
    return out;
  }
  throw new Error(`${wanted} is not in the archive`);
}

/** Writes `bytes` to `path` atomically, executable where that means something. */
export function place(bytes, path) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.part`;
  writeFileSync(tmp, bytes, { mode: 0o755 });
  renameSync(tmp, path);
  chmodSync(path, 0o755);
}

/** Where development builds of the service run from, if they exist yet. */
export function devTargetDirs() {
  return ["debug", "release"].map((profile) => join(root, "target", profile)).filter((dir) => existsSync(dir));
}

/**
 * Copies `src` to `dest` unless `dest` already holds the same bytes, which
 * also spares a copy in use: Windows keeps the WinDivert driver loaded from
 * target/debug after the service ran from there, and a running Xray locks its
 * file. Returns whether it copied.
 */
export function copyUnlessSame(src, dest) {
  if (existsSync(dest) && readFileSync(dest).equals(readFileSync(src))) return false;
  copyFileSync(src, dest);
  return true;
}
