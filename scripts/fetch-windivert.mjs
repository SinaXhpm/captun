#!/usr/bin/env node
// Fetches the WinDivert release pinned in windivert.lock.json (Windows only):
// the packet-capture driver that lets Captun route each hotspot device
// through its own outbound. Checks the archive's SHA-256 and each extracted
// file's SHA-256, then places WinDivert.dll and WinDivert64.sys:
//   - in apps/desktop/src-tauri/binaries/, where release bundling picks them up,
//   - next to the daemon in target/debug and target/release, for development.
//
// Usage: node scripts/fetch-windivert.mjs [--target <rust-target-triple>]

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { argValue, copyUnlessSame, devTargetDirs, extract, fetchVerified, hostTarget, place, root } from "./lib/fetch.mjs";

const lock = JSON.parse(readFileSync(join(root, "scripts", "windivert.lock.json"), "utf8"));
const target = argValue("--target") ?? hostTarget();
const files = lock.files[target];
if (!files) {
  console.log(`WinDivert is not needed or not available for ${target}; nothing to fetch.`);
  process.exit(0);
}

const url = `${lock.source}/releases/download/${lock.version}/${lock.file}`;
const zip = await fetchVerified(url, lock.sha256, join(root, "target", "windivert-cache", lock.version), lock.file);
const binaries = join(root, "apps", "desktop", "src-tauri", "binaries");
for (const [entry, expected] of Object.entries(files)) {
  const bytes = extract(zip, entry);
  const got = createHash("sha256").update(bytes).digest("hex");
  if (got !== expected) {
    console.error(`SHA-256 mismatch for ${entry}: expected ${expected}, got ${got}. Refusing to use it.`);
    process.exit(1);
  }
  const out = join(binaries, basename(entry));
  place(bytes, out);
  console.log(`WinDivert ${lock.version} ${basename(entry)} -> ${out}`);
  if (target === hostTarget()) {
    for (const dir of devTargetDirs()) {
      const dest = join(dir, basename(entry));
      console.log(`  ${copyUnlessSame(out, dest) ? "also ->" : "unchanged:"} ${dest}`);
    }
  }
}
