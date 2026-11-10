#!/usr/bin/env node
// Fetches the Xray-core release pinned in xray.lock.json for one target,
// checks its SHA-256 against the lock file, and extracts only the `xray`
// executable:
//   - to apps/desktop/src-tauri/binaries/xray-<target>[.exe], where release
//     bundling picks it up, and
//   - next to the daemon in target/debug and target/release, for development.
//
// Usage: node scripts/fetch-xray.mjs [--target <rust-target-triple>]
//
// Nothing downloaded is ever run here. A hash mismatch stops everything.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { argValue, copyUnlessSame, devTargetDirs, extract, fetchVerified, hostTarget, place, root } from "./lib/fetch.mjs";

const lock = JSON.parse(readFileSync(join(root, "scripts", "xray.lock.json"), "utf8"));
const target = argValue("--target") ?? hostTarget();
const asset = lock.assets[target];
if (!asset) {
  console.error(`No pinned Xray build for ${target}. Known targets: ${Object.keys(lock.assets).join(", ")}`);
  process.exit(1);
}
const windows = target.includes("windows");
const exe = windows ? "xray.exe" : "xray";
const bundled = join(root, "apps", "desktop", "src-tauri", "binaries", `xray-${target}${windows ? ".exe" : ""}`);

const url = `${lock.source}/releases/download/${lock.version}/${asset.file}`;
const zip = await fetchVerified(url, asset.sha256, join(root, "target", "xray-cache", lock.version), asset.file);
place(extract(zip, exe), bundled);
console.log(`Xray ${lock.version} (${target}) -> ${bundled}`);

// The daemon looks for Xray next to its own executable.
if (target === hostTarget()) {
  for (const dir of devTargetDirs()) {
    const dest = join(dir, exe);
    console.log(`  ${copyUnlessSame(bundled, dest) ? "also ->" : "unchanged:"} ${dest}`);
  }
}
