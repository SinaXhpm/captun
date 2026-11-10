#!/usr/bin/env node
// Builds an installable Captun for one target: the service, the pinned
// Xray-core, and the GUI bundled together, so the installed service finds
// Xray next to itself.
//
// Usage: node scripts/release.mjs [--target <rust-target-triple>]
//
// Development builds (`cargo build`, `npx tauri dev`) do not need this; they
// only need `node scripts/fetch-xray.mjs` once for VPN links to work.

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const desktop = join(root, "apps", "desktop");

function run(program, args, cwd = root) {
  console.log(`> ${program} ${args.join(" ")}`);
  // npm/npx are .cmd shims on Windows and need a shell there; every argument
  // here is fixed or a validated target triple.
  execFileSync(program, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });
}

function hostTarget() {
  const out = execFileSync("rustc", ["-vV"], { encoding: "utf8" });
  return out.match(/^host: (\S+)$/m)[1];
}

const i = process.argv.indexOf("--target");
const target = i === -1 ? hostTarget() : process.argv[i + 1];
if (!/^[a-z0-9_]+(-[a-z0-9_]+){2,3}$/.test(target ?? "")) {
  console.error(`Not a Rust target triple: ${target}`);
  process.exit(1);
}
const exe = target.includes("windows") ? ".exe" : "";

run("node", [join("scripts", "fetch-xray.mjs"), "--target", target]);
run("node", [join("scripts", "fetch-windivert.mjs"), "--target", target]);
run("cargo", ["build", "--release", "-p", "captun-daemon", "--target", target]);
const binaries = join(desktop, "src-tauri", "binaries");
mkdirSync(binaries, { recursive: true });
copyFileSync(join(root, "target", target, "release", `captun-daemon${exe}`), join(binaries, `captun-daemon-${target}${exe}`));

const configs = ["--config", join("src-tauri", "tauri.release.conf.json")];
if (target === "x86_64-pc-windows-msvc") {
  // Routing devices through Captun on Windows needs WinDivert (the DLL and
  // its signed driver) next to the service; fetch-windivert put them here.
  const overlay = join(binaries, "tauri.windows.release.json");
  const resources = { "binaries/WinDivert.dll": "WinDivert.dll", "binaries/WinDivert64.sys": "WinDivert64.sys" };
  writeFileSync(overlay, JSON.stringify({ bundle: { resources } }, null, 2));
  configs.push("--config", overlay);
}
run("npx", ["tauri", "build", "--target", target, ...configs], desktop);
