// Captun logo, design B ("network helm": six spokes as links, the handles as
// devices, a glowing hub for this computer, data sparks heading out).
// Writes every source SVG the icon set needs.
// Usage: node final.mjs <out dir>
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const out = process.argv[2] ?? "final";
mkdirSync(out, { recursive: true });

const f = (n) => Math.round(n * 1000) / 1000;
const pt = (cx, cy, r, deg) => {
  const a = (deg * Math.PI) / 180;
  return [f(cx + r * Math.cos(a)), f(cy + r * Math.sin(a))];
};

// Gradients are in user space scaled to the drawing, so small sizes keep the
// same brass sweep.
function defs(S) {
  const k = S / 1024;
  return `<defs>
  <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#17293b"/><stop offset="0.55" stop-color="#0d1a27"/><stop offset="1" stop-color="#060d15"/>
  </linearGradient>
  <radialGradient id="bgGlow" cx="0.5" cy="0.5" r="0.58">
    <stop offset="0" stop-color="#c98b2e" stop-opacity="0.3"/><stop offset="1" stop-color="#c98b2e" stop-opacity="0"/>
  </radialGradient>
  <linearGradient id="sheen" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#ffffff" stop-opacity="0.13"/><stop offset="0.32" stop-color="#ffffff" stop-opacity="0"/>
  </linearGradient>
  <linearGradient id="ink" gradientUnits="userSpaceOnUse" x1="${f(330 * k)}" y1="${f(110 * k)}" x2="${f(694 * k)}" y2="${f(914 * k)}">
    <stop offset="0" stop-color="#f7dc92"/><stop offset="0.5" stop-color="#e3b04e"/><stop offset="1" stop-color="#a8741f"/>
  </linearGradient>
  <linearGradient id="inkSmall" gradientUnits="userSpaceOnUse" x1="${f(330 * k)}" y1="${f(110 * k)}" x2="${f(694 * k)}" y2="${f(914 * k)}">
    <stop offset="0" stop-color="#fbe4a6"/><stop offset="0.5" stop-color="#ecbe5e"/><stop offset="1" stop-color="#c18a30"/>
  </linearGradient>
  <linearGradient id="trail" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="#ffe2a0" stop-opacity="0"/><stop offset="1" stop-color="#fff0c8" stop-opacity="0.8"/>
  </linearGradient>
  <radialGradient id="core" cx="0.36" cy="0.3" r="0.82">
    <stop offset="0" stop-color="#fffaf0"/><stop offset="0.25" stop-color="#f7d98c"/><stop offset="0.68" stop-color="#e0a947"/><stop offset="1" stop-color="#9c6a1d"/>
  </radialGradient>
  <radialGradient id="halo">
    <stop offset="0" stop-color="#ffd57a" stop-opacity="0.72"/><stop offset="0.42" stop-color="#f0b44a" stop-opacity="0.24"/><stop offset="1" stop-color="#f0b44a" stop-opacity="0"/>
  </radialGradient>
  <radialGradient id="spark">
    <stop offset="0" stop-color="#ffffff"/><stop offset="0.5" stop-color="#ffefc2"/><stop offset="1" stop-color="#f3c96a"/>
  </radialGradient>
  <filter id="glow" x="-25%" y="-25%" width="150%" height="150%">
    <feGaussianBlur stdDeviation="${f(7 * k)}" result="b"/>
    <feColorMatrix in="b" type="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 0.8 0" result="g"/>
    <feMerge><feMergeNode in="g"/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <filter id="blur3" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="${f(3 * k)}"/></filter>
  <filter id="drop" x="-20%" y="-20%" width="140%" height="150%"><feDropShadow dx="0" dy="${f(14 * k)}" stdDeviation="${f(16 * k)}" flood-color="#000" flood-opacity="0.38"/></filter>
</defs>`;
}

const tile = (S, inset = 0) => {
  const x = inset, w = S - 2 * inset, rx = f(w * 0.2266);
  return `<rect x="${x}" y="${x}" width="${w}" height="${w}" rx="${rx}" fill="url(#bg)"${inset ? ' filter="url(#drop)"' : ""}/>` +
    `<rect x="${x}" y="${x}" width="${w}" height="${w}" rx="${rx}" fill="url(#bgGlow)"/>` +
    `<rect x="${x}" y="${x}" width="${w}" height="${w}" rx="${rx}" fill="url(#sheen)"/>` +
    `<rect x="${f(x + w * 0.005)}" y="${f(x + w * 0.005)}" width="${f(w * 0.99)}" height="${f(w * 0.99)}" rx="${f(rx * 0.978)}" fill="none" stroke="#fff" stroke-opacity="0.09" stroke-width="${f(Math.max(w / 512, 0.5))}"/>`;
};

// The full drawing (1024-style, with glow and sparks), at scale k around (cx, cy).
function helmFull(cx, cy, k) {
  const rim = 250 * k, rimW = 40 * k, hub = 86 * k, hubW = 26 * k, core = 52 * k;
  const spokeW = 26 * k, reach = 365 * k, nodeR = 36 * k, count = 6, start = -90;
  const ink = (d, w) =>
    `<path d="${d}" fill="none" stroke="url(#ink)" stroke-width="${f(w)}" stroke-linecap="round" filter="url(#glow)"/>` +
    `<path d="${d}" fill="none" stroke="#fff" stroke-opacity="0.22" stroke-width="${f(w * 0.18)}" stroke-linecap="round" transform="translate(${f(-w * 0.1)} ${f(-w * 0.14)})"/>`;
  const ring = (r, w) => ink(`M${f(cx - r)} ${f(cy)}a${f(r)} ${f(r)} 0 1 0 ${f(2 * r)} 0a${f(r)} ${f(r)} 0 1 0 ${f(-2 * r)} 0`, w);
  const node = (x, y, r) =>
    `<circle cx="${x}" cy="${y}" r="${f(r * 2.4)}" fill="url(#halo)"/><circle cx="${x}" cy="${y}" r="${f(r)}" fill="url(#core)"/>` +
    `<circle cx="${x}" cy="${y}" r="${f(r * 0.97)}" fill="none" stroke="#ffefc2" stroke-opacity="0.35" stroke-width="${f(Math.max(1.5 * k, r / 25))}"/>` +
    `<ellipse cx="${f(x - r * 0.3)}" cy="${f(y - r * 0.36)}" rx="${f(r * 0.3)}" ry="${f(r * 0.19)}" fill="#fff" fill-opacity="0.7" filter="url(#blur3)" transform="rotate(-30 ${f(x - r * 0.3)} ${f(y - r * 0.36)})"/>`;
  const spark = (r, deg, size) => {
    const [x, y] = pt(cx, cy, r, deg);
    const len = size * 4.2;
    return `<g transform="rotate(${deg} ${x} ${y})" opacity="0.95"><rect x="${f(x - len)}" y="${f(y - size * 0.55)}" width="${f(len)}" height="${f(size * 1.1)}" rx="${f(size * 0.55)}" fill="url(#trail)"/></g>` +
      `<circle cx="${x}" cy="${y}" r="${f(size * 1.9)}" fill="url(#halo)" opacity="0.8"/><circle cx="${x}" cy="${y}" r="${f(size)}" fill="url(#spark)"/>`;
  };
  let d = "";
  for (let i = 0; i < count; i++) {
    const deg = start + (360 / count) * i;
    const a = pt(cx, cy, hub + hubW * 0.9, deg);
    const b = pt(cx, cy, reach - nodeR * 1.3, deg);
    d += `M${a[0]} ${a[1]}L${b[0]} ${b[1]}`;
  }
  let s = ink(d, spokeW) + ring(rim, rimW) + ring(hub, hubW);
  for (let i = 0; i < count; i++) {
    const [x, y] = pt(cx, cy, reach, start + (360 / count) * i);
    s += node(x, y, nodeR);
  }
  s += node(f(cx), f(cy), core);
  for (const i of [1, 3]) s += spark((hub + rim) / 2 + 8 * k, start + (360 / count) * i, 13 * k);
  return s;
}

// Hand-tuned small drawing: no blur, no sparks, strokes at least a pixel
// and a bit, the hub ring dropped below 32 px. `fill` is how much of the
// canvas the wheel (to the outside of the handles) may use.
function helmSmall(S, fill) {
  const c = S / 2;
  const outer = (S * fill) / 2; // radius to the outside of a handle
  const nodeR = Math.max(outer * 0.13, S <= 20 ? 1.15 : 1.3);
  const reach = outer - nodeR;
  const rim = reach * 0.66;
  const rimW = Math.max(rim * 0.17, S <= 20 ? 1.35 : 1.6);
  const spokeW = Math.max(rimW * 0.62, 0.9);
  const core = Math.max(rim * 0.24, 1.5);
  const showHubRing = S >= 32;
  const hub = rim * 0.36;
  const count = 6, start = -90;
  let d = "";
  for (let i = 0; i < count; i++) {
    const deg = start + (360 / count) * i;
    const a = pt(c, c, showHubRing ? hub : core * 0.8, deg);
    const b = pt(c, c, reach - nodeR * 0.6, deg);
    d += `M${a[0]} ${a[1]}L${b[0]} ${b[1]}`;
  }
  let s = `<path d="${d}" fill="none" stroke="url(#inkSmall)" stroke-width="${f(spokeW)}" stroke-linecap="round"/>`;
  s += `<circle cx="${f(c)}" cy="${f(c)}" r="${f(rim)}" fill="none" stroke="url(#inkSmall)" stroke-width="${f(rimW)}"/>`;
  if (showHubRing) s += `<circle cx="${f(c)}" cy="${f(c)}" r="${f(hub)}" fill="none" stroke="url(#inkSmall)" stroke-width="${f(spokeW)}"/>`;
  for (let i = 0; i < count; i++) {
    const [x, y] = pt(c, c, reach, start + (360 / count) * i);
    s += `<circle cx="${x}" cy="${y}" r="${f(nodeR)}" fill="url(#core)"/>`;
  }
  s += `<circle cx="${f(c)}" cy="${f(c)}" r="${f(core)}" fill="url(#core)"/>`;
  return s;
}

const svg = (S, body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${S} ${S}" width="${S}" height="${S}">${defs(S)}${body}</svg>`;

// Full-size sources.
writeFileSync(join(out, "icon.svg"), svg(1024, tile(1024) + helmFull(512, 512, 1)));
writeFileSync(join(out, "mark.svg"), svg(1024, helmFull(512, 512, 1.12)));
// macOS: the inset tile with a shadow (824 px on a 1024 canvas).
writeFileSync(join(out, "icon-mac.svg"), svg(1024, tile(1024, 100) + helmFull(512, 512, 0.8)));
// Android adaptive icon: the mark inside the 66 % safe zone, and the tile colours full bleed.
writeFileSync(join(out, "android-fg.svg"), svg(1024, helmFull(512, 512, 0.6)));
writeFileSync(join(out, "android-bg.svg"), svg(1024, `<rect width="1024" height="1024" fill="url(#bg)"/><rect width="1024" height="1024" fill="url(#bgGlow)"/>`));

// Tuned small sizes, with and without the tile.
const SIZES = [16, 20, 24, 32, 40, 48, 64];
for (const S of SIZES) {
  const inTile = S <= 20 ? 0.9 : S <= 32 ? 0.86 : 0.82;
  writeFileSync(join(out, `icon-${S}.svg`), svg(S, tile(S) + helmSmall(S, inTile)));
  writeFileSync(join(out, `mark-${S}.svg`), svg(S, helmSmall(S, S <= 20 ? 1 : 0.98)));
}

// Preview sheet: the tuned sizes next to the full drawing scaled down.
const cells = SIZES.map((S) => `<div><img src="icon-${S}.svg" width="${S}" height="${S}"><img src="icon.svg" width="${S}" height="${S}"><img src="mark-${S}.svg" width="${S}" height="${S}" class="m"><span>${S}</span></div>`).join("");
writeFileSync(join(out, "preview.html"), `<!doctype html><meta charset="utf-8"><style>
body{margin:0;padding:20px;background:#0a1521;color:#b9ab8f;font:12px system-ui;image-rendering:pixelated}
.big{display:flex;gap:20px;margin-bottom:20px}.row{display:flex;gap:24px;align-items:end}
.row div{display:flex;flex-direction:column;gap:6px;align-items:center}
.row img{zoom:3}.m{background:#112130}
.light{background:#f2f5fa;padding:10px;border-radius:10px;display:flex;gap:10px}
</style><div class="big"><img src="icon.svg" width="256"><img src="icon-mac.svg" width="256"><img src="mark.svg" width="256" style="background:#112130"><div class="light"><img src="mark.svg" width="96"><img src="mark-24.svg" width="24"><img src="mark-16.svg" width="16"></div></div><div class="row">${cells}</div>`);
console.log("wrote final sources to", out);
