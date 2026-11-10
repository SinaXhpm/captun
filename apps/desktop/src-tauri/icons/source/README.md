# Captun logo sources

The logo is the "network helm": a ship's wheel, for the captain in Captun, drawn
as a network. The glowing hub is this computer, the six spokes are links, the
handles are the devices, and two sparks carry data out to them. It keeps the
navy tile and the cyan-to-blue glow the whole app is themed on. These SVGs are
the source of every icon in the parent folder. `generate.mjs` writes all of
them (`node generate.mjs <out dir>`), so change the drawing there rather than
in the SVGs:

| File | Use |
|---|---|
| `icon.svg` | The app icon (navy tile), 1024 px. Rendered to `../icon-source.png`, which `npx tauri icon` turns into the PNG, Windows Store, Android and iOS icons. |
| `icon-mac.svg` | The same icon on macOS's inset tile with a shadow, for `../icon.icns`. |
| `mark.svg` | The bare mark (no tile), used in the app (`public/logo.png`). |
| `android-fg.svg`, `android-bg.svg` | The layers of Android's adaptive icon. |
| `icon-16.svg` … `icon-64.svg` | Hand-tuned drawings for 16, 20, 24, 32, 40, 48 and 64 px (Windows uses 20 and 40 at 125 % scale): strokes at least a pixel wide, no blur or sparks, and no hub ring below 32 px. They make up the small sizes of `../icon.ico`, with `icon.svg` at 96, 128 and 256 px, and replace `../32x32.png` and `../64x64.png`. |
| `mark-16.svg` … `mark-64.svg` | The tuned drawings without the tile, for the title bar (`public/logo-24.png`, `-32`, `-48`). |

To change the logo, regenerate these files, render each to a PNG at its own size
(headless Edge or any SVG renderer, with a transparent background),
run `npx tauri icon` on the new `icon-source.png` (with `icon-mac` for the
`.icns`), and pack the tuned PNGs into `icon.ico` with the 256 px image **first**: Tauri uses the first image as the window icon. (On Windows the app then replaces that icon with the right size from the whole `.ico`, see `src/window_icon.rs`, so the taskbar and Alt+Tab icons stay sharp at every scale.)
