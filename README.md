# Captun

Captun was called OmniHub before.

A cross-platform hotspot manager: it creates a Wi-Fi hotspot with your password,
shows every connected device, and decides per device what it may reach and
through which way out. That can be another uplink, a VPN adapter, a SOCKS5,
HTTP or HTTPS proxy, or a VPN link (VLESS, VMess, Trojan, Shadowsocks,
Hysteria2), with DNS control, firewall rules, bandwidth limits and opt-in TLS
inspection.

Written in Rust: a privileged service plus a Tauri GUI. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design, the security
model, platform status and the roadmap.

## Status

The foundation works end to end on Windows and Linux; macOS code is in place
and type-checks but has not run on a Mac yet:
- hotspot control
- the device list
- config with validation
- outbounds: network adapters, SOCKS5 with UDP, HTTP and HTTPS proxies,
  chaining, and VPN links through the bundled Xray-core (paste any share link)
- the DNS server (DoH/DoT, cache, blocklist, overrides)
- the policy engine
- authenticated IPC
- the GUI

Per-device routing, limits and TLS inspection are enforced once the packet
engine lands. Until then those settings are stored and validated but not
applied.

## Build

Requirements: Rust (stable, MSVC on Windows), Node.js 20+ and a C compiler,
since libusb and ring are compiled from source (MSVC already brings one; on
macOS the Xcode command line tools, on Linux gcc or clang); on Linux also
`libwebkit2gtk-4.1-dev`.

```bash
node scripts/fetch-xray.mjs        # once: pinned, checksum-verified Xray-core for VPN links
node scripts/fetch-windivert.mjs   # once, Windows: the capture driver for per-device outbounds
cargo build -p captun-daemon
cd apps/desktop && npm install && npx tauri dev
```

`node scripts/release.mjs` builds an installer with the service and Xray-core
bundled next to the GUI.

On Windows the installer installs Captun for all users, in
`C:\Program Files\Captun`, and Windows asks you to confirm once, when it
installs. The service runs with administrator rights, so only administrators
may change Captun's files. If OmniHub (its earlier name) or an older Captun
is installed for your account only (in `%LOCALAPPDATA%\OmniHub` or
`%LOCALAPPDATA%\Captun`), remove it first in Settings > Apps > Installed apps,
then run the installer again; your settings are kept. The first time Captun
starts it copies OmniHub's settings, saved lists and phone key, and leaves
OmniHub's own files as they are. Removing OmniHub closes its app but not its
service: until you restart the computer (or end `omnihub-daemon.exe`), Captun
says so and does not start its own service beside it. See
[Installing on Windows](docs/ARCHITECTURE.md#installing-on-windows).

The GUI starts the service for you, elevated through UAC, polkit or the macOS
administrator prompt, from next to its own executable. To run the service by hand:

```bash
# Windows (elevated prompt; `whoami /user` shows your SID, which lets the
# GUI run as your account read the token)
target\debug\captun-daemon.exe --token-file %LOCALAPPDATA%\Captun\ipc.token --allow-user <your SID>
# Linux
sudo target/debug/captun-daemon --token-file $XDG_RUNTIME_DIR/captun/ipc.token
# macOS
sudo target/debug/captun-daemon --token-file ~/Library/Application\ Support/Captun/ipc.token --owner-uid $(id -u)
```

On Windows, `captun-daemon.exe --install-usb-driver` and
`--remove-usb-driver`, from an elevated prompt, install and remove Captun's
USB driver for Android phones, as the installer and uninstaller do, then exit.

The app saves its settings encrypted in `captun.settings`, next to the
program, or in your profile where that folder cannot be written, as in
Program Files (Settings → About shows the exact path). Only your account on that
computer can open the file. A copy of Captun moved to another computer starts
with fresh settings. Run by hand as above, the service instead reads a plain
config file: `%ProgramData%\Captun\captun.toml` on Windows,
`/etc/captun/captun.toml` on Linux and
`/Library/Application Support/Captun/captun.toml` on macOS, or the file given
with `--config`. See [config/captun.example.toml](config/captun.example.toml)
for every option.

## What Captun needs on each system

Captun brings what it needs, or has the system's package manager install it.

- **Windows:** the installer puts Xray-core (for VPN links) and WinDivert
  (for routing devices through Captun; Microsoft signed its driver) next to
  the service, and libusb, which the built-in adb uses to talk to phones over
  USB, is part of the service itself. For USB to phone, Windows needs a USB
  driver for the phone's USB debugging connection: where Windows has none,
  the installer adds Captun's own, made and signed on your computer for your
  computer alone, and uninstalling Captun removes it again. A driver from
  the phone's maker, if you installed one, is still the one used. See
  [USB driver for phones on Windows](docs/ARCHITECTURE.md#usb-driver-for-phones-on-windows).
- **macOS:** nothing to install. The network adapter Captun routes devices
  through (utun) and USB access to phones are part of macOS, and libusb is
  part of the service.
- **Linux:** the `.deb` and `.rpm` packages install the tools the service
  runs: `ip` (iproute2), `iptables`, `iw`, `hostapd` and `sysctl` (procps).
  They also recommend NetworkManager, which Captun tries first for the
  hotspot (hostapd is the fallback), and dnsmasq, which NetworkManager's
  hotspot needs. libusb is part of the service, and the TUN network adapter
  Captun routes devices through is built into every mainstream
  distribution's kernel. The AppImage cannot install anything: install those
  packages yourself, for example
  `sudo apt install iproute2 iptables iw hostapd procps network-manager dnsmasq-base`.

See [What Captun needs on each system](docs/ARCHITECTURE.md#what-captun-needs-on-each-system)
for the details.

## Bundled third-party software

Installers include [Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0),
unmodified, at the version pinned in [scripts/xray.lock.json](scripts/xray.lock.json).
Its source is available from that repository at the same tag.

The service includes [libusb](https://github.com/libusb/libusb) 1.0.27
(LGPL-2.1), compiled in from the copy of its source that the
[`libusb1-sys`](https://crates.io/crates/libusb1-sys) 0.7.0 crate carries;
the built-in adb uses it to talk to phones over USB. libusb's own source is
available from its repository at the tag v1.0.27.

Windows installers also include [WinDivert](https://github.com/basil00/WinDivert)
(LGPL-3.0 or GPL-2.0), unmodified, at the version pinned in
[scripts/windivert.lock.json](scripts/windivert.lock.json): the packet-capture
driver that routing devices through Captun uses on Windows. Its driver also
carries Microsoft's Windows Hardware Compatibility signature.
