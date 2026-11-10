<p align="center">
  <img src="logo.png" alt="Captun logo: a ship's helm drawn as a network" width="128">
</p>

<h1 align="center">Captun</h1>

<p align="center">
  <b>Wi-Fi hotspot and internet sharing, with a captain at the helm.</b><br>
  Share your computer's internet, VPN or proxy with phones, TVs and other devices,<br>
  over a Wi-Fi hotspot, a network cable or USB, and decide where each device's traffic goes.
</p>

<p align="center">
  Windows · Linux · macOS (in progress) — written in Rust, with a Tauri desktop app
</p>

---

**Captun** (*captain* + *tun*) turns your computer into a smart hotspot. Phones,
laptops, smart TVs and game consoles connect to it, and you steer every
device: straight to the internet, through a VPN, or through a proxy, with your
own rules, ad and tracker blocking, and speed limits. You can also share
your computer's internet with an Android phone over a USB cable, without
root and without installing any app on the phone.

> **Status:** under active development. There is no release yet; you can build
> it from source (see [Build from source](#build-from-source)).

## What you can do with Captun

- **Share a VPN with devices that cannot run one.** Connect your PC to a VPN
  or proxy once, and your smart TV, console or a guest's phone uses it through
  the hotspot.
- **Give a phone internet over USB.** No mobile data, no Wi-Fi? Plug the
  Android phone into your computer and it goes online through it (reverse
  tethering).
- **Run a hotspot with your own rules.** Block ads and trackers for every
  device, keep some websites off-limits, or send only certain websites
  through a proxy.
- **Keep an eye on every device.** See who is connected and how much each
  one uses, approve new devices before they get online, block one, or set a
  speed limit.

## Features

- **Wi-Fi hotspot** with your own network name and password.
- **Cable sharing:** give devices on a network cable (or a USB network
  adapter) your internet, with addresses handed out automatically (DHCP).
- **USB to phone (reverse tethering)** for Android: no root, no app on the
  phone; Captun has adb built in. Captun only *gives* internet and never uses
  the phone's.
- **Device list:** every connected device, with its traffic, approval,
  blocking and a device limit.
- **Per-device outbound:** each device or group goes out the way you choose:
  - any network adapter of your computer (Ethernet, Wi-Fi, a VPN adapter),
  - a **SOCKS5**, **HTTP** or **HTTPS proxy** (chains supported),
  - a **VPN link** you paste: **VLESS** (including REALITY), **VMess**,
    **Trojan**, **Shadowsocks** and **Hysteria2**, run by the bundled
    [Xray-core](https://github.com/XTLS/Xray-core).
- **Rules:** by device, website name, address range, port, protocol and time
  of day; online blocklists (updated only when you press "Update lists");
  ready-made rules for ad blocking and popular apps.
- **Its own DNS server:** cache, blocklist, custom answers, DNS servers over
  UDP, TCP, DNS over TLS (DoT) or DNS over HTTPS (DoH), per device, and an
  option to make devices use it.
- **Speed limits** per device or group.
- **What devices can reach:** keep them away from this computer, from each
  other or from your home network.
- **A desktop app** that starts and talks to the Captun service for you.

Planned: HTTPS inspection that works **only with the explicit consent of the
device's user**, given on the device itself (it is not active in this
version).

## How it works

```
 phone ─┐                         ┌─ direct (any network adapter)
 TV    ─┼─ hotspot / cable / USB ─┤  Captun: rules, DNS, limits  ├─ VPN link (VLESS, VMess, Trojan, …)
 laptop ┘                         └─ SOCKS5 / HTTP(S) proxy
```

A small service with administrator rights runs the hotspot, the DNS server
and a packet engine that decides, connection by connection, which way each
device's traffic goes. The desktop app shows what is happening and changes the
settings. On Windows the engine captures devices' traffic with
[WinDivert](https://github.com/basil00/WinDivert); on Linux it uses a TUN
network adapter and policy routing. The full design is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Platforms

| | Windows | Linux | macOS |
|---|---|---|---|
| Wi-Fi hotspot | ✅ | ✅ NetworkManager or hostapd | the system's Internet Sharing |
| Cable sharing | ✅ | ✅ | not tested yet |
| USB to phone (Android) | ✅ | ✅ | not tested yet |
| Per-device outbounds and limits | ✅ | experimental | planned |

macOS code builds but has not run on a Mac yet. Details:
[Platform status](docs/ARCHITECTURE.md#platform-status).

## Build from source

You need Rust (stable; MSVC on Windows), Node.js 20 or newer and a C compiler
(libusb and ring are compiled from source: MSVC brings one on Windows, the
Xcode command line tools on macOS, gcc or clang on Linux). On Linux also
`libwebkit2gtk-4.1-dev`.

```bash
node scripts/fetch-xray.mjs        # once: pinned, checksum-verified Xray-core for VPN links
node scripts/fetch-windivert.mjs   # once, Windows: the packet capture driver
cargo build -p captun-daemon
cd apps/desktop && npm install && npx tauri dev
```

`node scripts/release.mjs` builds an installer with the service and Xray-core
next to the app. On Windows it installs for all users in
`C:\Program Files\Captun` and asks for administrator approval once.

The app starts the service itself (with UAC on Windows, polkit on Linux, the
administrator prompt on macOS). Settings are saved encrypted, readable only
by your account on that computer. Every option is described in
[config/captun.example.toml](config/captun.example.toml).

<details>
<summary>Running the service by hand</summary>

```bash
# Windows (elevated prompt; `whoami /user` shows your SID)
target\debug\captun-daemon.exe --token-file %LOCALAPPDATA%\Captun\ipc.token --allow-user <your SID>
# Linux
sudo target/debug/captun-daemon --token-file $XDG_RUNTIME_DIR/captun/ipc.token
# macOS
sudo target/debug/captun-daemon --token-file ~/Library/Application\ Support/Captun/ipc.token --owner-uid $(id -u)
```

Run this way, the service reads a plain config file:
`%ProgramData%\Captun\captun.toml` on Windows, `/etc/captun/captun.toml` on
Linux, `/Library/Application Support/Captun/captun.toml` on macOS, or the file
given with `--config`.
</details>

## What Captun needs on each system

- **Windows:** the installer brings Xray-core and WinDivert (its driver is
  signed by Microsoft); libusb is built into the service. If Windows has no
  driver for the phone's USB debugging connection, the installer adds
  Captun's own, made and signed on your computer for your computer alone,
  and removes it when Captun is uninstalled. See
  [USB driver for phones on Windows](docs/ARCHITECTURE.md#usb-driver-for-phones-on-windows).
- **Linux:** the `.deb` and `.rpm` packages install `ip` (iproute2),
  `iptables`, `iw`, `hostapd` and `sysctl` (procps), and recommend
  NetworkManager and dnsmasq. With the AppImage, install them yourself, for
  example `sudo apt install iproute2 iptables iw hostapd procps network-manager dnsmasq-base`.
- **macOS:** nothing to install.

More in [What Captun needs on each system](docs/ARCHITECTURE.md#what-captun-needs-on-each-system).

## FAQ

**Can I share my VPN connection over a Wi-Fi hotspot?**
Yes. Choose the VPN's network adapter, a proxy, or paste a VPN link (VLESS,
VMess, Trojan, Shadowsocks, Hysteria2) as the outbound for a device or for
everyone.

**Does USB tethering to the phone need root or an app?**
No. Turn on USB debugging on the Android phone and plug it in; Captun's
built-in adb does the rest. The phone uses your computer's internet, never
the other way round.

**Can different devices use different connections?**
Yes. Every device or group can have its own outbound, its own DNS servers
and its own speed limit, and rules can send single websites another way.

**Does Captun read my devices' traffic?**
No. It routes traffic and reads only what it needs to apply your rules (such
as the website name a connection asks for). Contents stay encrypted. The
planned HTTPS inspection will work only for a device whose user has agreed
to it on that device.

## Bundled third-party software

Installers include [Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0),
unmodified, at the version pinned in [scripts/xray.lock.json](scripts/xray.lock.json);
its source is available from that repository at the same tag.

The service includes [libusb](https://github.com/libusb/libusb) 1.0.27
(LGPL-2.1), compiled in from the copy of its source that the
[`libusb1-sys`](https://crates.io/crates/libusb1-sys) 0.7.0 crate carries; the
built-in adb uses it to talk to phones over USB. libusb's own source is
available from its repository at the tag v1.0.27.

Windows installers also include [WinDivert](https://github.com/basil00/WinDivert)
(LGPL-3.0 or GPL-2.0), unmodified, at the version pinned in
[scripts/windivert.lock.json](scripts/windivert.lock.json): the packet capture
driver Captun uses on Windows. Its driver carries Microsoft's Windows Hardware
Compatibility signature.

---

<sub>Captun was called OmniHub before. Keywords: Wi-Fi hotspot manager,
internet sharing, share VPN over hotspot, reverse tethering, USB tethering
Android without root, per-device routing, SOCKS5 proxy sharing, Xray, V2Ray,
VLESS, Shadowsocks, DNS ad blocker, Windows mobile hotspot, Linux hotspot.</sub>
