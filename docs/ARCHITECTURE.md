# Captun architecture

Captun turns a computer into a managed Wi-Fi hotspot: it creates the access
point, shows who is connected, and decides per device what each one may reach
and through which way out (another uplink, a VPN adapter, a SOCKS5, HTTP or
HTTPS proxy, or a VPN link such as VLESS, VMess, Trojan, Shadowsocks or
Hysteria2), with DNS control, firewall rules, bandwidth limits and opt-in TLS
inspection.

## Process model

```
┌──────────────────────┐   named pipe / unix socket    ┌──────────────────────────────┐
│ GUI (Tauri, user)    │ ◄──── JSON lines + token ────► │ captun-daemon (admin/root)  │
│ apps/desktop         │                                │  hub · monitor · DNS · IPC   │
└──────────────────────┘                                └──────────────┬───────────────┘
                                                                       │
              hotspot backend · routing engine · Xray sidecar (VPN links, loopback only)
```

- **The service** (`crates/captun-daemon`) runs elevated and is the only
  component that touches the network. Started by the GUI
  (`--settings-from-gui`), it keeps the settings in memory only and writes no
  file. Run on its own, it keeps them in a config file (`--config`).
- **The service's log** (`captun-daemon.log` in `%ProgramData%\Captun`,
  `/var/log/captun` or `/Library/Logs/Captun`) starts afresh once it holds
  16 MiB, and the two before it are kept as `.1` and `.2`, so whatever devices
  make the service log, it cannot fill the disk; each start of the service
  moves the last run's aside the same way. When another program holds the
  log open so it cannot be moved aside, that is tried again every 1 MiB, and
  once the log holds 32 MiB it is cut in place, starting with a line that
  says so. A log file is always made new: on
  Windows it is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and must not exist
  yet (`O_EXCL` elsewhere), so a link planted at its name is removed, never
  followed. Connected GUIs are sent warnings and errors only, at most 10 a
  second, with a count of any left out.
- **The GUI** (`apps/desktop`) runs as the normal user and can only do what
  the IPC protocol offers. It starts the service on demand through UAC
  (`runas`), polkit (`pkexec`) or the macOS administrator prompt
  (`osascript … with administrator privileges`, every argument shell-quoted).
- **Settings** belong to the GUI. It saves them encrypted as
  `captun.settings` next to the program. On Windows they are sealed with DPAPI
  under the user's account; on macOS and Linux with AES-256-GCM and a random
  key kept owner-only in the user's profile. A second encrypted copy in the
  profile lets a new copy or version start with the same settings. It is the
  only copy where the program's folder cannot be written (Program Files, a
  macOS app bundle, an AppImage). On every connection the GUI hands its saved
  settings to the service, which validates them. Each change the service
  accepts (`Event::ConfigChanged`) is saved again. A file that cannot be opened
  (from another account or computer) is renamed `captun.settings.unreadable`,
  never overwritten.
- **IPC** (`crates/captun-ipc`): newline-delimited JSON, protocol version 2.
  Each connection opens with a mutual proof of a 256-bit per-run token, which
  never crosses the connection (`handshake`): the GUI sends a random nonce, the
  service answers with its own and HMAC-SHA256(token, "captun-server" ‖ GUI
  nonce ‖ service nonce), and only once that checks out does the GUI send
  HMAC-SHA256(token, "captun-client" ‖ service nonce ‖ GUI nonce); 5 s for
  all of it. So a program posing as the service learns nothing and is sent
  nothing (the GUI says another program answered), and a proof seen once does
  not work again. The service takes the pipe first, then writes the token to
  a file only the GUI's user can read, always in the service's own folder,
  never in one of the user's, where a program of theirs could swap in a link
  and steer what the service deletes or makes (on Windows a protected DACL of
  its own: SYSTEM, Administrators, and the `--allow-user` account read-only,
  without one nobody else, in the data folder `%ProgramData%\Captun`, which
  the GUI finds as Windows has it, not from the environment, and whose file
  the user opens by its full path without any right to the folder; on macOS
  and Linux mode 0600, given to that user through the open file, beside the
  socket in `/var/run/captun` or `/run/captun`), and removes it on every way
  out but being killed. On
  Windows the pipe also carries a protected DACL (SYSTEM, Administrators,
  owner, and only the launching user's SID, without the right to create pipe
  instances), is created with `first_pipe_instance`, and rejects remote
  clients. Known limit: the pipe name is fixed, so another account that takes
  it first keeps the service from starting; it still gets nothing it can use.
  A run that cannot take the name says why in a log of its own
  (`captun-daemon.not-started.log`) and leaves the running service's log
  alone. A service from before version 2 refuses the new greeting (only that
  refusal counts: no older service challenges or welcomes first); the GUI
  then stops it once per run over the old protocol, sending only the old
  greeting (the token) and `Shutdown`, never settings, and holds that
  connection until the old service exits (at most 2 minutes). Meanwhile, on
  Windows, it keeps the name taken, so a new service cannot start before the
  old one has removed its token, which sits at the same path. A program
  posing as an older service gains nothing from the old greeting: a running
  service holds the name, so whatever answers in its place can only be
  offered a token no service accepts any more (one a killed run left
  behind). The window learns that an older service is being or was stopped,
  or that another program answered in the service's place, from the
  connection status's `service_notice`. An answer too
  large to send reaches the GUI as an error, an update too large to send is
  skipped, and a connection the service can no longer write to is closed, so
  the GUI connects again. The GUI passes name lookups on to its window in one
  `dns_queries` batch every 250 ms (the newest 500, oldest first, with a count
  of any left out) rather than one message each, and does not pass on the
  service's log lines, which the window does not show.

## Crates

| Crate | Role |
|---|---|
| `captun-core` | Domain types (`MacAddr`, `TargetAddr`, `DomainPattern`/`DomainSet`, `Secret`), the client registry, the config schema with full cross-reference validation and atomic save, and the share-link parser (`socks5://`, `http(s)://`, `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`) that both validation and the GUI use. |
| `captun-policy` | Pure decision engine: admission (approved / quarantined / blocked), first-match rules (who × where × port × protocol × schedule, "where" being websites, address ranges and online lists together), the same rules for name lookups, egress, DNS upstream and rate-limit fallbacks (device → group → global), the three-gate TLS inspection check, and a token bucket. Reads online lists in their many formats (`lists`). |
| `captun-sniff` | Bounds-checked parsers for the first bytes of a flow: TLS ClientHello (SNI, ALPN, ECH; reassembled across records) and HTTP/1.x `Host`. Fuzz-tested. |
| `captun-outbound` | The `Outbound` trait and its implementations: `Direct` (pinned to an interface with `IP_UNICAST_IF` / `SO_BINDTODEVICE` / `IP_BOUND_IF`), SOCKS5 (auth + UDP ASSOCIATE), HTTP CONNECT over TCP or TLS (HTTPS proxies, certificate checked against the bundled Mozilla roots), `Block`, chaining through `via`, and `Unavailable` for egresses that must fail closed. `Direct` looks names up on the system's resolver for at most 5 s, at most 16 at once for devices' traffic and 8 more kept for the service's own connections (a proxy's server named by host, list downloads), so slow names devices ask for never hold those up (getaddrinfo cannot be stopped, so a stalled one keeps its place until it ends rather than taking more of the shared blocking threads), and `udp_session_to` opens only the socket the target's address family needs; a SOCKS5 proxy opens its relay with it, so a UDP flow through Xray holds one UDP socket, not two. `fetch` downloads a file over HTTP(S) through any of them (online lists). |
| `captun-xray` | VPN-link egresses through a supervised [Xray-core] sidecar: turns parsed links into Xray JSON, runs the program with the config on stdin, gives every egress its own loopback SOCKS5 inbound with per-run credentials, restarts it with backoff, and scrubs secrets from its log lines. On Windows it runs Xray at low integrity, and settings that would make Xray use files on this computer are refused (`captun_core::link::xray_settings_problem`). Tested end to end against the real program. |
| `captun-dns` | DNS server (UDP+TCP) with blocklist, overrides, TTL-aware cache and per-device upstreams over UDP/TCP/DoT/DoH. Each query leaves the way the device's rules send its name (by default the device's own egress), so DNS never leaks around a proxy, and names the rules block are answered as blocked. |
| `captun-engine` | The routing engine. Userspace TCP stacks (smoltcp: retransmission on timers, fast retransmit, CUBIC congestion control, resets for unknown connections), one per processor, answer every connection a device opens and UDP flows are kept in a table; a `Dispatcher` classifies each flow (admission, rules, egress), and it is relayed through the chosen egress with per-client bandwidth limits and byte accounting. UDP an egress cannot carry (a SOCKS5 proxy that answers UDP ASSOCIATE with "command not supported", which the outbound remembers for a minute, or `udp = "block"`) is refused with ICMP port unreachable rather than dropped silently, so browsers give up on QUIC at once and use HTTPS over TCP. A failed flow keeps refusing its datagrams for 5 s before the egress is tried again, and nothing ever goes out another way. A SOCKS5/HTTP-CONNECT **inbound** drives the same path for traffic that arrives already proxied (reverse tethering). Fully tested without a packet device. |
| `captun-platform` | Hotspot backends (Windows: Mobile hotspot, falling back to the WLAN hosted network; Linux: NetworkManager, falling back to hostapd; macOS: observes the system's Internet Sharing) and interface discovery. The routing engine and capture steer by interface name, so any adapter the computer itself uses for internet (Ethernet, Wi-Fi, a VPN adapter) is a `direct` egress like any other. |
| `captun-adb` | Captun's **built-in adb**: a native USB Android Debug Bridge client (via [`adb_client`] over libusb, compiled into the service — device discovery, CNXN/AUTH with a persistent RSA key, shell, install), so no external `adb` binary or Android platform-tools is needed. Drives no-app reverse tethering (the phone uses this computer's internet over the RNDIS/NCM link), with a post-session safety notice. Operations are modelled as pure, unit-tested `AdbOp` plans. |
| `captun-usbdriver` | Captun's **USB driver for Android phones** on Windows: an INF that binds Windows' own WinUSB to every phone's USB debugging (ADB) interface by its compatible ID, a catalog for it signed on the computer with a one-off certificate whose key is destroyed once it has signed, and installing, removing and detecting it over the certificate stores, the driver store and the devices plugged in (see [USB driver for phones on Windows](#usb-driver-for-phones-on-windows)). Elsewhere it reports that no driver is needed. |
| `captun-dhcp` | A minimal, bounds-checked DHCPv4 server for wired/USB **access networks**: it hands plugged-in devices an address, the gateway and DNS, and its leases are the source of truth for which devices are present. The wire codec never panics on hostile input; the lease pool and request handling are unit-tested without a socket. |
| `captun-ipc` | Protocol types, framing, transport, token handling and the client used by the GUI. |
| `captun-tls` | HTTPS inspection certificates (see [HTTPS inspection](#https-inspection)): this install's own CA, its key kept where only the service can use it (a non-exportable CNG machine key on Windows, a root-only key file on Linux and macOS), site certificates made on demand and cached (also a rustls `ResolvesServerCert`), and what devices install (PEM, DER, fingerprint, iOS profile). Nothing uses it yet. |
| `captun-daemon` | Wires everything together: the hub state, the monitor loop, DNS lifecycle, request handling, and log forwarding to the GUI. |
| `apps/desktop` | Tauri 2 + React GUI with its own title bar, in one dark theme taken from the logo, a captain's bridge at night (a deep navy sea, brass for the helm and the accent, sailcloth-cream text, a serif for headings, the faint lines of a sea chart behind the pages): Home, kept simple (one big start button in the logo's style, what to join, a Wi-Fi/USB switch, and one line saying how many devices are connected and how many wait to be allowed, which opens Devices), Devices, Outbound, and Rules, DNS and Settings under More. The logo opens About: the version, a link to github.com/SinaXhpm/captun (only that page and its releases can be opened from the GUI), and an update check against that repository's latest GitHub release. The logo, the "network helm" (a ship's wheel drawn as a network: the hub is this computer, the spokes are links, the handles are devices), lives as SVG in `apps/desktop/src-tauri/icons/source/`, written by its `generate.mjs` (brass on a night-sea tile): a detailed master for 96 px and up, and hand-tuned drawings for 16–64 px that make up the small sizes of the Windows `.ico` and the title-bar logo. `npx tauri icon` builds the other platforms' icons from the rendered master. On Home the big button is a brass ship's wheel: while sharing turns on or off it gathers speed and turns once every 3 s, even when the system asks for reduced motion, as it is what says the app is at work; while sharing runs it keeps a calm turn (14 s) and its handles are lit. It stops when the window is hidden, and apart from that busy turn every animation is off when the system asks for reduced motion. |

## Security principles

- **Fail closed.** An egress whose interface is missing, or whose Xray
  sidecar is down, becomes `Unavailable` and refuses traffic instead of falling
  back to the default route (the per-device kill switch). Inside the sidecar,
  anything that matches no egress goes to a blackhole, never out directly.
- **Secrets stay out of argv and logs.** The `Secret` type is zeroized and
  redacted in `Debug`. The Linux hotspot passphrase goes into a root-only
  NetworkManager keyfile, never onto a command line.
- **TLS inspection needs three gates:** the global switch, the admin's
  per-device toggle, and the device user's own acceptance of the *current*
  terms version, recorded with a timestamp.
- **Least privilege at the boundary:** the GUI holds no privileges, every
  config change goes through validation in the service, and settings are
  written atomically, encrypted by the GUI with the user's own rights, so the
  elevated service never writes into folders the user controls.
- **The service's own folder (Windows).** The service keeps its log, the
  online lists and the phone key in `%ProgramData%\Captun`, and by default
  every user may add files under `%ProgramData%`. So the first thing the
  service does, before its log, the settings and the rest, is make that folder and its `lists` folder Captun's alone
  (`paths::prepare_data_dir`). A missing one is made with its owner
  (Administrators) and permissions (SYSTEM and Administrators only, nothing
  from the folder above) in the call that creates it. One already there is
  opened as itself, never through a link, and kept only if it is a folder
  owned by SYSTEM, Administrators or whoever Windows makes the owner of what
  the service creates (its user, under the "Object creator" policy, found
  from a scratch folder it makes and removes); it is then given the same
  owner and permissions through that very handle. Anything else at that name
  (a link, a file, a folder another account made) is moved aside as itself
  (`Captun.untrusted-<time>`) and the folder made afresh; if that keeps
  failing, the service does not start. Inside both, links are removed as
  links (never what they point to), and anything another account owns is
  moved aside the same way (`<name>.untrusted-<time>`, a name nothing reads),
  not deleted: it may be the service's own from a run whose files got another
  owner, or settings someone wrote by hand. What the service made (its logs,
  list copies, the phone key) stays, and what was moved aside before stays
  where it is. If something cannot be taken off its name (another account
  holds it open), the service does not start either, as it would read it or
  write through it. The list copies the service saves are owned by
  Administrators whichever shell or policy started it, so a later run never
  takes them for someone else's. The service also asks Windows not to
  follow junctions that other accounts made (Redirection Guard), where
  Windows offers that. Run without administrator rights (a development run),
  it leaves the folder as it is and says so in its log. Known limit: where
  `%ProgramData%` is comes from the `ProgramData` variable, which the user's
  own settings can change.
- **Hostile input:** every parser of network data is bounds-checked and never
  panics. Unsafe code is limited to small FFI modules with `SAFETY` comments
  (`unsafe_code = "deny"` workspace-wide).

## Platform status

| | Windows | Linux | macOS | Android | iOS |
|---|---|---|---|---|---|
| Builds and passes tests | ✅ | ✅ (checked in WSL Ubuntu) | type-checked only; needs a Mac or CI to build and run | — | — |
| Hotspot with custom SSID/password | ✅ Mobile hotspot → hosted network | ✅ NetworkManager → hostapd | the system's Internet Sharing (no public API; Captun observes it) | planned (root) | not possible (no API) |
| Connected devices | ✅ | ✅ (`iw` + neighbours + DHCP leases) | on Internet Sharing (bootpd leases + ARP), untested | planned | — |
| Outbounds: adapters, SOCKS5, HTTP(S), VPN links | ✅ | ✅ | same code, untested on a Mac | — | — |
| Cable sharing (wired/USB access network) | ✅ WinNAT | ✅ iptables | pf anchor + alias address, untested | — | — |
| USB to phone (reverse tethering) | ✅ | ✅ (NetworkManager told never to route through the phone) | untested | — | — |
| Per-device routing, limits | engine (WinDivert capture, ICS's copies dropped), works on a phone | engine (policy routing), experimental | planned (pf + utun) | planned (root) | — |
| What devices can reach (this computer, each other, home network) | WinDivert + firewall rule; device to device over Wi-Fi is up to the driver | iptables + the access point's isolation | not yet | — | — |

## What Captun needs on each system

Captun brings what it needs, or has the system's package manager install
it. On Windows that includes a USB driver for phones, made on the computer
itself.

- **libusb, on every system.** The built-in adb reaches phones through
  libusb (`rusb`). The workspace turns on rusb's `vendored` feature, so
  `libusb1-sys` 0.7 compiles libusb 1.0.27 from the source it carries and the
  service links it statically: macOS has no libusb of its own, and Linux
  needs no libusb package. `Cargo.lock` holds a single rusb, which
  `adb_client` uses too; its `usb` feature asks for `vendored` as well, and
  the workspace says so itself so that libusb stays built in should a later
  `adb_client` stop asking. On Linux, libusb finds phones in sysfs and hears
  of new ones over netlink, or uses libudev for both when the computer that
  builds Captun has libudev's headers; the packages require libudev for that
  case (systemd and eudev provide it on every mainstream distribution).
- **Windows:** the installer puts the rest next to the service: Xray-core
  (VPN links) and WinDivert (`WinDivert.dll` and its driver `WinDivert64.sys`,
  which carries Microsoft's signature), which captures devices' traffic for
  routing. Network settings go through Windows' own tools (PowerShell, netsh),
  started by their full path. libusb opens a phone's USB debugging interface
  through WinUSB, so that interface needs a driver that hands it to WinUSB.
  The newest Windows builds bring one themselves, and so do phones that tell
  Windows they are WinUSB devices; for the rest the installer adds Captun's
  own, made and signed on the computer (see
  [USB driver for phones on Windows](#usb-driver-for-phones-on-windows)). A
  phone maker's driver, where one is installed, is still the one used.
- **macOS** needs nothing extra: utun (the network adapter routing uses), pf
  (cable sharing), Internet Sharing (the hotspot) and IOKit (USB; libusb
  needs only the CoreFoundation, IOKit and Security frameworks) are part of
  macOS.
- **Linux:** `bundle.linux` in `apps/desktop/src-tauri/tauri.conf.json` makes
  the `.deb` and `.rpm` ask for what the service runs:
  - *required:* `ip` (iproute2), `iptables` and `ip6tables`, `iw` (which
    devices are on the hotspot), `hostapd` (the hotspot when NetworkManager
    cannot run one), `sysctl` (procps, to switch forwarding on) and libudev;
  - *recommended:* NetworkManager, which the hotspot tries first (hostapd
    hosts without it), and dnsmasq (`dnsmasq-base` in the deb: the program
    without its service), which NetworkManager runs to hand out addresses
    on its hotspot and which Fedora's NetworkManager does not pull in
    itself; without it, that hotspot fails and hostapd takes over;
  - *rpm names* that both Fedora and openSUSE answer to: `iproute`
    (openSUSE's iproute2 provides it), `procps` (Fedora's procps-ng provides
    it) and `libudev.so.1()(64bit)`, the form Tauri uses for the window's
    libraries (Captun's Linux builds are 64-bit only). The rpm also
    recommends `iptables-nft`, so dnf picks the nftables kind of `iptables`
    over the legacy one.

  Tauri adds WebKitGTK and GTK for the window itself. The TUN device
  (`/dev/net/tun`) is built into every mainstream distribution's kernel, so
  nothing ships for it. The AppImage cannot ask for packages; there the user
  installs them.

## Transparent routing

`network.transparent_routing` (the GUI's "Outbounds" switch, opt-in) connects
the engine to real traffic: without it devices use the computer's internet
directly and outbounds, the kill switch, limits and traffic figures do not
apply, which the GUI states plainly. One packet device and one engine serve
every managed network: `captun-platform::capture::create` opens the device and
a `Steerer`, and the daemon steers each network (the hotspot, the wired/USB
access network) into it, adding and removing steerings as each comes up or
down. A network whose steering changes is taken by the new steering before
the old one goes, so none of its packets slip past in between; a steering
whose system rules already fit the new settings stands for them instead
(`CaptureConfig::steers_like`: Windows' capture never follows the adapter's
name, and Linux cannot hold the same rules twice). The one exception is a
network that moves to another subnet on the same adapter on Linux (a
fallback way on a network of its own, say): both steerings would use the one
rule that sends the adapter's traffic to the TUN, which the old one's going
would take, so the old one goes first (`CaptureConfig::clashes_with`) and
the adapter is not taken for the moment the new rules need to go in. The
daemon reports the outcome (`ServiceStatus.routing`: off, waiting,
active, failed with the reason) and, on Windows, a count of captured packets so
it is visible whether traffic really arrives, and of those it had to drop
because the engine fell behind (`RoutingStatus.dropped_packets`, from
`Steerer::dropped_packets`). Both count from when outbounds began to apply;
Home shows the dropped ones, when there are any, as a running total beside
the packets taken ("3 dropped so far").

- **Linux:** a TUN device plus policy routing. A rule sends traffic arriving on
  the devices' interface to a dedicated table whose default route is the TUN,
  with a higher-priority exception that keeps traffic to their own subnet (the
  gateway, DNS, device to device) on the main table. Every network shares the
  table and the two priorities, so a network's rules are removed by everything
  they were added with (its interface, and for the exception its subnet):
  stopping cable sharing never takes the hotspot's rules, and the table is
  never emptied, since its one route goes away with the TUN when the engine
  stops. Before a network's rules go in, any that a run stopped abruptly left
  behind are removed, and if not all of them go in, those that did come out
  again.
- **Windows:** routing cannot select by source address, and the hotspot's
  traffic is forwarded and translated by Windows itself (ICS), so no route can
  take it. **WinDivert** (`captun-platform::divert`, a pinned, Microsoft-signed
  packet-capture driver loaded by full path from next to the service) takes the
  devices' packets out of the forward layer (where Windows shows traffic it
  routes for others, with the local inbound layer as a fallback) before ICS
  sees them, by a filter on the device subnet that leaves traffic to the subnet
  itself alone, except DNS queries to the hotspot address: ICS's own DNS server
  holds that address, so the engine takes the queries and hands them to the
  hub's DNS, which resolves them through each device's egress (with
  `dns.enforce`, queries to any DNS server are answered the same way). Replies
  are injected at the forward layer, falling back to the outbound path if
  Windows refuses that; answers from the hotspot address itself go out the
  outbound path. An earlier design that added a route
  for the hotspot subnet through a TUN could never work: that route only
  affects traffic *to* the devices.

  ICS's NAT driver (`ipnat.sys`) does not give way to the capture. It takes
  the same packets and injects translated copies of its own (source this
  computer's address, the device's TTL minus two), which leak the devices'
  traffic past the engine. The real servers answer those copies, and the
  device's kernel takes their reset (its sequence number is exactly the next
  one the device expects) before the engine's reply arrives. Measured on a
  phone on 2026-11-03: 169 of 174 connections reset after about 250 ms, with
  nothing the engine sent ever acknowledged. WinDivert marks packets another
  driver injected as `impostor`, so while a network is captured, two
  priority-3000 handles drop them. At the forward layer, where the copies
  arrive, every impostor bound for a single address goes, whatever its TTL: a
  phone starts at 64, a Windows laptop at 128 (its copies leave at 126),
  others at 255, and this computer's own packets never cross that layer. At
  the network layer the impostors dropped are those going to the devices and
  those leaving with a TTL other than this computer's own (read from a new
  socket when the network is captured; 128 unless Windows was set otherwise),
  so this computer's own traffic that other software injects again there (a
  VPN client, a security suite) keeps going. Packets from the hotspot's own
  address (ICS's DHCP, NetBIOS) and multicast are left alone. The engine's
  replies are injected from priority 0 and never reach those handles. With
  them in place, 80 of 80 connections closed normally. Each dropped copy is
  counted in the log (the first ten, then at powers of two). Virtual machines
  that reach the internet through Windows' own sharing (WSL, Docker Desktop,
  Hyper-V's Default Switch) look the same as the copies, so while a network is
  shared through the engine they may lose the internet.

The engine then applies `PolicyEngine::decide` per flow, sniffs SNI/Host for
domain rules (or takes the name the device's own lookups last gave the
address), dials the client's egress, holds each direction to the device's
speed limit and to the one on all devices together (`network.limit`), each a
token bucket (TCP waits for the tighter; a UDP datagram over either is dropped
and charged to neither), and records bytes in the `TrafficMeter`. A change of settings applies
to connections already open, not just new ones (`FlowControl`):


- A change to one device's own settings ends only that device's connections
  (`reset_devices`), and only when it changes what decides them: letting it
  in or blocking it, its group, its own outbound, its speed limit (a
  connection takes its limit when it starts). A group's outbound or speed
  limit ends its members' connections. A device's name, its DNS server and
  HTTPS inspection end none. A change to outbounds, rules or network
  settings ends every open connection (`reset_all`). Devices reconnect and
  are decided again. Xray starting, stopping or moving ends no working
  connection: those through it end when its process exits, and the open
  connections are checked again (below), so flows refused while its
  outbounds stood unavailable are decided again at once. Each flow learns
  its device when it is decided (`Dispatcher::dispatch_device`), refused
  flows too, so letting a device in also ends the refusals it is still
  being given. What has been reset only ever grows (a count, the count at
  the last reset of everything, and each device's), so two resets in a row
  both take effect, and a flow that learns its device after that device's
  reset (while its name was still being sniffed) still ends.
- A device's data allowance used up, or started over, ends that device's
  connections, so they reconnect cut off, slowed or back to normal (see
  *Data use and allowances* below).
- Time windows, the device limit and Xray are checked again on open
  connections (`recheck_all`): the monitor looks every 2 s, first thing in
  its tick, and asks when a rule's window opens or closes (the clock is
  compared each time, so a clock change cannot make it miss an edge, and
  the last look and this one are both judged by the rules in force now, so
  rules saved just before an edge cannot hide it), when the device limit
  holds a device back or lets one in again, and when Xray starts, stops or
  moves. Each open connection asks `Dispatcher::still_allowed`, which
  decides again at the current time without counting a rule hit, and ends
  when it would no longer go out the same outbound, or when the device
  list or the neighbor table names another device at its address (an
  entry missing for a moment, as while a phone sleeps, does not count).
  Connections to the hub's own DNS go on: each query is decided by itself.
  A refused UDP flow ends at once, so its next datagram is decided again.
  A flow watches for both from the moment it starts, before it is decided,
  so neither is missed in between. The USB proxy inbound's connections are
  treated the same way, as the phone's.

Both capture paths need validation on real hotspot hardware; the OS commands
and filters are built by pure, unit-tested functions and reverted when the
engine stops.

### Data use and allowances

The service reads every device's counters in the `TrafficMeter` every 5 s
(`captun-daemon/src/usage.rs`) and counts what moved since the last reading
in two places:

- **Per hour, for the Usage page.** Local hours (a half-hour time zone and a
  change of clocks come out right: the minutes and seconds the local clock
  shows are taken off), one JSON file per local day in the data folder's
  `usage` folder, today's held in memory and saved every minute and on
  shutdown, days past 400 deleted. `GetUsage` takes the bounds of the
  stretches asked about (local midnights or hours, worked out by the app) and
  answers what was used in each and by each device; an hour counts where it
  starts.
- **Per period, for allowances** (`Quota`: MB of 1,048,576 bytes, download
  and upload together, per day, week from `network.week_starts`, month, or in
  total). Each device keeps what it used in the current day, week and month
  and since its last reset by hand (`allowances.json`), so an allowance that
  changes period applies at once. A device's allowance is its own, else its
  group's, else `network.device_quota` (`Config::quota_for`); each device
  counts its own use. Devices that used nothing for 62 days are forgotten
  unless their allowance never starts over.

A device over its allowance goes into `Hub::over_quota`, which the policy
takes (`PolicyEngine::with_over_quota`): without `then_kbps` its admission
becomes `OverQuota` (no internet; a block still outranks it), with it its
speed limit becomes the tighter of its own and that speed. The service checks
on every reading, so a device is held at most about 5 s late; a change ends
its connections. `ResetQuota` starts the current period over and
`AddQuota` gives extra for it only. Like the speed limits, allowances work
while traffic goes through the engine (`transparent_routing`), and they go by
the device's hardware address: a phone that makes up a new one gets a new
allowance (a sign-in page with accounts closes that gap).

### Holding the line

What keeps every flow on the device's own outbound, or nowhere:

- **A flow's device:** the device list (polled every 2 s), checked against
  the system's neighbor table (`captun_platform::neighbors`,
  `GetIpNetTable2` or `/proc/net/arp`, read at most every half second, on
  demand and on the monitor's tick, never on the engine's or the DNS
  server's threads). Captun's own DHCP takes whatever hardware address a
  request claims, so a lease alone would let a waiting or blocked device
  pass for an approved one: the device list counts for an IPv4 address only
  when the neighbor table has the same hardware address there. Another one
  there, or none yet, is refused out loud (said once in the log per address
  and hardware address); the refusal makes the system look the device up,
  and its next try a moment later goes through. An address the device list
  does not have goes by the neighbor table alone: a new device is refused
  out loud until the table has it, moments later, then gets its own
  outbound and rules, and is never sent the default way. A source neither
  knows is refused the same way. A flow never changes its way later. DNS
  follows the same rule. A device behind a repeater or bridge that answers
  for it with its own hardware address is refused for as long as it stays
  there, with one warning in the log. macOS has no neighbor table to ask,
  so there the device list is trusted as it is.
- **What tells devices apart** is their hardware address, and a determined
  device can fake it: one that takes an approved device's hardware address
  is let in with that device's rules and outbound. Approval keeps out the
  casual guest, not a determined one; the check above only stops a device
  from using an address the device list gives another while keeping its own
  hardware address.
- **DNS:** while routing is on, the hub always answers the devices' DNS, even
  with its DNS server turned off (blocklist and overrides then dropped).
  Windows' own DNS on the hotspot address would resolve through this computer
  directly. It looks names up only for a device let in: one waiting for
  approval, a blocked one and one held back by the device limit get REFUSED
  (the blocklist and overrides are still answered), so a waiting device
  cannot get online over DNS alone (a DNS tunnel).
- **The hotspot's network:** recognized from the adapter list or, when that
  read fails, from Windows' host names (`GetHostNames`), since a hotspot without
  a known network would not be captured.
- **Starting:** with routing on, the hotspot's network is steered and held to
  the device rules before the access point starts, so the first packets of a
  device that joins at once are already taken. The network is the one the
  backend expects (`HotspotBackend::expected_network`; Mobile hotspot
  192.168.137.0/24), with this computer on its first address until the
  running hotspot tells; on Windows the capture goes by addresses alone, so
  the adapter Windows has yet to make is not needed (Linux steers by the
  adapter's name, so there this happens once it is known, as on a restart).
  The devices' DNS to this computer is taken from then on too, so none goes
  around their outbound to Windows' own DNS server; a lookup made before the
  hub's DNS is up fails and is asked again. If that steering fails with
  the kill switch on, the access point does not start (one already up for a
  restart goes off). After the start the expected network is asked again, as
  a fallback may have started another way on a network of its own. Those own
  networks (the hosted network, hostapd) share no internet through the
  system while routing is on (`HotspotBackend::set_engine_routed`, told at
  every start), as cable sharing does not, so their devices get out through
  Captun or not at all. On Linux their forwarding stays allowed either way
  (`ip_forward` and the `FORWARD` rules for the subnet), since the policy
  routing into the TUN forwards too; only the masquerading follows
  `set_engine_routed`. Turning outbounds off restarts a running hotspot of
  that kind (`HotspotBackend::shares_through_system` is false for it), so its
  network takes the system's sharing up again; Mobile hotspot and
  NetworkManager share through the system all along and keep running, so
  their devices are not dropped for nothing.
- **Stopping:** the access point stops before the capture is let go: the
  hotspot's steering and device rules stay while it starts or stops (the last
  network it had) and are lifted only once a stop has the access point down.
  When the access point goes off outside a start or stop, the monitor lets
  its network go. On Windows, where both go by addresses, they stay for 30 s
  after it was first seen off (`HOTSPOT_OFF_HOLD`), so a turn-on Windows makes
  soon after is taken from its first packet too, and are lifted after that,
  so an access point Windows' power saving turned off does not keep the
  capture up (while a network is captured, virtual machines on Windows' own
  sharing may lose the internet, see above). On Linux they name the Wi-Fi
  adapter, which the system may already use for this computer's own Wi-Fi
  again (NetworkManager took it back, after a suspend), so they are lifted
  at once. If the service dies instead, the GUI sees
  the pipe drop. If the hotspot is still up with routing and the kill switch
  on, the GUI turns it off itself.
- **A stopped engine:** rebuilt on the next monitor tick. The capture keeps the
  devices' packets meanwhile.
- **Windows' transitions** (its power-saving turn-off) are looked at every
  tick until they settle; a transition from running shows as "turning off".

### Rules, online lists and ready-made rules

- **Where traffic goes is one condition.** A rule's websites (`domains`),
  addresses (`cidrs`) and online `lists` together: going to any of them is
  enough (sing-box's meaning; Xray requires both). Every other filled-in
  condition must hold too.
- **Online lists** are links, downloaded only when the user presses Update
  lists, through an outbound they pick, since a source may be filtered on the
  direct way out (`Request::UpdateLists`; `captun_outbound::fetch`: HTTP/1.1,
  gzip, redirects followed but never from HTTPS down to HTTP, nor onto this
  computer or the local network unless the link itself points there, 48 MB and
  180 s per list). A redirect to an address there, or to a name that points
  there by itself (`localhost`, `.local`, `.lan`, `.home.arpa`, `.internal`,
  a name of one label), is refused through any outbound, since a proxy
  running on this computer would answer it here. Through the direct outbound
  a redirect's other names are looked up by `fetch` itself and the checked
  addresses are the ones connected to, so a second DNS answer cannot slip
  past; a name found to lead only inside is refused with a hint to pick
  another outbound, as that is how filtered networks block names. Through a
  proxy, which looks names up on its side, nothing more can be checked. A
  host of numbers alone (`127.1`, `0x7f.1`) is read as an IPv4 address, as
  browsers do, and an IPv4 address behind NAT64 (`64:ff9b::`) counts as
  itself.
  `captun_policy::lists` reads hosts files, adblock filters
  (`||name^`, with `@@||name^` exceptions; rules for pages, wildcards or with
  options other than `important` are skipped), dnsmasq, plain names and
  addresses, Clash and Surge rules and domain sets, Xray lists and JSON lines
  (Spamhaus). A downloaded list never names a whole top-level domain, private or
  special-use space, or a range wider than /8 (/16 for IPv6), so no list can
  cut devices off from this computer or the home network. A list holds at most
  2,000,000 entries, counted as each is read, so one long line (a hosts line
  giving an address millions of names) cannot pass the limit, and at most 1000
  keywords of 4 to 253 characters that a name can hold (`a-z`, `0-9`, `-`, `.`,
  `_`). Names are kept as 64-bit fingerprints (about 10 bytes each). Each list
  is saved, one entry per line, in `%ProgramData%\Captun\lists`
  (`/var/lib/captun/lists`), which only SYSTEM and Administrators can change
  (see [Security principles](#security-principles)), always as a new file
  that then takes the old copy's place: whatever was left under the new
  file's name is removed as itself first, never written through. A failed
  download keeps the copy from before, and a rule whose lists were never
  downloaded matches nothing.
- **Updating runs in the background** (`ListStore::try_start` / `update`):
  `Request::UpdateLists` starts the downloads and is answered at once with
  what `Request::GetLists` answers (`ListsProgress`: whether an update is
  under way, how many of how many lists it is through, and each list's
  state), so the page knows an update is running whenever it opens. One runs
  at a time; pressing again while one runs starts nothing. The lists are downloaded one after another, each put
  in use as soon as it is through (`refresh_policy`), and `Event::Lists`
  tells the app when the update starts, after each list and when it is over.
  The app keeps that above the pages (`ListsProvider`): the Rules page shows
  "Updating… 3 of 8 lists done" with the button off until the last, and a
  toast then says "Lists updated" or how many could not be downloaded,
  wherever the user is by then. While one runs the app also asks every 5 s,
  in case a busy connection dropped the event that ends it. When it is over,
  the lists the rules no longer name are let go of (`prune`, under the lock
  changes of settings take), so a list whose rule went while it downloaded is
  not kept in memory until the next change.
- **Saved copies are read off the async threads.** A change of settings
  first reads the saved copies of lists its rules now name and nothing holds
  yet (`ListStore::load_missing`, in `Hub::commit` before the swap): each on
  a blocking thread and none under a lock, since a big list takes seconds.
  Lists no rule uses any more are let go only after the swap (`prune`), as a
  rebuild for the device limit still compiles the rules before until then.
  Compiling the policy then only shares what is held; reading a copy on the
  spot is left to start-up (`Hub::new`), before anything is served.
- **Rules apply to name lookups** (`PolicyEngine::decide_lookup`): the rules a
  name alone decides (none about ports or a protocol; address-only rules wait
  for the connection), top to bottom. A blocked name is answered as blocked
  (`dns.block_response`), which also stops what no sniffing sees (QUIC, apps'
  own protocols). A name sent through an outbound is looked up through it, so a
  filtered network's fake answers never reach it. An Allow rule above a
  blocklist rule is its list of exceptions.
- **Connections that do not say their name** (QUIC, WhatsApp's and other
  apps' own protocols) go by the name the device's own lookups last gave
  their address (`names::LearnedNames`). Each device has names of its own,
  so another device's lookups never change its way, nor push out its names:
  two generations of 2,048 addresses per device, at most 32 taken from one
  answer, for at most 512 devices and 32 MiB in all (past either, the device
  that learned least recently is forgotten first). Only a device let in
  learns names, and a forgotten device's names go with it.
- **Hit counters and the tester.** Each rule counts the connections and name
  lookups it decided, and when it last did (`captun_policy::HitCounters`:
  atomics carried with the compiled rules, so a rebuild for other settings
  keeps them and a change to the rules starts them over; `Request::GetRuleHits`).
  The Rules page shows them on each row and has a "Which rule applies?" box
  (`Request::TestRules`): for a website or an address, a device or any, it
  reports what a lookup and a connection would get by the rules alone
  (`PolicyEngine::decide_rules`: admission aside) and which outbound really
  carries the connection (an outbound's UDP setting included), and for an
  address also by the name that device last looked it up by (for any device,
  the name a device last did). A test is never counted.
- **Ready-made rules** (`apps/desktop/src/ruleTemplates.ts`): blocklists
  (HaGeZi Normal and Threat Intelligence, PersianBlocker, Spamhaus DROP), 25
  apps and sites (Telegram with its published ranges, WhatsApp, Instagram,
  YouTube, ChatGPT and others) and Iran's sites and ranges. Each opens in the
  rule editor and becomes an ordinary rule.
- **Limits:** devices that use encrypted DNS of their own (Android's Private
  DNS set to a hostname, a browser's secure DNS) get past name blocking and the
  learned names; their TLS connections are still matched by SNI.

### Scale and fairness

- Per device: 256 TCP connections, 64 of them in their handshake at once, and
  256 UDP flows, inside the engine's 4096 connections, 1024 handshakes in
  progress and 4096 flows. The TCP caps count over all the TCP stacks below.
  The overall cap on handshakes keeps half-open connections from taking the
  room of finished ones (and their buffers under 320 MiB).
- The caps count per device, not per address. When a connection or flow
  opens, the engine asks whose budget it draws on
  (`Dispatcher::source_key`, answered from memory, never blocking): a device
  the device list has online and lets in is one budget, by its hardware
  address, whichever of its addresses it uses (those on the device list,
  and those the neighbor table names it at). Every address no listed device
  holds (a device too new to be on the list, a waiting or blocked one, one
  held back by the device limit, made-up addresses) draws on one small pool
  they all share: 32 handshakes, 64 connections and 64 flows. So no number
  of made-up addresses can take the listed devices' slots, and a new
  device's connections still get through before it is listed. A device on
  cable sharing with an address set by hand takes no lease, so it is never
  on the device list: the neighbor table finds it and its own outbound and
  rules apply, but it stays in the small pool, with the small TCP buffers
  (below). Once a second the engine asks again about what the pool holds,
  and moves a device's connections and flows to its own budget once it is
  listed. On its own the engine gives every address a budget of its own.
- Name lookups (UDP to port 53) have a reserve past the caps, 16 per device
  and 512 in all, so neither a full table nor a device's other flows stop
  them. They give their slot back after 5 s quiet. A UDP flow the policy
  refuses goes on refusing its datagrams for 5 s, then gives its slot back,
  however often the device sends; sooner when its device is reset or the
  rules are checked again.
- TCP buffers are allocated with the device's SYN: 32 KiB in and 64 KiB out,
  or for a listed device's first 32 connections at once (1024 over the
  engine) 64 KiB in and 256 KiB out. 64 KiB in flight holds a download to
  about 20 Mbit/s over a Wi-Fi link at 25 ms; 256 KiB to about 80. The pool
  of unlisted addresses always gets the small ones, so made-up addresses
  cannot take the big ones, and a connection gives its big ones' slot back
  when it ends. smoltcp's timeout counts from the device's last segment, so
  connections send keep-alives every 60 s; without them every idle push
  channel (notifications, MQTT) was reset after two minutes.
- A device's speed limit holds TCP back (the relay waits) but drops UDP
  datagrams over it, in both directions, rather than queueing them: a queue
  behind the limit only grows, and apps slow down when datagrams are lost. A
  datagram may leave the device's bucket about one burst (a quarter of a
  second, at least 16 KiB) in debt; one larger than two bursts needs a full
  bucket. So a call or a game still gets through beside a download that
  fills the limit; the download pays the debt by waiting. Drops are counted
  in the log.
- What may wait for a UDP flow's relay: 64 datagrams (the reader's batch) and
  96 KiB per flow, 4 MiB over a device's flows, 32 MiB over all; more is
  dropped. Answers are read into 4 KiB first, and into 64 KiB only for a flow
  that received a larger one, 256 such flows at once. That first larger
  answer is dropped. A name lookup gets one answer on its own source port,
  so it starts with 64 KiB while no more than 128 are taken, and gives it
  back after 5 s quiet. Answers dropped as too big are counted in the log.
- Memory at the caps, at worst: TCP buffers about 608 MiB (1024 connections
  with big ones at 320 KiB, 3072 with small ones at 96 KiB) and the TCP
  relays' 32 KiB per connection, 128 MiB; UDP queues 32 MiB, and the UDP
  relays' 8 KiB per flow (4608 with the lookups' reserve), 36 MiB, and 16 MiB
  of big answer buffers. About 820 MiB in all; an ordinary hotspot uses a
  small part of it.
- TCP runs in several smoltcp stacks side by side, one per processor up to 8,
  each in its own task with its own lock (`shard.rs`). A connection belongs to
  the stack its two ends hash to (a hash keyed afresh for each engine), so all
  its packets go there and all its replies come from there. One task reads the
  device and hands each TCP packet to its stack; a stack 1024 packets behind
  loses the rest, as a congested link would, without holding up the others.
  One task writes everything the stacks and the UDP flows send. When any of
  these tasks ends or fails, the whole engine stops (the daemon rebuilds it)
  and every stack resets its connections, so no relay task waits on it.
- Inside a stack each connection's socket has a smoltcp socket set of its own,
  and the stack keeps the connections' timers itself. A packet, a relay task's
  wake or a due timer runs only its own connection, so the cost of a packet no
  longer grows with the connections open (smoltcp looks at every socket of a
  set for each packet in and each packet out). Measured end to end with
  `time_per_packet_*` (debug build, 8 cores, a busy machine): 250–340 µs per
  packet at 1000 connections before, 26–51 µs after; at 4000 connections
  730–900 µs before (with the cap raised to allow them), 19–33 µs after.
- A device's speed limit is one token bucket per direction shared by all its
  flows (`TrafficMeter::bucket`), not one per flow. The limit on all devices
  together is one more bucket per direction, shared by every flow, which each
  flow's pacing handle reads as it goes, so a new limit reaches connections
  already open (`TrafficMeter::set_total_limit`, called at start and on every
  save). It is set in Settings, General; a device's own on the Devices page.
- UDP answers are taken only from the flow's destination, so nothing else that
  finds the socket can pose as it.
- Rules with address ranges are compiled into sorted, merged ranges and
  searched by bisection. Protocol and port are checked first.
- Connections to DNS servers (TCP, DoT, DoH on HTTP/1.1 keep-alive) are
  reused for up to 25 s after their last answer. At most 32 queries to one DNS
  server through one outbound use a connection at once; the others wait their
  turn (within the 5 s a query may take) and take a connection one of them put
  back, so a burst opens 32 connections at most rather than one (and a
  handshake) each. One device gets 8 of those turns at most, and its other
  queries wait behind its own, so a device whose names are slow to look up
  does not hold up the others. A query whose 5 s run out while it waits for a
  turn was never sent, and does not count against the DNS server (see below).
  Once its queries are answered, an outbound keeps 16 idle connections to a
  DNS server (while others are being asked, as many as they may want, so up
  to 32), and a DNS server keeps 64 over all outbounds, the one put back
  longest ago going first. A kept connection idle more than 3 s
  that does not answer within 1.5 s is given up on and the query asked again
  on a new one; one used more recently gets the whole 5 s. Connections belong
  to the outbound object they were opened through (`Upstream` holds a weak
  reference to it), so an outbound rebuilt under the same id never gets the
  old one's. Each query to a DNS server on UDP has a socket of its own (a new
  random source port, RFC 5452) and asks for answers of 1232 bytes at most,
  whatever the device asked for; an answer that fills the 4 KiB read buffer
  counts as cut short and is asked for again over TCP. The DNS cache key
  includes the outbound.
- The DNS cache holds at most `dns.cache_size` answers and 32 MiB (each answer
  counted at its size plus 512 bytes). Answers over 4 KiB are given but not
  kept, and the oldest answers go first, however long their TTL.
- The hub's DNS answers at most 1024 UDP queries at once, and 64 from one
  device (`DnsHandler::admit`): its own server and the engine's path to it
  (`local_dns.rs`, before a task is made for the query) both ask first and
  drop what is refused, and the device asks again. A query counts until its
  answer is handed back. The TCP server takes 256 connections, each
  answering one query at a time.
- The lookup log reaches the GUI in batches, not one message per lookup:
  while a GUI is connected and the log is on, the service keeps the lookups
  that come in (at most 500 and 1 MiB written out; the oldest are left out
  first, and counted) and sends them every 250 ms as one `dns_queries` event,
  only when there are any. With no GUI connected it keeps none.
- A device that goes out directly, the plain direct way rather than through
  a chosen network adapter, is answered by this computer's own resolver
  when its DNS server cannot be reached. The server counts as unreachable on
  that outbound after 3 errors within 10 s that say so (timed out, refused,
  reset, closed before answering), never after a bad answer, which a device
  can cause with a name of its choosing. While it counts as unreachable, one
  query about every 5 s still tries it, and the first answer ends that. At
  most 16 of this computer's lookups run at once, and 4 for one device, so a
  device whose names never resolve leaves room for the others. Each holds a
  thread until it ends (even after the 5 s a device waits); more get SERVFAIL
  at once. Their answers are kept up to 30 s, apart from the DNS servers'
  answers. Localhost names get the loopback address from the hub itself;
  names without a dot or under `.local`, which this computer would look for
  on its own networks, get SERVFAIL. A lookup sent through a network
  adapter that fails gets SERVFAIL, as one through a proxy does: this
  computer's resolver would go out its own way, around the adapter, to a
  network whose answers the adapter may be there to avoid.
- Rules with online lists match against compiled lists shared by every rule
  and every rebuild of the policy: a few hash probes per name, plus one pass
  over it for all of a list's keywords together (Aho-Corasick), and a
  bisection per address, however long the list.
- The device list stays bounded, though a device on the wire can send under
  any number of made-up MACs. Right after each 2 s look at who is there, the
  monitor forgets offline devices that have no saved settings and no
  connection still open (`Hub::prune_devices`, `ClientRegistry::prune`):
  those not seen for a day, and past 1000 such devices the ones seen longest
  ago. Their traffic counters go with them. The GUI is sent
  every device online, every device with saved settings, and the 500 offline
  ones seen most recently; the list is built only while a GUI is connected,
  and copied out of the device-list lock (which every new flow and name lookup
  waits on) before the rest is put together. The log gets each device's coming
  and going at debug level, and at most one line a tick when several came or
  went ("12 devices joined, 10 left").
- Speeds travel apart from the device list, which goes only when a device
  comes, goes or changes (`Event::Clients`). Once a second while a GUI is
  connected, a task of its own (`traffic.rs`) copies the online MACs under a
  brief device-list lock, reads their counters, and measures each speed from
  its own reading a second before, in bits per second as the GUI shows them:
  `Event::Traffic`, every online device that has had traffic, not sent again
  while it stays the same. The reading holds the devices it reports only, and
  starts afresh when no GUI is connected, so a speed is never an average over
  a gap. The device list shows the last reading's speeds without moving it.
  The window keeps the speeds in a context of their own, so only the cells
  that show them redraw every second.
- Reading the network adapters can take seconds on Windows (each gateway is
  asked for its MAC address), so the service reads them on a blocking thread,
  one read at a time, shared for 3 s (`iface::list_async`), never on the async
  threads or under a lock: the device rules the monitor renews every tick, the
  adapter list the GUI asks for every few seconds, the USB-to-phone route
  checks, and outbounds tied to an adapter and steerings into the engine
  (which on Windows look for their network's adapter while the engine is
  locked), both of which use a list read beforehand.
- Known limits: one task reads the device and one writes it, a packet at a
  time, and on Windows one thread sends every reply. The driver calls beneath
  them are batched: each capture thread takes up to 255 packets per
  `WinDivertRecvEx` and hands them straight to the engine's queue (4096 at
  most; more are dropped, as on a congested link, and counted in the routing
  status, next to the captured packets). While a capture thread is
  busy, the driver holds up to 16,384 of its packets or 32 MiB, so bursts
  wait. A write only queues its reply (4096 at most, likewise) for the thread
  that sends replies, which sends whatever has gathered, up to 255 per
  `WinDivertSendEx` and handle.

## What devices can reach

Devices always get the internet. Three settings decide what else they reach
(Settings → Local access, stored the "keep out" way round): this computer
(`network.block_host`), each other (`network.isolate_clients`) and the private
networks this computer is on, such as the home network and the router
(`network.block_host_lan`). All three keep devices out by default. These rules
do not depend on outbounds: the daemon's `reconcile_reach` puts them in for
every shared network (the hotspot and cable sharing) while it is up. It renews
them when the settings or this computer's addresses change, retries them every
few seconds while they fail, reports the result as `ServiceStatus.local_access`,
and lifts them on shutdown.

- **Windows:** `captun-platform::reach` opens WinDivert handles with the drop
  flag at priority 1000, ahead of the engine's capture (priority 0). At the
  local layer it drops devices' packets to each of this computer's addresses,
  its loopback, and its share of broadcast and multicast, sparing DHCP and DNS
  at the gateway. On the network's adapter it always drops the IPv6 router
  advertisements and redirects devices send, whatever the settings: with one,
  a device would make itself this computer's IPv6 router, and through the
  advertisement its DNS server too. With this computer kept out, it drops the
  rest of their IPv6 to this computer as well, apart from what finding
  neighbours needs (router and neighbour solicitations, neighbour
  advertisements). Should that router rule alone fail to go in, the rules say
  so as a warning rather than fail. At the forward layer it drops what
  passes through to another device or to a private range outside their network.
  Fake-address ranges of proxy tools (198.18.0.0/15) stay reachable. WinDivert
  takes `not` only before a single test, and a test on a missing header is
  false whichever way round, so negations use its `? false : true` form.
  Tests run every combination of settings against real packets with
  WinDivert's own compiler and evaluator, which need neither the driver nor
  administrator rights. Letting devices reach this computer also adds a Windows
  Firewall rule (group "Captun devices") for this computer's address on their
  network: Windows treats the hotspot as a public network and would refuse
  them otherwise. The daemon removes leftover rules of that group when it
  starts. Whether Wi-Fi devices reach each other directly is the Wi-Fi
  driver's decision: that traffic never reaches Windows' IP layer, and the GUI
  says so instead of offering a switch.
- **Linux:** iptables chains per network. `INPUT` covers this computer, sparing
  DHCP and DNS; `FORWARD` covers device to device through this computer and
  the private ranges; IPv6 to this computer is handled on a best-effort basis
  (`ip6tables`): router advertisements and redirects from devices are always
  dropped, and with this computer kept out, so is everything else but what
  finding neighbours needs, DHCPv6 and DNS.
  The access point's own isolation (`ap-isolation`, `ap_isolate`) keeps Wi-Fi
  devices apart, so the hotspot restarts when that setting changes.
- **Elsewhere:** not enforced yet (`local_access` says "unsupported").

The routing engine refuses the same destinations itself (`ReachView`, a TCP
reset or "port unreachable"). This covers flows that reach it anyway, such as
a phone on USB asking its proxy for this computer or for `localhost`. No device
may ever reach this computer's loopback, whatever the settings: the packet
parser drops such packets, and the dispatcher refuses them.

## VPN links (Xray sidecar)

VLESS (incl. REALITY and XTLS Vision), VMess, Trojan, Shadowsocks (incl.
2022 ciphers) and Hysteria2 run on [Xray-core], the reference implementation,
rather than a reimplementation: the protocols and their anti-censorship
transports (REALITY, XHTTP, gRPC, WebSocket, mKCP, QUIC) change too fast for a
second implementation to keep up.

- **Pinned and verified.** `scripts/xray.lock.json` pins one release and the
  SHA-256 of each platform's archive; `scripts/fetch-xray.mjs` refuses
  anything else and extracts only the executable. Installers ship it next to
  the service, so nothing is downloaded at run time (which would also fail on
  exactly the networks VPN links are for). The service only runs a program
  from next to itself (or, on Linux, root-owned package paths). On Linux and
  macOS it refuses one other users could modify. On Windows the file itself
  cannot show that, so the installer puts it in a folder only administrators
  can change (see [Installing on Windows](#installing-on-windows)), and the
  release service registers a check (`captun_xray::set_program_check`, with
  `captun_platform::trust::check_program_file`) that the program must pass
  when it is found and again right before every start: SYSTEM,
  Administrators or TrustedInstaller must own the file, and nobody else may
  change it, add files to its folder or rename any folder above it, with no
  link anywhere on the way. It is registered before anything looks for the
  program. A copy in a folder other accounts can change is never run; VPN
  links then say to reinstall Captun for all users. Development builds
  register none.
- **One process, one inbound per egress.** The service writes Xray's config to
  its stdin (never to disk): a loopback SOCKS5 inbound with random per-run
  credentials and UDP for each VPN-link egress, a routing rule tying it to that
  egress's outbound, and a blackhole for everything else. The data plane then
  treats the egress as a SOCKS5 proxy, so per-device routing, UDP, limits and
  stats are identical to any other egress.
- **Supervised.** The sidecar restarts with exponential backoff (1–30 s) and is
  restarted only when what it runs changes. Until it is up its egresses are
  `Unavailable` with a reason the GUI shows. It runs without privileges where
  the OS allows (on Linux and macOS as the user who started Captun, else
  `nobody`), dies with the service (a
  kill-on-close job object on Windows, `PR_SET_PDEATHSIG` on Linux), and its
  log lines are scrubbed of every secret before they reach the service log.
- **Checked early.** Links are validated when saved, with Xray's own rules in
  plain words: no certificate-check bypass without a pinned certificate
  (`allowInsecure` is gone from Xray), no unencrypted VLESS to public servers,
  no removed transports (HTTP/2, QUIC), no Shadowsocks plugins. An Xray
  config file used instead of a link is read by the service with full rights,
  so on Windows it must be on one of this computer's own drives (never
  `\\server\share`, `\\?\` or `\\.\`), checked when saved and again when read,
  and it must be an ordinary file: links and synced cloud files are opened as
  themselves and refused, and a pipe's server cannot act as the service. All
  config files are read at once and given 3 s together, on a blocking thread
  rather than the service's async workers, so files another program holds
  open delay applying settings by 3 s at most and hold nothing else up; a
  file whose read is still stuck is not read again until that read ends.

## Phone tethering over USB (built-in adb)

Captun speaks the ADB wire protocol itself, over libusb, through the
[`adb_client`] crate — **no external `adb` and no Android platform-tools**,
and no libusb to install: it is compiled into the service (see
[What Captun needs on each system](#what-captun-needs-on-each-system)). It
only needs USB debugging on the phone; for the default paths nothing is installed
on it. Devices are discovered straight from USB descriptors (so listing never
blocks on the "Allow USB debugging?" prompt), and a persistent RSA key in the
service's data directory means the phone only has to authorize Captun once. All
phone-side work is expressed as unit-tested `AdbOp` plans with a matching revert.

Once a phone has allowed it, that key opens the phone to whoever holds it, so
`captun-adb` (`key`) keeps it Captun's alone. On Windows it lives in
`%ProgramData%\Captun`. Nothing is checked, moved, deleted or made there
unless SYSTEM or Administrators own that folder and it is not a link (its
owner could change who may do what in it); the folder is held open meanwhile,
so it cannot be renamed or replaced. A key found there is used only if SYSTEM
or Administrators own it and its permissions, cut off from the folder's, let
in only them. Windows reports both, as SDDL (the same in every Windows
language), for the very file held open (`GetSecurityInfo`); no program is
started. Anything else (a link, a folder, a planted file, a key others can
read, as older versions could leave one) is moved aside, or deleted if it
cannot be moved, and a new key made; `Adb::prepare_key`, which the service
calls before it starts USB to phone, then reports `KeyStatus::Replaced` with
a note telling the user to revoke USB debugging authorizations on the phone.
The service adds that note to what starting USB to phone says, whether it
starts or not: first when it starts, as the app shows that message only
briefly, and after the reason when it does not. A new key gets its owner
(Administrators) and permissions (only SYSTEM and Administrators may read it)
in the call that creates it, so no one can open it in between; only then is it
written, and on any failure it is deleted and USB to phone does not start.
The key checked or made is held open for the rest of the run, and a phone
command that waits over 20 s for another one's check gives up rather than
queue behind a stuck one. On Linux and macOS it is created `0600` in a folder
only root can change.

Known limits: the key relies on the service making `%ProgramData%\Captun`
Captun's alone as it starts (see [Security principles](#security-principles)),
owned by Administrators and changeable by administrators only. A service run
without administrator rights leaves the folder as it is: a folder another
account made first is then refused, and USB to phone does not start.

**Captun only gives internet; it never takes it.** The one direction is the
phone using this computer's internet ("USB to phone"). There is deliberately no
mode in which this computer uses a phone's connection.

- **How:** two methods, no app store:
  - *System proxy (default, no app):* `captun-adb` switches the phone's USB
    function to `rndis,adb` (`svc usb setFunctions`, kept with `adb` so Captun
    does not lose control), which brings up a USB network link so the phone can
    reach the PC by IP. Captun runs a SOCKS5/HTTP proxy inbound bound to the PC's
    address on that link and points the phone's system HTTP proxy at it.
  - *Never the other way:* the phone's tethering offers itself to the PC as a
    gateway and DNS server on that link. `captun-platform::tether_net` refuses
    both: it removes the link's default routes (Windows also pushes its metric to
    the back; Linux tells NetworkManager, for this connection only, never to use it
    as a default or for DNS), drops the phone's DNS servers, and opens only the
    proxy port. The daemon then checks the outcome before sharing starts (the PC
    must reach the internet through its own adapter, never the phone's link, or
    sharing is refused) and every few seconds while it runs, removing any route a
    DHCP renewal brings back. Everything is reversed when the session ends.
  - The inbound feeds every flow into the policy engine as a managed client (a
    stable, locally-administered MAC derived from the serial), so the phone's
    egress, rules, limits and traffic stats all apply. Carries proxy-aware
    TCP/HTTPS only — no UDP, and apps that ignore the system proxy are not
    covered.
  - *Helper (full coverage):* a pushed helper's VPN would carry all traffic
    including UDP. The plan exists; the helper binary is not bundled yet, so the
    service reports it unsupported and falls back to the default.

Because it uses libusb directly, Captun needs exclusive USB access to the phone:
any other running adb server must be closed, and on Windows the phone's USB
debugging interface needs a driver that hands it to WinUSB, which Captun
installs itself where Windows has none (see
[USB driver for phones on Windows](#usb-driver-for-phones-on-windows)).

Captun reverts the phone-side changes it made when a session ends, but it does
not turn USB debugging off (that would cut its own control). After every session
it shows the user a caution on how and why to turn USB debugging back off.

## USB driver for phones on Windows

libusb reaches a phone on Windows only through WinUSB, and on many computers
a phone's USB debugging (ADB) interface has no driver at all: Device Manager
shows it without one (code 28) and USB to phone cannot see the phone.
`captun-usbdriver` gives Captun its own driver for it, the way Zadig
(libwdi) does, made and signed on the computer it is for:

- **The driver.** An INF (`captun_adb.inf`) that binds Windows' own WinUSB
  (`Include = winusb.inf`, `Needs = WINUSB.NT`) to the compatible ID every
  ADB interface carries, `USB\Class_FF&SubClass_42&Prot_01`, so no phone's
  own IDs are needed. It joins Windows' "Universal Serial Bus devices" class
  and registers the device interface ADB tools look for
  (`{F72FE0D4-CBCB-407d-8814-9ED673D0DD6B}`). It copies no file: the only
  driver that runs is Microsoft's `WinUSB.sys`. Windows ranks a driver that
  names the phone itself above one matched by a compatible ID, and a
  Windows-signed driver above this one, so a phone maker's driver, Google's,
  or Windows' own (the newest builds list the ADB interface in their
  `winusb.inf`; phones with Microsoft's descriptors get WinUSB by themselves)
  is always the one used where it exists. The package has a version of its
  own (`DRIVER_VERSION`, in the INF's `DriverVer`), raised only when the INF
  or the catalog definition changes; a test fails until it is raised for a
  changed package. Each copy made ends with a line of its own (`; This
  copy: ` and a random number), so Windows never takes a new copy for an
  earlier one that another certificate signed.
- **The catalog.** Made from a generated catalog definition with wintrust's
  `CryptCATCDFOpen` / `CryptCATCDFEnumMembersByCDFTagEx` /
  `CryptCATCDFClose`, as makecat does: a version 2 catalog listing the INF by
  its SHA-256 (and SHA-1) hash, with the OS attribute `2:6.2,2:6.3,2:10.0`
  (Windows 8 to 11).
- **A one-off certificate.** Self-signed, named "Captun USB driver (this
  computer only)", fit for signing code and nothing else (extended key usage
  code signing, key usage digital signature) and unable to vouch for other
  certificates (basic constraints: not an authority). Its private key is an
  RSA-3072 CNG key with no name, which Windows never writes anywhere, and
  which cannot be exported. It is tied to the certificate in memory only,
  signs the catalog once (`SignerSignEx2`, SHA-256, no time stamp), and is
  destroyed right after, whether signing worked or not. Before anything is
  trusted, the catalog is read back: it must list the INF as Windows hashes
  it, name the Windows versions, and be signed by that certificate alone.
- **Where it is made.** A new folder with a random name in the Windows
  folder's `Temp`, created with its owner (Administrators) and permissions
  (SYSTEM and Administrators only) in the creating call. No one else can add
  or swap a file between writing the INF and Windows taking the package, and
  no one but administrators may rename what others made in that `Temp`. The
  folder is deleted afterwards: Windows keeps its own copy.
- **Installing** (`captun_usbdriver::install`, refused without administrator
  rights). Where Windows' own `winusb.inf` already binds WinUSB to every ADB
  interface (the newest builds'), nothing of Captun's goes in: Windows'
  driver would always be used over it, so it would only add a certificate
  to trust. One put in earlier, before Windows had its own, comes out, and a
  phone without a driver is given Windows' own. Elsewhere the certificate
  goes into the machine's Root store (so the
  signature leads to something trusted) and TrustedPublisher store (so
  Windows adds the package without asking), as its encoded bytes alone.
  `SetupCopyOEMInf` then adds the package to the driver store, which checks
  the signature; SetupAPI is told never to show a window. Each ADB
  interface plugged in now that has code 28 (Windows found no driver), or
  no driver at all once Windows has finished setting up what was plugged in
  (`CMP_WaitNoPendingInstallEvents`, waited for up to 10 s), gets the best
  driver Windows keeps for it (`DiInstallDevice`), which is Captun's unless
  one naming the phone is there too. One Windows is still setting up is left
  to Windows, which picks from the same store. An interface with a driver,
  working or not, or one someone turned off, is never touched. Phones
  plugged in later get the driver from Windows on their own. What was
  installed (the name Windows gave its copy of the INF, `oemNN.inf`; the
  certificate's thumbprint; the package version) is noted under
  `HKLM\SOFTWARE\Captun` before each step, and a step that fails undoes the
  ones before it. Installing the same package version again keeps what is
  there, so updating Captun leaves phones' drivers alone. A different
  version is replaced the other way round from removing: the new package
  goes in first, and only then does the old one come out, so phones using
  it move to the new one rather than to none. Whatever an older version or
  an interrupted install left, noted or not, is found by Captun's mark (the
  INF's first line, in `%WINDIR%\INF\oem*.inf`) and name (the certificate's,
  in both stores) and removed after each install. Installs and removals
  take a machine-wide lock that only SYSTEM and Administrators can open, so
  the installer's and the service's never run at once (each would make a
  certificate, and one would go unnoted).
- **When.** The installer runs `captun-daemon.exe --install-usb-driver`
  after copying Captun's files; a failure only warns, as everything else
  works without it, and a passive install (`/P`, as the app's updates run)
  writes the warning to its log instead of waiting on a message box. The
  service, when listing phones finds none it can use but a USB debugging
  interface without a driver (code 28, or none once Windows has finished
  setting it up), starts installing it once a run (it runs elevated). The
  install runs in the background, since it can take longer than the app
  waits for an answer; meanwhile listing says "Captun is installing the USB
  driver for Android phones. Wait a moment, then press Start again.", and
  the app's next regular listing shows the phone once it has the driver.
  If a phone still has none after that, listing says "Captun installed the
  USB driver for Android phones. If the phone does not show, unplug it and
  plug it in again."; if the install failed, what went wrong and to install
  the phone maker's driver instead. A phone that has a driver but is not
  ready (another program holds it, or it was just plugged in) is listed as
  it is, whatever the driver did before.
- **Removing** (`captun_usbdriver::remove`, `--remove-usb-driver`, which the
  uninstaller runs before removing anything else, once it has asked to close
  Captun if it is running; an update with `/UPDATE` keeps the driver). Every
  copy of Captun's package Windows keeps, noted or not, leaves the driver
  store with `DiUninstallDriverW`, which first takes it off any phone using
  it (looked up when needed, as it exists only from Windows 10 1703; given
  Windows' copy of the INF, then the driver store's if Windows wants that
  one; without it, `SetupUninstallOEMInf`). Then every certificate of
  Captun's leaves both stores. Only Captun's own goes: a certificate must
  carry Captun's name as subject and issuer, and Windows' copy of an INF
  must start with Captun's first line, since Windows reuses `oemNN.inf`
  names.

Why this is safe to trust: the certificate is trusted by this computer only,
for signing code only, cannot issue certificates, and its key existed in
memory for one signature. With the key gone, no one, Captun included, can
sign anything else with it, so the trust it adds covers the one catalog it
signed. Adding a driver package still takes administrator rights; the
TrustedPublisher entry only saves the question "Would you like to install this
device software?" for this package. The package holds no program of its own.
Uninstalling Captun takes the certificate and the package away again.

Known limits: installing and removing touch the machine's certificate and
driver stores, so that path is tested only from an elevated prompt
(`cargo test -p captun-usbdriver -- --ignored`), and has not yet run on a
Windows 10 or 11 whose `winusb.inf` has no ADB line: before a release, run
that test, the installer and the uninstaller elevated on such a machine with
a phone plugged in, and compare `pnputil /enum-drivers` and the machine's
Root and TrustedPublisher stores before and after. What runs without
elevation is checked on every test run: the catalog and its signature, that
the signing key is gone from the certificate and signs nothing more, and
that Windows' chain checks for code signing (the chain itself, the
Authenticode and the base policy) find nothing wrong with the certificate,
its critical key usage and basic constraints included, once it is trusted
(built in memory with it as the only trusted root). Windows reads the
catalog definition as 8-bit text, so the folder it is made in must have a
plain ASCII path (the Windows folder's `Temp` does). A phone plugged in
while the driver is removed loses it and is back to having none. While
Windows reports device setup still going on (or cannot say), an interface
with no driver yet is left to Windows; it gets Captun's driver once Windows
gives up on it with code 28.

## HTTPS inspection

Phase 1 of 5 is done: the certificates, in `captun-tls`. Nothing intercepts
traffic yet, and the service does not use the crate yet (it still reports
`tls_inspection = false`).

- **This install's own CA**, "Captun HTTPS inspection CA <id>" (an
  eight-character id, new with each CA): ECDSA P-256, `CA:TRUE`,
  `pathlen:0`, key usage `keyCertSign` + `cRLSign`, extended key usage
  `serverAuth` only, valid three years. It is made the first time it is
  needed and never shipped or shared. Its folder holds `ca.pem` and `ca.json`
  (install id, when it was made, SHA-256 fingerprint, which key store holds
  the key). At every start the certificate must match its record, hold its
  key, carry its own valid signature and be this CA. One that fails, or has a
  day or less left, is replaced, and the service is told why, since devices
  must then install the new one. A failure to read or ask says nothing about
  the CA and is an error, never a reason to replace it. `reset` deletes the
  record, every CA key and the certificate, whatever is left of them, and the
  next start makes a new CA.
- **No name constraints**, on purpose: Captun inspects every site a
  consenting device opens except those on the bypass list, which permitted
  names cannot express. Excluding the bypass list would write it into the
  certificate, so each change would mean a new CA on every device, and not
  every platform applies name constraints to a root its user installed.
- **Site certificates** are made on demand for the name the client asks for
  (SNI) or the proxy request names (CONNECT): a fresh P-256 key made in memory
  and never written, the name as the only subject alternative name (no common
  name), `serverAuth`, valid from two days ago (for devices whose clocks run
  behind; never before the CA) for 30 days (never past the CA), a random
  serial and both key identifiers. They are cached for 4,096 sites (the least
  recently used goes first) and made again a day before they run out. Callers
  asking for the same site at the same time share one signature, and at most
  four signatures run at once, so one device asking for endless new names
  cannot keep the CA key busy for everyone; warnings about sites left without
  a certificate are rate-limited. As rustls' `ResolvesServerCert` the cache
  gives no certificate when the client names no site, so the caller can pass
  the connection through.
- **For devices**: the certificate as PEM and DER, its SHA-256 fingerprint to
  compare on screen, and an iOS/iPadOS profile, "Captun HTTPS inspection",
  whose description and consent text (English and Persian) say in plain words
  what it allows, including that the device trusts the certificate on every
  network until the profile is removed: Captun uses it only on its own
  network, but anyone who got the key could use it anywhere. A newer profile
  replaces the older one on the device.

**Threat model.** The CA key is everything: whoever holds it can pose as any
site to every device that trusts the CA. So each install has its own (one key
shared by every install was Superfish's mistake), and it stays where only the
service can use it:

- **Windows:** a machine key in CNG (Microsoft Software Key Storage
  Provider), `Captun-HTTPS-inspection-CA-<id>`, made only by the elevated
  service. Its export policy has no export flag at all, Administrators own
  it, and its permissions let only SYSTEM and Administrators use it
  (`O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)`). All of it is set before the key is
  finalized. Windows keeps the key in its key isolation service and signs
  there: Captun sends a SHA-256 hash and gets the signature back, so the
  private key never enters Captun's process. Each
  time the key is made or opened, it is checked again as Windows reports it
  (P-256, export policy zero, owned by SYSTEM or Administrators, no one else
  let in), and one that fails is never used. A question Windows cannot
  answer, or answers in a form Captun does not know, is an error, never a
  failed check, so a passing fault never replaces the CA. An ordinary program
  is refused before Windows is asked. The key storage is opened only after
  the service has started, on a worker thread, as Windows asks of services.
- **Linux and macOS** (until a keychain backend exists): a PKCS#8 file,
  `ca-key-<id>.pk8`, made only by root, created exclusively with mode `0600`
  and never opened through a link. A key file that belongs to anyone else or
  lets anyone else in is never used. The bytes read are wiped once the key is
  loaded (ring keeps a copy of its own while the key is in use).
- The CA's folder is controlled by the service alone. On Windows it is made
  with its own protected permissions (Administrators own it; only SYSTEM and
  Administrators get in, nothing inherited from ProgramData, which lets every
  user add files); a folder that is not Captun's alone is moved aside and made
  again, so no account can switch inspection off by planting one. Only
  Captun's own half-written files are ever cleaned up there. On Linux and
  macOS it is owned by root and writable by no one else; on Linux it lives in
  /var/lib/captun, never under /etc (etckeeper and /etc backups would keep
  copies of the key), and on macOS the key file is kept out of Time Machine.
- The machine-key tests need an administrator window; they have not yet run
  on real hardware, which is part of the phase 3 wiring.

**Consent.** Only a device whose user has given explicit, informed consent
is ever inspected, and its user installs the certificate themselves. Nothing
installs it silently, over adb or into a system certificate store, and
nothing ever will. Inspecting someone's traffic without their consent is a
crime in Iran (Computer Crimes Law, article 2), in the EU and in the US.

**Next.** Phase 2: the consent page that offers the certificate, with the
consent record owned by the service (written only by that page, unchanged by
`SetConfig` and `SetClientProfile`, tied to more than a MAC address) and a
"certificate installed" gate. Phase 3: TLS terminated on the USB phone's
proxy inbound, where CONNECT names the site and there is no QUIC
(`SiteCerts::leaf_for`, upstream certificates checked, bypass and automatic
bypass for apps that pin). Phase 4: the hotspot and cable path (sniffing
forced for inspected devices, UDP 443 refused for them, which `block_quic`
does not do yet, ECH configs withheld by the hub's DNS). Phase 5: a security
review of the key path and the terminator.

## Roadmap

1. **Foundation (done):** the crates above, the GUI, the end-to-end IPC, and
   the hotspot on Windows and Linux.
2. **Routing engine (done, experimental):** `captun-engine` plus the TUN-based
   capture and steering above. Still to do: validate on hardware, block
   DoT/known DoH when `dns.enforce` is on. Client DNS already goes to the
   hub's resolver, and what devices can reach is enforced (see above).
3. **Phone tethering over USB (done):** the built-in native-USB `captun-adb`
   (no external adb), the reverse proxy inbound over the USB link, the PC-side
   `tether_net` guard that keeps the PC off the phone's connection, the hub
   wiring (list devices, reverse-tether, caution), and the dashboard's "USB to
   phone" panel. Still to do: the bundled helper for
   full-coverage reverse tethering (UDP), and hardware validation across OEM
   USB stacks and Windows ADB drivers.
4. **Wired access networks (done; per-client routing experimental):** a
   client-facing backend that brings a wired Ethernet or USB-RNDIS interface up as
   the shared network, so clients need not be on Wi-Fi. `captun-platform::access`
   assigns the gateway address and sets up OS NAT (and, on Windows, a DHCP
   firewall rule scoped to the interface, one per subnet; PowerShell looks the
   adapter up by its index, so no adapter name is ever part of a script). When
   a step fails, the steps already done are undone at once, so a failed start
   leaves no gateway address behind to block the next one. Windows' own tools
   (PowerShell, netsh) are started by their full path in the Windows folder,
   never by a bare name the elevated service would look for next to itself
   first, and with an environment built from the Windows folder alone (a
   `PATH` of Windows' folders, PowerShell modules only from Windows' own and
   Program Files' folders, the temporary folder, nothing else): the service
   carries its user's environment, which any program of theirs can change, and
   a module folder or `COR_PROFILER` set there would otherwise load their code
   into the elevated PowerShell. `captun-dhcp` serves addresses on a
   socket isolated to that interface (`SO_BINDTODEVICE` on Linux; the
   per-interface firewall rule on Windows, so it never answers DHCP on another
   network). Anyone on the wire can send requests under any MAC, so an OFFER
   only holds its address for a minute (it never shortens a lease the device
   already has) and the lease starts with the ACK; only ACKed leases count as
   devices. New MACs get addresses in a burst of 64, then one a second, and at
   most 100 replies go out a second. A device with a live lease cannot move to
   another address, RELEASE frees a lease only when it names the address and
   comes from it, and DECLINE only touches the sender's own address, which is
   then not offered for ten minutes unless nothing else is free. Unknown MACs
   claiming a free address back (after a restart; leases are not saved) are
   still ACKed. Hostnames are cut to 63 characters, and a pool is cut to its
   first 4096 addresses (logged once). The Wi-Fi networks Captun runs itself
   (the Windows hosted network, hostapd: 10.74.0.0/24) use the same pieces, and
   their DHCP answers only stations associated with the access point (the hosted
   network's peer list, `iw dev <if> station dump` for hostapd). A request from
   a MAC not on the list reads it again, at most four times a second, so a new
   station's first DISCOVER is answered; if the list cannot be read at all,
   everyone is answered as before. Their device list shows a lease only while
   its station is associated. The daemon's `access_network` lifecycle
   (`StartAccessNetwork` / `StopAccessNetwork`), the monitor merges DHCP leases
   into the client list, and the GUI exposes it in Settings. With transparent
   routing off, internet is basic
   OS NAT; with it on, the access network is steered into the shared routing engine
   alongside the hotspot (one TUN, one engine, a steering per network, reconciled
   as each comes and goes), so per-client egress, limits and stats apply — the same
   experimental, hardware-unvalidated path as Wi-Fi. The networks Captun runs
   for its own access points skip OS NAT the same way: the daemon tells the
   backend at every start whether the engine routes
   (`HotspotBackend::set_engine_routed`, read at start), and a running hotspot
   on such a network starts again when outbounds are turned off, to share
   through the system once more (`HotspotBackend::shares_through_system`).
   On Linux, cable sharing and those networks allow forwarding for their
   subnet whether or not they masquerade it: the engine's policy routing
   forwards their packets into the TUN. `HotspotBackend::expected_network` gives a hotspot's network before it
   starts (Mobile hotspot: the /24 around ICS's `ScopeAddress` in the registry,
   192.168.137.0/24 unless someone changed it, which is also where its adapter
   is looked for; own networks 10.74.0.0/24), which the daemon steers before the
   access point is up (see "Holding the line").
5. **VPN links (done):** the Xray sidecar above, share-link parsing for every
   proxy and VPN-link scheme, HTTPS proxies, and release bundling
   (`scripts/release.mjs`). On Windows Xray runs at low integrity: the
   service marks its program file with a low mandatory label before every
   start (an elevated service that cannot do so does not start Xray; an
   unelevated run, as in tests, goes on without it, its Xray having only the
   user's rights), and a process gets the lower of its parent's level and its
   program file's, so whatever its settings say it can write almost nothing. Settings
   that make it use files (`certificateFile`, `keyFile`, `masterKeyLog`, at any
   depth and in any case, and network or device paths) are refused in links'
   xhttp `extra` and in outbound files alike
   (`captun_core::link::xray_settings_problem`), as it can still read what the
   service can, and a network path would make Windows sign in to it as the
   user. Still to do: reach a VPN link's server through another egress (`via`
   for VPN links).
6. **TLS inspection** (see [HTTPS inspection](#https-inspection); the
   per-install CA with its key in the OS key store, and leaf certificates
   made on the fly, are done in `captun-tls`): the consent portal with CA
   download, the TLS terminator, an HTTP/1.1 + h2 viewer, HAR/pcap export,
   and automatic bypass for pinned apps.
7. **Captive portal:** password, terms acceptance, sessions.
8. **More platforms:** macOS (in progress: everything type-checks for macOS
   and the platform pieces exist — admin prompt, `/var/run` paths, Internet
   Sharing observer, pf-based cable sharing — but nothing has run on a Mac
   yet), then Android (root).

## Development

```bash
node scripts/fetch-xray.mjs                # once: the pinned Xray-core, next to the service
cargo test --workspace                     # all Rust tests (the Xray end-to-end test needs the step above)
cargo clippy --workspace --all-targets     # must stay warning-free
cd apps/desktop && npm install && npm run build
node scripts/release.mjs                   # installer with the service and Xray bundled
```

### Installing on Windows

The Windows installer installs Captun for all users, in
`C:\Program Files\Captun` unless another folder is chosen, and asks for
Windows' confirmation once, at install. The service runs with administrator
rights and starts the programs beside it (Xray, WinDivert's library), so only
administrators may change that folder: an install for one user, in
`%LOCALAPPDATA%`, could be changed by any program that user runs, and with it
what the service runs. `apps/desktop/src-tauri/windows/hooks.nsh` makes sure
of it, for a folder chosen by hand too:

- **Before copying**, it refuses a whole drive, a link to a folder elsewhere,
  and a folder holding anything but an earlier Captun that Administrators
  own. An empty folder (usually one the installer has just made) is deleted
  and made again with its final owner and permissions in the creating call:
  Windows checks rights only when something is opened, so whoever made an
  empty folder beforehand could otherwise keep it open, with the right to
  change its permissions or rename it, past the install. If it cannot be
  deleted (such a handle is open) or someone made it again meanwhile, the
  install stops. The folder is then given to Administrators and its
  permissions replaced in one step: SYSTEM and Administrators may do
  anything, Users may read and run, nothing comes from the folder above.
- **After copying**, icacls makes Administrators own every file and sets the
  same permissions again (without `/C`, which reports success even when a
  file failed). Any failure stops the install with a plain message. Then the
  service installs the USB driver for phones (`--install-usb-driver`, see
  [USB driver for phones on Windows](#usb-driver-for-phones-on-windows)); a
  failure there only warns. The uninstaller first asks to close Captun if
  it is running, then removes that driver and its certificate
  (`--remove-usb-driver`) before anything else.
- **An older Captun installed for this user only** (Tauri's default
  before) stops the install with a request to remove it in Settings > Apps
  first. Such a copy is found by its entry in Installed apps,
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Captun`, which
  Tauri's installer writes for a copy installed for one user. Its uninstaller is not run from the elevated
  installer: any program of the user could have replaced it. An entry whose
  uninstaller is gone (its folder was deleted by hand) cannot be removed in
  Settings either, so it is ignored and left as it is. The settings
  stay in `%LOCALAPPDATA%\Captun`, where an all-users Captun keeps using
  them.
- Only this installer is built (`tauri.windows.conf.json`): Tauri's MSI would
  let any folder be chosen without these checks.

Known limits: when a standard user installs with an administrator's password,
the check for an older copy looks at the administrator's account, not the
user's. The installer cannot make safe a folder chosen by hand inside one
another account can change (that account could rename it and put another in
its place); refusing a program there is left to the service's program check
(see [VPN links](#vpn-links-xray-sidecar)). An earlier Captun's folder is
reused as it is: a handle someone opened on it before an older installer
locked it lasts as long as the program holding it keeps running.

Checking the other platforms from one machine:

- **Linux:** build and test in WSL or a VM (`libwebkit2gtk-4.1-dev` for the GUI).
- **macOS:** `sh scripts/check-macos.sh` from Linux or WSL runs clippy for both
  Mac targets with a stand-in C compiler (build scripts need an object file;
  `clippy` never links). That proves the Rust code compiles for macOS;
  running it needs a Mac, or the macOS job in `.github/workflows/ci.yml`.

[Xray-core]: https://github.com/XTLS/Xray-core
