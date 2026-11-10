//! Shared service state and the operations the GUI can request.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use captun_adb::{
    Adb, AdbOp, ReverseMethod, ReverseParams, SessionSummary, UsbFunction, link_down_command, link_up_command,
    post_session_caution, reverse_plan,
};
use captun_platform::tether_net::{self, ReverseNet};
use captun_core::{
    ClientRegistry, ClientState, Config, MacAddr, ObservedClient, Presence, TargetAddr,
    config::{ClientProfile, ConfigError},
    time::now_millis,
};
use captun_dns::{DnsHandler, DnsServerHandle, DnsSettings};
use captun_engine::{CounterSnapshot, EngineHandle, FlowControl, InboundConfig, TrafficMeter, serve_inbound};
use captun_platform::capture::{SteeringGuard, Steerer};
use captun_ipc::{
    AccessNetworkStatus, AdbDeviceInfo, Capabilities, ClientView, DeviceTraffic, EgressTestResult, ErrorCode, Event,
    HotspotState, HotspotStatus, InterfaceInfo, IpcError, ListsProgress, LocalAccessState, LocalAccessStatus, Request,
    Response, RuleHits, ServiceStatus, TetherOutcome, TetherSession, RoutingState, RoutingStatus, TetherStatus,
    TrafficStats, XrayState, XrayStatus,
};
use captun_outbound::OutboundSet;
use captun_platform::{
    BackendState, HotspotBackend, HotspotError, capture,
    capture::CaptureConfig,
    reach::{self, ReachConfig, ReachError, ReachGuard},
};
use captun_policy::PolicyEngine;
use captun_xray::{Sidecar, SidecarState};
use tokio::{net::TcpListener, sync::broadcast, time::timeout};
use tracing::{debug, info, warn};

use crate::{
    capacity::Capacity,
    dns,
    engine_glue::{FlowsEnded, Neighbors, OpenWindows},
    env::HostEnv,
    lists::{self, ListStore},
    local_access::{self, ReachView, SharedNetwork},
    names::LearnedNames,
    tether,
    traffic::Speeds,
};

const EGRESS_TEST_TARGET: &str = "cloudflare.com:443";
const EGRESS_TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Locks a std mutex, recovering from poisoning: every guarded value here is
/// replaced wholesale, so a panic mid-update cannot leave it half-written.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn read<T: Clone>(m: &RwLock<T>) -> T {
    m.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

fn write<T>(m: &RwLock<T>, value: T) {
    *m.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
}

struct DnsRuntime {
    handler: Arc<DnsHandler>,
    /// The address devices send their queries to.
    gateway: IpAddr,
    /// The listening socket there, when the system let us open one. Where
    /// another server holds the address (Windows' Internet Connection
    /// Sharing), the routing engine hands the queries over instead.
    _server: Option<DnsServerHandle>,
}

/// Holds the routing engine and its OS steering together so dropping this both
/// stops routing and reverts the routing changes.
/// Which network a steering belongs to, so reconciliation can add and remove them
/// independently as the hotspot and access network come and go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SteerKey {
    Hotspot,
    Access,
}

/// One network steered into the shared engine, kept alive by its guard.
struct ActiveSteering {
    key: SteerKey,
    config: CaptureConfig,
    _guard: SteeringGuard,
}

/// The shared routing engine and every network currently steered into it.
struct EngineRuntime {
    engine: EngineHandle,
    steerer: Steerer,
    steerings: Vec<ActiveSteering>,
}

/// What one shared network's devices may reach, kept in force by its guard.
struct ActiveReach {
    key: SteerKey,
    config: ReachConfig,
    guard: ReachGuard,
}

/// The phone this PC shares its internet with over USB. Reverting needs the
/// device serial and the adb commands that undo it.
#[derive(Default)]
struct TetherState {
    reverse: Option<ReverseSession>,
    /// What Captun's USB driver for phones has done this run (Windows).
    usb_driver: UsbDriverFix,
    /// How listing phones looks for and installs that driver.
    usb_driver_calls: UsbDriverCalls,
}

/// Captun's USB driver for phones is installed at most once a run, in the
/// background, the first time a phone shows up whose USB debugging
/// interface has no driver.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum UsbDriverFix {
    #[default]
    NotTried,
    Installing,
    /// Done: what the user is told while a phone still has no driver.
    Installed(&'static str),
    /// It could not be installed: what the user is told instead.
    Failed(String),
}

/// The driver calls listing phones makes: `captun_usbdriver`'s own, which
/// tests replace.
#[derive(Clone, Copy)]
struct UsbDriverCalls {
    detect: fn() -> Result<captun_usbdriver::Detection, captun_usbdriver::DriverError>,
    install: fn() -> Result<captun_usbdriver::Install, captun_usbdriver::DriverError>,
}

impl Default for UsbDriverCalls {
    fn default() -> Self {
        Self { detect: captun_usbdriver::detect, install: captun_usbdriver::install }
    }
}

/// What listing phones says about the USB driver, when no phone is ready.
#[derive(Debug, PartialEq, Eq)]
enum PhoneDriver {
    /// Nothing: the phones are listed as they are.
    Nothing,
    /// It is being installed: look again in a moment.
    Installing,
    /// Installed this run, and a phone still has no driver: plugging it in
    /// again gives it one.
    Installed(&'static str),
    /// It could not be installed: what to do instead.
    Failed(String),
}

/// What to tell the user about the USB driver when no phone is ready, from
/// what is plugged in now and what the driver did earlier this run.
fn usb_driver_advice(detected: &captun_usbdriver::Detection, fix: &UsbDriverFix) -> PhoneDriver {
    // Only a phone still without a driver is the driver's to explain. One
    // with a driver that cannot be used yet (another program holds it, a
    // maker's driver libusb cannot open, the moment after plugging it in),
    // or one Windows is still setting up, is listed as it is.
    let captun_usbdriver::Detection::Missing(_) = detected else { return PhoneDriver::Nothing };
    match fix {
        UsbDriverFix::NotTried => PhoneDriver::Nothing,
        UsbDriverFix::Installing => PhoneDriver::Installing,
        UsbDriverFix::Installed(notice) => PhoneDriver::Installed(notice),
        UsbDriverFix::Failed(message) => PhoneDriver::Failed(message.clone()),
    }
}

/// The phone list as the app gets it, once no phone is ready: the driver's
/// news, if any, comes instead of the list. The app's regular listing passes
/// over it and keeps the list it has; pressing Start shows it.
fn usb_driver_listing(listed: Vec<AdbDeviceInfo>, said: PhoneDriver) -> Result<Vec<AdbDeviceInfo>, IpcError> {
    match said {
        PhoneDriver::Nothing => Ok(listed),
        PhoneDriver::Installing => Err(IpcError::new(ErrorCode::BadRequest, captun_usbdriver::INSTALLING_NOTICE)),
        PhoneDriver::Installed(notice) => Err(IpcError::new(ErrorCode::BadRequest, notice)),
        PhoneDriver::Failed(message) => Err(IpcError::new(ErrorCode::Unsupported, message)),
    }
}

/// The PC-side network interface that appears when the USB link comes up.
struct LinkIface {
    name: String,
    system_name: String,
    index: u32,
    ipv4: Ipv4Addr,
}

/// Aborts a background task when dropped, tying it to its owner's lifetime.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// How often a running USB-to-phone session re-checks that the phone has not
/// become this PC's way to the internet.
const PHONE_ROUTE_CHECK: Duration = Duration::from_secs(3);

/// Whether the phone's link is this PC's default route, and whether any other
/// adapter is, in `ifaces` (read off the async threads: a read can take seconds).
fn route_state(ifaces: &[captun_platform::iface::Interface], link_index: u32) -> (bool, bool) {
    let via_link = ifaces.iter().any(|i| i.index == link_index && i.default_route);
    let via_other = ifaces.iter().any(|i| i.index != link_index && !i.loopback && i.default_route);
    (via_link, via_other)
}

/// Captun only gives internet. Makes sure this PC is not using the phone's
/// connection: removes any default route over the link until none is left,
/// and refuses when the PC has no internet of its own to give.
async fn keep_off_phone_route(net: &ReverseNet) -> Result<(), IpcError> {
    for _ in 0..6 {
        // A read begun after the last enforce, so a removed route is seen gone.
        let ifaces = captun_platform::iface::list_fresh_async().await;
        match route_state(&ifaces, net.interface_index) {
            (false, true) => return Ok(()),
            (false, false) => {
                return Err(IpcError::new(
                    ErrorCode::BadRequest,
                    "This computer is not connected to the internet, so there is nothing to share with the phone.",
                ));
            }
            (true, _) => {
                let net = net.clone();
                let _ = tokio::task::spawn_blocking(move || tether_net::enforce(&net)).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    Err(IpcError::new(
        ErrorCode::Internal,
        "The phone kept offering its own internet to this computer, and Captun never uses a phone's internet. Sharing was stopped.",
    ))
}

/// Keeps the phone's link off this PC's routes for as long as the session
/// runs: a DHCP renewal from the phone can bring a default route back.
fn watch_phone_route(net: ReverseNet) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        loop {
            tokio::time::sleep(PHONE_ROUTE_CHECK).await;
            if route_state(&captun_platform::iface::list_async().await, net.interface_index).0 {
                warn!("the phone offered itself as this computer's internet again; removing that route");
                let net = net.clone();
                let _ = tokio::task::spawn_blocking(move || tether_net::enforce(&net)).await;
            }
        }
    }))
}

/// A running wired/USB access network: the DHCP server and the PC-side setup
/// (gateway address, NAT, firewall). Dropping the session stops DHCP first, then
/// reverts the OS changes.
struct AccessSession {
    interface: String,
    gateway: Ipv4Addr,
    network: Ipv4Addr,
    prefix_len: u8,
    nat: bool,
    dhcp: captun_dhcp::DhcpServer,
    _net: captun_platform::access::AccessGuard,
}

/// The phone is using this PC's internet (reverse tethering). The inbound proxy
/// stops serving when this is dropped, and the PC-side network set-up is reversed
/// when `_net` is dropped; the phone-side adb changes are reverted explicitly.
struct ReverseSession {
    serial: String,
    /// The PC-side adapter of the USB link.
    interface: String,
    phone: MacAddr,
    revert: Vec<AdbOp>,
    /// Keeps the link off this PC's routes; stops before the guard reverts.
    _route_watch: AbortOnDrop,
    _net: tether_net::ReverseNetGuard,
    _inbound: EngineHandle,
}

/// What starting USB to phone tells the user, with `note` (what to do about a
/// phone key that was replaced), whichever way it went. On success it comes
/// first: the app shows that message only briefly, and the note is the part
/// that asks something of the user. A failure stays on screen, so there it
/// follows what went wrong.
fn with_key_note(started: Result<TetherOutcome, IpcError>, note: Option<&str>) -> Result<TetherOutcome, IpcError> {
    let Some(note) = note else { return started };
    match started {
        Ok(outcome) => Ok(TetherOutcome { message: format!("{note} {}", outcome.message), ..outcome }),
        Err(e) => Err(IpcError::new(e.code, format!("{} {note}", e.message))),
    }
}

/// The settings the hub's DNS runs with, or `None` when it should not run.
/// While Captun carries the devices' traffic their lookups go through their
/// outbounds too: left to Windows' own DNS they would go out directly (and,
/// where the internet is filtered, come back tampered with). With Captun's
/// DNS turned off that is all it does: no blocking, no answers of its own.
fn dns_config(config: &Config) -> Option<captun_core::config::DnsConfig> {
    match (config.dns.enabled, config.network.transparent_routing) {
        (true, _) => Some(config.dns.clone()),
        (false, true) => {
            let mut plain = config.dns.clone();
            plain.blocklist.clear();
            plain.overrides.clear();
            Some(plain)
        }
        (false, false) => None,
    }
}

/// Derives the hotspot /24 from the gateway address (the common case for ICS
/// and NetworkManager shared mode). IPv6 and non-/24 setups skip routing.
fn hotspot_subnet(gateway: Ipv4Addr) -> Option<ipnet::Ipv4Net> {
    ipnet::Ipv4Net::new(gateway, 24).ok().map(|net| net.trunc())
}

/// The hotspot's network, as steering it and the device rules need it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HotspotNet {
    /// OS name of its adapter; empty until known (Windows makes Mobile
    /// hotspot's adapter as the access point starts).
    interface: String,
    subnet: ipnet::Ipv4Net,
    /// This computer's address on it.
    gateway: Ipv4Addr,
}

impl HotspotNet {
    /// The network of a hotspot that runs and has its address.
    fn running(status: &HotspotStatus) -> Option<Self> {
        if status.state != HotspotState::Running {
            return None;
        }
        let (Some(IpAddr::V4(gateway)), Some(interface)) = (status.gateway, status.interface.clone()) else { return None };
        Some(Self { interface, subnet: hotspot_subnet(gateway)?, gateway })
    }
}

/// How long the hotspot's network stays steered and held to the device
/// rules once its access point is seen off outside a start or stop, where
/// both go by addresses (Windows): a turn-on soon after is taken from its
/// first packet, and an access point Windows' power saving turned off does
/// not keep the capture up for good.
const HOTSPOT_OFF_HOLD: Duration = Duration::from_secs(30);

/// Whether the hotspot is off as the monitor sees it: neither running nor
/// on its way on or off.
fn is_off(state: HotspotState) -> bool {
    matches!(state, HotspotState::Stopped | HotspotState::Failed)
}

/// Whether going from settings `previous` to `next` needs a running access
/// point started again. Keeping devices apart over Wi-Fi is the access
/// point's job where Captun can set it. Turning outbounds off needs it too
/// for a hotspot that runs its own network (`shares_through_system` false):
/// that network shares the internet through the system only if outbounds
/// were off as it started (see `start_hotspot`), and its devices would have
/// no way out. Mobile hotspot and NetworkManager share through the system
/// all along, so their devices are not dropped for nothing.
fn access_point_restarts(previous: &Config, next: &Config, shares_through_system: bool) -> bool {
    let routed = |c: &Config| c.network.transparent_routing && capture::supports_transparent_routing();
    !previous.hotspot.same_access_point(&next.hotspot)
        || (previous.network.isolate_clients != next.network.isolate_clients && reach::wifi_isolation_supported())
        || (routed(previous) && !routed(next) && !shares_through_system)
}

/// How many offline devices with nothing saved the device list sends the
/// GUI: those seen most recently. Bounds the list's message, whatever a
/// device sending under made-up MACs leaves behind.
const OFFLINE_SHOWN: usize = 500;

/// Copies of the device-list entries the GUI is sent: every device online,
/// every device `saved` names, and of the rest the `offline_shown` seen most
/// recently. Run under the device-list lock, so it copies only those.
fn shown_presences(registry: &ClientRegistry, saved: impl Fn(&MacAddr) -> bool, offline_shown: usize) -> Vec<Presence> {
    let mut shown = Vec::new();
    let mut others: Vec<&Presence> = Vec::new();
    for presence in registry.iter() {
        if presence.online || saved(&presence.mac) {
            shown.push(presence.clone());
        } else {
            others.push(presence);
        }
    }
    if others.len() > offline_shown {
        if offline_shown > 0 {
            // The `offline_shown` seen last end up first, in no particular order.
            others.select_nth_unstable_by(offline_shown - 1, |a, b| b.last_seen_ms.cmp(&a.last_seen_ms));
        }
        others.truncate(offline_shown);
    }
    shown.extend(others.into_iter().cloned());
    shown
}

pub(crate) struct Hub {
    /// Where changes are saved, or `None` when the GUI that started the
    /// service keeps the settings and this copy lives in memory only.
    config_file: Option<PathBuf>,
    /// Set until the GUI hands over its settings (when it keeps them), which
    /// is when hotspot autostart can run.
    awaiting_settings: AtomicBool,
    /// Persistent key for the built-in adb (no external adb binary is used).
    adb_key: PathBuf,
    config: RwLock<Arc<Config>>,
    policy: RwLock<Arc<PolicyEngine>>,
    /// The online lists rules use.
    lists: ListStore,
    /// Which name each device last looked up for an address, for its
    /// connections that do not say (QUIC, apps' own protocols).
    learned: Mutex<LearnedNames>,
    outbounds: RwLock<Arc<OutboundSet>>,
    /// Serializes outbound rebuilds, so the last one always reflects the
    /// newest config and the sidecar's newest endpoints.
    outbounds_build: Mutex<()>,
    /// Runs VPN-link outbounds (VLESS, VMess, …) through Xray. Shared so a
    /// change can be applied on a blocking thread (see `commit`).
    xray: Arc<Sidecar>,
    pub(crate) registry: Mutex<ClientRegistry>,
    /// The system's neighbor table, which vouches for the device list and
    /// finds devices before it lists them.
    neighbors: Neighbors,
    /// When the monitor last looked at the rules' time windows.
    schedules: Mutex<OpenWindows>,
    /// Hotspot slots under `hotspot.max_clients`, and who is waiting for one.
    capacity: Mutex<Capacity>,
    over_limit: Mutex<HashSet<MacAddr>>,
    meter: Arc<TrafficMeter>,
    /// The last speed reading, taken once a second while a GUI is connected
    /// (`crate::traffic`): what the next one measures from, and the speeds
    /// the device list shows.
    speeds: Mutex<Speeds>,
    backend: Box<dyn HotspotBackend>,
    hotspot: Mutex<HotspotStatus>,
    /// The hotspot's network as last known: expected before its access point
    /// is up, then as it ran. Kept from before a start until the access point
    /// is down after a stop (`let_go_of_hotspot`), so it stays steered and
    /// held to the device rules while the access point starts or stops: no
    /// device gets out around Captun meanwhile. When the access point goes
    /// off outside a start or stop (`release_hotspot_if_off`), it is let go
    /// at once where steering and the device rules name the adapter (Linux,
    /// which may be this computer's own Wi-Fi again), and on Windows, where
    /// they go by addresses, after `HOTSPOT_OFF_HOLD`.
    hotspot_net: Mutex<Option<HotspotNet>>,
    /// When the monitor first saw the access point off, outside a start or
    /// stop, while its network was held.
    hotspot_off_since: Mutex<Option<Instant>>,
    dns: Mutex<Option<DnsRuntime>>,
    engine: Mutex<Option<EngineRuntime>>,
    tether: Mutex<TetherState>,
    /// The running wired/USB access network, if any.
    access: Mutex<Option<AccessSession>>,
    /// Serializes hotspot start/stop and config writes.
    control: tokio::sync::Mutex<()>,
    /// Serializes phone-tethering operations independently of the hotspot.
    tether_ctl: tokio::sync::Mutex<()>,
    /// Serializes access-network start/stop.
    access_ctl: tokio::sync::Mutex<()>,
    /// Serializes routing-engine reconciliation.
    engine_ctl: tokio::sync::Mutex<()>,
    /// Ends open flows when settings change, or has them checked again when
    /// a time window or the device limit does, so the change applies to
    /// connections already open.
    flows: FlowControl,
    /// Why routing devices through Captun failed to start, if it did.
    routing_error: Mutex<Option<String>>,
    /// Why cable sharing was stopped by the kill switch, until it starts again.
    access_error: Mutex<Option<String>>,
    /// What devices may reach besides the internet, in force per shared network.
    reach: Mutex<Vec<ActiveReach>>,
    /// Serializes `reconcile_reach`.
    reach_ctl: tokio::sync::Mutex<()>,
    /// Why those rules are not in force, or what was left undone.
    reach_error: Mutex<Option<String>>,
    /// The system cannot put them in force at all.
    reach_unsupported: AtomicBool,
    /// The same settings for the routing engine, read for every new flow.
    reach_view: RwLock<Arc<ReachView>>,
    /// Set by a GUI that asked the service to stop.
    shutdown: tokio::sync::Notify,
    events: broadcast::Sender<Event>,
    started: Instant,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub").field("config_file", &self.config_file).finish_non_exhaustive()
    }
}

fn invalid_config(e: ConfigError) -> IpcError {
    match e {
        ConfigError::Invalid(errors) => IpcError::new(ErrorCode::InvalidConfig, errors.join("\n")),
        other => IpcError::new(ErrorCode::Internal, other.to_string()),
    }
}

fn hotspot_error(e: HotspotError) -> IpcError {
    match e {
        HotspotError::Unsupported(m) => IpcError::new(ErrorCode::Unsupported, m),
        HotspotError::InvalidConfig(m) => IpcError::new(ErrorCode::InvalidConfig, m),
        HotspotError::Failed(m) | HotspotError::Unavailable(m) => IpcError::new(ErrorCode::HotspotFailed, m),
    }
}

impl Hub {
    /// `config_file` is where changes are saved, `None` when the GUI keeps the
    /// settings. `user` is the unprivileged user who started the service
    /// (Unix), whom helper programs such as Xray run as.
    pub(crate) fn new(
        config_file: Option<PathBuf>,
        config: Config,
        backend: Box<dyn HotspotBackend>,
        events: broadcast::Sender<Event>,
        user: Option<u32>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|hub: &std::sync::Weak<Self>| {
            let hub = hub.clone();
            let xray = Arc::new(Sidecar::start(captun_xray::find_program(), user, move || {
                if let Some(hub) = hub.upgrade() {
                    hub.xray_changed();
                }
            }));
            xray.apply(&config.egresses);
            // Once, at start-up, before anything is served: the only adapter
            // read that may hold an async thread.
            let interfaces = captun_platform::iface::list();
            let reach_view = ReachView::new::<SteerKey>(&[], local_access::local_reach(&config), &interfaces);
            let lists = ListStore::new(crate::paths::lists_dir());
            Self {
                awaiting_settings: AtomicBool::new(config_file.is_none()),
                config_file,
                adb_key: crate::paths::adb_key(),
                policy: RwLock::new(Arc::new(PolicyEngine::build(&config, &lists.compiled(&config)))),
                lists,
                learned: Mutex::new(LearnedNames::default()),
                outbounds: RwLock::new(Arc::new(OutboundSet::build(
                    &config.egresses,
                    &HostEnv { xray: &xray, interfaces: &interfaces },
                ))),
                outbounds_build: Mutex::new(()),
                xray,
                config: RwLock::new(Arc::new(config)),
                registry: Mutex::new(ClientRegistry::new()),
                neighbors: Neighbors::default(),
                schedules: Mutex::new(OpenWindows::default()),
                capacity: Mutex::new(Capacity::default()),
                over_limit: Mutex::new(HashSet::new()),
                meter: Arc::new(TrafficMeter::new()),
                speeds: Mutex::new(Speeds::default()),
                backend,
                hotspot: Mutex::new(HotspotStatus::default()),
                hotspot_net: Mutex::new(None),
                hotspot_off_since: Mutex::new(None),
                dns: Mutex::new(None),
                engine: Mutex::new(None),
                tether: Mutex::new(TetherState::default()),
                access: Mutex::new(None),
                control: tokio::sync::Mutex::new(()),
                tether_ctl: tokio::sync::Mutex::new(()),
                access_ctl: tokio::sync::Mutex::new(()),
                engine_ctl: tokio::sync::Mutex::new(()),
                flows: FlowControl::new(),
                routing_error: Mutex::new(None),
                access_error: Mutex::new(None),
                reach: Mutex::new(Vec::new()),
                reach_ctl: tokio::sync::Mutex::new(()),
                reach_error: Mutex::new(None),
                reach_unsupported: AtomicBool::new(false),
                reach_view: RwLock::new(Arc::new(reach_view)),
                shutdown: tokio::sync::Notify::new(),
                events,
                started: Instant::now(),
            }
        })
    }

    /// Rebuilds every outbound from the current config and sidecar state.
    /// The adapters (for outbounds tied to one) are read first, off the async
    /// threads and with no lock held; the config and the sidecar's endpoints
    /// are read under the build lock, so the last build always has the newest.
    async fn rebuild_outbounds(&self) {
        let interfaces = captun_platform::iface::list_async().await;
        let _guard = lock(&self.outbounds_build);
        let config = self.config();
        let env = HostEnv { xray: &self.xray, interfaces: &interfaces };
        write(&self.outbounds, Arc::new(OutboundSet::build(&config.egresses, &env)));
    }

    /// The sidecar came up, went down or moved: re-point its outbounds, then
    /// have the open flows checked again. That ends the flows refused while
    /// its outbounds stood unavailable (a UDP flow would go on refusing for
    /// seconds after Xray is up), and any that would now go another way.
    /// Working connections go on, so an Xray that keeps failing to start
    /// never cuts anyone off; those through it end by themselves when its
    /// process exits.
    ///
    /// Called from the sidecar's own task, so the rebuild, which may wait for
    /// the adapters to be read, runs on a task of its own, and the flows are
    /// checked once it is done.
    fn xray_changed(self: &Arc<Self>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            warn!("the VPN-link engine changed outside the service's runtime; its outbounds were not updated");
            return;
        };
        let hub = self.clone();
        runtime.spawn(async move {
            hub.rebuild_outbounds().await;
            hub.flows.recheck_all();
            hub.emit(Event::Xray(hub.xray_status()));
        });
    }

    fn xray_status(&self) -> XrayStatus {
        let status = self.xray.status();
        let (state, error) = match status.state {
            SidecarState::Idle => (XrayState::Idle, None),
            SidecarState::Missing => (XrayState::Missing, None),
            SidecarState::Starting => (XrayState::Starting, None),
            SidecarState::Running => (XrayState::Running, None),
            SidecarState::Failed(why) => (XrayState::Failed, Some(why)),
        };
        XrayStatus { state, version: status.version, error }
    }

    /// The networks that should be steered into the engine right now, when
    /// transparent routing is on: the hotspot's from before its access point
    /// starts until it is down (see `hotspot_net`), and the access network
    /// while it is up.
    fn desired_steerings(&self) -> Vec<(SteerKey, CaptureConfig)> {
        let config = self.config();
        if !config.network.transparent_routing || !capture::supports_transparent_routing() {
            return Vec::new();
        }
        let mut desired = Vec::new();

        if let Some(net) = lock(&self.hotspot_net).clone() {
            // The devices' DNS sent to this computer is taken whenever the
            // hub is to answer it, even before its DNS is up (the access
            // point is starting, or Windows turned it off): such a lookup
            // fails and is asked again, rather than go around the device's
            // outbound to the system's own DNS server.
            let dns = dns_config(&config).is_some();
            desired.push((
                SteerKey::Hotspot,
                CaptureConfig {
                    hotspot_interface: net.interface,
                    subnet: ipnet::IpNet::V4(net.subnet),
                    gateway: IpAddr::V4(net.gateway),
                    dns,
                },
            ));
        }

        if let Some(access) = &*lock(&self.access) {
            match ipnet::Ipv4Net::new(access.network, access.prefix_len) {
                Ok(net) => desired.push((
                    SteerKey::Access,
                    CaptureConfig {
                        hotspot_interface: access.interface.clone(),
                        subnet: ipnet::IpNet::V4(net),
                        gateway: IpAddr::V4(access.gateway),
                        dns: false,
                    },
                )),
                Err(e) => warn!("cannot derive the access-network subnet: {e}"),
            }
        }

        desired
    }

    /// Brings the shared routing engine and its steerings in line with the current
    /// state: starts the engine and adds steerings when networks need routing,
    /// removes steerings that no longer apply, and stops the engine when nothing
    /// does. Safe to call on any change; a no-op when already in the desired state.
    /// Builds the routing engine again if it stopped by itself (it never
    /// should): its devices would have no way out until sharing restarted.
    /// The capture holds on to their packets meanwhile, so none go direct.
    pub(crate) async fn check_engine(self: &Arc<Self>) {
        let stopped = {
            let _guard = self.engine_ctl.lock().await;
            let mut engine = lock(&self.engine);
            let stopped = engine.as_ref().is_some_and(|runtime| !runtime.engine.is_running());
            if stopped {
                engine.take();
            }
            stopped
        };
        if stopped {
            warn!("the routing engine stopped by itself; starting it again");
            self.reconcile_engine().await;
        }
    }

    async fn reconcile_engine(self: &Arc<Self>) {
        let _guard = self.engine_ctl.lock().await;
        let desired = self.desired_steerings();

        if desired.is_empty() {
            *lock(&self.routing_error) = None;
            if lock(&self.engine).take().is_some() {
                info!("routing engine stopped");
            }
            return;
        }

        // With the kill switch on, a network whose traffic cannot be taken
        // through Captun stops sharing rather than let its devices use this
        // computer's internet directly.
        let kill_switch = self.config().network.kill_switch;
        // Where a steering looks for its network's adapter (Windows): read
        // now, off the async threads, because steerings open with the engine
        // locked. Mostly the list in hand: one read serves a few seconds.
        let adapters = captun_platform::iface::list_async().await;

        // Make sure the engine (and its packet device) exists before steering into it.
        if lock(&self.engine).is_none() {
            let (device, steerer) = match capture::create().await {
                Ok(opened) => opened,
                Err(e) => {
                    let reason = e.to_string();
                    if lock(&self.routing_error).as_deref() != Some(reason.as_str()) {
                        warn!("routing through Captun not started: {reason}");
                    }
                    *lock(&self.routing_error) = Some(reason.clone());
                    if kill_switch {
                        for (key, _) in desired {
                            tokio::spawn(self.clone().cut_off(key, reason.clone()));
                        }
                    }
                    return;
                }
            };
            let dispatcher: Arc<dyn captun_engine::Dispatcher> =
                Arc::new(crate::engine_glue::PolicyDispatcher::new(self));
            let handle = captun_engine::run(device, dispatcher, self.meter.clone(), self.flows.clone());
            *lock(&self.engine) = Some(EngineRuntime { engine: handle, steerer, steerings: Vec::new() });
            info!("routing engine started");
        }

        // Reconcile steerings against `desired` (no await while holding the lock).
        let previous = lock(&self.routing_error).clone();
        let mut guard = lock(&self.engine);
        let Some(runtime) = guard.as_mut() else { return };
        let mut failure = None;
        for (key, config) in &desired {
            // A steering whose rules already fit stands for the new config
            // (the adapter got its name, say); one the same rules would clash
            // with is never opened beside it.
            if let Some(active) = runtime.steerings.iter_mut().find(|s| s.key == *key && s.config.steers_like(config)) {
                active.config = config.clone();
                continue;
            }
            // The network's old steering goes first where the new one's rules
            // would clash with it (Linux, the same adapter on another subnet:
            // both use the one rule that sends the adapter's traffic to the
            // TUN, which the old one's going would take). The adapter is not
            // taken for the moment the new rules need to go in.
            runtime.steerings.retain(|s| !(s.key == *key && s.config.clashes_with(config)));
            match runtime.steerer.steer(config, &adapters) {
                Ok(guard) => runtime.steerings.push(ActiveSteering { key: *key, config: config.clone(), _guard: guard }),
                Err(e) => {
                    let reason = e.to_string();
                    // Retried every few seconds while it fails; said once.
                    if previous.as_deref() != Some(reason.as_str()) {
                        warn!(?key, "cannot steer traffic into the engine: {reason}");
                    }
                    if kill_switch {
                        tokio::spawn(self.clone().cut_off(*key, reason.clone()));
                    }
                    failure = Some(reason);
                }
            }
        }
        // Only now are the steerings no longer wanted let go: a network whose
        // steering changes is taken by the new one before the old one goes
        // (unless they clash, above), so none of its packets slip past in
        // between. One whose replacement could not open goes all the same, as
        // the kill switch counts on.
        runtime.steerings.retain(|s| desired.iter().any(|(key, config)| *key == s.key && *config == s.config));
        drop(guard);
        *lock(&self.routing_error) = failure;
    }

    /// The kill switch: stops sharing on a network whose traffic could not be
    /// taken through Captun, so its devices never use this computer's internet
    /// directly. Runs on its own task, after whatever operation found the
    /// failure has let go of the locks.
    async fn cut_off(self: Arc<Self>, key: SteerKey, reason: String) {
        let message = format!(
            "Sharing stopped so devices would not use this computer's internet directly: the outbounds could not be applied ({reason})"
        );
        match key {
            SteerKey::Hotspot => {
                let _guard = self.control.lock().await;
                // A later attempt may have succeeded, or the hotspot stopped anyway.
                if self.hotspot_status().state != HotspotState::Running || self.is_steered(key) {
                    return;
                }
                warn!("{message}");
                self.stop_dns();
                if let Err(e) = self.backend.stop().await {
                    warn!("cannot stop the hotspot: {e}");
                }
                let state = self.backend.state().await.unwrap_or_default();
                self.let_go_of_hotspot(&state);
                self.set_hotspot_status(Self::status_from_backend(&state, Some(message)));
            }
            SteerKey::Access => {
                let _guard = self.access_ctl.lock().await;
                if lock(&self.access).is_none() || self.is_steered(key) {
                    return;
                }
                warn!("{message}");
                self.stop_access_locked();
                *lock(&self.access_error) = Some(message);
            }
        }
        self.broadcast_clients();
    }

    /// Whether `key`'s network is being taken through the engine right now.
    fn is_steered(&self, key: SteerKey) -> bool {
        lock(&self.engine).as_ref().is_some_and(|runtime| runtime.steerings.iter().any(|s| s.key == key))
    }

    /// The networks Captun shares right now: the hotspot's from before its
    /// access point starts until it is down (see `hotspot_net`), and cable
    /// sharing.
    fn shared_networks(&self) -> Vec<SharedNetwork<SteerKey>> {
        let mut networks = Vec::new();
        if let Some(net) = lock(&self.hotspot_net).clone() {
            networks.push(SharedNetwork { key: SteerKey::Hotspot, interface: net.interface, subnet: net.subnet, gateway: net.gateway });
        }
        if let Some(access) = &*lock(&self.access)
            && let Ok(subnet) = ipnet::Ipv4Net::new(access.network, access.prefix_len)
        {
            networks.push(SharedNetwork {
                key: SteerKey::Access,
                interface: access.interface.clone(),
                subnet: subnet.trunc(),
                gateway: access.gateway,
            });
        }
        networks
    }

    /// What the routing engine refuses itself, on top of the system's rules.
    pub(crate) fn reach_view(&self) -> Arc<ReachView> {
        read(&self.reach_view)
    }

    /// Brings the "what devices can reach" rules in line with the settings and
    /// the networks being shared: puts them in for new networks, renews them
    /// when something they depend on changed (the settings, an address of this
    /// computer), and lifts those of networks no longer shared. Cheap when
    /// nothing changed: the monitor calls it every few seconds, which also
    /// retries rules that could not be put in.
    pub(crate) async fn reconcile_reach(self: &Arc<Self>) {
        let _guard = self.reach_ctl.lock().await;
        let networks = self.shared_networks();
        let reach = local_access::local_reach(&self.config());
        // Off the async threads: the monitor asks every tick, and a read can
        // take seconds on Windows.
        let ifaces = captun_platform::iface::list_async().await;
        write(&self.reach_view, Arc::new(ReachView::new(&networks, reach, &ifaces)));
        let desired = local_access::desired(&networks, reach, &ifaces);

        let current = std::mem::take(&mut *lock(&self.reach));
        let (kept, stale): (Vec<_>, Vec<_>) = current
            .into_iter()
            .partition(|active| desired.iter().any(|(key, config)| *key == active.key && *config == active.config));
        let missing: Vec<(SteerKey, ReachConfig)> = desired
            .into_iter()
            .filter(|(key, config)| !kept.iter().any(|active| active.key == *key && active.config == *config))
            .collect();
        if stale.is_empty() && missing.is_empty() {
            *lock(&self.reach) = kept;
            return;
        }

        // Rules may take the firewall's own tools to lift or put in: off the
        // async threads. A network's old rules go before its new ones, which
        // reuse their names.
        let applied = tokio::task::spawn_blocking(move || {
            drop(stale);
            missing.into_iter().map(|(key, config)| {
                let result = reach::apply(&config);
                (key, config, result)
            })
            .collect::<Vec<_>>()
        })
        .await;
        let mut active = kept;
        let (mut failure, mut unsupported) = (None, false);
        match applied {
            Ok(results) => {
                for (key, config, result) in results {
                    match result {
                        Ok(guard) => active.push(ActiveReach { key, config, guard }),
                        Err(ReachError::Unsupported) => unsupported = true,
                        Err(ReachError::Failed(e)) => failure = Some(e),
                    }
                }
            }
            Err(e) => failure = Some(format!("the device rules could not be put in: {e}")),
        }
        let problem = failure.or_else(|| active.iter().find_map(|a| a.guard.warning().map(str::to_owned)));
        {
            let mut error = lock(&self.reach_error);
            // Retried every few seconds while it fails; said once.
            match (&problem, &*error) {
                (Some(now), before) if before.as_deref() != Some(now.as_str()) => warn!("device rules: {now}"),
                (None, Some(_)) if !active.is_empty() => info!("device rules are in force again"),
                _ => {}
            }
            *error = problem;
        }
        self.reach_unsupported.store(unsupported, Ordering::Relaxed);
        *lock(&self.reach) = active;
    }

    /// Lifts every "what devices can reach" rule, when the service stops.
    async fn lift_reach(&self) {
        let _guard = self.reach_ctl.lock().await;
        let active = std::mem::take(&mut *lock(&self.reach));
        if !active.is_empty() {
            let _ = tokio::task::spawn_blocking(move || drop(active)).await;
        }
    }

    /// Whether the "what devices can reach" settings are in force.
    fn local_access_status(&self) -> LocalAccessStatus {
        let error = lock(&self.reach_error).clone();
        let active = !lock(&self.reach).is_empty();
        let state = if self.reach_unsupported.load(Ordering::Relaxed) {
            LocalAccessState::Unsupported
        } else if active {
            LocalAccessState::Active
        } else if error.is_some() {
            LocalAccessState::Failed
        } else {
            LocalAccessState::Idle
        };
        LocalAccessStatus { state, error }
    }

    /// Whether devices' traffic goes through Captun right now, and if not why.
    fn routing_status(&self) -> RoutingStatus {
        if !capture::supports_transparent_routing() {
            return RoutingStatus { state: RoutingState::Unsupported, ..RoutingStatus::default() };
        }
        if !self.config().network.transparent_routing {
            return RoutingStatus::default();
        }
        if let Some(error) = lock(&self.routing_error).clone() {
            return RoutingStatus { state: RoutingState::Failed, error: Some(error), ..RoutingStatus::default() };
        }
        match &*lock(&self.engine) {
            Some(runtime) if !runtime.steerings.is_empty() => RoutingStatus {
                state: RoutingState::Active,
                error: None,
                captured_packets: runtime.steerer.captured_packets(),
                dropped_packets: runtime.steerer.dropped_packets(),
            },
            _ => RoutingStatus { state: RoutingState::Waiting, ..RoutingStatus::default() },
        }
    }

    /// Resolves once a GUI has asked the service to stop.
    pub(crate) async fn shutdown_requested(&self) {
        self.shutdown.notified().await;
    }

    pub(crate) fn config(&self) -> Arc<Config> {
        read(&self.config)
    }

    /// The device holding `ip`: the one the device list (polled every two
    /// seconds) names there when the system's neighbor table names it too,
    /// or, for a device too new to be listed, the neighbor table's. A new
    /// device is refused out loud until the table has it, moments later,
    /// then gets its own outbound and rules, and is never sent the default
    /// way. A lease alone does not count: see [`Neighbors::device`]. Reads
    /// memory only, so the engine and DNS can ask for every flow and query.
    pub(crate) fn device_at(&self, ip: IpAddr) -> Option<MacAddr> {
        let listed = lock(&self.registry).by_ip(&ip.to_canonical()).map(|presence| presence.mac);
        self.neighbors.device(ip, listed)
    }

    /// Whether `mac` may still be taken to hold `ip`, for a connection it
    /// opened from there: neither the device list nor the neighbor table
    /// names another device at it. Only that ends the connection; a missing
    /// entry does not, unlike for a new one in [`Self::device_at`]. Reads
    /// memory only.
    pub(crate) fn still_at(&self, ip: IpAddr, mac: MacAddr) -> bool {
        let listed = lock(&self.registry).by_ip(&ip.to_canonical()).map(|presence| presence.mac);
        listed.is_none_or(|listed| listed == mac) && !self.neighbors.contradicts(ip, mac)
    }

    /// Starts a read of the system's neighbor table when the one in hand is
    /// older than half a second, off the async threads; never waits for it.
    /// The monitor's tick calls it, so a lookup seldom has to.
    pub(crate) fn refresh_neighbors(&self) {
        self.neighbors.refresh();
    }

    /// The neighbor table, for tests to give entries of their own.
    #[cfg(test)]
    pub(crate) fn neighbors(&self) -> &Neighbors {
        &self.neighbors
    }

    /// What ends and rechecks open flows, for tests to run flows under.
    #[cfg(test)]
    pub(crate) fn flows(&self) -> &FlowControl {
        &self.flows
    }

    /// Has the open flows checked again when a rule's time window opens or
    /// closes, so the window applies to connections already open, not only
    /// to new ones: a VPN connected at 21:59 does not outlast a 22:00 block,
    /// and a flow refused inside the window is decided again once it closes.
    /// Called first on every monitor tick; does nothing between the edges.
    pub(crate) fn check_schedules(&self) {
        self.check_schedules_at(crate::engine_glue::local_now());
    }

    /// [`Self::check_schedules`] as at `now`. Says whether the flows were
    /// checked again.
    pub(crate) fn check_schedules_at(&self, now: captun_policy::LocalTime) -> bool {
        let config = self.config();
        let edge = lock(&self.schedules).look(&config.rules, now);
        if edge {
            info!("a rule's time window opened or closed; checking open connections again");
            self.flows.recheck_all();
        }
        edge
    }

    pub(crate) fn policy(&self) -> Arc<PolicyEngine> {
        read(&self.policy)
    }

    pub(crate) fn outbounds(&self) -> Arc<OutboundSet> {
        read(&self.outbounds)
    }

    /// Re-applies the device limit to the hotspot stations seen now. Blocked
    /// stations never take a slot. Returns whether anyone's admission changed.
    pub(crate) fn update_capacity(&self, stations: &[MacAddr]) -> bool {
        // Held for the whole rebuild so `commit` cannot swap the config in between.
        let mut current = lock(&self.over_limit);
        let config = self.config();
        let present: Vec<MacAddr> = stations
            .iter()
            .copied()
            .filter(|mac| config.client(mac).is_none_or(|p| p.state != ClientState::Blocked))
            .collect();
        let held = lock(&self.capacity).update(&present, config.hotspot.max_clients);
        if *current == held {
            return false;
        }
        if !held.is_empty() {
            info!(held = held.len(), "hotspot is at its device limit");
        }
        self.install_policy(&config, &held);
        *current = held;
        drop(current);
        // Devices held back now lose their open connections, and those let
        // in again have their refused flows end, so their next try is decided
        // again. Never every device's connections: a guest coming and going
        // under made-up hardware addresses at a full hotspot could then cut
        // everyone off every two seconds.
        self.flows.recheck_all();
        true
    }

    /// Compiles the rules again with the lists as they are now.
    fn refresh_policy(&self) {
        // Under the capacity lock, as `commit` and `update_capacity`.
        let held = lock(&self.over_limit);
        let config = self.config();
        self.install_policy(&config, &held);
    }

    /// Swaps in the rules of `config`, compiled with the lists as they are
    /// now, holding back the stations in `held`. The rules' hit counters
    /// carry over unless the rules themselves changed, which shifts what each
    /// index means. Callers hold `over_limit`, under which the policy in force
    /// is always the one built from the config in force.
    fn install_policy(&self, config: &Config, held: &HashSet<MacAddr>) {
        let mut policy = PolicyEngine::build(config, &self.lists.compiled(config)).with_over_limit(held.clone());
        if self.config().rules == config.rules {
            policy = policy.with_hits(self.policy().hits().clone());
        }
        write(&self.policy, Arc::new(policy));
    }

    /// How often each rule decided since the rules last changed, in order.
    fn rule_hits(&self) -> Vec<RuleHits> {
        self.policy()
            .hits()
            .snapshot()
            .into_iter()
            .map(|hits| RuleHits { connections: hits.connections, lookups: hits.lookups, last_ms: hits.last_ms })
            .collect()
    }

    /// Remembers that `device` was given `addrs` when it looked up `name`.
    pub(crate) fn learn_name(&self, device: MacAddr, name: &str, addrs: &[IpAddr]) {
        // Made before the lock is taken, which every new flow may wait on.
        let name: Arc<str> = Arc::from(name);
        lock(&self.learned).learn(device, &name, addrs);
    }

    /// The name `device` last looked `ip` up by, if it did lately. Only the
    /// device's own lookups count.
    pub(crate) fn name_for(&self, device: MacAddr, ip: IpAddr) -> Option<Arc<str>> {
        lock(&self.learned).name_for(device, ip)
    }

    /// The name a device last looked `ip` up by, whichever device it was: for
    /// the rules tester when it is asked about any device.
    pub(crate) fn any_name_for(&self, ip: IpAddr) -> Option<Arc<str>> {
        lock(&self.learned).any_name_for(ip)
    }

    /// Forgets the names `device` looked up.
    pub(crate) fn forget_names(&self, device: MacAddr) {
        lock(&self.learned).forget(device);
    }

    pub(crate) fn hotspot_status(&self) -> HotspotStatus {
        lock(&self.hotspot).clone()
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub(crate) fn emit(&self, event: Event) {
        // No subscribers just means no GUI is connected.
        let _ = self.events.send(event);
    }

    /// Whether a GUI is connected to hear events, so what is gathered only to
    /// be shown (the lookup log) need not be while none is.
    pub(crate) fn has_listeners(&self) -> bool {
        self.events.receiver_count() > 0
    }

    pub(crate) fn backend(&self) -> &dyn HotspotBackend {
        self.backend.as_ref()
    }

    pub(crate) fn set_hotspot_status(&self, status: HotspotStatus) {
        // What a running hotspot has is the network kept for it from now on.
        if let Some(net) = HotspotNet::running(&status) {
            *lock(&self.hotspot_net) = Some(net);
        }
        // Up, or on its way on or off: a hold that ends counts from the next
        // time it is seen off.
        if !is_off(status.state) {
            lock(&self.hotspot_off_since).take();
        }
        let changed = {
            let mut current = lock(&self.hotspot);
            let changed = *current != status;
            *current = status.clone();
            changed
        };
        if changed {
            self.emit(Event::Hotspot(status));
        }
    }

    pub(crate) async fn handle(self: &Arc<Self>, request: Request) -> Result<Response, IpcError> {
        match request {
            Request::GetStatus => Ok(Response::Status(Box::new(self.status()))),
            Request::StartHotspot => self.start_hotspot().await.map(|()| Response::Ok),
            Request::StopHotspot => self.stop_hotspot().await.map(|()| Response::Ok),
            Request::ListClients => Ok(Response::Clients(self.client_views())),
            Request::SetClientProfile(profile) => self.set_client_profile(profile).await.map(|()| Response::Ok),
            Request::ForgetClient { mac } => self.forget_client(mac).await.map(|()| Response::Ok),
            Request::GetConfig => Ok(Response::Config(Box::new((*self.config()).clone()))),
            Request::SetConfig(config) => self.set_config(*config).await.map(|()| Response::Ok),
            Request::ListInterfaces => Ok(Response::Interfaces(self.interfaces().await)),
            Request::TestEgress { id, target } => Ok(Response::EgressTest(self.test_egress(&id, target).await)),
            Request::ListAdbDevices => self.list_adb_devices().await.map(Response::AdbDevices),
            Request::SetReverseTether { serial, enable, method } => {
                self.set_reverse_tether(serial, enable, tether::to_adb_method(method)).await.map(Response::Tether)
            }
            Request::StartAccessNetwork => self.start_access_network().await.map(|()| Response::Ok),
            Request::StopAccessNetwork => self.stop_access_network().await.map(|()| Response::Ok),
            Request::Shutdown => {
                info!("the GUI asked the service to stop");
                // notify_one keeps the request even if main is not waiting yet.
                self.shutdown.notify_one();
                Ok(Response::Ok)
            }
            Request::GetLists => Ok(Response::Lists(self.lists.progress(&self.config()))),
            Request::UpdateLists { through } => self.update_lists(through).map(Response::Lists),
            Request::GetRuleHits => Ok(Response::RuleHits(self.rule_hits())),
            Request::TestRules { target, device, port, protocol } => {
                crate::engine_glue::test_rules(self, &target, device, port, protocol)
                    .map(|result| Response::RuleTest(Box::new(result)))
            }
        }
    }

    /// Starts downloading the online lists the rules use, through `through`
    /// or the default outbound, and answers at once: a big list through a
    /// slow outbound takes minutes. Each new copy applies as it comes, and
    /// `Event::Lists` tells how far the update is after each list and once
    /// it is over. While one runs, nothing new starts: the answer says how
    /// far that one is.
    fn update_lists(self: &Arc<Self>, through: Option<captun_core::EgressId>) -> Result<ListsProgress, IpcError> {
        let config = self.config();
        let egress = through.unwrap_or_else(|| config.network.default_egress.clone());
        let outbound = self
            .outbounds()
            .get(&egress)
            .cloned()
            .ok_or_else(|| IpcError::new(ErrorCode::BadRequest, format!("there is no outbound {egress} to download through")))?;
        let links = lists::links(&config);
        if !links.is_empty()
            && let Some(updating) = self.lists.try_start(links.len())
        {
            info!(lists = links.len(), through = %egress, "updating online lists");
            let hub = self.clone();
            tokio::spawn(async move {
                hub.emit_lists();
                hub.lists
                    .update(updating, links, outbound, |renewed| {
                        if renewed {
                            hub.refresh_policy();
                        }
                        hub.emit_lists();
                    })
                    .await;
                {
                    // A list the rules stopped naming meanwhile was let go of
                    // by that change, then held again once downloaded: let go
                    // of it for good. Under `control`, so this never lands
                    // between a change reading its lists and putting them in
                    // force, which would let go of what it just read.
                    let _control = hub.control.lock().await;
                    hub.lists.prune(&hub.config());
                }
                // `updating` is let go by now: this one says it is over.
                hub.emit_lists();
                info!("online lists update finished");
            });
        }
        Ok(self.lists.progress(&self.config()))
    }

    /// Tells the app how the online lists stand.
    fn emit_lists(&self) {
        self.emit(Event::Lists(self.lists.progress(&self.config())));
    }

    fn status(&self) -> ServiceStatus {
        let notes = self.backend.notes();
        let config = self.config();
        let routing_supported = capture::supports_transparent_routing();
        let engine_running = lock(&self.engine).is_some();
        let mut capability_notes = notes.notes;
        if !routing_supported {
            capability_notes.push(
                "This system cannot steer device traffic yet, so per-device outbounds, limits and live stats are saved but not applied.".into(),
            );
        } else if !config.network.transparent_routing {
            capability_notes.push(
                "\"Route devices through Captun\" is off: outbound, rule and limit settings are saved but not applied. Turn it on in Settings to route each device (experimental).".into(),
            );
        } else if !engine_running {
            capability_notes.push(
                "Routing through Captun is on and starts with the hotspot or cable sharing.".into(),
            );
        }
        capability_notes.push(
            "HTTPS inspection is not active in this build yet; its settings are saved and checked but not applied.".into(),
        );
        let tether = {
            let sessions = lock(&self.tether);
            TetherStatus {
                reverse: sessions
                    .reverse
                    .as_ref()
                    .map(|s| TetherSession { serial: s.serial.clone(), interface: Some(s.interface.clone()) }),
            }
        };
        ServiceStatus {
            service_version: env!("CARGO_PKG_VERSION").into(),
            platform: std::env::consts::OS.into(),
            uptime_secs: self.started.elapsed().as_secs(),
            hotspot: self.hotspot_status(),
            access_network: self.access_status(),
            clients_online: lock(&self.registry).online_count(),
            dns_running: lock(&self.dns).is_some(),
            capabilities: Capabilities {
                hotspot: notes.hotspot,
                band_selection: notes.band_selection,
                per_client_routing: routing_supported,
                tls_inspection: false,
                wifi_isolation: reach::wifi_isolation_supported(),
                notes: capability_notes,
            },
            tether,
            xray: self.xray_status(),
            routing: self.routing_status(),
            local_access: self.local_access_status(),
        }
    }

    pub(crate) fn status_from_backend(state: &BackendState, error: Option<String>) -> HotspotStatus {
        HotspotStatus {
            state: match (state.running, state.transitioning) {
                (_, true) => HotspotState::Starting,
                (true, false) => HotspotState::Running,
                (false, false) if error.is_some() => HotspotState::Failed,
                (false, false) => HotspotState::Stopped,
            },
            ssid: state.ssid.clone(),
            interface: state.interface.clone(),
            gateway: state.gateway,
            max_clients: state.max_clients,
            error,
        }
    }

    pub(crate) async fn start_hotspot(self: &Arc<Self>) -> Result<(), IpcError> {
        let _guard = self.control.lock().await;
        let config = self.config();
        let mut status = self.hotspot_status();
        status.state = HotspotState::Starting;
        status.error = None;
        self.set_hotspot_status(status);

        // While Captun carries the devices' traffic, a network the hotspot
        // runs itself shares none through the system, as cable sharing does
        // not: its devices get out through Captun or not at all.
        let routed = config.network.transparent_routing && capture::supports_transparent_routing();
        self.backend.set_engine_routed(routed);
        // Their traffic is taken from the first packet: the network is
        // steered and held to the device rules before the access point is up.
        if routed {
            self.expect_hotspot_network(None);
            if lock(&self.hotspot_net).is_some() {
                self.reconcile_engine().await;
                self.reconcile_reach().await;
                if config.network.kill_switch && !self.is_steered(SteerKey::Hotspot) {
                    return Err(self.refuse_hotspot().await);
                }
            }
        }

        let options = captun_platform::StartOptions {
            isolate_clients: config.network.isolate_clients,
            dns_on_gateway: config.dns.enabled,
        };
        match self.backend.start(&config.hotspot, options).await {
            Ok(mut state) => {
                // The way that started may be another than the one expected
                // (a fallback), on a network of its own: that one is taken
                // before its adapter has its address too.
                if routed && self.expect_hotspot_network(state.interface.clone()) {
                    self.reconcile_engine().await;
                    self.reconcile_reach().await;
                }
                // Windows gives the hotspot adapter its address a few seconds after
                // the access point is up; DNS and routing need that address.
                for _ in 0..20 {
                    if !state.running || state.gateway.is_some() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    match self.backend.state().await {
                        Ok(now) => state = now,
                        Err(_) => break,
                    }
                }
                info!(ssid = state.ssid.as_deref().unwrap_or(""), gateway = ?state.gateway, "hotspot is up");
                self.set_hotspot_status(Self::status_from_backend(&state, None));
                if let Some(gateway) = state.gateway {
                    self.start_dns(gateway).await;
                }
                self.reconcile_engine().await;
                self.reconcile_reach().await;
                Ok(())
            }
            Err(e) => {
                let err = hotspot_error(e);
                warn!("hotspot failed to start: {}", err.message);
                // Down, unless the start was refused before it touched an
                // access point already up: only then is its network let go.
                let state = self.backend.state().await.unwrap_or_default();
                self.let_go_of_hotspot(&state);
                self.set_hotspot_status(HotspotStatus {
                    state: HotspotState::Failed,
                    error: Some(err.message.clone()),
                    ..Default::default()
                });
                self.reconcile_engine().await;
                self.reconcile_reach().await;
                Err(err)
            }
        }
    }

    /// Notes the hotspot's network as the backend expects it, so it can be
    /// steered and held to the device rules before the access point has its
    /// address. `interface` is its adapter, when known. Says whether that
    /// changed what is noted.
    fn expect_hotspot_network(&self, interface: Option<String>) -> bool {
        let Some(subnet) = self.backend.expected_network().map(|net| net.trunc()) else { return false };
        let mut known = lock(&self.hotspot_net);
        let noted = match known.as_ref() {
            // Known already (the access point restarts, or Windows turned it
            // off): kept, with its adapter.
            Some(net) if net.subnet == subnet => {
                HotspotNet { interface: interface.unwrap_or_else(|| net.interface.clone()), ..net.clone() }
            }
            _ => {
                // Without the adapter's name, only a capture that goes by
                // addresses can take the network yet.
                let Some(interface) = interface.or_else(|| capture::steers_by_address().then(String::new)) else {
                    return false;
                };
                // Mobile hotspot and the networks Captun runs serve from
                // their first address; once up, the real one replaces it.
                let Some(gateway) = subnet.hosts().next() else { return false };
                HotspotNet { interface, subnet, gateway }
            }
        };
        let changed = known.as_ref() != Some(&noted);
        *known = Some(noted);
        changed
    }

    /// Lets go of the hotspot's network once its access point is down, so the
    /// next reconciliation lifts its steering and device rules. While it is
    /// up, or still going down, they stay.
    fn let_go_of_hotspot(&self, state: &BackendState) {
        if !state.running && !state.transitioning {
            lock(&self.hotspot_net).take();
        }
    }

    /// The kill switch as the hotspot starts: its traffic cannot be taken
    /// through Captun, so the access point does not start, and one already up
    /// (restarting) goes off, rather than let devices use this computer's
    /// internet directly.
    async fn refuse_hotspot(self: &Arc<Self>) -> IpcError {
        let reason = lock(&self.routing_error).clone().unwrap_or_else(|| "routing did not start".into());
        let message = format!(
            "The hotspot did not start, so devices would not use this computer's internet directly: the outbounds could not be applied ({reason})"
        );
        warn!("{message}");
        self.stop_dns();
        if let Err(e) = self.backend.stop().await {
            warn!("cannot stop the hotspot: {e}");
        }
        let state = self.backend.state().await.unwrap_or_default();
        self.let_go_of_hotspot(&state);
        self.set_hotspot_status(Self::status_from_backend(&state, Some(message.clone())));
        self.reconcile_engine().await;
        self.reconcile_reach().await;
        IpcError::new(ErrorCode::HotspotFailed, message)
    }

    pub(crate) async fn stop_hotspot(self: &Arc<Self>) -> Result<(), IpcError> {
        let _guard = self.control.lock().await;
        let mut status = self.hotspot_status();
        status.state = HotspotState::Stopping;
        self.set_hotspot_status(status);
        self.stop_dns();
        let result = self.backend.stop().await.map_err(hotspot_error);
        let error = result.as_ref().err().map(|e| e.message.clone());
        let state = self.backend.state().await.unwrap_or_default();
        // Only once the access point is down are its steering and device
        // rules lifted, so a device still on it never gets out directly (the
        // access network, if up, keeps its own).
        self.let_go_of_hotspot(&state);
        self.set_hotspot_status(Self::status_from_backend(&state, error));
        self.reconcile_engine().await;
        self.reconcile_reach().await;
        result
    }

    /// The monitor's latest view of the hotspot. When it shows the hotspot came
    /// up, went down or changed address (Windows assigns the address a moment
    /// after the access point starts), the DNS server and the routing engine
    /// follow. When the access point goes off by itself, its network is let go
    /// as `release_hotspot_if_off` says: on Windows it stays steered and held
    /// to the device rules for a while (see `hotspot_net`), so a turn-on
    /// Windows makes soon after is taken from its first packet too. Skipped
    /// while a start or stop is in charge.
    pub(crate) async fn observe_hotspot(self: &Arc<Self>, mut status: HotspotStatus) {
        let Ok(_guard) = self.control.try_lock() else { return };
        let previous = self.hotspot_status();
        // The backend only knows "in transition": from a running access point
        // that is a turn-off, which the user should not see as "turning on".
        if status.state == HotspotState::Starting && matches!(previous.state, HotspotState::Running | HotspotState::Stopping) {
            status.state = HotspotState::Stopping;
        }
        // Windows can drop the hotspot's address from its adapter for an
        // instant. While the access point stays up its network is the same,
        // so routing and the device rules hold on to it rather than letting
        // go (and letting devices out directly) until the next look.
        if status.state == HotspotState::Running && previous.state == HotspotState::Running && status.gateway.is_none() {
            status.gateway = previous.gateway;
            status.interface = status.interface.or(previous.interface.clone());
        }
        let key = |s: &HotspotStatus| (s.state == HotspotState::Running, s.gateway, s.interface.clone());
        let (before, after) = (key(&previous), key(&status));
        let state = status.state;
        self.set_hotspot_status(status);
        let released = self.release_hotspot_if_off(state, Instant::now());
        if before == after && !released {
            // Taking the traffic through Captun failed before: try again. (With
            // the kill switch on, sharing was stopped instead.)
            if after.0 && lock(&self.routing_error).is_some() {
                self.reconcile_engine().await;
            }
            return;
        }
        if before != after {
            info!(running = after.0, gateway = ?after.1, interface = ?after.2, "hotspot changed; updating DNS and routing");
            if before.1 != after.1 {
                self.stop_dns();
            }
            if let (true, Some(gateway), Some(_)) = &after {
                if lock(&self.dns).is_none() {
                    self.start_dns(*gateway).await;
                }
            } else {
                self.stop_dns();
            }
        }
        self.reconcile_engine().await;
        if released {
            // At once rather than at the monitor's next look: on Linux those
            // rules hold up whatever uses the adapter now.
            self.reconcile_reach().await;
        }
    }

    /// Lets go of the hotspot's network, held while its access point is off
    /// outside a start or stop, once the hold is over at `now`, and says
    /// whether it did. Steering and the device rules go by the adapter where
    /// they cannot go by addresses (Linux: `iif`/`-i` rules on the Wi-Fi
    /// device), and the system may already use that adapter for this
    /// computer's own Wi-Fi (NetworkManager took it back, a suspend), so
    /// there the network goes at once. On Windows it is held for
    /// `HOTSPOT_OFF_HOLD` from when the access point was first seen off, so
    /// a turn-on Windows makes soon after is taken from its first packet.
    fn release_hotspot_if_off(&self, state: HotspotState, now: Instant) -> bool {
        let mut since = lock(&self.hotspot_off_since);
        let mut net = lock(&self.hotspot_net);
        if !is_off(state) || net.is_none() {
            *since = None;
            return false;
        }
        let off_since = *since.get_or_insert(now);
        if capture::steers_by_address() && now.saturating_duration_since(off_since) < HOTSPOT_OFF_HOLD {
            return false;
        }
        *since = None;
        net.take();
        info!("the hotspot is off, so its network is no longer held to Captun's routing and device rules");
        true
    }

    /// Starts the hub's DNS if the settings want it and the hotspot is up
    /// without it (the settings just changed, say).
    async fn ensure_dns(self: &Arc<Self>) {
        let hotspot = self.hotspot_status();
        if hotspot.state == HotspotState::Running
            && let Some(gateway) = hotspot.gateway
            && lock(&self.dns).is_none()
            && dns_config(&self.config()).is_some()
        {
            self.start_dns(gateway).await;
        }
    }

    async fn start_dns(self: &Arc<Self>, gateway: IpAddr) {
        let config = self.config();
        let Some(dns) = dns_config(&config) else { return };
        let settings = match DnsSettings::from_config(&dns) {
            Ok(settings) => settings,
            Err(e) => {
                warn!("DNS settings rejected: {e}");
                return;
            }
        };
        let handler = Arc::new(DnsHandler::new(settings, dns::router(self), Some(dns::observer(self))));
        let listen = SocketAddr::new(gateway, config.dns.port);
        let server = match captun_dns::serve(listen, handler.clone()).await {
            Ok(server) => {
                info!(%listen, "DNS server listening");
                Some(server)
            }
            // Windows ICS and NetworkManager's dnsmasq hold port 53 on the
            // hotspot address (and Windows may not have finished adding the
            // address yet). Devices routed through Captun are answered all
            // the same: the routing engine hands their queries over.
            Err(e) => {
                info!(%listen, "DNS answered through the routing engine only (no socket of our own: {e})");
                None
            }
        };
        *lock(&self.dns) = Some(DnsRuntime { handler, gateway, _server: server });
    }

    /// The hub's own DNS, when `destination` is where devices send DNS queries
    /// the hub answers: the hotspot address, or with "make devices use it"
    /// (`enforce`) any DNS server at all.
    pub(crate) fn local_dns_for(&self, destination: &TargetAddr) -> Option<Arc<DnsHandler>> {
        const DNS_PORT: u16 = 53;
        let TargetAddr::Ip(addr) = destination else { return None };
        if addr.port() != DNS_PORT {
            return None;
        }
        let enforce = self.config().dns.enforce;
        let dns = lock(&self.dns);
        let runtime = dns.as_ref()?;
        (runtime.gateway == addr.ip() || enforce).then(|| runtime.handler.clone())
    }

    fn stop_dns(&self) {
        lock(&self.dns).take();
    }

    pub(crate) async fn shutdown(self: &Arc<Self>) {
        {
            let _guard = self.tether_ctl.lock().await;
            self.stop_reverse_locked().await;
        }
        {
            let _guard = self.access_ctl.lock().await;
            self.stop_access_locked();
        }
        // The access point goes first: once the capture is gone, Windows would
        // send its devices out directly, around their outbounds. Whatever the
        // last look said, unless it said the access point is off.
        if self.hotspot_status().state != HotspotState::Stopped
            && let Err(e) = self.stop_hotspot().await
        {
            warn!("cannot stop hotspot on exit: {}", e.message);
        }
        lock(&self.engine).take();
        self.xray.apply(&[]);
        self.stop_dns();
        self.lift_reach().await;
    }

    /// `mac`'s totals now, beside `rates` (bits per second down and up, from
    /// the last speed reading). Reads only: the next reading still measures
    /// from the last one, however often the device list is put together.
    fn traffic_for(&self, mac: MacAddr, (rx_bps, tx_bps): (u64, u64)) -> TrafficStats {
        let Some(counters) = self.meter.snapshot(&mac) else { return TrafficStats::default() };
        TrafficStats {
            rx_bytes: counters.down_bytes,
            tx_bytes: counters.up_bytes,
            rx_bps,
            tx_bps,
            active_flows: u32::try_from(counters.active_flows).unwrap_or(u32::MAX),
        }
    }

    /// The traffic of every device online that has had any, read at `now`
    /// for the GUI (`crate::traffic`, once a second). `None` when no GUI is
    /// connected to be told, or nothing changed since the last report.
    pub(crate) fn read_traffic(&self, now: Instant) -> Option<Vec<DeviceTraffic>> {
        if self.events.receiver_count() == 0 {
            // Nobody to tell: the next reading starts afresh rather than
            // average over the time nobody watched.
            lock(&self.speeds).clear();
            return None;
        }
        // A reverse-tethered phone is online while its session runs.
        let phone = lock(&self.tether).reverse.as_ref().map(|s| s.phone);
        // Only the MACs are copied under the device-list lock, which every
        // new flow and name lookup waits on; the counters are read after.
        let mut online: Vec<MacAddr> = lock(&self.registry).iter().filter(|p| p.online).map(|p| p.mac).collect();
        online.extend(phone);
        online.sort_unstable();
        online.dedup();
        let counters: Vec<(MacAddr, CounterSnapshot)> =
            online.into_iter().filter_map(|mac| self.meter.snapshot(&mac).map(|counters| (mac, counters))).collect();
        lock(&self.speeds).read(counters, now)
    }

    /// Forgets offline devices nobody needs remembered
    /// (`ClientRegistry::prune`), so a device sending under made-up MACs
    /// cannot grow the device list without end. Devices with saved settings
    /// stay, and so do devices with connections still open, so those keep
    /// their counters and their one speed-limit bucket. Returns whether any
    /// went. (The speed reading keeps online devices only, so it holds none
    /// of them.)
    pub(crate) fn prune_devices(&self) -> bool {
        let config = self.config();
        let saved: HashSet<MacAddr> = config.clients.iter().map(|p| p.mac).collect();
        let removed = lock(&self.registry).prune(self.now_ms(), |mac| {
            saved.contains(mac) || self.meter.snapshot(mac).is_some_and(|s| s.active_flows > 0)
        });
        if removed.is_empty() {
            return false;
        }
        // Outside the device-list lock, which every new flow waits on.
        for mac in &removed {
            self.meter.forget(mac);
        }
        debug!(devices = removed.len(), "forgot offline devices nothing is saved for");
        true
    }

    pub(crate) fn client_views(&self) -> Vec<ClientView> {
        let config = self.config();
        let policy = self.policy();
        // A reverse-tethered phone is "online" while its session runs, even
        // though it is not a hotspot station the registry tracks.
        let reverse_phone = lock(&self.tether).reverse.as_ref().map(|s| s.phone);
        let over_limit = lock(&self.over_limit).clone();
        let profiles: HashMap<MacAddr, &ClientProfile> = config.clients.iter().map(|p| (p.mac, p)).collect();
        // Copied out under the device-list lock, which every new flow and
        // name lookup waits on; the rest is built after it is let go.
        let presences = shown_presences(&lock(&self.registry), |mac| profiles.contains_key(mac), OFFLINE_SHOWN);
        // The speeds of the last reading, which this does not move.
        let rates = lock(&self.speeds).rates();
        let consented = |p: &ClientProfile| {
            p.tls_consent.is_some_and(|c| c.terms_version == config.tls_inspection.terms_version)
        };
        let view = |mac: MacAddr, presence: Option<&Presence>| {
            let profile = profiles.get(&mac).copied();
            ClientView {
                mac,
                online: presence.is_some_and(|p| p.online) || Some(mac) == reverse_phone,
                addrs: presence.map(|p| p.addrs.clone()).unwrap_or_default(),
                hostname: presence.and_then(|p| p.hostname.clone()),
                alias: profile.and_then(|p| p.alias.clone()),
                state: profile.map(|p| p.state).unwrap_or_default(),
                over_limit: over_limit.contains(&mac),
                group: profile.and_then(|p| p.group.clone()),
                egress: profile.and_then(|p| p.egress.clone()),
                effective_egress: policy.egress_for(&mac).clone(),
                limit: profile.and_then(|p| p.limit),
                inspect_tls: profile.is_some_and(|p| p.inspect_tls),
                tls_consented: profile.is_some_and(consented),
                randomized_mac: mac.is_locally_administered(),
                first_seen_ms: presence.map_or(0, |p| p.first_seen_ms),
                last_seen_ms: presence.map_or(0, |p| p.last_seen_ms),
                traffic: self.traffic_for(mac, rates.get(&mac).copied().unwrap_or_default()),
            }
        };
        // Every device the list holds that has saved settings is among
        // `presences`; the rest of the saved ones were never seen this run.
        let listed: HashSet<MacAddr> = presences.iter().map(|p| p.mac).collect();
        let mut views: Vec<ClientView> = presences.iter().map(|p| view(p.mac, Some(p))).collect();
        views.extend(profiles.keys().filter(|mac| !listed.contains(mac)).map(|mac| view(*mac, None)));
        views.sort_by(|a, b| b.online.cmp(&a.online).then(a.mac.cmp(&b.mac)));
        views
    }

    pub(crate) fn broadcast_clients(&self) {
        // No GUI connected: nobody to build the list for.
        if self.events.receiver_count() == 0 {
            return;
        }
        self.emit(Event::Clients(self.client_views()));
    }

    /// Validates, persists, then swaps in everything derived from the config.
    /// The file is written first so a crash never leaves the running state
    /// ahead of what is on disk. Without a file the GUI saves the settings
    /// itself when told about the change (`Event::ConfigChanged`).
    async fn commit(&self, config: Config) -> Result<(), IpcError> {
        match &self.config_file {
            Some(path) => config.save(path).map_err(invalid_config)?,
            None => config.validate().map_err(invalid_config)?,
        }
        // Saved copies of lists the rules now name, read before anything is
        // swapped and off the async threads: one big list takes seconds.
        self.lists.load_missing(&config).await;
        let previous = self.config();
        let dns = dns_config(&config);
        if dns_config(&previous) != dns {
            let running = lock(&self.dns).as_ref().map(|runtime| runtime.handler.clone());
            match (dns, running) {
                (Some(dns), Some(handler)) => match DnsSettings::from_config(&dns) {
                    Ok(settings) => handler.update_settings(settings),
                    Err(e) => warn!("DNS settings rejected: {e}"),
                },
                (None, Some(_)) => self.stop_dns(),
                // Starting needs the hotspot's address: `ensure_dns` does it.
                (_, None) => {}
            }
        }
        {
            // Policy and config change together under the capacity lock (see
            // `update_capacity`); the device limit is re-applied on the next poll.
            let held = lock(&self.over_limit);
            self.install_policy(&config, &held);
            write(&self.config, Arc::new(config));
        }
        // Only now: until the swap, a rebuild for the device limit still
        // compiles the rules before, with their lists.
        self.lists.prune(&self.config());
        // After the config swap, so a rebuild the sidecar triggers meanwhile
        // can only ever see the new config. Applying reads the outbounds'
        // Xray config files, which may take up to the 3 s it gives them all
        // together (a file another program holds, a slow drive): on a
        // blocking thread, so no async worker waits that long. Waited for, so
        // the outbounds below are built from what it found.
        let (xray, egresses) = (self.xray.clone(), self.config().egresses.clone());
        if let Err(e) = tokio::task::spawn_blocking(move || xray.apply(&egresses)).await {
            warn!("applying the VPN link settings failed: {e}");
        }
        self.rebuild_outbounds().await;
        // A device's way out may have changed: end open connections so they
        // reconnect under the new settings instead of carrying on the old way.
        // Only those of the devices whose own settings changed, unless what
        // changed can change everyone's: letting one device in or renaming it
        // leaves the others' connections alone.
        match crate::engine_glue::flows_ended_by(&previous, &self.config()) {
            FlowsEnded::All => self.flows.reset_all(),
            FlowsEnded::Devices(devices) => self.flows.reset_devices(&devices),
        }
        self.emit(Event::ConfigChanged);
        self.broadcast_clients();
        Ok(())
    }

    async fn set_config(self: &Arc<Self>, config: Config) -> Result<(), IpcError> {
        let restart_hotspot = {
            let _guard = self.control.lock().await;
            let previous = self.config();
            let running = self.hotspot_status().state == HotspotState::Running;
            // Asked of the way running: only a network of its own needs it.
            let hotspot_changed = access_point_restarts(&previous, &config, self.backend.shares_through_system());
            self.commit(config).await?;
            hotspot_changed && running
        };
        if restart_hotspot {
            // A hotspot restart re-applies steerings itself; otherwise reconcile the
            // engine so a routing (or access-network) change takes effect now.
            info!("hotspot settings changed; restarting the access point");
            let hub = self.clone();
            tokio::spawn(async move {
                if let Err(e) = hub.start_hotspot().await {
                    warn!("hotspot restart failed: {}", e.message);
                }
            });
        } else {
            // Before the engine, so its capture takes the devices' DNS too.
            self.ensure_dns().await;
            self.reconcile_engine().await;
        }
        self.reconcile_reach().await;
        // The GUI's settings just arrived: this is when the service "starts".
        if self.awaiting_settings.swap(false, Ordering::SeqCst) {
            self.autostart();
        }
        Ok(())
    }

    /// Turns on what the settings say should come up with the service: the
    /// hotspot (once it has a password) and the cable-shared network.
    pub(crate) fn autostart(self: &Arc<Self>) {
        let config = self.config();
        if config.hotspot.autostart && !config.hotspot.passphrase.is_empty() {
            let hub = self.clone();
            tokio::spawn(async move {
                if let Err(e) = hub.start_hotspot().await {
                    warn!("autostart failed: {}", e.message);
                }
            });
        }
        if config.access_network.enabled && config.access_network.autostart {
            let hub = self.clone();
            tokio::spawn(async move {
                if let Err(e) = hub.start_access_network().await {
                    warn!("access-network autostart failed: {}", e.message);
                }
            });
        }
    }

    async fn set_client_profile(&self, profile: ClientProfile) -> Result<(), IpcError> {
        let _guard = self.control.lock().await;
        let mut config = (*self.config()).clone();
        let mac = profile.mac;
        *config.client_mut(mac) = profile;
        self.commit(config).await
    }

    async fn forget_client(&self, mac: MacAddr) -> Result<(), IpcError> {
        let _guard = self.control.lock().await;
        if lock(&self.registry).get(&mac).is_some_and(|p| p.online) {
            return Err(IpcError::new(ErrorCode::BadRequest, "this device is connected; block it instead of forgetting it"));
        }
        lock(&self.registry).forget(&mac);
        self.meter.forget(&mac);
        self.forget_names(mac);
        let mut config = (*self.config()).clone();
        let before = config.clients.len();
        config.clients.retain(|c| c.mac != mac);
        if config.clients.len() == before {
            self.broadcast_clients();
            return Ok(());
        }
        self.commit(config).await
    }

    async fn interfaces(&self) -> Vec<InterfaceInfo> {
        // The GUI asks every few seconds: read off the async threads.
        let interfaces = captun_platform::iface::list_async().await;
        let hotspot_iface = self.hotspot_status().interface;
        // The USB link to a phone carries this PC's internet to it, never the reverse.
        let phone_link = lock(&self.tether).reverse.as_ref().map(|s| s.interface.clone());
        interfaces
            .into_iter()
            .filter(|i| !i.loopback)
            .map(|i| InterfaceInfo {
                index: i.index,
                is_hotspot: [&hotspot_iface, &phone_link].iter().any(|n| n.as_deref() == Some(i.name.as_str())),
                name: i.name,
                description: i.description,
                kind: i.kind,
                physical: i.physical,
                mac: i.mac,
                ipv4: i.ipv4,
                ipv6: i.ipv6,
                up: i.up,
                has_gateway: i.has_gateway,
                gateway: i.gateway,
                default_route: i.default_route,
                speed_mbps: i.speed_mbps,
            })
            .collect()
    }

    async fn test_egress(&self, id: &captun_core::EgressId, target: Option<TargetAddr>) -> EgressTestResult {
        let failure = |error: String| EgressTestResult { ok: false, latency_ms: None, error: Some(error), udp: None };
        let Some(outbound) = self.outbounds().get(id).cloned() else {
            return failure(format!("unknown outbound {id}"));
        };
        let target = match target {
            Some(target) => target,
            None => match EGRESS_TEST_TARGET.parse::<TargetAddr>() {
                Ok(target) => target,
                Err(e) => return failure(e.to_string()),
            },
        };
        let started = Instant::now();
        match timeout(EGRESS_TEST_TIMEOUT, outbound.connect_tcp(&target)).await {
            Ok(Ok(_stream)) => EgressTestResult {
                ok: true,
                latency_ms: Some(started.elapsed().as_millis() as u64),
                error: None,
                udp: self.carries_udp(id).await,
            },
            Ok(Err(e)) => failure(e.to_string()),
            Err(_) => failure(format!("no connection to {target} within {}s", EGRESS_TEST_TIMEOUT.as_secs())),
        }
    }

    /// Whether devices' UDP gets out through `id`: through the outbound itself
    /// or the one its UDP goes through. `None` when that cannot be told.
    async fn carries_udp(&self, id: &captun_core::EgressId) -> Option<bool> {
        let Some(outbound) = self.outbounds().for_udp(id).cloned() else { return Some(false) };
        match timeout(EGRESS_TEST_TIMEOUT, outbound.udp_session()).await {
            Ok(Ok(_session)) => Some(true),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Unsupported => Some(false),
            _ => None,
        }
    }

    // -- phone tethering (built-in adb) -------------------------------------

    /// A built-in-adb runner not pinned to a device.
    fn adb(&self) -> Adb {
        Adb::new(self.adb_key.clone())
    }

    /// A built-in-adb runner pinned to one device serial.
    fn adb_for(&self, serial: &str) -> Adb {
        Adb::with_serial(self.adb_key.clone(), serial)
    }

    async fn list_adb_devices(self: &Arc<Self>) -> Result<Vec<AdbDeviceInfo>, IpcError> {
        let devices = self.adb().devices().await.map_err(tether::adb_error)?;
        let listed: Vec<AdbDeviceInfo> = devices.iter().map(tether::device_info).collect();
        if !captun_usbdriver::NEEDED || devices.iter().any(|d| d.state.is_ready()) {
            return Ok(listed);
        }
        // No phone can be used yet. On Windows that is often one whose USB
        // debugging interface has no driver: libusb cannot open it, so it is
        // listed as not openable, or not at all.
        usb_driver_listing(listed, self.phone_usb_driver().await)
    }

    /// Whether a phone plugged in now is held back by a missing USB driver.
    /// The first time one is, Captun starts installing its own (the service
    /// runs elevated); a phone with a driver is never touched.
    async fn phone_usb_driver(self: &Arc<Self>) -> PhoneDriver {
        let calls = lock(&self.tether).usb_driver_calls;
        let detected = match tokio::task::spawn_blocking(calls.detect).await {
            Ok(Ok(detected)) => detected,
            Ok(Err(e)) => {
                warn!("cannot tell whether a phone needs a USB driver: {e}");
                return PhoneDriver::Nothing;
            }
            Err(e) => {
                warn!("looking for phones without a USB driver stopped: {e}");
                return PhoneDriver::Nothing;
            }
        };
        let start = {
            let mut state = lock(&self.tether);
            let first = matches!(detected, captun_usbdriver::Detection::Missing(_))
                && state.usb_driver == UsbDriverFix::NotTried;
            if first {
                state.usb_driver = UsbDriverFix::Installing;
            }
            first
        };
        if start {
            if let captun_usbdriver::Detection::Missing(devices) = &detected {
                info!("a phone's USB debugging interface has no driver ({}); installing Captun's", devices.join(", "));
            }
            self.install_usb_driver(calls.install);
        }
        usb_driver_advice(&detected, &lock(&self.tether).usb_driver)
    }

    /// Installs the USB driver for phones in the background, as it can take
    /// longer than the app waits for an answer (another install may hold
    /// it up, and Windows may take a while), and notes how it went for the
    /// listings after. The app's regular listing shows the phone once it
    /// has the driver.
    fn install_usb_driver(
        self: &Arc<Self>,
        install: fn() -> Result<captun_usbdriver::Install, captun_usbdriver::DriverError>,
    ) {
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            let outcome = tokio::task::spawn_blocking(install).await.unwrap_or_else(|stopped| {
                Err(captun_usbdriver::DriverError::Failed {
                    step: "installing",
                    source: std::io::Error::other(stopped),
                })
            });
            let fix = match outcome {
                Ok(done) => {
                    info!("{done}");
                    UsbDriverFix::Installed(done.notice())
                }
                Err(e) => {
                    warn!("cannot install the USB driver for phones: {e}");
                    UsbDriverFix::Failed(e.install_advice())
                }
            };
            lock(&hub.tether).usb_driver = fix;
        });
    }

    /// Brings up the USB network link (RNDIS/NCM) and returns the new PC-side
    /// interface once it has an IPv4 address. Reconfiguring the USB gadget briefly
    /// drops the ADB session, so a failed `setFunctions` is tolerated and the real
    /// signal is a new interface appearing.
    async fn bring_up_usb_link(&self, serial: &str, function: UsbFunction) -> Result<LinkIface, IpcError> {
        // Fresh reads, off the async threads: an adapter that came up a moment
        // ago must count as "before", and the new one must be seen at once.
        let before: HashSet<String> =
            captun_platform::iface::list_fresh_async().await.into_iter().map(|i| i.name).collect();
        if let Err(e) = self.adb_for(serial).shell(&link_up_command(function)).await {
            // A disconnect here is expected (the USB gadget is reconfiguring); only
            // a hard failure before that — e.g. the phone never authorized us — is
            // worth surfacing, and the interface wait below will catch "nothing
            // happened" either way.
            warn!("usb link setFunctions reported: {e} (often just the USB gadget reconfiguring)");
        }
        // Wait for the new interface to appear and get an address from the phone.
        for _ in 0..12 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Some(iface) = captun_platform::iface::list_fresh_async().await.into_iter().find(|i| {
                !i.loopback && !before.contains(&i.name) && !i.ipv4.is_empty()
            })
                && let Some(ipv4) = iface.ipv4.first().copied()
            {
                return Ok(LinkIface { name: iface.name, system_name: iface.system_name, index: iface.index, ipv4 });
            }
        }
        Err(IpcError::new(
            ErrorCode::BadRequest,
            format!(
                "The USB network link did not come up on {serial}. {}",
                captun_adb::link_hint()
            ),
        ))
    }

    /// Turns reverse tethering on (the phone uses this PC's internet) or off. The
    /// default method installs nothing on the phone: Captun brings up the USB
    /// network link, runs a proxy inbound on the PC, and points the phone's system
    /// proxy at the PC's address on that link. The phone is routed as a managed
    /// client so its egress, rules and limits apply. Captun only gives
    /// internet: the PC never uses the phone's, which is checked before
    /// sharing starts and for as long as it runs.
    async fn set_reverse_tether(
        self: &Arc<Self>,
        serial: String,
        enable: bool,
        method: ReverseMethod,
    ) -> Result<TetherOutcome, IpcError> {
        let _guard = self.tether_ctl.lock().await;
        if !enable {
            self.stop_reverse_locked().await;
            self.broadcast_clients();
            let caution = post_session_caution(&SessionSummary { reverse: Some(method) });
            return Ok(TetherOutcome {
                ok: true,
                message: "Stopped sharing this computer's internet with the phone.".into(),
                caution: Some(caution),
            });
        }
        if method == ReverseMethod::Helper {
            return Err(IpcError::new(
                ErrorCode::Unsupported,
                "The full-coverage helper method is not bundled in this build yet. Use the default no-app method (system proxy).",
            ));
        }
        // Before the phone is touched: a phone key Captun did not make is
        // replaced, and the user is told to revoke it on the phone, whether
        // the session then starts or not.
        let key_note = self.adb().prepare_key().await.map_err(tether::adb_error)?.note();
        with_key_note(self.start_reverse_locked(serial).await, key_note)
    }

    /// Starts sharing this computer's internet with the phone `serial` the
    /// default way (system proxy). Callers must hold `tether_ctl`.
    async fn start_reverse_locked(self: &Arc<Self>, serial: String) -> Result<TetherOutcome, IpcError> {
        // Replace any running reverse session.
        self.stop_reverse_locked().await;

        // There must be internet here to give before touching the phone.
        if !captun_platform::iface::list_async().await.iter().any(|i| !i.loopback && i.default_route) {
            return Err(IpcError::new(
                ErrorCode::BadRequest,
                "This computer is not connected to the internet, so there is nothing to share with the phone.",
            ));
        }

        let phone = tether::phone_mac_from_serial(&serial);
        self.ensure_phone_profile(phone, &serial).await?;

        // Bring up the USB link so the phone can reach this PC by IP.
        let link = self.bring_up_usb_link(&serial, UsbFunction::Rndis).await?;

        // The proxy inbound the phone's traffic arrives on, bound to the PC's
        // address on the USB link, fed into the policy engine as the phone.
        let listener = TcpListener::bind((link.ipv4, 0))
            .await
            .map_err(|e| IpcError::new(ErrorCode::Internal, format!("cannot open the reverse proxy inbound: {e}")))?;
        let pc_port =
            listener.local_addr().map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?.port();

        // Keep the PC on its own internet and let the phone reach the proxy.
        let spec = ReverseNet { interface_index: link.index, interface_name: link.system_name.clone(), proxy_port: pc_port };
        let link_down = [AdbOp::shell(link_down_command())];
        let net = match tether_net::protect(&spec) {
            Ok(guard) => guard,
            Err(e) => {
                self.adb_for(&serial).run_revert(&link_down).await;
                return Err(IpcError::new(ErrorCode::Internal, format!("cannot prepare this computer's side of the USB link: {e}")));
            }
        };
        if let Err(e) = keep_off_phone_route(&spec).await {
            drop(net);
            self.adb_for(&serial).run_revert(&link_down).await;
            return Err(e);
        }

        let dispatcher: Arc<dyn captun_engine::Dispatcher> = Arc::new(tether::ReverseDispatcher::new(self, phone));
        let inbound =
            serve_inbound(listener, InboundConfig::new(IpAddr::V4(link.ipv4)), dispatcher, self.meter.clone(), self.flows.clone());

        let plan =
            reverse_plan(ReverseMethod::SystemProxy, &ReverseParams::system_proxy(link.ipv4.to_string(), pc_port));
        if let Err(e) = self.adb_for(&serial).apply(&plan).await {
            drop(inbound);
            drop(net);
            self.adb_for(&serial).run_revert(&link_down).await;
            return Err(tether::adb_error(e));
        }
        lock(&self.tether).reverse = Some(ReverseSession {
            serial,
            interface: link.name,
            phone,
            revert: plan.revert,
            _route_watch: watch_phone_route(spec),
            _net: net,
            _inbound: inbound,
        });
        self.broadcast_clients();
        Ok(TetherOutcome {
            ok: true,
            message: "The phone now uses this computer's internet over USB (no app installed). Web and app traffic (TCP) goes through; games and calls (UDP) do not in this mode. The phone is listed under Devices, where you can pick its outbound and limits."
                .into(),
            caution: None,
        })
    }

    /// Stops the reverse session, if any, reverting the phone-side changes and the
    /// USB link. Callers must hold `tether_ctl`.
    async fn stop_reverse_locked(&self) {
        let session = lock(&self.tether).reverse.take();
        if let Some(session) = session {
            // Clear the phone's proxy before the inbound and PC-side network set-up
            // (held in `session`) are dropped at the end of this scope.
            let mut revert = session.revert.clone();
            revert.push(AdbOp::shell(link_down_command()));
            self.adb_for(&session.serial).run_revert(&revert).await;
        }
    }

    /// Makes sure the phone has a profile so it is manageable and visible, like
    /// any other client. Created approved the first time; later left untouched.
    async fn ensure_phone_profile(&self, phone: MacAddr, serial: &str) -> Result<(), IpcError> {
        if self.config().client(&phone).is_some() {
            return Ok(());
        }
        let _guard = self.control.lock().await;
        let mut config = (*self.config()).clone();
        let profile = config.client_mut(phone);
        profile.state = ClientState::Approved;
        profile.alias = Some(format!("Phone ({serial})"));
        self.commit(config).await
    }

    // -- wired/USB access network -------------------------------------------

    /// Brings the wired/USB access network up from the `access_network` config:
    /// assigns the gateway address, sets up NAT and the per-interface DHCP
    /// firewall rule, and starts the DHCP server on that interface.
    pub(crate) async fn start_access_network(self: &Arc<Self>) -> Result<(), IpcError> {
        *lock(&self.access_error) = None;
        let config = self.config();
        let settings = config.access_network.clone();
        if !settings.enabled {
            return Err(IpcError::new(ErrorCode::BadRequest, "cable sharing is turned off in Settings"));
        }
        let Some(name) = settings.interface.clone() else {
            return Err(IpcError::new(ErrorCode::BadRequest, "choose a network adapter for cable sharing in Settings"));
        };
        if !captun_platform::access::supported() {
            return Err(IpcError::new(ErrorCode::Unsupported, "cable sharing is not supported on this system yet"));
        }
        // When transparent routing is on, the engine carries the traffic (per-client
        // egress/limits), so skip OS NAT to avoid NATing twice.
        let engine_routed = config.network.transparent_routing && captun_platform::capture::supports_transparent_routing();
        let effective_nat = settings.nat && !engine_routed;

        {
            let _guard = self.access_ctl.lock().await;
            // A fresh read, off the async threads: the adapter may have been
            // plugged in a moment ago.
            let iface = captun_platform::iface::list_fresh_async()
                .await
                .into_iter()
                .find(|i| i.name.eq_ignore_ascii_case(&name) || i.system_name.eq_ignore_ascii_case(&name))
                .ok_or_else(|| IpcError::new(ErrorCode::BadRequest, format!("network adapter {name:?} was not found")))?;

            // Replace any running session (drops it: DHCP stops, OS changes revert).
            lock(&self.access).take();

            let setup = captun_platform::access::AccessSetup {
                interface_index: iface.index,
                interface_system_name: iface.system_name.clone(),
                interface_alias: iface.name.clone(),
                gateway: settings.gateway,
                prefix_len: settings.prefix_len,
                network: settings.network(),
                nat: effective_nat,
            };
            let net = captun_platform::access::bring_up(&setup)
                .map_err(|e| IpcError::new(ErrorCode::Internal, format!("cannot start cable sharing: {e}")))?;
            let socket = captun_platform::access::bind_dhcp_socket(&iface)
                .map_err(|e| IpcError::new(ErrorCode::Internal, format!("cannot open the DHCP socket (is UDP port 67 free?): {e}")))?;
            let pool = Arc::new(Mutex::new(captun_dhcp::LeasePool::new(
                settings.gateway,
                settings.dhcp_start,
                settings.dhcp_end,
                u64::from(settings.lease_secs) * 1000,
            )));
            let server_config = captun_dhcp::ServerConfig {
                gateway: settings.gateway,
                subnet_mask: settings.netmask(),
                dns: settings.gateway,
            };
            let dhcp = captun_dhcp::DhcpServer::start(socket, server_config, pool);

            info!(interface = %iface.name, gateway = %settings.gateway, nat = effective_nat, routed = engine_routed, "access network up");
            *lock(&self.access) = Some(AccessSession {
                interface: iface.name,
                gateway: settings.gateway,
                network: settings.network(),
                prefix_len: settings.prefix_len,
                nat: effective_nat,
                dhcp,
                _net: net,
            });
        }
        // Steer the access network into the engine if transparent routing is on.
        self.reconcile_engine().await;
        self.reconcile_reach().await;
        Ok(())
    }

    pub(crate) async fn stop_access_network(self: &Arc<Self>) -> Result<(), IpcError> {
        {
            let _guard = self.access_ctl.lock().await;
            self.stop_access_locked();
        }
        self.reconcile_engine().await;
        self.reconcile_reach().await;
        self.broadcast_clients();
        Ok(())
    }

    /// Drops the access session (stops DHCP, reverts the OS changes). Callers that
    /// need ordering with other access operations hold `access_ctl`.
    fn stop_access_locked(&self) {
        if let Some(session) = lock(&self.access).take() {
            info!(interface = %session.interface, "access network down");
        }
    }

    /// The access network's DHCP leases, as observed clients for the monitor.
    pub(crate) fn access_leases(&self) -> Vec<ObservedClient> {
        let leases = match &*lock(&self.access) {
            Some(session) => session.dhcp.leases(),
            None => return Vec::new(),
        };
        leases
            .into_iter()
            .map(|lease| ObservedClient {
                mac: MacAddr::new(lease.mac),
                addrs: vec![IpAddr::V4(lease.ip)],
                hostname: lease.hostname,
            })
            .collect()
    }

    fn access_status(&self) -> AccessNetworkStatus {
        match &*lock(&self.access) {
            Some(session) => AccessNetworkStatus {
                running: true,
                interface: Some(session.interface.clone()),
                gateway: Some(IpAddr::V4(session.gateway)),
                leases: session.dhcp.leases().len(),
                nat: session.nat,
                error: None,
            },
            None => AccessNetworkStatus { error: lock(&self.access_error).clone(), ..AccessNetworkStatus::default() },
        }
    }

    pub(crate) fn now_ms(&self) -> u64 {
        now_millis()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    // Hub::new starts the VPN-link supervisor, which needs a runtime. The
    // default settings start nothing, so no network adapter is touched.
    fn hub(config_file: Option<PathBuf>) -> (Arc<Hub>, broadcast::Receiver<Event>) {
        let (events, rx) = broadcast::channel(16);
        (Hub::new(config_file, Config::default(), captun_platform::default_backend(), events, None), rx)
    }

    fn profile(alias: &str) -> ClientProfile {
        let mut config = Config::default();
        let profile = config.client_mut("02:00:00:00:00:07".parse().unwrap());
        profile.alias = Some(alias.into());
        profile.clone()
    }

    #[test]
    fn a_replaced_phone_key_is_told_about_however_usb_to_phone_went() {
        const NOTE: &str = "Captun found a phone key it did not make and replaced it.";
        const STARTED: &str = "The phone now uses this computer's internet.";
        const FAILED: &str = "The USB network link did not come up.";
        let ok = || Ok(TetherOutcome { ok: true, message: STARTED.into(), caution: None });
        let failed = || Err(IpcError::new(ErrorCode::BadRequest, FAILED));

        assert_eq!(with_key_note(ok(), None).unwrap().message, STARTED);
        // First, in a message the app shows only briefly.
        assert_eq!(with_key_note(ok(), Some(NOTE)).unwrap().message, format!("{NOTE} {STARTED}"));
        let error = with_key_note(failed(), Some(NOTE)).unwrap_err();
        assert_eq!(error.code, ErrorCode::BadRequest);
        assert_eq!(error.message, format!("{FAILED} {NOTE}"));
        assert_eq!(with_key_note(failed(), None).unwrap_err().message, FAILED);
    }

    /// A VPN-link outbound `vpn` set up from the Xray config file at `path`.
    fn xray_from_file(path: PathBuf) -> captun_core::EgressConfig {
        captun_core::EgressConfig {
            id: "vpn".into(),
            name: None,
            kind: captun_core::EgressKind::Xray { link: None, config_file: Some(path) },
            udp: captun_core::UdpPolicy::Native,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn an_xray_config_file_is_read_before_the_outbounds_are_rebuilt() {
        let (hub, _events) = hub(None);
        let missing = std::env::temp_dir().join(format!("captun-no-such-outbound-{}.json", std::process::id()));
        let mut config = (*hub.config()).clone();
        config.egresses.push(xray_from_file(missing.clone()));
        // Only the settings change: nothing on this computer is touched.
        hub.commit(config).await.unwrap();
        // Read on a blocking thread, and done by the time the change is.
        let why = hub.xray.endpoint(&"vpn".into()).unwrap_err();
        assert!(why.contains(&missing.display().to_string()), "{why}");
    }

    // One thread for every task, as one busy async thread would be: while a
    // change waits for an Xray config file (up to 3 s when another program
    // holds it), what else runs there must go on. A file cannot be made to
    // hold up its reader from here (the reader refuses pipes and FIFOs, and
    // holding a file needs an oplock), but no wait is needed to tell: nothing
    // else in a change without lists waits, so read on this thread, no other
    // task would run at all until the change is done.
    #[tokio::test(flavor = "current_thread")]
    async fn other_tasks_go_on_while_a_change_reads_xray_config_files() {
        let (hub, _events) = hub(None);
        // Read in full, but no outbound: Xray is not started.
        let file = std::env::temp_dir().join(format!("captun-not-an-outbound-{}.json", std::process::id()));
        std::fs::write(&file, "{}").unwrap();
        let mut config = (*hub.config()).clone();
        config.egresses.push(xray_from_file(file.clone()));
        let turns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let other = tokio::spawn({
            let turns = turns.clone();
            async move {
                loop {
                    turns.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                }
            }
        });
        let before = turns.load(Ordering::SeqCst);
        hub.commit(config).await.unwrap();
        let meanwhile = turns.load(Ordering::SeqCst) - before;
        other.abort();
        let _ = std::fs::remove_file(&file);
        assert!(meanwhile > 0, "the change held up the async thread while the file was read");
        let why = hub.xray.endpoint(&"vpn".into()).unwrap_err();
        assert!(why.contains("holds no Xray outbound"), "read by the time the change is done: {why}");
    }

    /// A list server on this computer that answers only when told, and then
    /// "not found", so no copy is saved anywhere: the list's link, what tells
    /// the server to answer, and how often it was asked for the list.
    async fn list_server_on_hold() -> (String, Arc<tokio::sync::Notify>, Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let link = format!("http://{}/list.txt", server.local_addr().unwrap());
        let answer = Arc::new(tokio::sync::Notify::new());
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn({
            let (answer, asked) = (answer.clone(), asked.clone());
            async move {
                while let Ok((mut socket, _)) = server.accept().await {
                    asked.fetch_add(1, Ordering::SeqCst);
                    answer.notified().await;
                    // The request is read first and the connection closed
                    // gently: Windows resets one closed with data unread.
                    let mut request = Vec::new();
                    let mut buf = [0; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = socket.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
                    let _ = socket.shutdown().await;
                    while socket.read(&mut buf).await.is_ok_and(|n| n > 0) {}
                }
            }
        });
        (link, answer, asked)
    }

    /// A rule that blocks what the list at `link` names.
    fn list_rule(link: &str) -> captun_core::config::RuleConfig {
        captun_core::config::RuleConfig {
            name: None,
            enabled: true,
            clients: Vec::new(),
            groups: Vec::new(),
            domains: Vec::new(),
            cidrs: Vec::new(),
            lists: vec![link.to_owned()],
            ports: Vec::new(),
            protocol: None,
            schedule: None,
            action: captun_core::config::RuleAction::Deny,
        }
    }

    /// The `done` counts the app is told until the update is over, and how
    /// the lists stand then.
    async fn until_the_update_is_over(events: &mut broadcast::Receiver<Event>) -> (Vec<usize>, ListsProgress) {
        let mut told = Vec::new();
        loop {
            match timeout(Duration::from_secs(30), events.recv()).await.expect("the update never ended") {
                Ok(Event::Lists(progress)) if !progress.updating => return (told, progress),
                Ok(Event::Lists(progress)) => told.push(progress.done),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[tokio::test]
    async fn updating_lists_answers_at_once_and_tells_how_it_goes() {
        let (link, answer, asked) = list_server_on_hold().await;
        let (hub, mut events) = hub(None);
        let mut config = (*hub.config()).clone();
        config.rules.push(list_rule(&link));
        hub.commit(config).await.unwrap();

        // The download is still waiting for the server.
        let started = hub.update_lists(None).unwrap();
        assert_eq!((started.updating, started.done, started.total), (true, 0, 1));
        // A second press while it runs starts nothing, and says how far it is.
        let again = hub.update_lists(None).unwrap();
        assert_eq!((again.updating, again.done), (true, 0));
        assert!(matches!(
            hub.handle(Request::GetLists).await,
            Ok(Response::Lists(ListsProgress { updating: true, .. }))
        ));

        answer.notify_one();
        let (told, over) = until_the_update_is_over(&mut events).await;
        assert_eq!(told, [0, 1], "when it started and after the list");
        assert_eq!((over.done, over.total), (1, 1));
        let why = over.lists[0].error.as_deref().unwrap();
        assert!(why.contains("404"), "{why}");
        assert_eq!(asked.load(Ordering::SeqCst), 1, "downloaded once, for the first press only");
        assert!(!hub.lists.progress(&hub.config()).updating);
        assert!(hub.lists.holds(&link), "a list the rules use stays held");
    }

    #[tokio::test]
    async fn a_list_the_rules_stop_naming_during_an_update_is_let_go_of_after_it() {
        let (link, answer, _asked) = list_server_on_hold().await;
        let (hub, mut events) = hub(None);
        let mut config = (*hub.config()).clone();
        config.rules.push(list_rule(&link));
        hub.commit(config).await.unwrap();
        assert!(hub.update_lists(None).unwrap().updating);

        // The rule goes while the list downloads, and the download then
        // comes back: here as "not found", which is held all the same, as a
        // list would be (nothing is saved).
        let mut config = (*hub.config()).clone();
        config.rules.clear();
        hub.commit(config).await.unwrap();
        assert!(!hub.lists.holds(&link), "let go of by the change");
        answer.notify_one();
        let (_, over) = until_the_update_is_over(&mut events).await;
        assert!(over.lists.is_empty());
        assert!(!hub.lists.holds(&link), "let go of again once the update is over");
    }

    #[tokio::test]
    async fn settings_from_the_gui_live_in_memory_and_announce_changes() {
        let (hub, mut events) = hub(None);
        hub.set_client_profile(profile("Tablet")).await.unwrap();
        assert_eq!(hub.config().clients.len(), 1);
        // The GUI saves the settings when told they changed.
        assert!(std::iter::from_fn(|| events.try_recv().ok()).any(|e| matches!(e, Event::ConfigChanged)));

        let mut invalid = (*hub.config()).clone();
        invalid.hotspot.ssid = String::new();
        let err = hub.set_config(invalid).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidConfig);
        assert_eq!(hub.config().hotspot.ssid, Config::default().hotspot.ssid);
    }

    #[tokio::test]
    async fn autostart_waits_for_the_guis_first_settings() {
        let (hub, _events) = hub(None);
        assert!(hub.awaiting_settings.load(Ordering::SeqCst));
        hub.set_config(Config::default()).await.unwrap();
        assert!(!hub.awaiting_settings.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_running_hotspot_keeps_its_address_through_a_blink() {
        let (hub, _events) = hub(None);
        // An address this computer does not have, so nothing really listens.
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let running = |gateway: Option<IpAddr>| HotspotStatus {
            state: HotspotState::Running,
            ssid: Some("Captun".into()),
            interface: gateway.map(|_| "Local Area Connection* 2".into()),
            gateway,
            ..HotspotStatus::default()
        };
        hub.observe_hotspot(running(Some(gateway))).await;
        hub.observe_hotspot(running(None)).await;
        let status = hub.hotspot_status();
        assert_eq!((status.gateway, status.interface.as_deref()), (Some(gateway), Some("Local Area Connection* 2")));
        hub.observe_hotspot(HotspotStatus::default()).await;
        assert_eq!(hub.hotspot_status().gateway, None, "a stopped hotspot lets go of it");
    }

    /// What a fake hotspot did and was told, shared with the test.
    #[derive(Debug, Default)]
    struct Fake {
        running: AtomicBool,
        starts: AtomicUsize,
        stops: AtomicUsize,
        /// What `set_engine_routed` was told last.
        routed: Mutex<Option<bool>>,
        /// Runs a network of its own, as the hosted network and hostapd do.
        own_network: AtomicBool,
        /// The network it expects to run, before a start.
        expected: Mutex<Option<ipnet::Ipv4Net>>,
        /// The hub it serves, to see what that steered and held to the device
        /// rules as the access point was started.
        hub: Mutex<std::sync::Weak<Hub>>,
        at_start: Mutex<Option<AtStart>>,
    }

    /// The hub as the fake's access point was started.
    #[derive(Clone, Debug)]
    #[cfg_attr(not(windows), allow(dead_code))]
    struct AtStart {
        steered: Vec<(SteerKey, CaptureConfig)>,
        held: Vec<SteerKey>,
        /// Steering was tried (and failed, without the packet driver).
        tried: bool,
    }

    impl Fake {
        fn snapshot(&self) -> BackendState {
            let running = self.running.load(Ordering::SeqCst);
            BackendState {
                running,
                transitioning: false,
                ssid: Some("Captun".into()),
                interface: running.then(|| "Local Area Connection* 2".into()),
                // An address this computer does not have.
                gateway: running.then_some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                max_clients: Some(8),
            }
        }
    }

    /// A hotspot that only pretends, on 192.0.2.0/24.
    #[derive(Debug)]
    struct FakeHotspot(Arc<Fake>);

    #[async_trait::async_trait]
    impl HotspotBackend for FakeHotspot {
        fn notes(&self) -> captun_platform::PlatformNotes {
            captun_platform::PlatformNotes::default()
        }

        async fn start(
            &self,
            _config: &captun_core::config::HotspotConfig,
            _options: captun_platform::StartOptions,
        ) -> Result<BackendState, HotspotError> {
            let hub = lock(&self.0.hub).upgrade();
            if let Some(hub) = hub {
                *lock(&self.0.at_start) = Some(AtStart {
                    steered: hub.desired_steerings(),
                    held: hub.shared_networks().into_iter().map(|n| n.key).collect(),
                    tried: lock(&hub.routing_error).is_some(),
                });
            }
            self.0.starts.fetch_add(1, Ordering::SeqCst);
            self.0.running.store(true, Ordering::SeqCst);
            Ok(self.0.snapshot())
        }

        async fn stop(&self) -> Result<(), HotspotError> {
            self.0.running.store(false, Ordering::SeqCst);
            self.0.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn state(&self) -> Result<BackendState, HotspotError> {
            Ok(self.0.snapshot())
        }

        async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError> {
            Ok(Vec::new())
        }

        fn expected_network(&self) -> Option<ipnet::Ipv4Net> {
            *lock(&self.0.expected)
        }

        fn set_engine_routed(&self, routed: bool) {
            *lock(&self.0.routed) = Some(routed);
        }

        fn shares_through_system(&self) -> bool {
            !self.0.own_network.load(Ordering::SeqCst)
        }
    }

    /// A hub over a fake hotspot that expects 192.0.2.0/24, with outbounds
    /// (`routing`) and the kill switch on or off.
    fn hub_with_fake(routing: bool, kill_switch: bool) -> (Arc<Hub>, Arc<Fake>) {
        let fake = Arc::new(Fake { expected: Mutex::new("192.0.2.0/24".parse().ok()), ..Fake::default() });
        let mut config = Config::default();
        config.network.transparent_routing = routing;
        config.network.kill_switch = kill_switch;
        let (events, _) = broadcast::channel(16);
        let hub = Hub::new(None, config, Box::new(FakeHotspot(fake.clone())), events, None);
        *lock(&fake.hub) = Arc::downgrade(&hub);
        (hub, fake)
    }

    /// A hub sharing over the fake hotspot with outbounds on, as the monitor
    /// sees it come up.
    #[cfg(windows)]
    async fn sharing_with_outbounds(kill_switch: bool) -> (Arc<Hub>, Arc<Fake>) {
        let (hub, fake) = hub_with_fake(true, kill_switch);
        fake.running.store(true, Ordering::SeqCst);
        let state = hub.backend().state().await.unwrap();
        hub.observe_hotspot(Hub::status_from_backend(&state, None)).await;
        (hub, fake)
    }

    // Taking the traffic through Captun fails here as it would with a blocked
    // driver: WinDivert is not next to the test binary.
    #[cfg(windows)]
    #[tokio::test]
    async fn the_kill_switch_stops_sharing_when_outbounds_cannot_apply() {
        let (hub, fake) = sharing_with_outbounds(true).await;
        for _ in 0..250 {
            if fake.stops.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(fake.stops.load(Ordering::SeqCst), 1, "the hotspot should have been stopped");
        let status = hub.hotspot_status();
        assert_eq!(status.state, HotspotState::Failed);
        assert!(status.error.unwrap().starts_with("Sharing stopped"));
        assert!(lock(&hub.hotspot_net).is_none(), "its network is let go once it is down");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn without_the_kill_switch_sharing_goes_on_and_routing_is_retried() {
        let (hub, fake) = sharing_with_outbounds(false).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fake.stops.load(Ordering::SeqCst), 0);
        assert_eq!(hub.hotspot_status().state, HotspotState::Running);
        assert_eq!(hub.routing_status().state, RoutingState::Failed);
        // The monitor's next look tries again, and fails the same way.
        let state = hub.backend().state().await.unwrap();
        hub.observe_hotspot(Hub::status_from_backend(&state, None)).await;
        assert_eq!(hub.routing_status().state, RoutingState::Failed);
    }

    fn expected_steering() -> (SteerKey, CaptureConfig) {
        let config = CaptureConfig {
            hotspot_interface: String::new(),
            subnet: "192.0.2.0/24".parse().unwrap(),
            gateway: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            // Outbounds are on, so the hub answers the devices' DNS.
            dns: true,
        };
        (SteerKey::Hotspot, config)
    }

    // Starting and stopping put the device rules in and take them out, which
    // on Linux would run iptables: Windows only, where the missing packet
    // driver makes both fail without touching anything.
    #[cfg(windows)]
    #[tokio::test]
    async fn the_hotspots_network_is_taken_before_its_access_point_starts_and_until_it_is_down() {
        let (hub, fake) = hub_with_fake(true, false);
        hub.start_hotspot().await.unwrap();
        assert_eq!(*lock(&fake.routed), Some(true), "a network of its own shares no internet through the system");
        let at_start = lock(&fake.at_start).clone().unwrap();
        assert_eq!(at_start.steered, [expected_steering()], "steered by its addresses, before the adapter exists");
        assert_eq!(at_start.held, [SteerKey::Hotspot], "and held to the device rules");
        assert!(at_start.tried, "steering was tried before the access point started");
        let net = lock(&hub.hotspot_net).clone().unwrap();
        assert_eq!(net.interface, "Local Area Connection* 2", "once up, as it runs");

        // Windows turns the access point off by itself: still taken for a
        // while, so its turning on again soon is caught from the first packet.
        fake.running.store(false, Ordering::SeqCst);
        let state = hub.backend().state().await.unwrap();
        hub.observe_hotspot(Hub::status_from_backend(&state, None)).await;
        assert_eq!(hub.hotspot_status().state, HotspotState::Stopped);
        assert_eq!(hub.desired_steerings().len(), 1);
        assert_eq!(hub.shared_networks().len(), 1);

        // Stopped from Captun: let go once the access point is down.
        hub.stop_hotspot().await.unwrap();
        assert!(hub.desired_steerings().is_empty());
        assert!(hub.shared_networks().is_empty());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn the_kill_switch_keeps_the_access_point_off_when_its_traffic_cannot_be_taken() {
        let (hub, fake) = hub_with_fake(true, true);
        let err = hub.start_hotspot().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::HotspotFailed);
        assert!(err.message.starts_with("The hotspot did not start"), "{}", err.message);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 0, "the access point never started");
        let status = hub.hotspot_status();
        assert_eq!(status.state, HotspotState::Failed);
        assert_eq!(status.error.as_deref(), Some(err.message.as_str()));
        assert!(lock(&hub.hotspot_net).is_none());
        assert!(hub.desired_steerings().is_empty());
        assert!(hub.shared_networks().is_empty());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn without_outbounds_the_hotspot_shares_through_the_system_and_starts_as_before() {
        let (hub, fake) = hub_with_fake(false, true);
        hub.start_hotspot().await.unwrap();
        assert_eq!(*lock(&fake.routed), Some(false));
        let at_start = lock(&fake.at_start).clone().unwrap();
        assert!(at_start.steered.is_empty() && at_start.held.is_empty() && !at_start.tried, "{at_start:?}");
        assert_eq!(hub.hotspot_status().state, HotspotState::Running);
        hub.stop_hotspot().await.unwrap();
    }

    // Only the hub's own state: nothing is steered or put in.
    #[tokio::test]
    async fn the_hotspots_network_is_kept_while_its_access_point_comes_and_goes() {
        if !capture::supports_transparent_routing() {
            return;
        }
        let (hub, fake) = hub_with_fake(true, false);
        assert!(hub.desired_steerings().is_empty(), "nothing before a start");

        // Before the access point starts: the network expected.
        if capture::steers_by_address() {
            assert!(hub.expect_hotspot_network(None));
            assert_eq!(hub.desired_steerings(), [expected_steering()]);
            assert_eq!(hub.shared_networks().len(), 1);
        } else {
            assert!(!hub.expect_hotspot_network(None), "steering needs the adapter's name, not known yet");
            assert!(hub.desired_steerings().is_empty());
        }

        // Running: the network as it runs, with its adapter.
        hub.set_hotspot_status(HotspotStatus {
            state: HotspotState::Running,
            interface: Some("wlan0".into()),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            ..HotspotStatus::default()
        });
        assert_eq!(hub.desired_steerings()[0].1.hotspot_interface, "wlan0");
        // A restart expects the same network: it keeps its adapter.
        assert!(!hub.expect_hotspot_network(None), "nothing new");
        assert_eq!(lock(&hub.hotspot_net).clone().unwrap().interface, "wlan0");

        // Starting, stopping or stopped: the status alone never lets go of it
        // (a stop does, or the monitor seeing it off, see the next test).
        for state in [HotspotState::Starting, HotspotState::Stopping, HotspotState::Stopped] {
            hub.set_hotspot_status(HotspotStatus { state, ..HotspotStatus::default() });
            assert_eq!(hub.desired_steerings().len(), 1, "{state:?}");
            assert_eq!(hub.shared_networks().len(), 1, "{state:?}");
        }

        // Let go only once the access point is down.
        hub.let_go_of_hotspot(&BackendState { running: true, ..BackendState::default() });
        assert!(lock(&hub.hotspot_net).is_some(), "still up");
        hub.let_go_of_hotspot(&BackendState { transitioning: true, ..BackendState::default() });
        assert!(lock(&hub.hotspot_net).is_some(), "still going down");
        hub.let_go_of_hotspot(&BackendState::default());
        assert!(hub.desired_steerings().is_empty());
        assert!(hub.shared_networks().is_empty());

        // The way that started was another, on a network of its own: that one.
        *lock(&fake.expected) = "198.51.100.0/24".parse().ok();
        assert!(hub.expect_hotspot_network(Some("Wi-Fi 2".into())));
        let net = lock(&hub.hotspot_net).clone().unwrap();
        assert_eq!((net.interface.as_str(), net.subnet.to_string(), net.gateway), ("Wi-Fi 2", "198.51.100.0/24".into(), Ipv4Addr::new(198, 51, 100, 1)));
    }

    // Only the hub's own state. Where the network is let go at once (Linux)
    // nothing is steered or put in for it on the way; on Windows the missing
    // packet driver makes steering fail without touching anything.
    #[tokio::test]
    async fn an_access_point_gone_off_by_itself_has_its_network_let_go() {
        let (hub, _fake) = hub_with_fake(true, false);
        hub.set_hotspot_status(HotspotStatus {
            state: HotspotState::Running,
            interface: Some("wlan0".into()),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            ..HotspotStatus::default()
        });
        // Up, or on its way on or off: held, however long, wherever.
        let much_later = Instant::now() + 10 * HOTSPOT_OFF_HOLD;
        for state in [HotspotState::Running, HotspotState::Starting, HotspotState::Stopping] {
            assert!(!hub.release_hotspot_if_off(state, much_later), "{state:?}");
            assert_eq!(hub.shared_networks().len(), 1, "{state:?}");
        }

        // The monitor sees it off (NetworkManager took the adapter back for
        // this computer's own Wi-Fi, or Windows' power saving turned it off).
        hub.observe_hotspot(HotspotStatus::default()).await;
        assert_eq!(hub.hotspot_status().state, HotspotState::Stopped);
        if capture::steers_by_address() {
            // Windows: held a while, so a turn-on soon after is taken from
            // its first packet...
            assert_eq!(hub.shared_networks().len(), 1);
            let seen_off = lock(&hub.hotspot_off_since).unwrap();
            assert!(!hub.release_hotspot_if_off(HotspotState::Stopped, seen_off + HOTSPOT_OFF_HOLD / 2));
            assert_eq!(hub.shared_networks().len(), 1, "within the hold");
            // ...but not for good: the monitor's first look after the hold
            // lets go.
            let Some(long_ago) = Instant::now().checked_sub(HOTSPOT_OFF_HOLD) else { return };
            *lock(&hub.hotspot_off_since) = Some(long_ago);
            hub.observe_hotspot(HotspotStatus::default()).await;
        }
        // Elsewhere at once: the rules name the adapter, which may be this
        // computer's own Wi-Fi again.
        assert!(lock(&hub.hotspot_net).is_none());
        assert!(hub.shared_networks().is_empty(), "no device rules");
        assert!(hub.desired_steerings().is_empty(), "no steering");
        assert!(lock(&hub.hotspot_off_since).is_none());
        if capture::supports_transparent_routing() {
            assert_eq!(hub.routing_status().state, RoutingState::Waiting, "nothing taken any more");
        }
    }

    #[test]
    fn turning_outbounds_off_restarts_only_a_hotspot_that_runs_its_own_network() {
        let direct = Config::default();
        let mut routed = direct.clone();
        routed.network.transparent_routing = true;
        assert!(!access_point_restarts(&routed, &direct, true), "Mobile hotspot and NetworkManager share all along");
        assert_eq!(
            access_point_restarts(&routed, &direct, false),
            capture::supports_transparent_routing(),
            "a network of its own starts again to share through the system"
        );
        assert!(!access_point_restarts(&direct, &routed, false), "turning them on waits for the next start");
        assert!(!access_point_restarts(&routed, &routed, false), "nothing changed");
        let mut renamed = routed.clone();
        renamed.hotspot.ssid = "Elsewhere".into();
        assert!(access_point_restarts(&routed, &renamed, true), "the access point's own settings");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn turning_outbounds_off_restarts_a_running_hotspot_only_when_it_runs_its_own_network() {
        for own_network in [false, true] {
            let (hub, fake) = hub_with_fake(true, false);
            fake.own_network.store(own_network, Ordering::SeqCst);
            hub.start_hotspot().await.unwrap();
            let mut config = (*hub.config()).clone();
            config.network.transparent_routing = false;
            hub.set_config(config).await.unwrap();
            // A restart runs on a task of its own.
            for _ in 0..50 {
                if fake.starts.load(Ordering::SeqCst) > 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let starts = fake.starts.load(Ordering::SeqCst);
            assert_eq!(starts, if own_network { 2 } else { 1 }, "own network: {own_network}");
            if own_network {
                assert_eq!(*lock(&fake.routed), Some(false), "it shares through the system again");
            }
            hub.stop_hotspot().await.unwrap();
        }
    }

    #[tokio::test]
    async fn speeds_are_read_for_a_connected_gui_and_shown_without_moving_them() {
        let (hub, _fake) = hub_with_fake(false, false);
        let (device, quiet) = (nth(5), nth(6));
        lock(&hub.registry).apply_snapshot(&[seen(device, Some("10.0.0.5")), seen(quiet, Some("10.0.0.6"))], hub.now_ms());
        // `quiet` never had traffic: no counters, so it is left out.
        let _counters = hub.meter.counters(Some(device));
        let start = Instant::now();
        assert!(hub.read_traffic(start).is_none(), "no GUI connected");

        let gui = hub.subscribe();
        let report = hub.read_traffic(start).unwrap();
        assert_eq!(report.iter().map(|d| d.mac).collect::<Vec<_>>(), [device]);
        assert!(hub.read_traffic(start + Duration::from_secs(1)).is_none(), "nothing changed");
        // The device list shows the last reading's speeds, and reads only.
        let views = hub.client_views();
        assert!(views.iter().all(|v| v.traffic == TrafficStats::default()));
        assert!(hub.read_traffic(start + Duration::from_secs(2)).is_none(), "still the same reading");

        // Gone offline: left out.
        lock(&hub.registry).apply_snapshot(&[], hub.now_ms());
        assert_eq!(hub.read_traffic(start + Duration::from_secs(3)), Some(Vec::new()));
        // The GUI went: nothing read, and the next reading starts afresh.
        drop(gui);
        assert!(hub.read_traffic(start + Duration::from_secs(4)).is_none());
        assert!(lock(&hub.speeds).rates().is_empty());
    }

    #[tokio::test]
    async fn xray_coming_and_going_ends_no_working_connection() {
        use crate::engine_glue::test_flows::{Open, echo_server};

        let (hub, _events) = hub(None);
        let echo = echo_server().await;
        let mut working = Open::new(&hub, "02:00:00:00:00:01".parse().unwrap(), true, echo).await;
        // One the open flows' check no longer lets through, as a UDP flow
        // refused while Xray's outbounds stood unavailable.
        let mut refused = Open::new(&hub, "02:00:00:00:00:02".parse().unwrap(), false, echo).await;
        hub.xray_changed();
        assert!(working.goes_on().await, "Xray coming up ended a working connection");
        assert!(!refused.goes_on().await, "the open flows were not checked again");
        hub.xray_changed();
        assert!(working.goes_on().await, "Xray going down again ended a working connection");
    }

    #[tokio::test]
    async fn dns_to_the_hotspot_address_is_answered_without_a_socket_there() {
        let (hub, _events) = hub(None);
        hub.set_config(Config::default()).await.unwrap();
        // An address this computer does not have: no socket can be opened, as
        // when Windows' Internet Connection Sharing holds the hotspot address.
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        hub.start_dns(gateway).await;
        let at = |s: &str| hub.local_dns_for(&s.parse().unwrap()).is_some();
        assert!(at("192.0.2.1:53"));
        assert!(!at("192.0.2.1:80"), "only DNS");
        // "Make devices use it" catches lookups sent to any server.
        assert!(at("8.8.8.8:53"));
        let mut config = (*hub.config()).clone();
        config.dns.enforce = false;
        hub.set_config(config).await.unwrap();
        assert!(!at("8.8.8.8:53"));
        assert!(at("192.0.2.1:53"));
        hub.stop_dns();
        assert!(!at("192.0.2.1:53"));
    }

    fn seen(mac: MacAddr, ip: Option<&str>) -> ObservedClient {
        ObservedClient { mac, addrs: ip.map(|ip| vec![ip.parse().unwrap()]).unwrap_or_default(), hostname: None }
    }

    fn nth(n: u32) -> MacAddr {
        let b = n.to_be_bytes();
        MacAddr::new([2, 0, b[0], b[1], b[2], b[3]])
    }

    #[test]
    fn the_gui_gets_online_and_saved_devices_and_the_offline_seen_last() {
        let mut registry = ClientRegistry::new();
        // Devices 0..20 each come and go, one a millisecond; 100 stays.
        for n in 0..20 {
            registry.apply_snapshot(&[seen(nth(n), None)], u64::from(n));
        }
        registry.apply_snapshot(&[seen(nth(100), Some("10.0.0.2"))], 50);
        let saved = nth(0);
        let shown = shown_presences(&registry, |mac| *mac == saved, 5);
        let macs: HashSet<MacAddr> = shown.iter().map(|p| p.mac).collect();
        assert_eq!(macs.len(), 7, "{macs:?}");
        assert!(macs.contains(&nth(100)), "online");
        assert!(macs.contains(&saved), "saved, though seen first of all");
        for n in 15..20 {
            assert!(macs.contains(&nth(n)), "device {n} was among the five seen last");
        }
        assert_eq!(shown_presences(&registry, |_| false, 0).len(), 1, "online only");
        assert_eq!(shown_presences(&registry, |_| false, 500).len(), 21, "all of them");
    }

    #[tokio::test]
    async fn devices_offline_for_long_with_nothing_saved_are_forgotten() {
        let (hub, _events) = hub(None);
        hub.set_client_profile(profile("Tablet")).await.unwrap();
        let (named, stranger) = ("02:00:00:00:00:07".parse().unwrap(), nth(1));
        let two_days_ago = hub.now_ms() - 2 * captun_core::client::OFFLINE_RETENTION_MS;
        lock(&hub.registry).apply_snapshot(&[seen(named, None), seen(stranger, None)], two_days_ago);
        lock(&hub.registry).apply_snapshot(&[], two_days_ago + 1);
        let _counters = hub.meter.counters(Some(stranger));

        assert!(hub.prune_devices());
        assert!(lock(&hub.registry).get(&stranger).is_none());
        assert!(hub.meter.snapshot(&stranger).is_none(), "its counters went too");
        assert!(lock(&hub.registry).get(&named).is_some(), "a device with saved settings stays");
        assert!(!hub.prune_devices(), "nothing more to forget");
        assert_eq!(hub.client_views().len(), 1);
    }

    #[tokio::test]
    async fn the_device_list_is_built_only_for_a_connected_gui() {
        let (events, _) = broadcast::channel(16);
        let hub = Hub::new(None, Config::default(), captun_platform::default_backend(), events, None);
        // Nobody listening: nothing is built or sent, and nothing fails.
        hub.broadcast_clients();
        let mut gui = hub.subscribe();
        hub.broadcast_clients();
        assert!(matches!(gui.try_recv(), Ok(Event::Clients(_))));
    }

    #[tokio::test]
    async fn a_config_file_is_written_on_every_change() {
        let dir = std::env::temp_dir().join(format!("captun-hub-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join("captun.toml");
        let (hub, _events) = hub(Some(file.clone()));
        assert!(!hub.awaiting_settings.load(Ordering::SeqCst));
        hub.set_client_profile(profile("Laptop")).await.unwrap();
        let saved = Config::load_or_default(&file).unwrap();
        assert_eq!(saved.clients[0].alias.as_deref(), Some("Laptop"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_usb_driver_notice_follows_what_is_plugged_in_and_what_was_done() {
        use captun_usbdriver::Detection;
        let missing = Detection::Missing(vec![r"USB\VID_18D1&PID_4EE7&MI_01\6&1".into()]);
        let installed = UsbDriverFix::Installed(captun_usbdriver::INSTALLED_NOTICE);
        let failed = UsbDriverFix::Failed("Install the phone maker's driver.".into());
        let every = [UsbDriverFix::NotTried, UsbDriverFix::Installing, installed.clone(), failed.clone()];
        // No phone, phones with a driver (whatever else keeps them from being
        // ready), or one Windows is still setting up: listed as they are,
        // whatever the driver did before.
        for detected in [Detection::None, Detection::Working, Detection::BeingSetUp] {
            for fix in &every {
                assert_eq!(usb_driver_advice(&detected, fix), PhoneDriver::Nothing, "{detected:?} after {fix:?}");
            }
        }
        // A phone still without a driver: what the driver is up to.
        assert_eq!(usb_driver_advice(&missing, &UsbDriverFix::NotTried), PhoneDriver::Nothing);
        assert_eq!(usb_driver_advice(&missing, &UsbDriverFix::Installing), PhoneDriver::Installing);
        assert_eq!(usb_driver_advice(&missing, &installed), PhoneDriver::Installed(captun_usbdriver::INSTALLED_NOTICE));
        assert_eq!(
            usb_driver_advice(&missing, &failed),
            PhoneDriver::Failed("Install the phone maker's driver.".into())
        );
    }

    #[test]
    fn the_driver_news_comes_instead_of_the_phone_list() {
        let phone = AdbDeviceInfo {
            serial: "18d1:4ee7".into(),
            label: "18d1:4ee7".into(),
            state: "no_permissions".into(),
            model: None,
            ready: false,
        };
        assert_eq!(
            usb_driver_listing(vec![phone.clone()], PhoneDriver::Nothing).unwrap(),
            std::slice::from_ref(&phone)
        );
        let installing = usb_driver_listing(vec![phone.clone()], PhoneDriver::Installing).unwrap_err();
        assert_eq!(
            (installing.code, installing.message.as_str()),
            (ErrorCode::BadRequest, captun_usbdriver::INSTALLING_NOTICE)
        );
        let installed =
            usb_driver_listing(vec![phone.clone()], PhoneDriver::Installed(captun_usbdriver::INSTALLED_NOTICE));
        assert_eq!(installed.unwrap_err().message, captun_usbdriver::INSTALLED_NOTICE);
        let failed = usb_driver_listing(vec![phone], PhoneDriver::Failed("Install the maker's driver.".into()));
        let failed = failed.unwrap_err();
        assert_eq!((failed.code, failed.message.as_str()), (ErrorCode::Unsupported, "Install the maker's driver."));
    }

    mod usb_driver {
        use std::sync::atomic::AtomicUsize;

        use captun_usbdriver::{Detection, DriverError, Install, Phones};

        use super::*;

        fn missing() -> Result<Detection, DriverError> {
            Ok(Detection::Missing(vec![r"USB\VID_18D1&PID_4EE7&MI_01\6&1".into()]))
        }

        fn working() -> Result<Detection, DriverError> {
            Ok(Detection::Working)
        }

        fn hub_with(calls: UsbDriverCalls) -> Arc<Hub> {
            let (hub, _events) = hub(None);
            lock(&hub.tether).usb_driver_calls = calls;
            hub
        }

        /// What the background install came to, once it has finished.
        async fn finished(hub: &Hub) -> UsbDriverFix {
            for _ in 0..1000 {
                let fix = lock(&hub.tether).usb_driver.clone();
                if fix != UsbDriverFix::Installing {
                    return fix;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("the install did not finish");
        }

        #[tokio::test]
        async fn a_phone_without_a_driver_has_it_installed_once_in_the_background() {
            static INSTALLS: AtomicUsize = AtomicUsize::new(0);
            static GO_ON: AtomicBool = AtomicBool::new(false);
            fn install() -> Result<Install, DriverError> {
                INSTALLS.fetch_add(1, Ordering::SeqCst);
                while !GO_ON.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(Install::Installed(Phones { given: 0, failed: 1, restart: false }))
            }
            let hub = hub_with(UsbDriverCalls { detect: missing, install });
            assert_eq!(lock(&hub.tether).usb_driver, UsbDriverFix::NotTried);
            // The listing that finds it starts the install and answers at
            // once; listings while it runs say the same and start no other.
            assert_eq!(hub.phone_usb_driver().await, PhoneDriver::Installing);
            assert_eq!(hub.phone_usb_driver().await, PhoneDriver::Installing);
            GO_ON.store(true, Ordering::SeqCst);
            assert_eq!(finished(&hub).await, UsbDriverFix::Installed(captun_usbdriver::INSTALLED_NOTICE));
            // The phone still has none: plug it in again.
            assert_eq!(hub.phone_usb_driver().await, PhoneDriver::Installed(captun_usbdriver::INSTALLED_NOTICE));
            // Once it has one, it is listed as it is.
            lock(&hub.tether).usb_driver_calls.detect = working;
            assert_eq!(hub.phone_usb_driver().await, PhoneDriver::Nothing);
            // A phone without a driver later in the run starts no other.
            lock(&hub.tether).usb_driver_calls.detect = missing;
            assert_eq!(hub.phone_usb_driver().await, PhoneDriver::Installed(captun_usbdriver::INSTALLED_NOTICE));
            assert_eq!(INSTALLS.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn a_failed_install_says_what_to_do_and_is_not_tried_again() {
            static INSTALLS: AtomicUsize = AtomicUsize::new(0);
            fn install() -> Result<Install, DriverError> {
                INSTALLS.fetch_add(1, Ordering::SeqCst);
                Err(DriverError::Failed { step: "signing the driver", source: std::io::Error::other("no room") })
            }
            let hub = hub_with(UsbDriverCalls { detect: missing, install });
            assert_eq!(hub.phone_usb_driver().await, PhoneDriver::Installing);
            let UsbDriverFix::Failed(advice) = finished(&hub).await else { panic!("the install should have failed") };
            assert!(
                advice.starts_with("Captun could not install the USB driver for Android phones: signing the driver")
            );
            assert_eq!(hub.phone_usb_driver().await, PhoneDriver::Failed(advice.clone()));
            assert_eq!(hub.phone_usb_driver().await, PhoneDriver::Failed(advice));
            assert_eq!(INSTALLS.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn only_a_phone_without_a_driver_starts_an_install() {
            static INSTALLS: AtomicUsize = AtomicUsize::new(0);
            fn install() -> Result<Install, DriverError> {
                INSTALLS.fetch_add(1, Ordering::SeqCst);
                Ok(Install::NotNeeded)
            }
            fn none() -> Result<Detection, DriverError> {
                Ok(Detection::None)
            }
            fn being_set_up() -> Result<Detection, DriverError> {
                Ok(Detection::BeingSetUp)
            }
            fn cannot_tell() -> Result<Detection, DriverError> {
                Err(DriverError::Failed {
                    step: "looking for phones without a driver",
                    source: std::io::Error::other("no"),
                })
            }
            let hub = hub_with(UsbDriverCalls { detect: none, install });
            for detect in [none, working, being_set_up, cannot_tell] {
                lock(&hub.tether).usb_driver_calls.detect = detect;
                assert_eq!(hub.phone_usb_driver().await, PhoneDriver::Nothing);
                assert_eq!(lock(&hub.tether).usb_driver, UsbDriverFix::NotTried);
            }
            assert_eq!(INSTALLS.load(Ordering::SeqCst), 0);
        }
    }
}
