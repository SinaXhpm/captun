use std::{net::IpAddr, sync::Mutex};

use async_trait::async_trait;
use ipnet::Ipv4Net;
use captun_core::{ObservedClient, config::HotspotConfig};
use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum HotspotError {
    #[error("hotspot is not supported on this platform: {0}")]
    Unsupported(String),
    #[error("hotspot configuration rejected: {0}")]
    InvalidConfig(String),
    /// This way of hosting cannot work on this computer (no capable driver,
    /// nothing to share, missing tool); another way might.
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Failed(String),
}

/// What the OS reports about the access point right now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackendState {
    pub running: bool,
    /// The OS is still switching the AP on or off.
    pub transitioning: bool,
    pub ssid: Option<String>,
    pub interface: Option<String>,
    pub gateway: Option<IpAddr>,
    pub max_clients: Option<u32>,
}

/// Static facts about a backend that the GUI shows to explain limitations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlatformNotes {
    pub hotspot: bool,
    pub band_selection: bool,
    pub notes: Vec<String>,
}

/// How to bring the access point up, beyond its radio settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartOptions {
    /// Stations must not reach each other. Enforced by the access point itself:
    /// frames between stations of one BSS are bridged by the Wi-Fi stack and
    /// never reach the host firewall.
    pub isolate_clients: bool,
    /// Captun's resolver answers on the gateway, so backends that run their
    /// own DHCP hand the gateway out as DNS.
    pub dns_on_gateway: bool,
}

#[async_trait]
pub trait HotspotBackend: Send + Sync + std::fmt::Debug {
    fn notes(&self) -> PlatformNotes;

    /// Applies SSID/passphrase/band and brings the access point up,
    /// restarting it if it was already running with other settings.
    async fn start(&self, config: &HotspotConfig, options: StartOptions) -> Result<BackendState, HotspotError>;

    async fn stop(&self) -> Result<(), HotspotError>;

    async fn state(&self) -> Result<BackendState, HotspotError>;

    /// Stations currently associated with the access point.
    async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError>;

    /// The devices' network as far as it is known before the access point
    /// starts (Windows Mobile hotspot: 192.168.137.0/24; the networks Captun
    /// runs itself: 10.74.0.0/24), so it can be prepared for before the
    /// adapter has its address. `None` when only the running hotspot can tell.
    fn expected_network(&self) -> Option<Ipv4Net> {
        None
    }

    /// Whether Captun's routing engine carries the devices' traffic. Backends
    /// that run their own network then share no internet through the system,
    /// as cable sharing does, so traffic is not shared twice. Read at the next
    /// start; off until told.
    fn set_engine_routed(&self, _routed: bool) {}

    /// Whether the system shares the internet with this hotspot's devices by
    /// itself, whatever [`Self::set_engine_routed`] said (Windows Mobile
    /// hotspot, NetworkManager, macOS Internet Sharing). A network Captun
    /// runs itself shares only as told at its start, so one started while
    /// the engine carried its traffic must start again to share once the
    /// engine stops. Asks the way running, or else the one tried first.
    fn shares_through_system(&self) -> bool {
        true
    }
}

/// Placeholder for platforms without a backend yet.
#[derive(Debug)]
pub struct Unsupported;

#[async_trait]
impl HotspotBackend for Unsupported {
    fn notes(&self) -> PlatformNotes {
        PlatformNotes {
            hotspot: false,
            band_selection: false,
            notes: vec!["This platform has no hotspot backend yet.".into()],
        }
    }

    async fn start(&self, _config: &HotspotConfig, _options: StartOptions) -> Result<BackendState, HotspotError> {
        Err(HotspotError::Unsupported(std::env::consts::OS.into()))
    }

    async fn stop(&self) -> Result<(), HotspotError> {
        Ok(())
    }

    async fn state(&self) -> Result<BackendState, HotspotError> {
        Ok(BackendState::default())
    }

    async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError> {
        Ok(Vec::new())
    }
}

// The fallback chain is for systems where Captun hosts the hotspot itself
// (Windows, Linux); macOS only observes its own Internet Sharing.
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Active {
    Primary,
    Secondary,
}

/// Hosts with the OS's own hotspot when it can and falls back to a second way
/// (one Captun runs DHCP and NAT for) when the first reports `Unavailable`,
/// so adapters the OS feature refuses still work. Wi-Fi is switched on first.
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct FallbackHotspot {
    primary: Box<dyn HotspotBackend>,
    secondary: Box<dyn HotspotBackend>,
    /// Labels for messages, e.g. "Windows Mobile hotspot".
    names: (&'static str, &'static str),
    /// Switch Wi-Fi on before starting (off in tests, which must never touch
    /// the machine's adapters).
    prepare_wifi: bool,
    active: Mutex<Option<Active>>,
}

#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
impl FallbackHotspot {
    pub(crate) fn new(
        primary: Box<dyn HotspotBackend>,
        secondary: Box<dyn HotspotBackend>,
        names: (&'static str, &'static str),
    ) -> Self {
        Self { primary, secondary, names, prepare_wifi: true, active: Mutex::new(None) }
    }

    fn active(&self) -> Option<Active> {
        *self.active.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_active(&self, active: Option<Active>) {
        *self.active.lock().unwrap_or_else(|e| e.into_inner()) = active;
    }

    fn backend(&self, which: Active) -> &dyn HotspotBackend {
        match which {
            Active::Primary => self.primary.as_ref(),
            Active::Secondary => self.secondary.as_ref(),
        }
    }
}

#[async_trait]
impl HotspotBackend for FallbackHotspot {
    fn notes(&self) -> PlatformNotes {
        let primary = self.primary.notes();
        let mut notes = primary.notes;
        notes.push(format!(
            "When {} cannot run on this computer, Captun falls back to {} and hands out addresses itself.",
            self.names.0, self.names.1
        ));
        PlatformNotes { hotspot: primary.hotspot, band_selection: primary.band_selection, notes }
    }

    async fn start(&self, config: &HotspotConfig, options: StartOptions) -> Result<BackendState, HotspotError> {
        check_config(config)?;
        if self.prepare_wifi {
            for done in crate::wifi::prepare().await {
                info!("{done}");
            }
        }
        // Switching ways leaves no half-running access point behind.
        if self.active() == Some(Active::Secondary) {
            let _ = self.secondary.stop().await;
        }
        let first = match self.primary.start(config, options).await {
            Ok(state) => {
                self.set_active(Some(Active::Primary));
                return Ok(state);
            }
            Err(HotspotError::Unavailable(reason)) => reason,
            Err(e) => return Err(e),
        };
        warn!("{} unavailable ({first}); trying {}", self.names.0, self.names.1);
        match self.secondary.start(config, options).await {
            Ok(state) => {
                self.set_active(Some(Active::Secondary));
                Ok(state)
            }
            Err(HotspotError::Unavailable(second) | HotspotError::Failed(second)) => {
                self.set_active(None);
                Err(HotspotError::Failed(format!(
                    "{}: {first}. {}: {second}. If this Wi-Fi adapter cannot host a hotspot at all, a USB Wi-Fi adapter that supports access-point mode will work.",
                    self.names.0, self.names.1
                )))
            }
            Err(e) => {
                self.set_active(None);
                Err(e)
            }
        }
    }

    async fn stop(&self) -> Result<(), HotspotError> {
        let result = match self.active() {
            Some(which) => self.backend(which).stop().await,
            // Started by an earlier run: stop whichever is up.
            None => {
                let _ = self.secondary.stop().await;
                self.primary.stop().await
            }
        };
        self.set_active(None);
        result
    }

    async fn state(&self) -> Result<BackendState, HotspotError> {
        match self.active() {
            Some(which) => self.backend(which).state().await,
            None => match self.primary.state().await {
                Ok(state) if state.running || state.transitioning => Ok(state),
                // The OS feature may not even be queryable here (no connection to
                // share); that only means it is not running.
                _ => Ok(self.secondary.state().await.unwrap_or_default()),
            },
        }
    }

    async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError> {
        match self.active() {
            Some(which) => self.backend(which).clients().await,
            None => match self.primary.clients().await {
                Err(HotspotError::Unavailable(_)) => Ok(Vec::new()),
                other => other,
            },
        }
    }

    /// The running way's network; before a start, the first way's, which is
    /// tried first. After a fallback it is the second way's.
    fn expected_network(&self) -> Option<Ipv4Net> {
        self.backend(self.active().unwrap_or(Active::Primary)).expected_network()
    }

    fn set_engine_routed(&self, routed: bool) {
        self.primary.set_engine_routed(routed);
        self.secondary.set_engine_routed(routed);
    }

    fn shares_through_system(&self) -> bool {
        self.backend(self.active().unwrap_or(Active::Primary)).shares_through_system()
    }
}

/// Whether this computer can host a Wi-Fi hotspot, and if not, why. Needs no
/// privileges, so the GUI asks before the service even runs.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct HotspotSupport {
    pub supported: bool,
    /// Why not, when not supported.
    pub reason: Option<String>,
    /// Something Start takes care of first, such as switching Wi-Fi on.
    pub notice: Option<String>,
}

/// Only a computer without any Wi-Fi hardware is turned away: a disabled
/// adapter or one the OS hotspot feature refuses can still be used, because
/// Start enables it and Captun falls back to hosting by itself.
pub fn hotspot_support() -> HotspotSupport {
    #[cfg(target_os = "macos")]
    return HotspotSupport { supported: false, reason: Some(crate::macos::HOW_TO_SHARE.into()), notice: None };
    #[cfg(not(target_os = "macos"))]
    wifi_support()
}

#[cfg(not(target_os = "macos"))]
fn wifi_support() -> HotspotSupport {
    let no = |reason: &str| HotspotSupport { supported: false, reason: Some(reason.into()), notice: None };
    if !cfg!(any(windows, target_os = "linux")) {
        return no("Captun cannot host a hotspot on this system yet.");
    }
    let adapters = crate::wifi::adapters();
    if adapters.is_empty() {
        return no("This computer has no Wi-Fi adapter. Plug in a USB Wi-Fi adapter to host a hotspot.");
    }
    if let Some(reason) = crate::wifi::missing_tools() {
        return no(&reason);
    }
    let notice = if adapters.iter().all(|a| !a.enabled) {
        let name = &adapters[0].name;
        let what = if ["wi-fi", "wifi", "wlan"].iter().any(|n| name.eq_ignore_ascii_case(n)) {
            "Wi-Fi".to_owned()
        } else {
            format!("The Wi-Fi adapter ({name})")
        };
        Some(format!("{what} is turned off on this computer. Start turns it on."))
    } else {
        crate::wifi::os_hotspot_blocker().map(|why| format!("{why} Captun will host the hotspot itself instead."))
    };
    HotspotSupport { supported: true, reason: None, notice }
}

/// Shared pre-flight check so every backend rejects the same inputs.
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
pub(crate) fn check_config(config: &HotspotConfig) -> Result<(), HotspotError> {
    use captun_core::config::{validate_passphrase, validate_ssid};
    if config.passphrase.is_empty() {
        return Err(HotspotError::InvalidConfig("set a hotspot password first".into()));
    }
    validate_ssid(&config.ssid).map_err(HotspotError::InvalidConfig)?;
    validate_passphrase(config.passphrase.expose()).map_err(HotspotError::InvalidConfig)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Debug)]
    struct Fake {
        result: fn() -> Result<BackendState, HotspotError>,
        starts: AtomicUsize,
        network: Option<Ipv4Net>,
        routed: Arc<AtomicBool>,
        /// Runs a network of its own, as the hosted network and hostapd do.
        own_network: bool,
    }

    impl Fake {
        fn boxed(result: fn() -> Result<BackendState, HotspotError>) -> Box<Self> {
            Box::new(Self { result, starts: AtomicUsize::new(0), network: None, routed: Arc::default(), own_network: false })
        }
    }

    #[async_trait]
    impl HotspotBackend for Fake {
        fn notes(&self) -> PlatformNotes {
            PlatformNotes { hotspot: true, ..Default::default() }
        }
        async fn start(&self, _: &HotspotConfig, _: StartOptions) -> Result<BackendState, HotspotError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            (self.result)()
        }
        async fn stop(&self) -> Result<(), HotspotError> {
            Ok(())
        }
        async fn state(&self) -> Result<BackendState, HotspotError> {
            Ok(BackendState::default())
        }
        async fn clients(&self) -> Result<Vec<ObservedClient>, HotspotError> {
            Ok(Vec::new())
        }
        fn expected_network(&self) -> Option<Ipv4Net> {
            self.network
        }
        fn set_engine_routed(&self, routed: bool) {
            self.routed.store(routed, Ordering::SeqCst);
        }
        fn shares_through_system(&self) -> bool {
            !self.own_network
        }
    }

    fn up() -> Result<BackendState, HotspotError> {
        Ok(BackendState { running: true, ..Default::default() })
    }
    fn unavailable() -> Result<BackendState, HotspotError> {
        Err(HotspotError::Unavailable("no driver support".into()))
    }
    fn bad_band() -> Result<BackendState, HotspotError> {
        Err(HotspotError::InvalidConfig("band".into()))
    }

    fn config() -> HotspotConfig {
        HotspotConfig { passphrase: "long enough".into(), ..HotspotConfig::default() }
    }

    fn chain(
        primary: fn() -> Result<BackendState, HotspotError>,
        secondary: fn() -> Result<BackendState, HotspotError>,
        names: (&'static str, &'static str),
    ) -> FallbackHotspot {
        FallbackHotspot { prepare_wifi: false, ..FallbackHotspot::new(Fake::boxed(primary), Fake::boxed(secondary), names) }
    }

    #[tokio::test]
    async fn falls_back_only_when_the_first_way_is_unavailable() {
        let both = chain(unavailable, up, ("A", "B"));
        assert!(both.start(&config(), StartOptions::default()).await.unwrap().running);
        assert_eq!(both.active(), Some(Active::Secondary));

        // A settings problem is the user's to fix; trying another way would hide it.
        let both = chain(bad_band, up, ("A", "B"));
        assert!(matches!(both.start(&config(), StartOptions::default()).await, Err(HotspotError::InvalidConfig(_))));
        assert_eq!(both.active(), None);
    }

    #[tokio::test]
    async fn both_failing_explains_both() {
        let chain = chain(unavailable, unavailable, ("Mobile hotspot", "Hosted network"));
        let Err(HotspotError::Failed(message)) = chain.start(&config(), StartOptions::default()).await else {
            panic!("expected a failure");
        };
        assert!(message.contains("Mobile hotspot: no driver support"), "{message}");
        assert!(message.contains("Hosted network: no driver support"), "{message}");
    }

    #[tokio::test]
    async fn bad_settings_are_refused_before_touching_wifi() {
        let chain = chain(up, up, ("A", "B"));
        let empty = HotspotConfig::default();
        assert!(matches!(chain.start(&empty, StartOptions::default()).await, Err(HotspotError::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn the_network_is_the_way_that_runs_and_routing_reaches_both() {
        let net = |s: &str| Some(s.parse::<Ipv4Net>().unwrap());
        let (first, second) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let fake = |result, network, routed: &Arc<AtomicBool>, own_network| {
            Box::new(Fake { result, starts: AtomicUsize::new(0), network, routed: Arc::clone(routed), own_network })
        };
        let chain = FallbackHotspot {
            prepare_wifi: false,
            ..FallbackHotspot::new(
                fake(unavailable, net("192.168.137.0/24"), &first, false),
                fake(up, net("10.74.0.0/24"), &second, true),
                ("A", "B"),
            )
        };
        assert_eq!(chain.expected_network(), net("192.168.137.0/24"), "before a start: the way tried first");
        assert!(chain.shares_through_system(), "the way tried first shares through the system");
        chain.set_engine_routed(true);
        assert!(first.load(Ordering::SeqCst) && second.load(Ordering::SeqCst));
        chain.start(&config(), StartOptions::default()).await.unwrap();
        assert_eq!(chain.expected_network(), net("10.74.0.0/24"), "after falling back");
        assert!(!chain.shares_through_system(), "the way running runs a network of its own");
        assert_eq!(Unsupported.expected_network(), None);
        assert!(Unsupported.shares_through_system());
    }
}
