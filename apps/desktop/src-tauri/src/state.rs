use std::{
    collections::VecDeque,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use captun_core::{Config, config::ConfigError};
use captun_ipc::{
    CallError, DnsQueryBatch, DnsQueryLog, Endpoint, Event, IpcClient, Request, Response, Token, TokenError,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::{RwLock, mpsc};

use crate::{
    error::{CommandError, NOT_THE_SERVICE},
    paths,
    settings::{Loaded, Settings},
};

const RECONNECT_INTERVAL: Duration = Duration::from_secs(2);

const NOT_RUNNING: &str = "The Captun service is not running.";
const OLDER_SERVICE_STOPPING: &str =
    "An older Captun service is running. Captun is stopping it so the new one can start.";
const OLDER_SERVICE_STOPPED: &str = "An older Captun service was running. It was stopped so the new one can start.";
const OLDER_SERVICE_KEPT: &str =
    "An older Captun service is running and did not stop when asked. Restart the computer, then press Start.";

/// Which run of an older service was asked to stop (by its token: each run
/// writes a new one), and how that went.
type OlderServiceAsked = Mutex<Option<(Token, &'static str)>>;

/// Pushed to the webview as the `connection` event whenever it changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ConnectionStatus {
    pub(crate) connected: bool,
    pub(crate) service_version: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) token_path: String,
    pub(crate) endpoint: String,
    /// Where the settings are saved (encrypted).
    pub(crate) settings_path: String,
    /// Settings changed while the service was off and not handed over yet.
    pub(crate) config_pending: bool,
    /// Why the service refused the saved settings, if it did.
    pub(crate) config_sync_error: Option<String>,
    /// Why saved settings could not be opened when Captun started, if so.
    pub(crate) settings_notice: Option<String>,
    /// Why the settings OmniHub (Captun's earlier name) saved could not be
    /// brought over when Captun started with none of its own, if so.
    pub(crate) earlier_settings_notice: Option<String>,
    /// Something about the service to show on screen while not connected:
    /// an older service is being or was stopped (which turned its sharing
    /// off), or another program answered in its place. Unlike `error`, never
    /// just "not running"; cleared once connected.
    pub(crate) service_notice: Option<String>,
}

/// The single service connection shared by all commands, and the saved
/// settings. A background loop owns (re)connecting; commands only borrow the
/// current client.
///
/// The GUI keeps the settings: the service holds them in memory only, is
/// handed the saved ones whenever it (re)connects, and every change it
/// accepts is saved here.
pub(crate) struct AppState {
    client: RwLock<Option<Arc<IpcClient>>>,
    status: Mutex<ConnectionStatus>,
    endpoint: Endpoint,
    token_path: PathBuf,
    settings: Settings,
    /// What is saved now (`None` until something is). Held across a save, so
    /// saves land in the order they were made.
    saved: tokio::sync::Mutex<Option<Config>>,
    older_service: OlderServiceAsked,
}

impl AppState {
    pub(crate) fn new() -> Self {
        let endpoint = Endpoint::default_service();
        let token_path = paths::token_path();
        let settings = Settings::new();
        let (saved, notice, earlier_notice) = match settings.load() {
            Loaded::Saved(config) => (Some(*config), None, None),
            Loaded::Missing => (None, None, None),
            Loaded::Unreadable(why) => (None, Some(why), None),
            Loaded::NotTakenOver(why) => (None, None, Some(why)),
        };
        let status = ConnectionStatus {
            connected: false,
            service_version: None,
            error: None,
            token_path: token_path.display().to_string(),
            endpoint: endpoint.as_str().to_owned(),
            settings_path: settings.location().display().to_string(),
            config_pending: false,
            config_sync_error: None,
            settings_notice: notice,
            earlier_settings_notice: earlier_notice,
            service_notice: None,
        };
        Self {
            client: RwLock::new(None),
            status: Mutex::new(status),
            endpoint,
            token_path,
            settings,
            saved: tokio::sync::Mutex::new(saved),
            older_service: Mutex::new(None),
        }
    }

    pub(crate) fn token_path(&self) -> &Path {
        &self.token_path
    }

    /// The saved settings, or defaults when nothing has been saved yet.
    pub(crate) async fn saved_or_default(&self) -> Config {
        self.saved.lock().await.clone().unwrap_or_default()
    }

    /// Whether the saved settings were refused by the service and wait to be
    /// fixed; until then they, not the service's copy, are what to show.
    pub(crate) fn sync_failed(&self) -> bool {
        self.lock_status().config_sync_error.is_some()
    }

    /// Saves `config` unless that is what is saved already.
    fn persist(&self, saved: &mut Option<Config>, config: &Config) -> Result<(), ConfigError> {
        if saved.as_ref() != Some(config) {
            self.settings.save(config)?;
            *saved = Some(config.clone());
        }
        Ok(())
    }

    /// Saves edits made while the service is off; it gets them when it starts.
    pub(crate) async fn save_offline(&self, app: &AppHandle, config: &Config) -> Result<(), ConfigError> {
        self.persist(&mut *self.saved.lock().await, config)?;
        self.update_status(app, |s| {
            s.config_pending = true;
            s.settings_notice = None;
            s.earlier_settings_notice = None;
        });
        Ok(())
    }

    /// Saves settings the service has just accepted.
    pub(crate) async fn save_accepted(&self, app: &AppHandle, config: &Config) -> Result<(), ConfigError> {
        self.persist(&mut *self.saved.lock().await, config)?;
        self.update_status(app, |s| {
            s.config_pending = false;
            s.config_sync_error = None;
            s.settings_notice = None;
            s.earlier_settings_notice = None;
        });
        Ok(())
    }

    /// Saves the service's settings after it changed them itself (a device's
    /// profile, a phone it added). Skipped while the saved settings wait to be
    /// fixed, so a refusal never overwrites them.
    pub(crate) async fn save_from_service(&self) {
        // Fetched under the lock, so a slower fetch can never save older settings.
        let mut saved = self.saved.lock().await;
        if self.sync_failed() {
            return;
        }
        match self.call(Request::GetConfig).await {
            Ok(Response::Config(config)) => {
                if let Err(e) = self.persist(&mut saved, &config) {
                    tracing::warn!("cannot save the settings: {e}");
                }
            }
            Ok(other) => tracing::warn!("unexpected answer to GetConfig: {other:?}"),
            Err(e) => tracing::debug!("cannot fetch the settings to save them: {}", e.message),
        }
    }

    /// Settles a fresh connection before any command can use it: the service
    /// gets the saved settings, or, with nothing saved yet, its settings are
    /// saved as they are.
    async fn hand_over(&self, client: &IpcClient) -> Option<String> {
        let mut saved = self.saved.lock().await;
        match saved.clone() {
            Some(config) => match client.call(Request::SetConfig(Box::new(config))).await {
                Ok(Response::Ok) => None,
                Ok(other) => Some(format!("Unexpected response from the service: {other:?}")),
                Err(e) => Some(format!("The service did not accept the saved settings: {e}")),
            },
            None => match client.call(Request::GetConfig).await {
                Ok(Response::Config(config)) => {
                    if let Err(e) = self.persist(&mut saved, &config) {
                        tracing::warn!("cannot save the settings: {e}");
                    }
                    None
                }
                Ok(other) => Some(format!("Unexpected response from the service: {other:?}")),
                Err(e) => Some(format!("Cannot read the service's settings: {e}")),
            },
        }
    }

    pub(crate) fn status(&self) -> ConnectionStatus {
        self.lock_status().clone()
    }

    pub(crate) async fn call(&self, request: Request) -> Result<Response, CommandError> {
        let client = self.client.read().await.clone();
        match client {
            Some(client) if client.is_connected() => Ok(client.call(request).await?),
            _ => Err(CommandError::not_connected()),
        }
    }

    fn lock_status(&self) -> MutexGuard<'_, ConnectionStatus> {
        self.status.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Applies `change` and emits the status only when something actually
    /// changed, so a retry loop against a stopped service does not spam the
    /// webview.
    fn update_status(&self, app: &AppHandle, change: impl FnOnce(&mut ConnectionStatus)) {
        let snapshot = {
            let mut status = self.lock_status();
            let mut next = status.clone();
            change(&mut next);
            if *status == next {
                return;
            }
            *status = next.clone();
            next
        };
        if let Err(e) = app.emit("connection", snapshot) {
            tracing::warn!("cannot emit connection status: {e}");
        }
    }

    async fn connect_once(&self, app: &AppHandle) -> Result<(IpcClient, mpsc::Receiver<Event>), Failure> {
        let token = Token::read(&self.token_path).map_err(|e| match e {
            TokenError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => Failure::NotRunning,
            other => Failure::Other(other.to_string()),
        })?;
        match IpcClient::connect(&self.endpoint, &token).await {
            Ok(connected) => Ok(connected),
            // It keeps the name the new service needs: stop it, then the
            // usual start (or reconnect) follows.
            Err(e) if e.is_older_service() => {
                let stopping = || self.update_status(app, |s| s.service_notice = Some(OLDER_SERVICE_STOPPING.to_owned()));
                Err(Failure::Notice(stop_older_service(&self.endpoint, &token, &self.older_service, stopping).await))
            }
            Err(e) => Err(failure(e)),
        }
    }
}

/// Why an attempt to connect failed.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// No token, or nothing holds the service's name.
    NotRunning,
    /// Also shown on screen, as `service_notice`.
    Notice(&'static str),
    Other(String),
}

impl Failure {
    /// For `error`.
    fn into_message(self) -> String {
        match self {
            Self::NotRunning => NOT_RUNNING.to_owned(),
            Self::Notice(notice) => notice.to_owned(),
            Self::Other(message) => message,
        }
    }
}

/// A failed [`IpcClient::connect`], other than an older service.
fn failure(e: CallError) -> Failure {
    match e {
        CallError::NotTheService => Failure::Notice(NOT_THE_SERVICE),
        CallError::Io(io) if io.kind() == io::ErrorKind::NotFound => Failure::NotRunning,
        e => Failure::Other(CommandError::from(e).message),
    }
}

/// The notice to show after a failed attempt. That an older service was
/// stopped explains why none is running, so "not running" leaves it up; any
/// other lasts only as long as what it describes.
fn notice_after(shown: Option<String>, failure: &Failure) -> Option<String> {
    match failure {
        Failure::Notice(notice) => Some((*notice).to_owned()),
        Failure::NotRunning if shown.as_deref() == Some(OLDER_SERVICE_STOPPED) => shown,
        Failure::NotRunning | Failure::Other(_) => None,
    }
}

/// Asks a service from before this app's protocol to stop, once per run of
/// it, over its own protocol and with nothing but that request. `stopping`
/// runs just before it is asked, as waiting for it to go can take a while.
async fn stop_older_service(
    endpoint: &Endpoint,
    token: &Token,
    asked: &OlderServiceAsked,
    stopping: impl FnOnce(),
) -> &'static str {
    let earlier = lock(asked).as_ref().filter(|(before, _)| before == token).map(|&(_, outcome)| outcome);
    if let Some(outcome) = earlier {
        return outcome;
    }
    stopping();
    let outcome = match IpcClient::shutdown_legacy(endpoint, token).await {
        Ok(()) => {
            tracing::info!("stopped an older Captun service so the new one can start");
            OLDER_SERVICE_STOPPED
        }
        Err(e) => {
            tracing::warn!("cannot stop the older Captun service: {e}");
            OLDER_SERVICE_KEPT
        }
    };
    *lock(asked) = Some((token.clone(), outcome));
    outcome
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Keeps one live connection to the service, retrying every couple of
/// seconds, and forwards the service's events to the webview as `ipc-event`
/// (see [`forward`]).
pub(crate) fn spawn_connection_loop(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let state = app.state::<AppState>();
            let current = state.client.read().await.clone();
            if !current.as_ref().is_some_and(|c| c.is_connected()) {
                // A connection that was up has gone down: the service stopped.
                if current.is_some() {
                    tauri::async_runtime::spawn(after_service_lost(app.clone()));
                }
                state.client.write().await.take();
                match state.connect_once(&app).await {
                    Ok((client, events)) => {
                        let version = client.service_version().to_owned();
                        let sync_error = state.hand_over(&client).await;
                        if let Some(message) = &sync_error {
                            tracing::warn!("{message}");
                        }
                        *state.client.write().await = Some(Arc::new(client));
                        state.update_status(&app, |s| {
                            s.connected = true;
                            s.service_version = Some(version);
                            s.error = None;
                            s.service_notice = None;
                            s.config_pending &= sync_error.is_some();
                            s.config_sync_error = sync_error;
                        });
                        forward_events(app.clone(), events);
                    }
                    Err(failure) => state.update_status(&app, |s| {
                        s.connected = false;
                        s.service_version = None;
                        s.service_notice = notice_after(s.service_notice.take(), &failure);
                        s.error = Some(failure.into_message());
                    }),
                }
            }
            tokio::time::sleep(RECONNECT_INTERVAL).await;
        }
    });
}

/// The service went away without turning sharing off first (a crash, a
/// kill; a clean stop turns the hotspot off before it goes): Windows keeps the
/// hotspot up and shares this computer's internet with it directly, around
/// every outbound. With the kill switch on, the GUI turns the hotspot off.
async fn after_service_lost(app: AppHandle) {
    let config = app.state::<AppState>().saved_or_default().await;
    if !(config.network.transparent_routing && config.network.kill_switch) {
        return;
    }
    let backend = captun_platform::default_backend();
    if !backend.state().await.is_ok_and(|state| state.running) {
        return;
    }
    tracing::warn!("the service stopped while sharing; turning the hotspot off so devices do not go out directly");
    if let Err(e) = backend.stop().await {
        tracing::warn!("cannot turn the hotspot off: {e}");
    }
}

fn forward_events(app: AppHandle, events: mpsc::Receiver<Event>) {
    tauri::async_runtime::spawn(async move {
        forward(events, |event| {
            if matches!(event, Event::ConfigChanged) {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { app.state::<AppState>().save_from_service().await });
            }
            if let Err(e) = app.emit("ipc-event", &event) {
                tracing::warn!("cannot forward service event: {e}");
            }
        })
        .await;
    });
}

/// How often name lookups go to the webview, together.
const LOOKUPS_EVERY: Duration = Duration::from_millis(250);
/// The most lookups one batch carries; the newest are kept.
const LOOKUPS_KEPT: usize = 500;

/// Hands the service's events to `emit` until the connection drops. Name
/// lookups go as one `DnsQueries` batch per [`LOOKUPS_EVERY`], since one
/// webview message per lookup can flood it on a busy network; the service's
/// log is not passed on, as the webview shows none. The rest goes at once,
/// the devices' speeds (`Traffic`, once a second at most) among them.
async fn forward(mut events: mpsc::Receiver<Event>, mut emit: impl FnMut(Event)) {
    let mut lookups = Lookups::default();
    // The first tick a full interval in, so the first lookups are not split.
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + LOOKUPS_EVERY, LOOKUPS_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(event) => {
                    if let Some(event) = lookups.sort(event) {
                        emit(event);
                    }
                }
                // The client closes the channel when the connection drops.
                None => break,
            },
            _ = tick.tick() => {
                if let Some(batch) = lookups.take() {
                    emit(Event::DnsQueries(batch));
                }
            }
        }
    }
    // What came in before the drop still goes.
    if let Some(batch) = lookups.take() {
        emit(Event::DnsQueries(batch));
    }
}

/// Name lookups waiting for the next batch: the newest [`LOOKUPS_KEPT`],
/// oldest first, and how many were left out.
#[derive(Debug, Default)]
struct Lookups {
    entries: VecDeque<DnsQueryLog>,
    dropped: u32,
}

impl Lookups {
    /// Keeps name lookups for the next batch and leaves out the service's
    /// log; anything else is handed back to go at once.
    fn sort(&mut self, event: Event) -> Option<Event> {
        match event {
            Event::DnsQuery(entry) => self.push(entry),
            Event::DnsQueries(batch) => {
                self.dropped = self.dropped.saturating_add(batch.dropped);
                batch.entries.into_iter().for_each(|entry| self.push(entry));
            }
            Event::Log(_) => {}
            other => return Some(other),
        }
        None
    }

    fn push(&mut self, entry: DnsQueryLog) {
        if self.entries.len() >= LOOKUPS_KEPT {
            self.entries.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.entries.push_back(entry);
    }

    /// The batch to send, if anything came in since the last one.
    fn take(&mut self) -> Option<DnsQueryBatch> {
        if self.entries.is_empty() && self.dropped == 0 {
            return None;
        }
        Some(DnsQueryBatch { entries: self.entries.drain(..).collect(), dropped: std::mem::take(&mut self.dropped) })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use captun_ipc::{IpcListener, PipeAccess, split};
    use serde_json::{Value, json};

    use super::*;

    fn test_endpoint(name: &str) -> Endpoint {
        #[cfg(windows)]
        return Endpoint::new(format!(r"\\.\pipe\captun-desktop-test-{name}-{}", std::process::id()));
        #[cfg(unix)]
        return Endpoint::new(std::env::temp_dir().join(format!("captun-desktop-test-{name}-{}.sock", std::process::id())).display().to_string());
    }

    /// A service from before version 2 that stops when asked, counting the
    /// connections it gets.
    fn spawn_old_service(endpoint: &Endpoint, connections: Arc<AtomicUsize>) {
        let mut listener = IpcListener::bind(endpoint, &PipeAccess::InteractiveUsers).unwrap();
        tokio::spawn(async move {
            while let Ok(stream) = listener.accept().await {
                connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (mut rx, mut tx) = split::<_, Value, Value>(stream);
                    let Ok(Some(_greeting)) = rx.next().await else { return };
                    tx.send(&json!({ "type": "welcome", "version": 1, "service_version": "0.0.9" })).await.unwrap();
                    while let Ok(Some(frame)) = rx.next().await {
                        if frame["request"]["method"] == "shutdown" {
                            let stopped = json!({ "type": "response", "id": frame["id"], "result": { "Ok": { "kind": "ok" } } });
                            tx.send(&stopped).await.unwrap();
                            return;
                        }
                    }
                });
            }
        });
    }

    #[tokio::test]
    async fn each_run_of_an_older_service_is_asked_to_stop_once() {
        let endpoint = test_endpoint("older");
        let connections = Arc::new(AtomicUsize::new(0));
        spawn_old_service(&endpoint, connections.clone());
        let asked = OlderServiceAsked::default();
        let told = AtomicUsize::new(0);
        let stopping = || {
            told.fetch_add(1, Ordering::SeqCst);
        };

        let token = Token::generate();
        assert_eq!(stop_older_service(&endpoint, &token, &asked, stopping).await, OLDER_SERVICE_STOPPED);
        assert_eq!(stop_older_service(&endpoint, &token, &asked, stopping).await, OLDER_SERVICE_STOPPED);
        assert_eq!(connections.load(Ordering::SeqCst), 1, "the same run is asked once");
        assert_eq!(told.load(Ordering::SeqCst), 1, "and the window told once that it is being stopped");

        // Another run writes another token, and is asked in its turn.
        assert_eq!(stop_older_service(&endpoint, &Token::generate(), &asked, stopping).await, OLDER_SERVICE_STOPPED);
        assert_eq!((connections.load(Ordering::SeqCst), told.load(Ordering::SeqCst)), (2, 2));
    }

    #[tokio::test]
    async fn an_older_service_that_cannot_be_reached_is_reported() {
        let endpoint = test_endpoint("gone");
        let asked = OlderServiceAsked::default();
        let token = Token::generate();
        assert_eq!(stop_older_service(&endpoint, &token, &asked, || {}).await, OLDER_SERVICE_KEPT);
        assert_eq!(stop_older_service(&endpoint, &token, &asked, || {}).await, OLDER_SERVICE_KEPT);
    }

    #[test]
    fn what_holds_the_name_is_shown_on_screen_and_not_running_is_not() {
        assert_eq!(failure(CallError::NotTheService), Failure::Notice(NOT_THE_SERVICE));
        assert_eq!(failure(CallError::Io(io::ErrorKind::NotFound.into())), Failure::NotRunning);
        let Failure::Other(other) = failure(CallError::Timeout) else { panic!("a timeout is no notice") };
        assert_eq!(Failure::Other(other.clone()).into_message(), other);
        assert_eq!(Failure::NotRunning.into_message(), NOT_RUNNING);
        assert_eq!(Failure::Notice(NOT_THE_SERVICE).into_message(), NOT_THE_SERVICE);
    }

    #[test]
    fn the_note_that_an_older_service_was_stopped_outlasts_not_running() {
        let stopped = Some(OLDER_SERVICE_STOPPED.to_owned());
        assert_eq!(notice_after(stopped.clone(), &Failure::NotRunning), stopped);
        assert_eq!(notice_after(stopped.clone(), &Failure::Other("Something else".into())), None);
        assert_eq!(notice_after(stopped, &Failure::Notice(NOT_THE_SERVICE)).as_deref(), Some(NOT_THE_SERVICE));
        // Being stopped, then stopped: the outcome replaces the wait.
        let stopping = Some(OLDER_SERVICE_STOPPING.to_owned());
        assert_eq!(notice_after(stopping, &Failure::Notice(OLDER_SERVICE_STOPPED)).as_deref(), Some(OLDER_SERVICE_STOPPED));
        // Another program, or an older service that would not stop, is
        // news only while it holds the name.
        for gone in [NOT_THE_SERVICE, OLDER_SERVICE_KEPT] {
            assert_eq!(notice_after(Some(gone.to_owned()), &Failure::NotRunning), None, "{gone}");
        }
        assert_eq!(notice_after(None, &Failure::NotRunning), None);
    }

    fn lookup(at_ms: u64) -> DnsQueryLog {
        DnsQueryLog {
            at_ms,
            client: None,
            client_ip: std::net::Ipv4Addr::new(192, 168, 137, 2).into(),
            name: "example.com".into(),
            qtype: "A".into(),
            outcome: "NOERROR".into(),
            answers: Vec::new(),
            upstream: None,
            latency_ms: 1,
        }
    }

    fn times(batch: &DnsQueryBatch) -> Vec<u64> {
        batch.entries.iter().map(|entry| entry.at_ms).collect()
    }

    #[test]
    fn a_batch_keeps_the_newest_lookups_oldest_first_and_counts_the_rest() {
        let mut lookups = Lookups::default();
        assert_eq!(lookups.take(), None, "nothing came in");
        let total = LOOKUPS_KEPT as u64 + 20;
        for at in 0..total {
            assert!(lookups.sort(Event::DnsQuery(lookup(at))).is_none());
        }
        let batch = lookups.take().unwrap();
        assert_eq!(batch.dropped, 20);
        assert_eq!(times(&batch), (20..total).collect::<Vec<_>>());
        assert_eq!(lookups.take(), None, "each lookup goes once");
    }

    #[test]
    fn the_services_own_batches_and_counts_join_in() {
        let mut lookups = Lookups::default();
        assert!(lookups.sort(Event::DnsQuery(lookup(1))).is_none());
        let from_service = DnsQueryBatch { entries: vec![lookup(2), lookup(3)], dropped: 7 };
        assert!(lookups.sort(Event::DnsQueries(from_service)).is_none());
        let batch = lookups.take().unwrap();
        assert_eq!((times(&batch), batch.dropped), (vec![1, 2, 3], 7));

        // A batch over the limit keeps its newest, and its count adds up.
        let big = DnsQueryBatch { entries: (0..LOOKUPS_KEPT as u64 + 5).map(lookup).collect(), dropped: 1 };
        assert!(lookups.sort(Event::DnsQueries(big)).is_none());
        let batch = lookups.take().unwrap();
        assert_eq!((batch.entries.len(), batch.dropped, batch.entries[0].at_ms), (LOOKUPS_KEPT, 6, 5));

        // Only a count still reaches the webview.
        assert!(lookups.sort(Event::DnsQueries(DnsQueryBatch { entries: Vec::new(), dropped: 2 })).is_none());
        assert_eq!(lookups.take(), Some(DnsQueryBatch { entries: Vec::new(), dropped: 2 }));
    }

    #[test]
    fn the_log_stays_behind_and_the_rest_goes_at_once() {
        let mut lookups = Lookups::default();
        let line =
            captun_ipc::LogLine { at_ms: 1, level: captun_ipc::LogLevel::Info, target: "t".into(), message: "m".into() };
        assert!(lookups.sort(Event::Log(line)).is_none());
        assert_eq!(lookups.take(), None);
        assert!(matches!(lookups.sort(Event::ConfigChanged), Some(Event::ConfigChanged)));
        assert!(matches!(lookups.sort(Event::Hotspot(Default::default())), Some(Event::Hotspot(_))));
        // Device speeds, once a second: as they come, never held for a batch.
        let speeds = captun_ipc::DeviceTraffic {
            mac: "02:00:00:00:00:07".parse().unwrap(),
            rx_bytes: 10,
            tx_bytes: 20,
            rx_bps: 80,
            tx_bps: 160,
            active_flows: 1,
        };
        let Some(Event::Traffic(passed)) = lookups.sort(Event::Traffic(vec![speeds])) else { panic!("held back") };
        assert_eq!(passed, [speeds]);
        assert_eq!(lookups.take(), None);
        // How an update of the online lists goes, as it comes, for the Rules page.
        let progress = captun_ipc::ListsProgress { updating: true, done: 3, total: 8, lists: Vec::new() };
        assert!(matches!(lookups.sort(Event::Lists(progress.clone())), Some(Event::Lists(sent)) if sent == progress));
    }

    #[tokio::test]
    async fn lookups_reach_the_webview_as_one_batch_per_tick() {
        let (tx, rx) = mpsc::channel(16);
        for at in 0..3 {
            tx.send(Event::DnsQuery(lookup(at))).await.unwrap();
        }
        tx.send(Event::ConfigChanged).await.unwrap();
        let emitted = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let emitted = emitted.clone();
            forward(rx, move |event| lock(&emitted).push(event))
        });

        // At once for the rest, on the next tick for the lookups.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while lock(&emitted).len() < 2 {
            assert!(tokio::time::Instant::now() < deadline, "no batch");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        {
            let seen = lock(&emitted);
            assert!(matches!(seen[0], Event::ConfigChanged));
            let Event::DnsQueries(batch) = &seen[1] else { panic!("not a batch: {:?}", seen[1]) };
            assert_eq!((times(batch), batch.dropped), (vec![0, 1, 2], 0));
        }

        // Lookups that came in just before the connection dropped still go.
        tx.send(Event::DnsQuery(lookup(9))).await.unwrap();
        drop(tx);
        tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
        let seen = lock(&emitted);
        assert_eq!(seen.len(), 3, "nothing else, no empty batches: {seen:?}");
        let Event::DnsQueries(last) = &seen[2] else { panic!("not a batch: {:?}", seen[2]) };
        assert_eq!(times(last), vec![9]);
    }
}
