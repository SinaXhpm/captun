//! Runs Xray-core as a supervised child process. The configuration goes in
//! over stdin (never to disk), every outbound gets its own loopback SOCKS5
//! inbound with per-run random credentials, and the child is restarted with
//! backoff if it dies. Until it is up, its outbounds report why they cannot
//! be used, so traffic fails closed instead of leaking out directly.

use std::{
    collections::{HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::{Duration, Instant},
};

use captun_core::{EgressConfig, EgressId, EgressKind, Secret, ShareLink};
use captun_outbound::{Credentials, XrayEndpoint};
use rand::RngCore;
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::watch,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{debug, info, warn};

use crate::{
    config::{Route, full_config, outbound_for_link, outbounds_from_files},
    process,
};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// A child that stayed up this long is healthy; its next crash starts the
/// backoff from the beginning.
const HEALTHY_AFTER: Duration = Duration::from_secs(60);
const LOG_TAIL: usize = 12;

/// What the sidecar is doing, for the status page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SidecarState {
    /// No outbound needs Xray.
    #[default]
    Idle,
    /// Outbounds need Xray but its program is not installed.
    Missing,
    Starting,
    Running,
    Failed(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SidecarStatus {
    pub state: SidecarState,
    /// Xray's version, once known.
    pub version: Option<String>,
}

/// What the child should run: one outbound per egress, plus every secret in
/// it so log lines can be scrubbed.
#[derive(Debug, PartialEq)]
struct Spec {
    outbounds: Vec<(EgressId, Value)>,
    secrets: Vec<Secret>,
}

struct Shared {
    binary: Option<PathBuf>,
    /// No program was given because the service's check refused the one in
    /// place (see [`crate::set_program_check`]), not because there is none.
    refused: bool,
    /// The unprivileged user Xray runs as (Linux, macOS).
    run_as: Option<u32>,
    status: Mutex<SidecarStatus>,
    endpoints: RwLock<HashMap<EgressId, XrayEndpoint>>,
    /// Per-egress problems found while building the spec (bad link, unreadable file).
    problems: RwLock<HashMap<EgressId, String>>,
    on_change: Box<dyn Fn() + Send + Sync>,
    #[cfg(windows)]
    job: Option<process::Job>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write<T>(m: &RwLock<T>, value: T) {
    *m.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
}

impl Shared {
    /// Records a new state and endpoint set, telling the owner only when
    /// something it can see changed.
    fn publish(&self, state: SidecarState, endpoints: HashMap<EgressId, XrayEndpoint>) {
        let changed = {
            let mut status = lock(&self.status);
            let changed = status.state != state;
            status.state = state;
            changed
        };
        let had = !self.endpoints.read().unwrap_or_else(|p| p.into_inner()).is_empty();
        let has = !endpoints.is_empty();
        write(&self.endpoints, endpoints);
        if changed || had || has {
            (self.on_change)();
        }
    }
}

/// The supervised Xray process. Dropping it stops the child.
pub struct Sidecar {
    spec: watch::Sender<Option<Arc<Spec>>>,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for Sidecar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sidecar").field("binary", &self.shared.binary).field("status", &self.status()).finish()
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        // Aborting drops the child, and `kill_on_drop` ends it.
        self.task.abort();
    }
}

impl Sidecar {
    /// Starts the supervisor (idle until [`apply`](Self::apply) asks for
    /// outbounds). `binary` is the Xray program, if installed; `run_as` is
    /// the user who started Captun, whom Xray runs as on Linux and macOS;
    /// `on_change` runs whenever endpoints or the state change, from a
    /// runtime thread.
    pub fn start(binary: Option<PathBuf>, run_as: Option<u32>, on_change: impl Fn() + Send + Sync + 'static) -> Self {
        let refused = binary.is_none() && crate::program_refused();
        let shared = Arc::new(Shared {
            binary,
            refused,
            run_as,
            status: Mutex::new(SidecarStatus::default()),
            endpoints: RwLock::new(HashMap::new()),
            problems: RwLock::new(HashMap::new()),
            on_change: Box::new(on_change),
            #[cfg(windows)]
            job: process::Job::kill_on_close()
                .inspect_err(|e| warn!("Xray will not be tied to the service's lifetime: {e}"))
                .ok(),
        });
        let (spec, rx) = watch::channel(None);
        let task = tokio::spawn(supervise(shared.clone(), rx));
        Self { spec, shared, task }
    }

    /// Brings the child in line with the configured outbounds. Restarts it
    /// only when what it runs actually changes.
    pub fn apply(&self, egresses: &[EgressConfig]) {
        let (spec, problems) = build_spec(egresses);
        write(&self.shared.problems, problems);
        let spec = spec.map(Arc::new);
        self.spec.send_if_modified(|current| {
            let same = match (&*current, &spec) {
                (Some(a), Some(b)) => a == b,
                (None, None) => true,
                _ => false,
            };
            if !same {
                *current = spec;
            }
            !same
        });
    }

    pub fn status(&self) -> SidecarStatus {
        lock(&self.shared.status).clone()
    }

    /// Where egress `id` is served, or why it is not.
    pub fn endpoint(&self, id: &EgressId) -> Result<XrayEndpoint, String> {
        if let Some(problem) = self.shared.problems.read().unwrap_or_else(|p| p.into_inner()).get(id) {
            return Err(problem.clone());
        }
        if let Some(endpoint) = self.shared.endpoints.read().unwrap_or_else(|p| p.into_inner()).get(id) {
            return Ok(endpoint.clone());
        }
        Err(match self.status().state {
            SidecarState::Missing => "the VPN link engine (Xray) is not installed; reinstall Captun".into(),
            // Already a whole sentence that says what to do.
            SidecarState::Failed(why) if why == crate::REFUSED => why,
            SidecarState::Failed(why) => format!("the VPN link engine stopped: {why}"),
            SidecarState::Idle | SidecarState::Starting | SidecarState::Running => {
                "the VPN link engine is starting".into()
            }
        })
    }
}

/// Collects the outbounds Xray must run. A broken one is reported on its own
/// and left out, so it never stops the others.
fn build_spec(egresses: &[EgressConfig]) -> (Option<Spec>, HashMap<EgressId, String>) {
    // All config files are read at once, under one time limit, so files
    // another program holds cost that limit once rather than once each.
    let files: Vec<&Path> = egresses
        .iter()
        .filter_map(|egress| match &egress.kind {
            EgressKind::Xray { link: None, config_file: Some(path) } => Some(path.as_path()),
            _ => None,
        })
        .collect();
    let mut from_files = outbounds_from_files(&files).into_iter();
    let mut outbounds = Vec::new();
    let mut secrets = Vec::new();
    let mut problems = HashMap::new();
    for egress in egresses {
        let EgressKind::Xray { link, config_file } = &egress.kind else { continue };
        let outbound = match (link, config_file) {
            (Some(link), _) => match ShareLink::parse(link.expose()) {
                Ok(ShareLink::Vpn(vpn)) => {
                    secrets.extend(crate::link_secrets(&vpn));
                    Ok(outbound_for_link(&vpn))
                }
                Ok(_) => Err("this is a plain proxy link, not a VPN link".to_owned()),
                Err(e) => Err(e.to_string()),
            },
            // In the same order as `files` above.
            (None, Some(path)) => {
                from_files.next().unwrap_or_else(|| Err(format!("cannot read {}", path.display())))
            }
            (None, None) => Err("no link or config file is set".to_owned()),
        };
        match outbound {
            Ok(outbound) => outbounds.push((egress.id.clone(), outbound)),
            Err(why) => {
                problems.insert(egress.id.clone(), why);
            }
        }
    }
    let spec = (!outbounds.is_empty()).then_some(Spec { outbounds, secrets });
    (spec, problems)
}

async fn supervise(shared: Arc<Shared>, mut rx: watch::Receiver<Option<Arc<Spec>>>) {
    let mut backoff = FIRST_BACKOFF;
    loop {
        let Some(spec) = rx.borrow_and_update().clone() else {
            shared.publish(SidecarState::Idle, HashMap::new());
            if rx.changed().await.is_err() {
                return;
            }
            continue;
        };
        let Some(binary) = shared.binary.clone() else {
            let state = if shared.refused { SidecarState::Failed(crate::REFUSED.into()) } else { SidecarState::Missing };
            shared.publish(state, HashMap::new());
            if rx.changed().await.is_err() {
                return;
            }
            continue;
        };
        // The file may have been swapped since start-up. A refused one stays
        // refused until something changes; retrying would only fill the log.
        if let Err(why) = crate::allow_run(&binary) {
            shared.publish(SidecarState::Failed(why), HashMap::new());
            if rx.changed().await.is_err() {
                return;
            }
            continue;
        }
        if lock(&shared.status).version.is_none() {
            let version = process::version(&binary, shared.run_as).await;
            lock(&shared.status).version = version;
        }

        shared.publish(SidecarState::Starting, HashMap::new());
        match launch(&shared, &binary, &spec).await {
            Ok(mut running) => {
                let since = Instant::now();
                info!(outbounds = running.endpoints.len(), "VPN link engine (Xray) running");
                shared.publish(SidecarState::Running, running.endpoints.clone());
                tokio::select! {
                    exit = running.child.wait() => {
                        let why = running.failure(exit.ok());
                        warn!("VPN link engine stopped: {why}");
                        shared.publish(SidecarState::Failed(why), HashMap::new());
                        if since.elapsed() > HEALTHY_AFTER {
                            backoff = FIRST_BACKOFF;
                        }
                    }
                    changed = rx.changed() => {
                        running.stop().await;
                        if changed.is_err() {
                            return;
                        }
                        backoff = FIRST_BACKOFF;
                        continue;
                    }
                }
            }
            Err(why) => {
                warn!("VPN link engine did not start: {why}");
                shared.publish(SidecarState::Failed(why), HashMap::new());
            }
        }

        // Retry after the backoff, or right away if the outbounds change.
        tokio::select! {
            _ = sleep(backoff) => {}
            changed = rx.changed() => {
                if changed.is_err() {
                    return;
                }
                backoff = FIRST_BACKOFF;
                continue;
            }
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Recent output lines, scrubbed of secrets, for error messages.
type Tail = Arc<Mutex<VecDeque<String>>>;

struct Running {
    child: Child,
    endpoints: HashMap<EgressId, XrayEndpoint>,
    tail: Tail,
}

impl Running {
    fn failure(&self, exit: Option<std::process::ExitStatus>) -> String {
        let tail = lock(&self.tail);
        let last = tail.iter().rev().find(|l| l.contains("Failed") || l.contains("failed")).or(tail.back());
        match (last, exit) {
            (Some(line), _) => line.clone(),
            (None, Some(status)) => format!("exited ({status})"),
            (None, None) => "exited".into(),
        }
    }

    async fn stop(mut self) {
        let _ = self.child.start_kill();
        let _ = timeout(Duration::from_secs(5), self.child.wait()).await;
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Free loopback ports, one per outbound. They are released just before
/// Xray binds them; a lost race shows up as a failed start and a retry.
fn free_ports(count: usize) -> Result<Vec<u16>, String> {
    let listeners: Vec<TcpListener> = (0..count)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("no free local port: {e}"))?;
    listeners.iter().map(|l| l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())).collect()
}

async fn launch(shared: &Shared, binary: &Path, spec: &Spec) -> Result<Running, String> {
    let ports = free_ports(spec.outbounds.len())?;
    let mut secrets: Vec<String> = spec.secrets.iter().map(|s| s.expose().to_owned()).collect();
    let mut endpoints = HashMap::new();
    let mut accounts = Vec::new();
    for ((id, _), port) in spec.outbounds.iter().zip(&ports) {
        let (user, pass) = (random_token(), random_token());
        secrets.push(pass.clone());
        endpoints.insert(
            id.clone(),
            XrayEndpoint {
                addr: SocketAddr::from((Ipv4Addr::LOCALHOST, *port)),
                auth: Some(Credentials { username: user.clone(), password: Secret::new(pass.clone()) }),
            },
        );
        accounts.push((user, pass));
    }
    // Tags are indexes, not egress ids, so nothing user-chosen reaches Xray's config keys.
    let tags: Vec<String> = (0..spec.outbounds.len()).map(|i| i.to_string()).collect();
    let routes: Vec<Route<'_>> = spec
        .outbounds
        .iter()
        .zip(&ports)
        .zip(&accounts)
        .zip(&tags)
        .map(|((((_, outbound), port), (user, pass)), tag)| Route { tag, outbound, port: *port, user, pass })
        .collect();
    let config = Secret::new(full_config(&routes).to_string());

    let mut command = Command::new(binary);
    command
        .args(["run", "-config", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    process::harden(&mut command, shared.run_as);
    crate::allow_run(binary)?;
    // Never with the service's full rights: what it is told comes from links
    // other people share. Run without them (tests, development), Xray gets
    // the user's own rights either way, and the program file may be one the
    // user cannot mark.
    #[cfg(windows)]
    if let Err(e) = process::lower_integrity(binary) {
        if process::elevated() {
            warn!(path = %binary.display(), "not running the VPN link engine (Xray): cannot mark it to run at low integrity: {e}");
            return Err(format!("cannot limit the VPN link engine (Xray) to low rights: {e}"));
        }
        debug!(path = %binary.display(), "Xray runs with this process's own rights, not elevated: cannot mark it to run at low integrity: {e}");
    }
    let mut child = command.spawn().map_err(|e| format!("cannot run {}: {e}", binary.display()))?;
    #[cfg(windows)]
    if let (Some(job), Some(handle)) = (&shared.job, child.raw_handle())
        && let Err(e) = job.assign(handle)
    {
        warn!("Xray will not be tied to the service's lifetime: {e}");
    }

    let tail: Tail = Arc::new(Mutex::new(VecDeque::with_capacity(LOG_TAIL)));
    let secrets = Arc::new(secrets);
    if let Some(out) = child.stdout.take() {
        tokio::spawn(forward_lines(out, tail.clone(), secrets.clone()));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(forward_lines(err, tail.clone(), secrets.clone()));
    }
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(config.expose().as_bytes()).await.map_err(|e| format!("cannot pass the configuration to Xray: {e}"))?;
        // Closing stdin tells Xray the configuration is complete.
        drop(stdin);
    }

    let mut running = Running { child, endpoints, tail };
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(Some(status)) = running.child.try_wait() {
            // Give the readers a moment to collect Xray's last words.
            sleep(Duration::from_millis(200)).await;
            return Err(running.failure(Some(status)));
        }
        if all_listening(&ports).await {
            return Ok(running);
        }
        if Instant::now() > deadline {
            running.stop().await;
            return Err(format!("Xray did not open its local ports within {}s", READY_TIMEOUT.as_secs()));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn all_listening(ports: &[u16]) -> bool {
    for port in ports {
        let probe = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, *port));
        if !matches!(timeout(Duration::from_millis(500), probe).await, Ok(Ok(_))) {
            return false;
        }
    }
    true
}

fn scrub(line: &str, secrets: &[String]) -> String {
    let mut line = line.to_owned();
    for secret in secrets.iter().filter(|s| s.len() >= 3) {
        if line.contains(secret.as_str()) {
            line = line.replace(secret.as_str(), "***");
        }
    }
    line
}

/// Strips Xray's "2026/01/02 15:04:05.000000 [Warning] " prefix.
fn message_of(line: &str) -> &str {
    match line.find("] ") {
        Some(i) if line.starts_with(|c: char| c.is_ascii_digit()) => &line[i + 2..],
        _ => line,
    }
}

async fn forward_lines(stream: impl tokio::io::AsyncRead + Unpin, tail: Tail, secrets: Arc<Vec<String>>) {
    let mut lines = BufReader::new(stream).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = scrub(line.trim_end(), &secrets);
        if line.is_empty() {
            continue;
        }
        if line.contains("[Warning]") || line.contains("[Error]") || line.contains("Failed") {
            warn!(target: "xray", "{line}");
        } else {
            debug!(target: "xray", "{line}");
        }
        let mut tail = lock(&tail);
        if tail.len() == LOG_TAIL {
            tail.pop_front();
        }
        tail.push_back(message_of(&line).to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xray(id: &str, link: &str) -> EgressConfig {
        EgressConfig {
            id: id.into(),
            name: None,
            kind: EgressKind::Xray { link: Some(link.into()), config_file: None },
            udp: Default::default(),
            enabled: true,
        }
    }

    #[test]
    fn broken_links_are_reported_alone() {
        let good = xray("good", "trojan://pw@t.example.com:443");
        let bad = xray("bad", "vless://nope");
        let (spec, problems) = build_spec(&[good, bad]);
        let spec = spec.unwrap();
        assert_eq!(spec.outbounds.len(), 1);
        assert_eq!(spec.outbounds[0].0.as_str(), "good");
        assert!(problems.contains_key(&EgressId::from("bad")));
        assert!(spec.secrets.iter().any(|s| s.expose() == "pw"));
        assert!(build_spec(&[]).0.is_none());
    }

    #[test]
    fn config_files_and_links_each_get_their_own_result() {
        let dir = std::env::temp_dir().join(format!("captun-spec-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (freedom, blocked) = (dir.join("freedom.json"), dir.join("blocked.json"));
        std::fs::write(&freedom, r#"{"protocol":"freedom"}"#).unwrap();
        std::fs::write(&blocked, r#"{"outbounds":[{"protocol":"blackhole"}]}"#).unwrap();
        let file = |id: &str, path: PathBuf| EgressConfig {
            kind: EgressKind::Xray { link: None, config_file: Some(path) },
            ..xray(id, "")
        };

        let (spec, problems) = build_spec(&[
            file("a", freedom.clone()),
            xray("link", "trojan://pw@t.example.com:443"),
            file("missing", dir.join("missing.json")),
            file("b", blocked),
            file("a-again", freedom),
        ]);
        let spec = spec.unwrap();
        let protocol = |id: &str| {
            spec.outbounds.iter().find(|(egress, _)| egress.as_str() == id).map(|(_, o)| o["protocol"].clone())
        };
        assert_eq!(protocol("a").unwrap(), "freedom");
        assert_eq!(protocol("link").unwrap(), "trojan");
        assert_eq!(protocol("b").unwrap(), "blackhole");
        assert_eq!(protocol("a-again").unwrap(), "freedom");
        assert_eq!(problems.len(), 1);
        assert!(problems[&EgressId::from("missing")].starts_with("cannot open"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn secrets_are_scrubbed_from_log_lines() {
        let line = "2026/10/31 10:00:00.1 [Warning] failed to dial with user b831381d-6324";
        let scrubbed = scrub(line, &["b831381d-6324".into()]);
        assert!(!scrubbed.contains("b831381d"));
        assert_eq!(message_of(&scrubbed), "failed to dial with user ***");
    }

    /// Refuses programs in folders named for it; every other path passes, so
    /// the other tests in this binary are not affected.
    fn refuse_marked(path: &Path) -> std::io::Result<()> {
        if path.to_string_lossy().contains("captun-refused") {
            Err(std::io::Error::other("other accounts can change this folder"))
        } else {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_program_the_service_refuses_is_never_run() {
        crate::set_program_check(refuse_marked);
        let dir = std::env::temp_dir().join(format!("captun-refused-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join(crate::PROGRAM);
        std::fs::write(&program, "not a program").unwrap();
        assert!(!process::trusted(&program), "found, but not trusted");

        let sidecar = Sidecar::start(Some(program.clone()), None, || {});
        sidecar.apply(&[xray("vpn", "trojan://pw@t.example.com:443")]);
        for _ in 0..100 {
            if matches!(sidecar.status().state, SidecarState::Failed(_)) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        // Had it been started, the error would be that it cannot run.
        assert_eq!(sidecar.status().state, SidecarState::Failed(crate::REFUSED.into()));
        assert_eq!(sidecar.status().version, None, "not even asked for its version");
        assert_eq!(sidecar.endpoint(&"vpn".into()).unwrap_err(), crate::REFUSED);
        drop(sidecar);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn missing_program_is_reported_per_outbound() {
        let sidecar = Sidecar::start(None, None, || {});
        sidecar.apply(&[xray("vpn", "trojan://pw@t.example.com:443")]);
        for _ in 0..50 {
            if sidecar.status().state == SidecarState::Missing {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(sidecar.status().state, SidecarState::Missing);
        assert!(sidecar.endpoint(&"vpn".into()).unwrap_err().contains("not installed"));
    }
}
