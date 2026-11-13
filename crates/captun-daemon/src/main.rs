//! The privileged Captun service. It owns the hotspot and the network
//! plumbing, and serves the unprivileged GUI over authenticated local IPC.
//! Started by the GUI, it keeps the settings in memory and the GUI stores
//! them; run on its own, it keeps them in a config file.

mod capacity;
mod dns;
mod engine_glue;
mod env;
mod hub;
mod ipc_server;
mod lists;
mod local_access;
mod local_dns;
mod logging;
mod monitor;
mod names;
mod paths;
mod tether;
mod traffic;
mod usage;

use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Parser;
use captun_core::Config;
use captun_ipc::{Endpoint, IpcListener, PipeAccess, Token};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::hub::Hub;

#[derive(Debug, Parser)]
#[command(name = "captun-daemon", version, about = "Captun service")]
struct Args {
    /// Config file (created with defaults on first save).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Keep no config file: the GUI that started the service stores the
    /// settings (encrypted, next to the app) and hands them over when it
    /// connects. Autostart waits until then.
    #[arg(long, conflicts_with = "config")]
    settings_from_gui: bool,
    /// Named pipe (Windows) or Unix socket path to listen on.
    #[arg(long)]
    endpoint: Option<String>,
    /// Where to write the per-run IPC token for the GUI. Its folder must be
    /// one only root or administrators can change, as the default is (beside
    /// the socket on Unix, the data folder on Windows).
    #[arg(long)]
    token_file: Option<PathBuf>,
    /// SID of the account allowed to open the service pipe and read the token
    /// file (Windows). Without it any interactive user may open the pipe, and
    /// only SYSTEM and Administrators may read the token.
    #[arg(long)]
    allow_user: Option<String>,
    /// User ID that should own the token file (Unix). Defaults to the user
    /// who ran sudo or pkexec.
    #[arg(long)]
    owner_uid: Option<u32>,
    /// tracing filter, e.g. `info` or `captun=debug,info`.
    #[arg(long, default_value = "info")]
    log_level: String,
    /// Install Captun's USB driver for Android phones (Windows, from an
    /// elevated prompt), say what happened and exit. The installer runs it.
    #[arg(long, conflicts_with = "remove_usb_driver")]
    install_usb_driver: bool,
    /// Remove Captun's USB driver for Android phones and its certificate
    /// (Windows, from an elevated prompt), say what happened and exit. The
    /// uninstaller runs it.
    #[arg(long)]
    remove_usb_driver: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // A one-off job for the installer, before anything of the service: no
    // pipe, no log, no settings.
    if args.install_usb_driver || args.remove_usb_driver {
        std::process::exit(usb_driver_job(args.install_usb_driver).await);
    }

    // Before any file work: junctions other accounts made are not followed
    // (where Windows offers that), and the data folder is made Captun's
    // alone, so the log, the lists and the phone key never land in a folder
    // or through a link someone else controls.
    #[cfg(windows)]
    let _ = captun_ipc::enforce_redirection_trust();
    let data_dir_notes = match paths::prepare_data_dir() {
        Ok(notes) => notes,
        // No log: it would be written into that very folder. Returned, the
        // reason is written out once, to the console if there is one.
        Err(why) => anyhow::bail!(
            "Captun's data folder cannot be made safe to use: {why}. Restart the computer, then start Captun again; if this keeps happening, delete what is named here first."
        ),
    };
    // Before Hub::new, which looks for the Xray program.
    register_program_check();

    // The name first, the token after: a run that cannot have the name
    // (another service, or another program, holds it) leaves no fresh token
    // for the GUI to offer whoever does. Before the log too, as opening it
    // moves the last one aside: such a run says why in a log of its own and
    // leaves the running service's alone.
    let endpoint = args.endpoint.map(Endpoint::new).unwrap_or_else(Endpoint::default_service);
    let access = args.allow_user.clone().map(PipeAccess::User).unwrap_or_default();
    let bound = IpcListener::bind(&endpoint, &access);
    let (events, _) = broadcast::channel(1024);
    logging::init(&args.log_level, events.clone(), &log_file(bound.is_ok()))?;
    for note in data_dir_notes {
        warn!("{note}");
    }
    let listener = match bound {
        Ok(listener) => listener,
        Err(e) => {
            // The service has no console: the log is where this is read.
            error!(
                "cannot open {} for the Captun app: {e}. Another Captun service, or another program, may be using it.",
                endpoint.as_str()
            );
            return Err(e).with_context(|| format!("cannot listen on {} (is another Captun service running?)", endpoint.as_str()));
        }
    };
    let (config_file, config) = if args.settings_from_gui {
        (None, take_legacy_config(&paths::default_config()))
    } else {
        let path = args.config.unwrap_or_else(paths::default_config);
        let config = Config::load_or_default(&path).with_context(|| format!("cannot load config from {}", path.display()))?;
        (Some(path), config)
    };
    let user = paths::invoking_uid(args.owner_uid);
    let hub = Hub::new(config_file.clone(), config, captun_platform::default_backend(), events, user);

    let token = Token::generate();
    let token_path = args.token_file.unwrap_or_else(paths::default_token);
    // Removed again on every way out of this function.
    let token_file = match token.write_for(&token_path, user, args.allow_user.as_deref()) {
        Ok(file) => file,
        Err(e) => {
            error!("cannot write the key the Captun app needs: {e}");
            return Err(e).context("cannot write the IPC token");
        }
    };
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_file.as_deref().map_or_else(|| "kept by the GUI".into(), |p| p.display().to_string()),
        endpoint = endpoint.as_str(),
        "Captun service started"
    );
    // Only now, as the one service running: a run that stopped abruptly may
    // have left device rules behind. Before any are put in, which reuse names.
    let _ = tokio::task::spawn_blocking(captun_platform::reach::clear_leftovers).await;

    let monitor = tokio::spawn(monitor::run(hub.clone()));
    // Device speeds for the GUI, once a second while one is connected.
    let traffic = tokio::spawn(traffic::run(hub.clone()));
    // Each device's data use, for the Usage page and the data allowances.
    let usage = tokio::spawn(usage::run(hub.clone()));
    // With the GUI keeping the settings, autostart runs once they arrive.
    if config_file.is_some() {
        hub.autostart();
    }

    tokio::select! {
        result = ipc_server::serve(listener, hub.clone(), token) => result?,
        () = shutdown_signal() => info!("shutting down"),
        () = hub.shutdown_requested() => info!("shutting down at the GUI's request"),
    }

    // No new connection is served any more, so the token goes first.
    drop(token_file);
    monitor.abort();
    traffic.abort();
    usage.abort();
    hub.shutdown().await;
    // What was counted since the last save.
    hub.save_usage().await;
    Ok(())
}

/// Makes every program the service runs pass [`program_check`] first: in
/// Windows release builds only. A development build runs from `target\`,
/// which its user can change, and would otherwise lose VPN links.
fn register_program_check() {
    #[cfg(all(windows, not(debug_assertions)))]
    captun_xray::set_program_check(program_check);
}

/// Refuses a program file that anyone but Windows and the administrators
/// could change (or a DLL planted beside it), in the form the Xray module
/// takes: the reason in plain words, as permission denied.
#[cfg(any(test, all(windows, not(debug_assertions))))]
fn program_check(path: &Path) -> std::io::Result<()> {
    captun_platform::trust::check_program_file(path)
        .map_err(|why| std::io::Error::new(std::io::ErrorKind::PermissionDenied, why.to_string()))
}

/// Installs (or removes) Captun's USB driver for phones and says what
/// happened, which the installer keeps in its log. Returns the exit code: 0
/// when it is done, 1 when it is not.
async fn usb_driver_job(install: bool) -> i32 {
    let job = tokio::task::spawn_blocking(move || {
        if install {
            captun_usbdriver::install()
                .map(|done| done.to_string())
                .map_err(|e| format!("Captun could not install the USB driver for Android phones: {e}."))
        } else {
            captun_usbdriver::remove()
                .map(|done| done.to_string())
                .map_err(|e| format!("Captun could not remove its USB driver for Android phones: {e}."))
        }
    })
    .await;
    match job {
        Ok(Ok(done)) => {
            println!("{done}");
            0
        }
        Ok(Err(failed)) => {
            eprintln!("{failed}");
            1
        }
        Err(e) => {
            eprintln!("Captun could not finish with the USB driver for Android phones: the job stopped ({e}).");
            1
        }
    }
}

/// The service's log, or for a run that could not take the pipe name (and so
/// stops at once) a log of its own beside it.
fn log_file(bound: bool) -> PathBuf {
    let log = paths::log_file();
    if bound { log } else { log.with_extension("not-started.log") }
}

/// The plain-text config file older versions kept. It holds secrets, so once
/// read into memory it is removed: the GUI takes the settings over and stores
/// them encrypted. A file that cannot be read is left alone.
fn take_legacy_config(path: &Path) -> Config {
    match Config::load_or_default(path) {
        Ok(config) => {
            match std::fs::remove_file(path) {
                Ok(()) => info!("moved the old settings file {} into memory for the GUI", path.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!("cannot remove the old settings file {}: {e}", path.display()),
            }
            config
        }
        Err(e) => {
            warn!("ignoring the old settings file {}: {e}", path.display());
            Config::default()
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
                return;
            }
            Err(e) => warn!("cannot watch SIGTERM: {e}"),
        }
    }
    if let Err(e) = tokio::signal::ctrl_c().await {
        warn!("cannot watch Ctrl+C: {e}");
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_usb_driver_jobs_are_flags_of_their_own() {
        let parse = |args: &[&str]| Args::try_parse_from(std::iter::once("captun-daemon").chain(args.iter().copied()));
        let install = parse(&["--install-usb-driver"]).unwrap();
        assert!(install.install_usb_driver && !install.remove_usb_driver);
        let remove = parse(&["--remove-usb-driver"]).unwrap();
        assert!(remove.remove_usb_driver && !remove.install_usb_driver);
        assert!(parse(&["--install-usb-driver", "--remove-usb-driver"]).is_err());
        let service = parse(&[]).unwrap();
        assert!(!service.install_usb_driver && !service.remove_usb_driver);
    }

    #[test]
    fn a_run_that_cannot_take_the_name_keeps_off_the_services_log() {
        let (running, extra) = (log_file(true), log_file(false));
        assert_eq!(running, paths::log_file());
        assert_eq!(extra.parent(), running.parent());
        assert_eq!(extra.file_name().unwrap(), "captun-daemon.not-started.log");
        // Opening a log moves the previous one to `.1`: never the service's.
        assert_ne!(extra.with_extension("log.1"), running.with_extension("log.1"));
        assert_ne!(extra.with_extension("log.1"), running);
    }

    #[test]
    fn a_program_others_can_change_is_refused_in_plain_words() {
        let dir = std::env::temp_dir().join(format!("captun-program-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("xray.exe");
        std::fs::write(&program, b"not really").unwrap();
        let checked = program_check(&program);
        // %TEMP% is the user's own: on Windows that is exactly what is refused.
        #[cfg(windows)]
        {
            let refused = checked.unwrap_err();
            assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(!refused.to_string().contains("Untrusted"), "a sentence, not a type name: {refused}");
            assert!(std::fs::read(&program).is_ok(), "only looked at");
        }
        // Elsewhere the program's own owner and mode checks apply instead.
        #[cfg(not(windows))]
        assert!(checked.is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_old_plain_settings_file_is_read_once_then_removed() {
        let dir = std::env::temp_dir().join(format!("captun-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("captun.toml");

        let mut config = Config::default();
        config.hotspot.ssid = "Old settings".into();
        config.save(&file).unwrap();
        assert_eq!(take_legacy_config(&file).hotspot.ssid, "Old settings");
        assert!(!file.exists());

        // Nothing there: defaults. Unreadable: defaults, and the file is kept.
        assert_eq!(take_legacy_config(&file), Config::default());
        std::fs::write(&file, "not = [valid").unwrap();
        assert_eq!(take_legacy_config(&file), Config::default());
        assert!(file.exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
