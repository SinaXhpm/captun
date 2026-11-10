//! The async runner over Captun's built-in adb. It drives the synchronous
//! native USB transport ([`crate::native`]) on a blocking thread, bounds every
//! operation with a timeout, and reverts plans best-effort.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use tracing::warn;

use crate::{
    device::AdbDevice,
    key::{self, KeyStatus},
    native,
    plan::{AdbOp, ReversiblePlan},
};

/// Long enough to let the user tap "Allow USB debugging?" on the phone the first
/// time, after which the operation proceeds.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum AdbError {
    #[error("USB error: {0}")]
    Usb(String),
    #[error("no phone found with serial {0}")]
    DeviceNotFound(String),
    #[error("this operation needs a target phone, but no serial was set")]
    NoSerial,
    #[error("the phone is busy — another program (often a running adb server) is holding it over USB")]
    Busy,
    #[error(
        "timed out talking to the phone — if it is showing \"Allow USB debugging?\", tap \"Always allow\" and try again"
    )]
    Timeout,
    #[error("`{command}` failed on the phone: {stderr}")]
    Command { command: String, stderr: String },
    #[error("adb error: {0}")]
    Adb(String),
    /// Captun's phone key could not be checked, made or kept private; a
    /// whole sentence for the user (details go to the service log).
    #[error("{0}")]
    Key(String),
}

/// Runs operations against a phone over the built-in USB adb. Cheap to clone and
/// re-target.
#[derive(Clone, Debug)]
pub struct Adb {
    /// Path to the persistent adb RSA private key (created on first use).
    key: PathBuf,
    serial: Option<String>,
    timeout: Duration,
}

impl Adb {
    /// A runner not yet pinned to a device, e.g. just to list devices.
    pub fn new(key_path: impl Into<PathBuf>) -> Self {
        Self { key: key_path.into(), serial: None, timeout: DEFAULT_TIMEOUT }
    }

    /// A runner pinned to one device serial.
    pub fn with_serial(key_path: impl Into<PathBuf>, serial: impl Into<String>) -> Self {
        Self { key: key_path.into(), serial: Some(serial.into()), timeout: DEFAULT_TIMEOUT }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The same runner, pinned to one device serial.
    pub fn select(&self, serial: impl Into<String>) -> Self {
        Self { key: self.key.clone(), serial: Some(serial.into()), timeout: self.timeout }
    }

    pub fn serial(&self) -> Option<&str> {
        self.serial.as_deref()
    }

    /// Lists every connected device that presents an ADB interface. Needs no
    /// target and never raises the phone's authorization prompt.
    pub async fn devices(&self) -> Result<Vec<AdbDevice>, AdbError> {
        self.blocking(native::enumerate).await
    }

    /// Makes sure Captun's phone key exists and is private before a session,
    /// making or replacing it as needed. [`KeyStatus::Replaced`] (also for a
    /// replacement an earlier command of this run made) comes with a note for
    /// the user: [`KeyStatus::note`].
    pub async fn prepare_key(&self) -> Result<KeyStatus, AdbError> {
        let key = self.key.clone();
        self.blocking(move || key::prepare_key(&key)).await
    }

    /// Runs one shell command and returns its stdout.
    pub async fn shell(&self, command: &str) -> Result<String, AdbError> {
        let serial = self.serial.clone().ok_or(AdbError::NoSerial)?;
        let key = self.key.clone();
        let command = command.to_owned();
        self.blocking(move || {
            key::ensure_key(&key)?;
            native::run_shell(&serial, &key, &command)
        })
        .await
    }

    /// Installs an APK onto the device.
    pub async fn install(&self, apk: &Path) -> Result<(), AdbError> {
        let serial = self.serial.clone().ok_or(AdbError::NoSerial)?;
        let key = self.key.clone();
        let apk = apk.to_string_lossy().into_owned();
        self.blocking(move || {
            key::ensure_key(&key)?;
            native::install(&serial, &key, &apk)
        })
        .await
    }

    async fn run_op(&self, op: &AdbOp) -> Result<(), AdbError> {
        match op {
            AdbOp::Shell(command) => self.shell(command).await.map(drop),
            AdbOp::Install(apk) => self.install(apk).await,
            AdbOp::Uninstall(package) => self.shell(&format!("pm uninstall {package}")).await.map(drop),
        }
    }

    /// Applies a plan; if any step fails, best-effort reverts whatever may have
    /// taken effect and returns the original error.
    pub async fn apply(&self, plan: &ReversiblePlan) -> Result<(), AdbError> {
        for op in &plan.apply {
            if let Err(e) = self.run_op(op).await {
                self.run_revert(&plan.revert).await;
                return Err(e);
            }
        }
        Ok(())
    }

    /// Best-effort: runs every step, logging failures instead of stopping, so a
    /// revert undoes as much as it can even if one step no longer applies.
    pub async fn run_revert(&self, ops: &[AdbOp]) {
        for op in ops {
            if let Err(e) = self.run_op(op).await {
                warn!("adb revert `{}` failed: {e}", op.display());
            }
        }
    }

    /// Runs a blocking native operation on a worker thread, bounded by the
    /// timeout. A timeout returns [`AdbError::Timeout`]; the worker thread is left
    /// to finish on its own (it unblocks as soon as the phone responds, e.g. once
    /// the user taps "Allow").
    async fn blocking<T, F>(&self, f: F) -> Result<T, AdbError>
    where
        F: FnOnce() -> Result<T, AdbError> + Send + 'static,
        T: Send + 'static,
    {
        match tokio::time::timeout(self.timeout, tokio::task::spawn_blocking(f)).await {
            Ok(Ok(result)) => result,
            Ok(Err(join)) => Err(AdbError::Adb(format!("adb worker crashed: {join}"))),
            Err(_elapsed) => Err(AdbError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shell_without_a_serial_is_an_error() {
        let adb = Adb::new("adbkey");
        assert!(matches!(adb.shell("echo hi").await, Err(AdbError::NoSerial)));
    }

    #[tokio::test]
    async fn enumeration_runs_on_this_host() {
        // Exercises the real libusb path (Context::new + device walk). With no
        // phone attached this returns an empty list; it must not error, which also
        // proves libusb initialises on this OS. Hosts with no USB at all (WSL,
        // containers) have nothing to walk and are skipped.
        if cfg!(target_os = "linux") && !std::path::Path::new("/dev/bus/usb").exists() {
            eprintln!("skipped: this host has no USB devices to enumerate");
            return;
        }
        let adb = Adb::new(std::env::temp_dir().join("captun-adbkey-smoketest"));
        assert!(adb.devices().await.is_ok(), "libusb enumeration should not error");
    }

    #[test]
    fn select_pins_the_serial_and_keeps_the_key() {
        let adb = Adb::new("/data/adbkey").select("SER1");
        assert_eq!(adb.serial(), Some("SER1"));
        assert_eq!(adb.key, PathBuf::from("/data/adbkey"));
    }
}
