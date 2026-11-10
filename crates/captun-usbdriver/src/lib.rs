//! Captun's USB driver for Android phones.
//!
//! On Windows the built-in adb (libusb) can open a phone's USB debugging
//! (ADB) interface only through WinUSB, and many computers have no driver
//! that hands that interface to WinUSB: the phone shows in Device Manager
//! without a driver and "USB to phone" cannot see it. Captun brings its own,
//! the way Zadig (libwdi) does:
//!
//! - an INF ([`inf_text`]) that binds Windows' own WinUSB driver to every ADB
//!   interface by its compatible ID ([`ADB_COMPATIBLE_ID`]), so no phone's
//!   own IDs are needed, while a phone maker's driver, which names the phone
//!   itself, still ranks higher and wins;
//! - a catalog for it, made from a catalog definition ([`cdf_text`]) and
//!   signed on this computer with a certificate made for this one package
//!   ([`CERTIFICATE_NAME`]). Its private key has no name, so Windows never
//!   writes it anywhere: it exists in memory for the one signature and is
//!   destroyed right after, and the certificate can never sign anything else;
//! - [`install`] trusts that certificate on this computer (the machine's
//!   Root and TrustedPublisher stores), adds the package to Windows' driver
//!   store, gives it to phones plugged in now that have no driver, and notes
//!   what it installed under `HKLM\SOFTWARE\Captun`; [`remove`] takes exactly
//!   that away again, the certificate included.
//!
//! An ADB interface that already has a driver is never touched, and neither
//! is one Windows is still setting up. [`detect`] tells whether one is
//! waiting for a driver, so the service can fix it or explain it. macOS and
//! Linux need no driver: there every call reports that ([`NEEDED`] is
//! false).

mod package;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
mod unneeded;

use std::{fmt, io};

#[cfg(not(windows))]
use unneeded as sys;
#[cfg(windows)]
use windows as sys;

pub use package::{
    ADB_COMPATIBLE_ID, ADB_INTERFACE_GUID, CAT_NAME, CDF_NAME, CERTIFICATE_NAME, DRIVER_DATE, DRIVER_VERSION, INF_MARK,
    INF_NAME, OS_ATTRIBUTE, PROVIDER, USB_DEVICE_CLASS, cdf_text, inf_text,
};
#[cfg(windows)]
pub use windows::{Package, build_package};

/// Whether this system needs Captun's USB driver for phones: only Windows does.
pub const NEEDED: bool = cfg!(windows);

/// What to tell someone while Captun installs the driver for a phone that
/// has none.
pub const INSTALLING_NOTICE: &str =
    "Captun is installing the USB driver for Android phones. Wait a moment, then press Start again.";

/// What to tell someone once Captun has installed the driver for a phone
/// that still does not show.
pub const INSTALLED_NOTICE: &str =
    "Captun installed the USB driver for Android phones. If the phone does not show, unplug it and plug it in again.";

/// The same, once Windows' own driver for phones was given to a phone
/// that had none.
pub const WINDOWS_DRIVER_NOTICE: &str =
    "Windows set up its own USB driver for the phone. If the phone does not show, unplug it and plug it in again.";

/// Installs Captun's USB driver for phones (or keeps the same package
/// installed before) and gives it to the phones plugged in now whose USB
/// debugging interface has no driver. A different package installed before
/// comes out only once the new one is in, so phones using it move to the
/// new one. Where Windows binds its own driver to every such interface,
/// installs nothing (Windows' would be used anyway) and removes what an
/// earlier install put in. Needs administrator rights; refused without.
pub fn install() -> Result<Install, DriverError> {
    sys::install()
}

/// Removes everything [`install`] ever put in: Captun's driver packages
/// from Windows' driver store and their certificates from both stores,
/// found by Captun's mark and name whether or not they were noted. Needs
/// administrator rights; refused without.
pub fn remove() -> Result<Remove, DriverError> {
    sys::remove()
}

/// Whether a phone's USB debugging interface plugged in now is waiting for
/// a driver. One without a driver counts only once Windows has finished
/// setting up what was plugged in (or has given up on it): in the first
/// seconds after a phone is plugged in, Windows may still find one itself.
/// Needs no administrator rights.
pub fn detect() -> Result<Detection, DriverError> {
    sys::detect()
}

/// What [`install`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Install {
    /// This system needs no driver for phones.
    NotNeeded,
    /// Windows binds its own driver to every phone's USB debugging
    /// interface, so nothing of Captun's is installed; phones that had no
    /// driver were given Windows' own.
    WindowsHasOne(Phones),
    /// Installed now.
    Installed(Phones),
    /// It was installed already.
    AlreadyInstalled(Phones),
}

/// Phones plugged in now whose USB debugging interface had no driver.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Phones {
    /// Given the driver now.
    pub given: usize,
    /// Not given it now; they get it when plugged in again.
    pub failed: usize,
    /// Windows wants a restart before they can use it.
    pub restart: bool,
}

/// What [`remove`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remove {
    /// This system needs no driver for phones.
    NotNeeded,
    /// Captun's driver was not installed.
    NothingInstalled,
    /// The driver and its certificate are gone.
    Removed {
        /// Windows wants a restart to finish.
        restart: bool,
    },
}

/// Whether a phone's USB debugging interface is waiting for a driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Detection {
    /// None is plugged in (or this system needs no driver).
    None,
    /// None plugged in is waiting for a driver: each has one (working or
    /// not), or was turned off.
    Working,
    /// One plugged in has no driver yet, and Windows is still setting up
    /// what was plugged in: it may find one itself, so look again later.
    BeingSetUp,
    /// These have no driver, and Windows found none for them (Windows'
    /// instance IDs).
    Missing(Vec<String>),
}

/// Why installing, removing or looking failed.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// Installing and removing a driver need administrator rights.
    #[error("it needs administrator rights")]
    NotElevated,
    /// A step failed.
    #[error("{step} failed: {source}")]
    Failed {
        /// What was being done, in plain words.
        step: &'static str,
        #[source]
        source: io::Error,
    },
}

impl Install {
    /// What to tell someone whose phone still does not show after this.
    pub fn notice(&self) -> &'static str {
        match self {
            Self::WindowsHasOne(_) => WINDOWS_DRIVER_NOTICE,
            _ => INSTALLED_NOTICE,
        }
    }
}

impl DriverError {
    /// What to tell someone when installing failed: what happened, and what
    /// to do instead.
    pub fn install_advice(&self) -> String {
        format!(
            "Captun could not install the USB driver for Android phones: {self}. Install the USB driver from the phone maker's website, then unplug the phone and plug it in again."
        )
    }
}

impl fmt::Display for Install {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNeeded => f.write_str(NOT_NEEDED),
            Self::WindowsHasOne(phones) => {
                write!(
                    f,
                    "Windows on this computer brings its own USB driver for Android phones, so Captun installed none.{phones}"
                )
            }
            Self::Installed(phones) => write!(f, "Captun installed the USB driver for Android phones.{phones}"),
            Self::AlreadyInstalled(phones) => {
                write!(f, "Captun's USB driver for Android phones was already installed.{phones}")
            }
        }
    }
}

/// Follows a sentence, so it starts with a space when it says anything.
impl fmt::Display for Phones {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.given {
            0 => {}
            1 => f.write_str(" The phone plugged in now has it.")?,
            n => write!(f, " The {n} phones plugged in now have it.")?,
        }
        match self.failed {
            0 => {}
            1 => f.write_str(" A phone plugged in now did not get it: unplug it and plug it in again.")?,
            n => write!(f, " {n} phones plugged in now did not get it: unplug them and plug them in again.")?,
        }
        if self.restart {
            f.write_str(" Restart the computer before using the phone.")?;
        }
        Ok(())
    }
}

impl fmt::Display for Remove {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNeeded => f.write_str(NOT_NEEDED),
            Self::NothingInstalled => f.write_str("Captun's USB driver for Android phones was not installed."),
            Self::Removed { restart } => {
                f.write_str(
                    "Captun removed its USB driver for Android phones and the certificate it was signed with.",
                )?;
                if *restart {
                    f.write_str(" Restart the computer to finish.")?;
                }
                Ok(())
            }
        }
    }
}

const NOT_NEEDED: &str = "This system needs no USB driver for Android phones.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_read_as_plain_sentences() {
        assert_eq!(Install::NotNeeded.to_string(), NOT_NEEDED);
        assert_eq!(
            Install::Installed(Phones::default()).to_string(),
            "Captun installed the USB driver for Android phones."
        );
        assert_eq!(
            Install::Installed(Phones { given: 1, failed: 0, restart: false }).to_string(),
            "Captun installed the USB driver for Android phones. The phone plugged in now has it."
        );
        assert_eq!(
            Install::AlreadyInstalled(Phones { given: 2, failed: 1, restart: true }).to_string(),
            "Captun's USB driver for Android phones was already installed. The 2 phones plugged in now have it. \
             A phone plugged in now did not get it: unplug it and plug it in again. \
             Restart the computer before using the phone."
        );
        assert!(Install::WindowsHasOne(Phones::default()).to_string().starts_with("Windows on this computer brings"));
        assert_eq!(Install::WindowsHasOne(Phones::default()).notice(), WINDOWS_DRIVER_NOTICE);
        assert_eq!(Install::Installed(Phones::default()).notice(), INSTALLED_NOTICE);
        assert_eq!(Remove::NothingInstalled.to_string(), "Captun's USB driver for Android phones was not installed.");
        assert!(Remove::Removed { restart: true }.to_string().ends_with(" Restart the computer to finish."));
    }

    #[test]
    fn a_failure_says_what_failed_and_what_to_do() {
        let error = DriverError::Failed { step: "signing the driver", source: io::Error::other("no room") };
        assert_eq!(error.to_string(), "signing the driver failed: no room");
        let advice = error.install_advice();
        assert!(
            advice.starts_with("Captun could not install the USB driver for Android phones: signing the driver failed")
        );
        assert!(advice.ends_with("then unplug the phone and plug it in again."));
        assert_eq!(DriverError::NotElevated.to_string(), "it needs administrator rights");
    }

    #[test]
    fn only_windows_needs_a_driver() {
        assert_eq!(NEEDED, cfg!(windows));
        if !NEEDED {
            assert_eq!(install().ok(), Some(Install::NotNeeded));
            assert_eq!(remove().ok(), Some(Remove::NotNeeded));
            assert_eq!(detect().ok(), Some(Detection::None));
        }
    }

    #[cfg(windows)]
    #[test]
    fn installing_and_removing_are_refused_without_administrator_rights() {
        // A test run from an elevated prompt has the rights; that run is
        // covered by the ignored store test instead.
        if sys::is_elevated() {
            eprintln!("skipped: this test runs elevated");
            return;
        }
        assert!(matches!(install(), Err(DriverError::NotElevated)));
        assert!(matches!(remove(), Err(DriverError::NotElevated)));
    }
}
