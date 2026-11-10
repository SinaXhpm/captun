//! Captun's **built-in adb**: a native USB Android Debug Bridge client, so the
//! app needs no external `adb` binary and no Android platform-tools installed.
//! Only USB debugging on the phone is required.
//!
//! It drives one thing: **reverse tethering** ([`reverse_plan`]), the phone
//! using *this PC's* internet. Captun only ever gives internet; it never uses
//! the phone's. The default, privacy-preserving method installs nothing: it
//! brings up the USB network link ([`link_up_command`]) and points the phone's
//! system HTTP proxy at the PC. A fuller method that also carries UDP uses a
//! helper pushed over adb (no app store, removable).
//!
//! The ADB wire protocol (device discovery, CNXN/AUTH with a persistent RSA key,
//! shell, install) is spoken directly over libusb by the [`native`] module via
//! the [`adb_client`] crate. That key, which a phone trusts once the user
//! allows it, is checked and kept private by the [`key`] module. The [`Adb`]
//! runner drives it all asynchronously with a timeout and reverts plans
//! best-effort. Operations are modelled as pure [`AdbOp`] data so plans are
//! unit-tested without a phone attached.
//!
//! After any session, show the user [`post_session_caution`]: Captun reverts the
//! phone-side changes it made, but it cannot turn USB debugging back off itself
//! (that would cut its own control), so the user must.

mod caution;
mod command;
mod device;
mod key;
mod link;
mod native;
mod plan;
mod reverse;
mod runner;

pub use caution::{SessionSummary, post_session_caution};
pub use command::UsbFunction;
pub use device::{AdbDevice, DeviceState};
pub use key::{KeyStatus, KeyTakeover, take_over_key};
pub use link::{link_down_command, link_hint, link_up_command};
pub use plan::{AdbOp, ReversiblePlan};
pub use reverse::{HelperApp, ReverseMethod, ReverseParams, reverse_plan};
pub use runner::{Adb, AdbError};
