//! HTTPS inspection, phase 1: the certificates. Nothing in this crate touches
//! traffic; the TLS terminators of later phases use what it makes.
//!
//! - [`CertAuthority`]: this install's own CA, "Captun HTTPS inspection CA
//!   <id>", made the first time it is needed and never shipped or shared: two
//!   installs never have the same key, so a key taken from one computer opens
//!   nothing on devices that trust another (the Superfish mistake, US-CERT
//!   TA15-051A, was one key for every install). ECDSA P-256, `CA:TRUE`,
//!   `pathlen:0`, key usage `keyCertSign` + `cRLSign`, extended key usage
//!   `serverAuth` only (so on platforms that apply it to the whole chain the
//!   key cannot vouch for code, mail or client certificates), valid three
//!   years. [`reset`] deletes it, and the next start makes a new one.
//! - The CA's private key is kept where only the service can use it
//!   ([`KeyStore`], [`system_key_store`]). On Windows it is a machine key in
//!   CNG that Windows will not export, which only SYSTEM and Administrators
//!   may use; Windows keeps it in its key isolation service and signs on
//!   Captun's behalf, so the key never enters Captun's process. On Linux and
//!   macOS (until a keychain backend exists) it is a PKCS#8 file only root
//!   may read, in a folder only root may change.
//! - [`SiteCerts`]: certificates for the sites a device opens, made on demand
//!   with a fresh in-memory key each, valid 30 days, cached, and re-made a day
//!   before they run out; also a rustls `ResolvesServerCert`.
//! - What devices install: the CA certificate as PEM and DER, its SHA-256
//!   fingerprint to compare on screen, and an iOS/iPadOS profile
//!   ([`CertAuthority::mobileconfig`]).
//!
//! **No name constraints.** The CA carries no `nameConstraints`: Captun
//! inspects every site a consenting device opens except those on the bypass
//! list, and "everything but these" cannot be said with permitted names.
//! Excluding the bypass list would put it into the certificate, so every
//! change to it would mean a new CA, installed again on every device; and
//! not every platform applies name constraints to a root its user installed.
//! What limits the damage of a stolen key instead: one CA per install, the
//! key kept where only the service can use it, `serverAuth` only, three
//! years, and rotation with [`reset`].
//!
//! **Consent.** The certificate is only ever handed to a device for its user
//! to install themselves, after they have read and accepted what it allows.
//! Nothing here installs it anywhere, and nothing ever should: no silent
//! install, no system certificate store. Inspecting someone's traffic without
//! their consent is a crime in most places.

mod ca;
mod clock;
#[cfg(windows)]
mod cng;
mod error;
#[cfg(any(unix, test))]
mod file_store;
mod fsutil;
mod key;
mod name;
mod profile;
#[cfg(any(windows, test))]
mod sddl;
mod sites;
#[cfg(test)]
mod tests;

use std::path::Path;

pub use ca::{CaStatus, CertAuthority, DER_CONTENT_TYPE, Fingerprint, PEM_CONTENT_TYPE, ReplaceReason, reset};
#[cfg(windows)]
pub use cng::CngKeyStore;
pub use error::TlsError;
#[cfg(any(unix, test))]
pub use file_store::FileKeyStore;
pub use key::{CaKey, InstallId, KeyLookup, KeyStore, MemoryKeyStore};
pub use name::SiteName;
pub use profile::MOBILECONFIG_CONTENT_TYPE;
pub use sites::{DEFAULT_CAPACITY, SiteCerts};

/// The key store the service keeps the CA key in on this system: on Windows
/// a non-exportable machine key in CNG ([`CngKeyStore`]); on Linux and macOS
/// a key file only root may read, in `dir` ([`FileKeyStore`]). `dir` is the
/// folder [`CertAuthority::open_or_create`] is given.
///
/// Where `dir` goes matters for the key file: on Linux use the service's
/// state folder, `/var/lib/captun/https-inspection`, never anything under
/// `/etc` (etckeeper commits /etc into git and routine backups copy it, and a
/// reset cannot delete those copies). On macOS the key file is kept out of
/// Time Machine. On Windows, call it after the service has finished starting,
/// on a worker thread (see [`CertAuthority::open_or_create`]).
pub fn system_key_store(#[cfg_attr(windows, allow(unused_variables))] dir: &Path) -> Box<dyn KeyStore> {
    #[cfg(windows)]
    return Box::new(CngKeyStore::new());
    #[cfg(unix)]
    return Box::new(FileKeyStore::new(dir));
}
