//! This install's own CA (see the crate docs): made once, reloaded at every
//! start, and replaced only when it cannot be used any more.
//!
//! The folder it is kept in holds `ca.pem` (the certificate, public),
//! `ca.json` (its record: install id, when it was made, its SHA-256
//! fingerprint, which key store holds its key) and, for the key file store,
//! the key. The record is written last and deleted first, so a CA cut short
//! either way is never taken for a whole one. At every start the certificate
//! must still match its record, belong to its key, carry its own valid
//! signature and be this CA (its name, `CA:TRUE`, `pathlen:0`, may sign
//! certificates); the key must pass its store's checks. A CA that fails, or
//! has a day or less left, is replaced, and the caller is told why
//! ([`CaStatus`]). A failure to read or ask (a file the service may not
//! read, Windows' key service not answering) is an error instead: it says
//! nothing about the CA, and replacing it would make every device install a
//! new one for nothing.

use std::{fmt, path::Path, sync::Arc, time::SystemTime};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, SerialNumber, SignatureAlgorithm,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _},
};
use rustls::{
    crypto::ring::sign::any_ecdsa_type,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem, x509::X509Version};
use zeroize::Zeroizing;

use crate::{
    SiteName, TlsError,
    clock::{Clock, SystemClock},
    error::file_error,
    fsutil::{self, Contents},
    key::{CaSigner, InstallId, KeyLookup, KeyStore},
};

/// The content type for [`CertAuthority::certificate_pem`].
pub const PEM_CONTENT_TYPE: &str = "application/x-pem-file";
/// The content type for [`CertAuthority::certificate_der`]: Android and
/// Windows offer to install a CA certificate served as this.
pub const DER_CONTENT_TYPE: &str = "application/x-x509-ca-cert";

const CERT_FILE: &str = "ca.pem";
const RECORD_FILE: &str = "ca.json";
const RECORD_VERSION: u32 = 1;
/// Larger than any certificate or record Captun writes.
const MAX_FILE: u64 = 64 * 1024;

const NAME: &str = "Captun HTTPS inspection CA";
const ORGANIZATION: &str = "Captun";
/// The subject of every site certificate: no common name (nothing should
/// rely on one), only who made it, for anyone who looks.
const SITE_ORGANIZATION: &str = "Captun HTTPS inspection";
/// How long a CA is valid: three years.
const CA_LIFETIME: Duration = Duration::days(3 * 365);
/// How long a site certificate is valid. Apple accepts up to 825 days from a
/// CA its user added; short is safer, and costs only a new signature.
const SITE_LIFETIME: Duration = Duration::days(30);
/// How far back certificates start, for devices whose clocks run behind (a
/// phone with a flat battery or a laptop on the wrong time zone): two days,
/// as other inspection tools use. A site certificate never starts before the
/// CA itself.
const BACKDATE: Duration = Duration::days(2);
/// A site certificate is made again once less than this is left, and a CA
/// with less than this left is replaced.
pub(crate) const RENEW_BEFORE: Duration = Duration::days(1);

/// The CA's record, `ca.json`.
#[derive(Serialize, Deserialize)]
struct Record {
    version: u32,
    install_id: String,
    created_unix: i64,
    fingerprint_sha256: String,
    key_store: String,
}

/// What [`CertAuthority::open_or_create`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaStatus {
    /// The CA made before was used.
    Loaded,
    /// There was none; a new one was made.
    Created,
    /// The CA made before could not be used, for the reason given, and a new
    /// one took its place. Devices that installed the old one must install
    /// the new one ([`CaStatus::note`]).
    Replaced(ReplaceReason),
}

impl CaStatus {
    /// What to tell the person running Captun, if anything.
    pub fn note(&self) -> Option<String> {
        match self {
            Self::Replaced(reason) => Some(format!(
                "Captun made a new HTTPS inspection certificate because the old one {reason}. Devices that installed the old one must install the new one, and should remove the old one."
            )),
            Self::Loaded | Self::Created => None,
        }
    }
}

/// Why a CA was replaced.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplaceReason {
    /// Its record (`ca.json`) was missing or damaged.
    RecordLost,
    /// Its key was kept by another kind of key store than the one in use.
    OtherKeyStore,
    /// Its key was gone.
    KeyMissing,
    /// Its key was there but must not be used: not protected the way Captun
    /// protects its keys, or damaged.
    KeyUnusable(String),
    /// Its certificate file was gone.
    CertificateMissing,
    /// Its certificate was not the one made with its key and record.
    CertificateDamaged(String),
    /// It had a day or less left.
    Expired,
}

impl fmt::Display for ReplaceReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordLost => f.write_str("had lost its record"),
            Self::OtherKeyStore => f.write_str("kept its key where Captun no longer keeps it"),
            Self::KeyMissing => f.write_str("had lost its key"),
            Self::KeyUnusable(why) => write!(f, "had a key Captun could not trust ({why})"),
            Self::CertificateMissing => f.write_str("had lost its certificate file"),
            Self::CertificateDamaged(why) => write!(f, "had a damaged certificate ({why})"),
            Self::Expired => f.write_str("had run out"),
        }
    }
}

/// The SHA-256 fingerprint of a certificate, for people to compare what a
/// device shows with what Captun shows. Displayed as `AB:CD:…`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub(crate) fn of(der: &[u8]) -> Self {
        let hash = digest::digest(&digest::SHA256, der);
        Self(hash.as_ref().try_into().unwrap_or_default())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex without separators.
    pub fn hex(&self) -> String {
        fsutil::hex(&self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// This install's CA, ready to sign site certificates. Its private key stays
/// in its key store: every signature is asked of it.
pub struct CertAuthority {
    id: InstallId,
    name: String,
    created: OffsetDateTime,
    /// When the CA certificate starts, as it says itself (older CAs were
    /// backdated less), so no site certificate starts before it.
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    der: CertificateDer<'static>,
    fingerprint: Fingerprint,
    issuer: Issuer<'static, CaSigner>,
    clock: Arc<dyn Clock>,
    rng: SystemRandom,
}

/// What [`CertAuthority::load`] found.
enum Loaded {
    Ready(Box<CertAuthority>),
    Nothing,
    Replace(ReplaceReason),
}

fn damaged(why: &str) -> Loaded {
    Loaded::Replace(ReplaceReason::CertificateDamaged(why.to_owned()))
}

impl CertAuthority {
    /// The CA kept in `dir` with its key in `keys`: the one made before if
    /// it can still be used, otherwise a new one (see the module docs and
    /// [`CaStatus`]). `dir` is made if it is not there, and made again
    /// (Windows) or refused (Unix) if another account controls it. Only the
    /// service calls this, once at a time.
    ///
    /// An error (a key store that could not answer, a file that could not be
    /// read) leaves everything as it was: callers should report it and try
    /// again later, never reset. On Windows, call it after the service has
    /// finished starting, on a worker thread: Windows' documentation says a
    /// service must not open its key storage from its start-up routine, and
    /// early in boot the key isolation service may not be ready yet.
    pub fn open_or_create(dir: &Path, keys: &dyn KeyStore) -> Result<(Self, CaStatus), TlsError> {
        Self::open_or_create_with(dir, keys, Arc::new(SystemClock))
    }

    pub(crate) fn open_or_create_with(
        dir: &Path,
        keys: &dyn KeyStore,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, CaStatus), TlsError> {
        keys.prepare_folder(dir)?;
        let status = match Self::load(dir, keys, &clock)? {
            Loaded::Ready(ca) => {
                info!("using the HTTPS inspection certificate {} ({})", ca.name, ca.fingerprint);
                return Ok((*ca, CaStatus::Loaded));
            }
            Loaded::Nothing => CaStatus::Created,
            Loaded::Replace(reason) => {
                warn!("making a new HTTPS inspection certificate: the old one {reason}");
                CaStatus::Replaced(reason)
            }
        };
        let ca = Self::create(dir, keys, clock)?;
        info!("made the HTTPS inspection certificate {} ({})", ca.name, ca.fingerprint);
        Ok((ca, status))
    }

    fn load(dir: &Path, keys: &dyn KeyStore, clock: &Arc<dyn Clock>) -> Result<Loaded, TlsError> {
        let record_path = dir.join(RECORD_FILE);
        let cert_path = dir.join(CERT_FILE);
        let read_cert = || fsutil::read_small(&cert_path, MAX_FILE).map_err(file_error("read", &cert_path));
        let record = match fsutil::read_small(&record_path, MAX_FILE).map_err(file_error("read", &record_path))? {
            Contents::Bytes(bytes) => serde_json::from_slice::<Record>(&bytes).ok(),
            Contents::TooLarge => None,
            // Nothing at all is a first start; a certificate without its
            // record is what is left of a CA.
            Contents::Missing => {
                return Ok(match read_cert()? {
                    Contents::Missing => Loaded::Nothing,
                    _ => Loaded::Replace(ReplaceReason::RecordLost),
                });
            }
        };
        let Some((record, id, created)) = record.filter(|record| record.version == RECORD_VERSION).and_then(|record| {
            let id = InstallId::parse(&record.install_id)?;
            let created = OffsetDateTime::from_unix_timestamp(record.created_unix).ok()?;
            Some((record, id, created))
        }) else {
            return Ok(Loaded::Replace(ReplaceReason::RecordLost));
        };
        if record.key_store != keys.kind() {
            return Ok(Loaded::Replace(ReplaceReason::OtherKeyStore));
        }
        let key = match keys.open(&id)? {
            KeyLookup::Found(key) => key,
            KeyLookup::Missing => return Ok(Loaded::Replace(ReplaceReason::KeyMissing)),
            KeyLookup::Unusable(why) => return Ok(Loaded::Replace(ReplaceReason::KeyUnusable(why))),
        };
        let der = match read_cert()? {
            Contents::Missing => return Ok(Loaded::Replace(ReplaceReason::CertificateMissing)),
            Contents::TooLarge => return Ok(damaged("it is not a certificate")),
            Contents::Bytes(pem) => match der_from_pem(&pem) {
                Some(der) => der,
                None => return Ok(damaged("it is not a certificate")),
            },
        };
        let signer = CaSigner::new(key);
        if let Err(why) = check_ca(&der, &id, &signer, &record) {
            return Ok(damaged(why));
        }
        let ca = match Self::assemble(id, der, signer, created, Arc::clone(clock)) {
            Ok(ca) => ca,
            Err(why) => return Ok(damaged(why)),
        };
        if ca.not_after - clock.now() < RENEW_BEFORE {
            return Ok(Loaded::Replace(ReplaceReason::Expired));
        }
        Ok(Loaded::Ready(Box::new(ca)))
    }

    /// Makes a new CA in `dir` with a new key in `keys`, after deleting
    /// whatever is left of any earlier one. On failure nothing is left.
    fn create(dir: &Path, keys: &dyn KeyStore, clock: Arc<dyn Clock>) -> Result<Self, TlsError> {
        clear(dir, keys)?;
        let id = InstallId::random()?;
        let signer = CaSigner::new(keys.create(&id)?);
        let made = Self::make(dir, keys, id, signer, clock);
        if made.is_err()
            && let Err(e) = clear(dir, keys)
        {
            warn!("could not clean up after the HTTPS inspection certificate failed: {e}");
        }
        made
    }

    fn make(
        dir: &Path,
        keys: &dyn KeyStore,
        id: InstallId,
        signer: CaSigner,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, TlsError> {
        let rng = SystemRandom::new();
        let created = clock.now();
        let params = ca_params(&id, created, random_serial(&rng)?);
        let der = params.self_signed(&signer).map_err(|e| signer.explain(e))?.der().to_vec();
        let cert_path = dir.join(CERT_FILE);
        fsutil::write_replacing(&cert_path, pem_from_der(&der).as_bytes()).map_err(file_error("write", &cert_path))?;
        let record = Record {
            version: RECORD_VERSION,
            install_id: id.to_string(),
            created_unix: created.unix_timestamp(),
            fingerprint_sha256: Fingerprint::of(&der).hex(),
            key_store: keys.kind().to_owned(),
        };
        let json = serde_json::to_vec_pretty(&record).map_err(|e| TlsError::Certificate(e.to_string()))?;
        // The record last: until it is there, nothing here is taken for a CA.
        let record_path = dir.join(RECORD_FILE);
        fsutil::write_replacing(&record_path, &json).map_err(file_error("write", &record_path))?;
        Self::assemble(id, der, signer, created, clock).map_err(|why| TlsError::Certificate(why.to_owned()))
    }

    fn assemble(
        id: InstallId,
        der: Vec<u8>,
        signer: CaSigner,
        created: OffsetDateTime,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, &'static str> {
        let der = CertificateDer::from(der);
        let (not_before, not_after) = {
            let (_, cert) = parse_x509_certificate(&der).map_err(|_| "it is not a certificate")?;
            let at = |time: x509_parser::time::ASN1Time| {
                OffsetDateTime::from_unix_timestamp(time.timestamp()).map_err(|_| "its dates are wrong")
            };
            (at(cert.validity().not_before)?, at(cert.validity().not_after)?)
        };
        // The issuer's name and key identifier come from the certificate
        // itself, so site certificates name it exactly as it names itself.
        let issuer = Issuer::from_ca_cert_der(&der, signer).map_err(|_| "it is not a certificate")?;
        Ok(Self {
            name: ca_name(&id),
            id,
            created,
            not_before,
            not_after,
            fingerprint: Fingerprint::of(&der),
            der,
            issuer,
            clock,
            rng: SystemRandom::new(),
        })
    }

    /// The short id in this CA's name.
    pub fn install_id(&self) -> &InstallId {
        &self.id
    }

    /// This CA's name, as devices show it: "Captun HTTPS inspection CA <id>".
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn created(&self) -> SystemTime {
        self.created.into()
    }

    /// When this CA runs out (three years after it was made).
    pub fn not_after(&self) -> SystemTime {
        self.not_after.into()
    }

    /// The CA certificate in DER, as Android and Windows install it
    /// ([`DER_CONTENT_TYPE`]).
    pub fn certificate_der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// The CA certificate in PEM ([`PEM_CONTENT_TYPE`]).
    pub fn certificate_pem(&self) -> String {
        pem_from_der(&self.der)
    }

    /// The SHA-256 fingerprint of the CA certificate, to show beside it.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// A file name for downloads of the certificate, without an extension:
    /// `Captun-HTTPS-inspection-CA-<id>`.
    pub fn file_stem(&self) -> String {
        format!("Captun-HTTPS-inspection-CA-{}", self.id)
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// A new certificate for `site`, signed by this CA, with a P-256 key of
    /// its own made in memory and never written anywhere. Its only name is
    /// `site` (a subject alternative name; no common name), for `serverAuth`
    /// only, valid from two days ago (never before the CA) for 30 days (never past the CA), with a
    /// random serial number and both key identifiers. Each call makes a new
    /// one; [`crate::SiteCerts`] keeps them.
    pub fn issue(&self, site: &SiteName) -> Result<Arc<CertifiedKey>, TlsError> {
        self.issue_until(site).map(|(key, _)| key)
    }

    /// [`CertAuthority::issue`], with when the certificate runs out.
    pub(crate) fn issue_until(&self, site: &SiteName) -> Result<(Arc<CertifiedKey>, OffsetDateTime), TlsError> {
        let now = self.clock.now();
        if self.not_after - now < RENEW_BEFORE {
            return Err(TlsError::CaExpired);
        }
        let not_after = now.saturating_add(SITE_LIFETIME).min(self.not_after);
        let no_key = |_| TlsError::Certificate("a key for the site could not be made".into());
        let pkcs8 = Zeroizing::new(
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.rng).map_err(no_key)?.as_ref().to_vec(),
        );
        let point = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &self.rng)
            .map_err(|_| TlsError::Certificate("a key for the site could not be made".into()))?
            .public_key()
            .as_ref()
            .to_vec();

        let mut params = CertificateParams::default();
        let mut subject = DistinguishedName::new();
        subject.push(DnType::OrganizationName, SITE_ORGANIZATION);
        params.distinguished_name = subject;
        params.subject_alt_names = vec![site.subject_alt_name()?];
        // `CA:FALSE`, which also brings the subject key identifier.
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now.saturating_sub(BACKDATE).max(self.not_before);
        params.not_after = not_after;
        params.serial_number = Some(SerialNumber::from_slice(&random_serial(&self.rng)?));
        let cert = params.signed_by(&SitePublicKey(point), &self.issuer).map_err(|e| self.issuer.key().explain(e))?;

        let key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_slice())))
            .map_err(|e| TlsError::Certificate(format!("the site's key was refused ({e})")))?;
        Ok((Arc::new(CertifiedKey::new(vec![cert.into()], key)), not_after))
    }
}

impl fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertAuthority")
            .field("name", &self.name)
            .field("fingerprint", &self.fingerprint)
            .field("not_after", &self.not_after)
            .field("key", self.issuer.key())
            .finish_non_exhaustive()
    }
}

/// Deletes this install's CA kept in `dir`, and every CA key in `keys`,
/// whatever is left of them, so the next start makes a new CA. Deleting
/// carries on past a failure and reports the first one.
///
/// Devices that installed the CA keep trusting it until their users remove
/// it, but no one can sign with it any more. Drop the [`CertAuthority`]
/// (and what holds it) first: one still in use may not be able to sign.
pub fn reset(dir: &Path, keys: &dyn KeyStore) -> Result<(), TlsError> {
    clear(dir, keys)?;
    info!("deleted the HTTPS inspection certificate and its key");
    Ok(())
}

/// The record first: whatever a failure leaves behind is then not taken for
/// a CA.
fn clear(dir: &Path, keys: &dyn KeyStore) -> Result<(), TlsError> {
    let record = dir.join(RECORD_FILE);
    let cert = dir.join(CERT_FILE);
    let outcomes = [
        fsutil::remove_if_there(&record).map_err(file_error("delete", &record)),
        keys.delete_all(),
        fsutil::remove_if_there(&cert).map_err(file_error("delete", &cert)),
        fsutil::remove_unfinished(dir, &[CERT_FILE, RECORD_FILE]).map_err(file_error("clean up", dir)),
    ];
    outcomes.into_iter().find_map(Result::err).map_or(Ok(()), Err)
}

fn ca_name(id: &InstallId) -> String {
    format!("{NAME} {id}")
}

fn ca_params(id: &InstallId, now: OffsetDateTime, serial: [u8; 16]) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, ORGANIZATION);
    name.push(DnType::CommonName, ca_name(id));
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // TLS server certificates only: where a platform applies this to the
    // whole chain, the key cannot vouch for code, mail or client
    // certificates. No name constraints (see the crate docs).
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = now.saturating_sub(BACKDATE);
    params.not_after = now.saturating_add(CA_LIFETIME);
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params
}

/// A random serial number, 16 bytes that stay 16 in DER: the top bit clear
/// (a negative number is not a serial) and the next one set (no leading
/// zero to drop); 126 random bits.
fn random_serial(rng: &SystemRandom) -> Result<[u8; 16], TlsError> {
    let mut serial = [0u8; 16];
    rng.fill(&mut serial).map_err(|_| TlsError::Certificate("the computer gave no random numbers".into()))?;
    serial[0] = (serial[0] & 0x3F) | 0x40;
    Ok(serial)
}

/// Why `der` is not this CA's certificate, if it is not: the one its record
/// names, holding its key, signed by it, named for it, and a CA allowed to
/// sign certificates and nothing below it.
fn check_ca(der: &[u8], id: &InstallId, signer: &CaSigner, record: &Record) -> Result<(), &'static str> {
    if Fingerprint::of(der).hex() != record.fingerprint_sha256 {
        return Err("it is not the one its record names");
    }
    let (rest, cert) = parse_x509_certificate(der).map_err(|_| "it is not a certificate")?;
    if !rest.is_empty() || cert.version() != X509Version::V3 {
        return Err("it is not a certificate");
    }
    if cert.public_key().raw != signer.subject_public_key_info().as_slice() {
        return Err("it does not hold its key");
    }
    if cert.verify_signature(None).is_err() || cert.subject().as_raw() != cert.issuer().as_raw() {
        return Err("it is not signed with its key");
    }
    let name = cert.subject().iter_common_name().next().and_then(|name| name.as_str().ok());
    if name != Some(ca_name(id).as_str()) {
        return Err("it has another name");
    }
    let ca_only = cert
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|constraints| constraints.value.ca && constraints.value.path_len_constraint == Some(0));
    let signs = cert.key_usage().ok().flatten().is_some_and(|usage| usage.value.key_cert_sign());
    if !ca_only || !signs {
        return Err("it is not the CA Captun makes");
    }
    Ok(())
}

/// A site's public key, as rcgen puts it in the certificate.
struct SitePublicKey(Vec<u8>);

impl PublicKeyData for SitePublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

/// `der` as PEM, 64 characters a line, `\n` line ends on every system.
pub(crate) fn pem_from_der(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut pem = String::with_capacity(body.len() + body.len() / 64 + 64);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn der_from_pem(pem: &[u8]) -> Option<Vec<u8>> {
    let (_, pem) = parse_x509_pem(pem).ok()?;
    (pem.label == "CERTIFICATE").then_some(pem.contents)
}
