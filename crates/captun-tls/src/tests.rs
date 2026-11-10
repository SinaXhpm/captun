//! The CA end to end, with the key in memory or in a key file (the Windows
//! machine key, which needs an elevated run, is tested in `cng.rs`).

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::{
    ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::ring::default_provider,
    pki_types::{ServerName, UnixTime},
    sign::CertifiedKey,
};
use time::{Duration, OffsetDateTime};
use x509_parser::{
    certificate::X509Certificate,
    extensions::{GeneralName, ParsedExtension},
    oid_registry::{
        OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256, OID_X509_EXT_NAME_CONSTRAINTS, Oid,
    },
    parse_x509_certificate,
    pem::parse_x509_pem,
    x509::X509Version,
};

use crate::{
    CaStatus, CertAuthority, FileKeyStore, KeyLookup, KeyStore, MemoryKeyStore, ReplaceReason, SiteCerts, SiteName,
    TlsError,
    ca::Fingerprint,
    clock::{Clock, TestClock},
    reset,
};

/// A fresh, empty folder for one test.
fn folder(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("captun-tls-{test}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn open(dir: &Path, keys: &dyn KeyStore, clock: &Arc<TestClock>) -> (CertAuthority, CaStatus) {
    CertAuthority::open_or_create_with(dir, keys, Arc::clone(clock) as Arc<dyn Clock>).unwrap()
}

/// A new CA in memory, with a clock the test moves.
fn fresh(test: &str) -> (PathBuf, MemoryKeyStore, Arc<TestClock>, CertAuthority) {
    let dir = folder(test);
    let keys = MemoryKeyStore::new();
    let clock = TestClock::new();
    let (ca, status) = open(&dir, &keys, &clock);
    assert_eq!(status, CaStatus::Created);
    (dir, keys, clock, ca)
}

fn site(name: &str) -> SiteName {
    SiteName::parse(name).unwrap()
}

fn parsed(der: &[u8]) -> X509Certificate<'_> {
    let (rest, cert) = parse_x509_certificate(der).unwrap();
    assert!(rest.is_empty());
    cert
}

/// The subject and authority key identifiers of `cert`.
fn key_ids(cert: &X509Certificate<'_>) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let (mut subject, mut authority) = (None, None);
    for extension in cert.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => subject = Some(id.0.to_vec()),
            ParsedExtension::AuthorityKeyIdentifier(id) => {
                authority = id.key_identifier.as_ref().map(|id| id.0.to_vec());
            }
            _ => {}
        }
    }
    (subject, authority)
}

fn is_p256(cert: &X509Certificate<'_>) -> bool {
    let key = cert.public_key();
    let curve = key.algorithm.parameters.clone().and_then(|p| Oid::try_from(p).ok());
    key.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && curve == Some(OID_EC_P256)
        && key.subject_public_key.data.len() == 65
}

/// Checks `leaf` for `name` the way rustls' own (webpki) verifier does, with
/// only `ca` trusted, at the CA's time.
pub(crate) fn verify_leaf(ca: &CertAuthority, leaf: &CertifiedKey, name: &str) -> Result<(), rustls::Error> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate_der().clone())?;
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(default_provider()))
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    let name = ServerName::try_from(name.to_owned()).map_err(|e| rustls::Error::General(e.to_string()))?;
    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(ca.now().unix_timestamp().unsigned_abs()));
    verifier.verify_server_cert(&leaf.cert[0], &[], &name, &[], now).map(|_| ())
}

#[test]
fn a_new_ca_is_made_once_then_used_again() {
    let (dir, keys, clock, ca) = fresh("again");
    let (again, status) = open(&dir, &keys, &clock);
    assert_eq!(status, CaStatus::Loaded);
    assert_eq!(status.note(), None);
    assert_eq!(again.fingerprint(), ca.fingerprint());
    assert_eq!(again.install_id(), ca.install_id());
    assert_eq!(again.certificate_der(), ca.certificate_der());
    assert_eq!(again.created(), ca.created());
    // The one reloaded signs certificates the old one's devices accept.
    let leaf = again.issue(&site("example.com")).unwrap();
    verify_leaf(&ca, &leaf, "example.com").unwrap();
    // Another install has another CA.
    let (_, _, _, other) = fresh("again-other");
    assert_ne!(other.fingerprint(), ca.fingerprint());
    assert!(verify_leaf(&other, &leaf, "example.com").is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_ca_certificate_is_what_was_promised() {
    let (dir, _keys, clock, ca) = fresh("promised");
    let cert = parsed(ca.certificate_der());
    let made = clock.now().unix_timestamp();
    assert_eq!(cert.version(), X509Version::V3);
    assert_eq!(ca.name(), format!("Captun HTTPS inspection CA {}", ca.install_id()));
    let name = cert.subject().iter_common_name().next().unwrap().as_str().unwrap();
    assert_eq!(name, ca.name());
    assert_eq!(cert.subject().iter_organization().next().unwrap().as_str().unwrap(), "Captun");
    assert_eq!(cert.issuer().as_raw(), cert.subject().as_raw(), "self-signed");
    cert.verify_signature(None).unwrap();
    assert_eq!(cert.signature_algorithm.algorithm, OID_SIG_ECDSA_WITH_SHA256);
    assert!(is_p256(&cert), "ECDSA P-256");

    let constraints = cert.basic_constraints().unwrap().unwrap();
    assert!(constraints.critical && constraints.value.ca);
    assert_eq!(constraints.value.path_len_constraint, Some(0));
    let usage = cert.key_usage().unwrap().unwrap();
    assert!(usage.critical && usage.value.key_cert_sign() && usage.value.crl_sign());
    assert!(!usage.value.digital_signature() && !usage.value.key_encipherment());
    let extended = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(extended.server_auth);
    assert!(!extended.any && !extended.client_auth && !extended.code_signing && !extended.email_protection);
    assert!(extended.other.is_empty());
    assert!(cert.extensions().iter().all(|e| e.oid != OID_X509_EXT_NAME_CONSTRAINTS), "no name constraints");
    let (subject_id, _) = key_ids(&cert);
    assert_eq!(subject_id.map(|id| id.len()), Some(20));

    assert_eq!(cert.validity().not_before.timestamp(), made - 2 * 86400);
    assert_eq!(cert.validity().not_after.timestamp(), made + 3 * 365 * 86400);
    assert_eq!(OffsetDateTime::from(ca.not_after()).unix_timestamp(), made + 3 * 365 * 86400);
    assert_eq!(OffsetDateTime::from(ca.created()).unix_timestamp(), made);
    assert_eq!(cert.raw_serial().len(), 16);
    assert_eq!(cert.raw_serial()[0] & 0xC0, 0x40);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_key_file_store_keeps_the_ca_between_runs() {
    let dir = folder("file-store");
    let keys = FileKeyStore::for_this_user(&dir);
    let clock = TestClock::new();
    let (ca, status) = open(&dir, &keys, &clock);
    assert_eq!(status, CaStatus::Created);
    let key_file = dir.join(format!("ca-key-{}.pk8", ca.install_id()));
    assert!(key_file.is_file());
    let names: Vec<String> =
        fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names.len(), 3, "the key, the certificate and its record: {names:?}");

    // A new run, with a new store, finds the same CA.
    let (again, status) = open(&dir, &FileKeyStore::for_this_user(&dir), &clock);
    assert_eq!(status, CaStatus::Loaded);
    assert_eq!(again.fingerprint(), ca.fingerprint());
    verify_leaf(&ca, &again.issue(&site("example.com")).unwrap(), "example.com").unwrap();

    // The record holds the install id, when it was made and the fingerprint.
    let record: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("ca.json")).unwrap()).unwrap();
    assert_eq!(record["install_id"], ca.install_id().as_str());
    assert_eq!(record["fingerprint_sha256"], ca.fingerprint().hex());
    assert_eq!(record["created_unix"], clock.now().unix_timestamp());
    assert_eq!(record["key_store"], "file");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn site_certificates_check_out_with_rustls_for_names_and_addresses() {
    let (dir, _keys, _clock, ca) = fresh("verify");
    for (asked, checked) in [
        ("example.com", "example.com"),
        ("WWW.Example.COM.", "www.example.com"),
        ("localhost", "localhost"),
        ("192.0.2.7", "192.0.2.7"),
        ("[2001:db8::1]", "2001:db8::1"),
    ] {
        let leaf = ca.issue(&site(asked)).unwrap();
        verify_leaf(&ca, &leaf, checked).unwrap_or_else(|e| panic!("{asked}: {e}"));
        leaf.keys_match().unwrap();
    }
    // A certificate is for its own site only.
    let leaf = ca.issue(&site("example.com")).unwrap();
    for other in ["www.example.com", "example.org", "192.0.2.7"] {
        let err = verify_leaf(&ca, &leaf, other).unwrap_err();
        assert!(matches!(err, rustls::Error::InvalidCertificate(_)), "{other}: {err}");
    }
    let leaf = ca.issue(&site("192.0.2.7")).unwrap();
    assert!(verify_leaf(&ca, &leaf, "192.0.2.8").is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn site_certificates_carry_what_was_promised() {
    let (dir, _keys, clock, ca) = fresh("leaf");
    let ca_cert = parsed(ca.certificate_der());
    let now = clock.now().unix_timestamp();
    let leaf = ca.issue(&site("www.example.com")).unwrap();
    assert_eq!(leaf.cert.len(), 1, "only the site's own certificate is sent");
    let cert = parsed(&leaf.cert[0]);

    assert_eq!(cert.version(), X509Version::V3);
    let names = cert.subject_alternative_name().unwrap().unwrap().value.general_names.clone();
    assert_eq!(names, vec![GeneralName::DNSName("www.example.com")]);
    assert_eq!(cert.subject().iter_common_name().count(), 0, "no common name");
    assert_eq!(cert.subject().iter_organization().next().unwrap().as_str().unwrap(), "Captun HTTPS inspection");
    assert_eq!(cert.issuer().as_raw(), ca_cert.subject().as_raw());
    cert.verify_signature(Some(ca_cert.public_key())).unwrap();
    assert_eq!(cert.signature_algorithm.algorithm, OID_SIG_ECDSA_WITH_SHA256);

    let extended = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(extended.server_auth);
    assert!(!extended.any && !extended.client_auth && !extended.code_signing && extended.other.is_empty());
    let usage = cert.key_usage().unwrap().unwrap();
    assert!(usage.value.digital_signature() && !usage.value.key_cert_sign());
    let constraints = cert.basic_constraints().unwrap().unwrap();
    assert!(!constraints.value.ca);

    assert_eq!(cert.validity().not_before.timestamp(), now - 2 * 86400);
    assert_eq!(cert.validity().not_after.timestamp(), now + 30 * 86400);
    assert!(is_p256(&cert), "ECDSA P-256");
    assert_eq!(cert.raw_serial().len(), 16);

    let (subject_id, authority_id) = key_ids(&cert);
    assert!(subject_id.is_some());
    assert_eq!(authority_id, key_ids(&ca_cert).0, "names the CA's key");

    // An IP address is an IP address name, not a DNS one.
    let by_address = ca.issue(&site("192.0.2.7")).unwrap();
    let names = parsed(&by_address.cert[0]).subject_alternative_name().unwrap().unwrap().value.general_names.clone();
    assert_eq!(names, vec![GeneralName::IPAddress(&[192, 0, 2, 7])]);

    // Every certificate has a key and a serial number of its own.
    let again = ca.issue(&site("www.example.com")).unwrap();
    let again = parsed(&again.cert[0]);
    assert_ne!(again.public_key().raw, cert.public_key().raw);
    assert_ne!(again.raw_serial(), cert.raw_serial());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_site_certificate_never_outlives_the_ca() {
    let (dir, _keys, clock, ca) = fresh("ca-end");
    let end = OffsetDateTime::from(ca.not_after()).unix_timestamp();
    clock.advance(Duration::days(3 * 365 - 10));
    let leaf = ca.issue(&site("example.com")).unwrap();
    assert_eq!(parsed(&leaf.cert[0]).validity().not_after.timestamp(), end);
    verify_leaf(&ca, &leaf, "example.com").unwrap();

    clock.advance(Duration::days(10) - Duration::hours(12));
    assert!(matches!(ca.issue(&site("example.com")), Err(TlsError::CaExpired)));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_cache_keeps_at_most_its_capacity_dropping_the_least_recently_used() {
    let (dir, _keys, _clock, ca) = fresh("cache");
    let certs = SiteCerts::with_capacity(Arc::new(ca), 3);
    assert!(certs.is_empty());
    let a = certs.leaf_for("a.example").unwrap();
    let b = certs.leaf_for("b.example").unwrap();
    let c = certs.leaf_for("c.example").unwrap();
    assert!(Arc::ptr_eq(&certs.leaf_for("a.example").unwrap(), &a), "kept");
    // b is now the one used longest ago, so d takes its place.
    certs.leaf_for("d.example").unwrap();
    assert_eq!(certs.len(), 3);
    assert!(Arc::ptr_eq(&certs.leaf_for("a.example").unwrap(), &a));
    assert!(Arc::ptr_eq(&certs.leaf_for("c.example").unwrap(), &c));
    let b_again = certs.leaf_for("b.example").unwrap();
    assert!(!Arc::ptr_eq(&b_again, &b), "made again");
    assert_eq!(certs.len(), 3);
    // One site, however it is spelled, is one entry.
    assert!(Arc::ptr_eq(&certs.leaf_for("B.Example.").unwrap(), &b_again));
    assert!(certs.leaf_for("not a name").is_err());
    assert_eq!(certs.len(), 3);

    let one = SiteCerts::with_capacity(Arc::clone(certs.authority()), 0);
    one.leaf_for("a.example").unwrap();
    one.leaf_for("b.example").unwrap();
    assert_eq!(one.len(), 1, "room for one at least");
    assert_eq!(crate::DEFAULT_CAPACITY, 4096);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_cache_makes_a_certificate_again_when_less_than_a_day_is_left() {
    let (dir, _keys, clock, ca) = fresh("remint");
    let certs = SiteCerts::new(Arc::new(ca));
    let first = certs.leaf_for("example.com").unwrap();
    clock.advance(Duration::days(28));
    assert!(Arc::ptr_eq(&certs.leaf_for("example.com").unwrap(), &first), "two days left: kept");
    clock.advance(Duration::hours(36));
    let second = certs.leaf_for("example.com").unwrap();
    assert!(!Arc::ptr_eq(&second, &first), "half a day left: made again");
    verify_leaf(certs.authority(), &second, "example.com").unwrap();
    assert!(Arc::ptr_eq(&certs.leaf_for("example.com").unwrap(), &second));
    assert_eq!(certs.len(), 1);
    fs::remove_dir_all(&dir).unwrap();
}

/// Moves what `from` has to send into `to`.
fn transfer(from: &mut Connection, to: &mut Connection) -> Result<(), rustls::Error> {
    let io = |e: std::io::Error| rustls::Error::General(e.to_string());
    let mut bytes = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut bytes).map_err(io)?;
    }
    let mut unread = &bytes[..];
    while !unread.is_empty() {
        to.read_tls(&mut unread).map_err(io)?;
        to.process_new_packets()?;
    }
    Ok(())
}

/// A whole TLS handshake in memory: a client that trusts only `ca`, asking
/// for `name`, and a server that takes its certificates from `certs`.
fn handshake(certs: Arc<SiteCerts>, name: ServerName<'static>) -> Result<(), rustls::Error> {
    let provider = Arc::new(default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(certs.authority().certificate_der().clone())?;
    let client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(certs);
    let mut client = Connection::from(ClientConnection::new(Arc::new(client), name)?);
    let mut server = Connection::from(ServerConnection::new(Arc::new(server))?);
    for _ in 0..10 {
        transfer(&mut client, &mut server)?;
        transfer(&mut server, &mut client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err(rustls::Error::General("the handshake did not finish".into()))
}

#[test]
fn the_resolver_answers_by_the_name_asked_for_and_not_without_one() {
    let (dir, _keys, _clock, ca) = fresh("resolver");
    let certs = Arc::new(SiteCerts::new(Arc::new(ca)));
    handshake(Arc::clone(&certs), ServerName::try_from("example.com").unwrap()).unwrap();
    handshake(Arc::clone(&certs), ServerName::try_from("www.example.org").unwrap()).unwrap();
    assert_eq!(certs.len(), 2);
    // A client asking for an address sends no name (SNI): no certificate,
    // so the caller can pass the connection through.
    let err = handshake(Arc::clone(&certs), ServerName::try_from("192.0.2.7").unwrap()).unwrap_err();
    assert!(err.to_string().contains("no server certificate"), "{err}");
    assert_eq!(certs.len(), 2);
    fs::remove_dir_all(&dir).unwrap();
}

/// Makes a CA, deletes it with `reset`, and checks that nothing is left and
/// the next start makes a new one.
fn reset_round_trip(dir: &Path, keys: &dyn KeyStore) {
    let clock = TestClock::new();
    let (ca, _) = CertAuthority::open_or_create_with(dir, keys, Arc::clone(&clock) as Arc<dyn Clock>).unwrap();
    let (id, old) = (ca.install_id().clone(), ca.fingerprint());
    drop(ca);
    reset(dir, keys).unwrap();
    assert!(matches!(keys.open(&id).unwrap(), KeyLookup::Missing));
    let left: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert!(left.is_empty(), "nothing is left: {left:?}");

    let (ca, status) = CertAuthority::open_or_create_with(dir, keys, clock).unwrap();
    assert_eq!(status, CaStatus::Created, "a new CA, not a replacement: nothing was left of the old one");
    assert_ne!(ca.fingerprint(), old);
    drop(ca);
    reset(dir, keys).unwrap();
}

#[test]
fn reset_deletes_everything_and_the_next_start_makes_a_new_ca() {
    let dir = folder("reset-memory");
    reset_round_trip(&dir, &MemoryKeyStore::new());
    let dir = folder("reset-file");
    reset_round_trip(&dir, &FileKeyStore::for_this_user(&dir));
    fs::remove_dir_all(&dir).unwrap();
    // Nothing there at all is fine too.
    let nowhere = folder("reset-nowhere");
    reset(&nowhere, &FileKeyStore::for_this_user(&nowhere)).unwrap();
    assert!(!nowhere.exists());
}

#[test]
fn reset_works_on_whatever_is_left() {
    let dir = folder("reset-half");
    let keys = FileKeyStore::for_this_user(&dir);
    let clock = TestClock::new();
    let parts: [&[&str]; 4] = [&["ca.json"], &["ca.pem"], &["ca.json", "ca.pem"], &["key"]];
    for gone in parts {
        let (ca, _) = open(&dir, &keys, &clock);
        let key_file = dir.join(format!("ca-key-{}.pk8", ca.install_id()));
        drop(ca);
        for part in gone {
            fs::remove_file(if *part == "key" { key_file.clone() } else { dir.join(part) }).unwrap();
        }
        // And a file a crash left half written.
        fs::write(dir.join("ca.pem.unfinished-0011223344556677"), b"half").unwrap();
        reset(&dir, &keys).unwrap();
        let left: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(left.is_empty(), "{gone:?} gone, then nothing is left: {left:?}");
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_ca_with_parts_missing_or_damaged_is_replaced_with_a_reason() {
    let dir = folder("parts");
    let keys = MemoryKeyStore::new();
    let clock = TestClock::new();
    let record = dir.join("ca.json");
    let cert = dir.join("ca.pem");
    let (other_dir, _, _, other) = fresh("parts-other");

    /// What is done to the CA, and why it is then replaced.
    type Damage<'a> = (&'static str, Box<dyn Fn() + 'a>, ReplaceReason);
    let damages: Vec<Damage<'_>> = vec![
        ("the key gone", Box::new(|| keys.delete_all().unwrap()), ReplaceReason::KeyMissing),
        ("the certificate gone", Box::new(|| fs::remove_file(&cert).unwrap()), ReplaceReason::CertificateMissing),
        ("the record gone", Box::new(|| fs::remove_file(&record).unwrap()), ReplaceReason::RecordLost),
        ("the record not JSON", Box::new(|| fs::write(&record, b"{ not json").unwrap()), ReplaceReason::RecordLost),
        (
            "the record far too big",
            Box::new(|| fs::write(&record, vec![b' '; 100_000]).unwrap()),
            ReplaceReason::RecordLost,
        ),
        (
            "the record from another key store",
            Box::new(|| edit_record(&record, "key_store", "file".into())),
            ReplaceReason::OtherKeyStore,
        ),
        (
            "the record with a bad id",
            Box::new(|| edit_record(&record, "install_id", "../../etc".into())),
            ReplaceReason::RecordLost,
        ),
        (
            "the certificate not PEM",
            Box::new(|| fs::write(&cert, b"hello").unwrap()),
            ReplaceReason::CertificateDamaged("it is not a certificate".into()),
        ),
        (
            "the certificate of another CA",
            Box::new(|| fs::copy(other_dir.join("ca.pem"), &cert).map(drop).unwrap()),
            ReplaceReason::CertificateDamaged("it is not the one its record names".into()),
        ),
        (
            "the certificate and the fingerprint of another CA",
            Box::new(|| {
                fs::copy(other_dir.join("ca.pem"), &cert).unwrap();
                edit_record(&record, "fingerprint_sha256", other.fingerprint().hex().into());
            }),
            ReplaceReason::CertificateDamaged("it does not hold its key".into()),
        ),
    ];
    for (what, damage, reason) in damages {
        let (ca, _) = open(&dir, &keys, &clock);
        let old = ca.fingerprint();
        drop(ca);
        damage();
        let (ca, status) = open(&dir, &keys, &clock);
        assert_eq!(status, CaStatus::Replaced(reason), "{what}");
        assert!(status.note().unwrap().contains("Devices that installed the old one must install the new one"));
        assert_ne!(ca.fingerprint(), old, "{what}");
        verify_leaf(&ca, &ca.issue(&site("example.com")).unwrap(), "example.com").unwrap();
        drop(ca);
        let (_, status) = open(&dir, &keys, &clock);
        assert_eq!(status, CaStatus::Loaded, "{what}: the new one is used from then on");
    }
    fs::remove_dir_all(&dir).unwrap();
    fs::remove_dir_all(&other_dir).unwrap();
}

/// Sets `field` of the record at `path` to `value`.
fn edit_record(path: &Path, field: &str, value: serde_json::Value) {
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    record[field] = value;
    fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
}

#[test]
fn a_ca_that_runs_out_is_replaced() {
    let (dir, keys, clock, ca) = fresh("expired");
    let old = ca.fingerprint();
    drop(ca);
    clock.advance(Duration::days(3 * 365 - 2));
    let (ca, status) = open(&dir, &keys, &clock);
    assert_eq!(status, CaStatus::Loaded, "two days left: still used");
    drop(ca);
    clock.advance(Duration::days(1) + Duration::hours(12));
    let (ca, status) = open(&dir, &keys, &clock);
    assert_eq!(status, CaStatus::Replaced(ReplaceReason::Expired));
    assert!(status.note().unwrap().contains("because the old one had run out"));
    assert_ne!(ca.fingerprint(), old);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn what_devices_get() {
    let (dir, _keys, _clock, ca) = fresh("devices");
    let der = ca.certificate_der().to_vec();

    let pem = ca.certificate_pem();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n") && pem.ends_with("-----END CERTIFICATE-----\n"));
    assert!(!pem.contains('\r') && pem.lines().all(|line| line.len() <= 64));
    let (_, read) = parse_x509_pem(pem.as_bytes()).unwrap();
    assert_eq!(read.contents, der);
    assert_eq!(fs::read_to_string(dir.join("ca.pem")).unwrap(), pem, "the saved file is the same");

    let fingerprint = ca.fingerprint();
    assert_eq!(fingerprint, Fingerprint::of(&der));
    let shown = fingerprint.to_string();
    assert_eq!(shown.len(), 32 * 3 - 1);
    assert!(
        shown
            .split(':')
            .all(|pair| pair.len() == 2 && pair.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()))
    );
    assert_eq!(shown.replace(':', "").to_ascii_lowercase(), fingerprint.hex());
    assert_eq!(ca.file_stem(), format!("Captun-HTTPS-inspection-CA-{}", ca.install_id()));

    let profile = ca.mobileconfig();
    assert!(profile.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist"));
    for part in [
        "<string>com.apple.security.root</string>",
        "<string>Configuration</string>",
        "<string>Captun HTTPS inspection</string>",
        // Honest about the scope: the device trusts it everywhere.
        "on every network until you remove this profile",
        "<key>fa</key>",
        "<string>app.captun.https-inspection</string>",
        "<key>ConsentText</key>",
        "Certificate Trust Settings",
        "passwords",
        "<key>PayloadRemovalDisallowed</key>",
        "<false/>",
    ] {
        assert!(profile.contains(part), "{part}");
    }
    assert!(!profile.contains("this network only"), "no promise the device does not keep");
    assert!(profile.contains(&format!("<string>{}</string>", ca.name())));
    assert!(profile.contains(&format!("<string>{}.cer</string>", ca.file_stem())));
    for (open, close) in
        [("<dict>", "</dict>"), ("<array>", "</array>"), ("<data>", "</data>"), ("<string>", "</string>")]
    {
        assert_eq!(profile.matches(open).count(), profile.matches(close).count(), "{open}");
    }
    let data = profile.split("<data>").nth(1).unwrap().split("</data>").next().unwrap();
    assert_eq!(STANDARD.decode(data.split_whitespace().collect::<String>()).unwrap(), der, "it holds this CA");
    assert_eq!(profile, ca.mobileconfig(), "the same CA gives the same profile");

    // Another CA: another certificate and other payload ids, the same
    // profile identifier (a newer one replaces the older one on a device).
    let (other_dir, _, _, other) = fresh("devices-other");
    let uuids = |profile: &str| -> Vec<String> {
        let values = profile.split("<key>PayloadUUID</key>").skip(1);
        values
            .map(|rest| rest.split("</string>").next().unwrap().trim().trim_start_matches("<string>").to_owned())
            .collect()
    };
    let (mine, theirs) = (uuids(&profile), uuids(&other.mobileconfig()));
    assert_eq!(mine.len(), 2);
    assert!(mine.iter().all(|id| !theirs.contains(id)));
    assert!(other.mobileconfig().contains("<string>app.captun.https-inspection</string>"));
    fs::remove_dir_all(&dir).unwrap();
    fs::remove_dir_all(&other_dir).unwrap();
}

#[cfg(unix)]
#[test]
fn a_key_file_others_may_read_gets_the_ca_replaced() {
    use std::os::unix::fs::PermissionsExt;

    let dir = folder("loose-key");
    let keys = FileKeyStore::for_this_user(&dir);
    let clock = TestClock::new();
    let (ca, _) = open(&dir, &keys, &clock);
    let key_file = dir.join(format!("ca-key-{}.pk8", ca.install_id()));
    drop(ca);
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();

    let (ca, status) = open(&dir, &keys, &clock);
    assert_eq!(
        status,
        CaStatus::Replaced(ReplaceReason::KeyUnusable("other users may read or change the key file".into()))
    );
    assert!(!key_file.exists(), "the old key is deleted");
    let new_key = dir.join(format!("ca-key-{}.pk8", ca.install_id()));
    assert_eq!(fs::metadata(&new_key).unwrap().permissions().mode() & 0o777, 0o600);
    fs::remove_dir_all(&dir).unwrap();
}

/// A key store that answers like the real one until it is told to fail
/// every question, the way a passing fault in Windows' key service would.
#[derive(Debug)]
struct Flaky<'a> {
    inner: &'a MemoryKeyStore,
}

impl KeyStore for Flaky<'_> {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    fn prepare_folder(&self, dir: &Path) -> Result<(), TlsError> {
        self.inner.prepare_folder(dir)
    }

    fn create(&self, _id: &crate::key::InstallId) -> Result<Box<dyn crate::CaKey>, TlsError> {
        Err(TlsError::Key("Windows could not make the key (error 0x80090030)".into()))
    }

    fn open(&self, _id: &crate::key::InstallId) -> Result<KeyLookup, TlsError> {
        Err(TlsError::Key("Windows could not say who may use the key (error 0x80090030)".into()))
    }

    fn delete_all(&self) -> Result<(), TlsError> {
        Err(TlsError::Key("Windows could not list its keys (error 0x80090030)".into()))
    }
}

/// A store that cannot answer is an error, never a reason to replace the CA:
/// the certificate, its record and its key all stay, and the next start with
/// a working store loads the very same CA.
#[test]
fn a_store_that_cannot_answer_leaves_the_ca_alone() {
    let (dir, keys, clock, ca) = fresh("flaky-store");
    let fingerprint = ca.fingerprint();
    drop(ca);

    let flaky = Flaky { inner: &keys };
    let failed = CertAuthority::open_or_create_with(&dir, &flaky, Arc::clone(&clock) as Arc<dyn Clock>);
    assert!(failed.is_err(), "a failed question must fail the start");
    assert!(dir.join("ca.pem").exists() && dir.join("ca.json").exists(), "nothing was deleted");

    let (again, status) = open(&dir, &keys, &clock);
    assert_eq!(status, CaStatus::Loaded);
    assert_eq!(again.fingerprint(), fingerprint, "the same CA, so no device has to install it again");
    fs::remove_dir_all(&dir).unwrap();
}

/// Certificates start two days back for devices whose clocks run behind, but
/// a site certificate never starts before the CA itself, even when this
/// computer's clock was put back after the CA was made.
#[test]
fn site_certificates_never_start_before_the_ca() {
    let (dir, _keys, clock, ca) = fresh("leaf-start");
    let ca_start = parsed(ca.certificate_der()).validity().not_before.timestamp();
    assert_eq!(ca_start, clock.now().unix_timestamp() - 2 * 86400);
    clock.advance(Duration::days(-1));
    let leaf = ca.issue(&site("example.com")).unwrap();
    assert_eq!(parsed(&leaf.cert[0]).validity().not_before.timestamp(), ca_start);
    fs::remove_dir_all(&dir).unwrap();
}

/// Connections that ask for the same site at the same time share one
/// certificate (one signature by the CA key), not one each.
#[test]
fn callers_at_the_same_time_share_one_certificate() {
    let (dir, _keys, _clock, ca) = fresh("single-flight");
    let certs = Arc::new(SiteCerts::new(Arc::new(ca)));
    let start = Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let certs = Arc::clone(&certs);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                certs.leaf_for("same.example").unwrap()
            })
        })
        .collect();
    let got: Vec<Arc<CertifiedKey>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(got.iter().all(|cert| Arc::ptr_eq(cert, &got[0])), "one certificate for everyone");
    assert_eq!(certs.len(), 1);
    fs::remove_dir_all(&dir).unwrap();
}
