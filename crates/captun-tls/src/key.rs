//! Where the CA's private key is kept, and how certificates are signed with
//! it without taking it out of there.

use std::{
    cell::RefCell,
    collections::HashMap,
    fmt, fs,
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use rcgen::{PKCS_ECDSA_P256_SHA256, PublicKeyData, SignatureAlgorithm, SigningKey};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _},
};
use zeroize::Zeroizing;

use crate::{TlsError, error::file_error};

/// Which CA a key belongs to: eight characters (0-9, A-F), random for each
/// CA. It is in the CA's name, so devices and people can tell one CA from
/// the one before it, and in the name the key is kept under.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct InstallId(String);

impl InstallId {
    /// A new random id.
    pub(crate) fn random() -> Result<Self, TlsError> {
        let mut bytes = [0u8; 4];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| TlsError::Key("the computer gave no random numbers to make it with".into()))?;
        Ok(Self(bytes.iter().map(|b| format!("{b:02X}")).collect()))
    }

    /// `text` if it is an id: exactly eight characters 0-9 or A-F.
    pub fn parse(text: &str) -> Option<Self> {
        (text.len() == 8 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))).then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InstallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for InstallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InstallId({})", self.0)
    }
}

/// The CA's key wherever it is kept. It gives out its public key and signs;
/// it never gives out its private key.
pub trait CaKey: Send + Sync + fmt::Debug {
    /// The public key: an uncompressed P-256 point (65 bytes, the first 0x04).
    fn public_point(&self) -> &[u8];

    /// Signs `message` with ECDSA P-256 over its SHA-256 hash, and gives the
    /// signature in ASN.1 DER (as certificates carry it).
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError>;
}

impl<K: CaKey + ?Sized> CaKey for Arc<K> {
    fn public_point(&self) -> &[u8] {
        (**self).public_point()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        (**self).sign(message)
    }
}

/// What [`KeyStore::open`] found.
#[derive(Debug)]
pub enum KeyLookup {
    /// The key, checked.
    Found(Box<dyn CaKey>),
    /// There is no key for that CA.
    Missing,
    /// There is one, but it must not be used (it is not protected the way
    /// Captun protects its keys, or it is damaged), and why in plain words.
    Unusable(String),
}

/// Where CA keys are kept. A store only ever makes new keys: it never takes
/// over a key that was there before, since whoever put it there may know it.
pub trait KeyStore: Send + Sync + fmt::Debug {
    /// Which store this is, kept with each CA so a CA is only ever used with
    /// the store that made its key.
    fn kind(&self) -> &'static str;

    /// Makes `dir`, the folder the CA's certificate and record are kept in
    /// (and, for the key file store, its key), if it is not there, and makes
    /// sure no other account controls it.
    fn prepare_folder(&self, dir: &Path) -> Result<(), TlsError>;

    /// Makes a new key for the CA `id`. Fails if one is there already.
    fn create(&self, id: &InstallId) -> Result<Box<dyn CaKey>, TlsError>;

    /// The key for the CA `id`, checked.
    fn open(&self, id: &InstallId) -> Result<KeyLookup, TlsError>;

    /// Deletes every CA key in this store, whatever its id; none is fine.
    fn delete_all(&self) -> Result<(), TlsError>;
}

/// A P-256 key held by `ring` in this process: what the key file and the
/// memory store sign with. The copies of the private key made here are wiped
/// when dropped; `ring` keeps one of its own while the key is in use, which
/// it does not wipe and offers no way to.
pub(crate) struct SoftKey {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl SoftKey {
    /// A new key, as PKCS#8 DER.
    pub(crate) fn generate_pkcs8() -> Result<Zeroizing<Vec<u8>>, TlsError> {
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .map_err(|_| TlsError::Key("a new key could not be made".into()))?;
        Ok(Zeroizing::new(document.as_ref().to_vec()))
    }

    /// The key in `pkcs8`, if it is a P-256 key.
    pub(crate) fn from_pkcs8(pkcs8: &[u8]) -> Option<Self> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng).ok()?;
        Some(Self { pair, rng })
    }
}

impl CaKey for SoftKey {
    fn public_point(&self) -> &[u8] {
        self.pair.public_key().as_ref()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        let signature =
            self.pair.sign(&self.rng, message).map_err(|_| TlsError::Key("the key could not sign".into()))?;
        Ok(signature.as_ref().to_vec())
    }
}

impl fmt::Debug for SoftKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftKey").finish_non_exhaustive()
    }
}

/// Keeps CA keys in this process only: a new process has none, so it makes a
/// new CA. For tests and tools; the service uses [`crate::system_key_store`].
#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    keys: Mutex<HashMap<InstallId, Arc<SoftKey>>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn keys(&self) -> MutexGuard<'_, HashMap<InstallId, Arc<SoftKey>>> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl KeyStore for MemoryKeyStore {
    fn kind(&self) -> &'static str {
        "memory"
    }

    fn prepare_folder(&self, dir: &Path) -> Result<(), TlsError> {
        fs::create_dir_all(dir).map_err(file_error("make the folder", dir))
    }

    fn create(&self, id: &InstallId) -> Result<Box<dyn CaKey>, TlsError> {
        let mut keys = self.keys();
        if keys.contains_key(id) {
            return Err(TlsError::Key(format!("there is a key for {id} already")));
        }
        let pkcs8 = SoftKey::generate_pkcs8()?;
        let key = Arc::new(SoftKey::from_pkcs8(&pkcs8).ok_or_else(|| TlsError::Key("the new key was refused".into()))?);
        keys.insert(id.clone(), Arc::clone(&key));
        Ok(Box::new(key))
    }

    fn open(&self, id: &InstallId) -> Result<KeyLookup, TlsError> {
        Ok(self.keys().get(id).map_or(KeyLookup::Missing, |key| KeyLookup::Found(Box::new(Arc::clone(key)))))
    }

    fn delete_all(&self) -> Result<(), TlsError> {
        self.keys().clear();
        Ok(())
    }
}

thread_local! {
    /// Why the last signature made on this thread failed. rcgen calls
    /// `SigningKey::sign` on the caller's own thread and passes on only that
    /// it failed; keeping the reason per thread means two certificates made
    /// at the same time never get each other's reason.
    static LAST_FAILURE: RefCell<Option<TlsError>> = const { RefCell::new(None) };
}

/// The CA key as rcgen signs with it: each signature is asked of the
/// [`CaKey`], so the private key stays wherever it is kept.
pub(crate) struct CaSigner {
    key: Box<dyn CaKey>,
}

impl CaSigner {
    pub(crate) fn new(key: Box<dyn CaKey>) -> Self {
        Self { key }
    }

    /// `error` from rcgen as Captun reports it: when a signature failed, the
    /// key store's own reason (and plain words if, somehow, there is none).
    pub(crate) fn explain(&self, error: rcgen::Error) -> TlsError {
        let failure = LAST_FAILURE.with(|slot| slot.borrow_mut().take());
        match (error, failure) {
            (rcgen::Error::RemoteKeyError, Some(failure)) => failure,
            (rcgen::Error::RemoteKeyError, None) => TlsError::Key("the CA key did not sign".into()),
            (error, _) => TlsError::Certificate(error.to_string()),
        }
    }
}

impl PublicKeyData for CaSigner {
    fn der_bytes(&self) -> &[u8] {
        self.key.public_point()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for CaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        // A reason left from an earlier failure is not this call's.
        LAST_FAILURE.with(|slot| slot.borrow_mut().take());
        self.key.sign(message).map_err(|failure| {
            LAST_FAILURE.with(|slot| *slot.borrow_mut() = Some(failure));
            rcgen::Error::RemoteKeyError
        })
    }
}

impl fmt::Debug for CaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaSigner").field("key", &self.key).finish_non_exhaustive()
    }
}

/// An ECDSA P-256 signature given as r ‖ s, 32 bytes each (as Windows gives
/// it), in the ASN.1 DER form certificates carry: SEQUENCE { INTEGER r,
/// INTEGER s }.
#[cfg(any(windows, test))]
pub(crate) fn der_from_fixed(fixed: &[u8]) -> Option<Vec<u8>> {
    if fixed.len() != 64 {
        return None;
    }
    let (r, s) = fixed.split_at(32);
    let (r, s) = (der_integer(r)?, der_integer(s)?);
    // At most 2 × 35 bytes: the length fits in one byte.
    let body = u8::try_from(r.len() + s.len()).ok()?;
    let mut der = Vec::with_capacity(2 + usize::from(body));
    der.extend_from_slice(&[0x30, body]);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    Some(der)
}

/// The unsigned big-endian number `digits` as a DER INTEGER: no leading
/// zeros but one before a first byte with its top bit set (which would read
/// as negative).
#[cfg(any(windows, test))]
fn der_integer(digits: &[u8]) -> Option<Vec<u8>> {
    let first = digits.iter().position(|&b| b != 0).unwrap_or(digits.len().saturating_sub(1));
    let digits = digits.get(first..).filter(|d| !d.is_empty())?;
    let pad = digits[0] & 0x80 != 0;
    let len = u8::try_from(digits.len() + usize::from(pad)).ok()?;
    let mut der = Vec::with_capacity(2 + usize::from(len));
    der.extend_from_slice(&[0x02, len]);
    if pad {
        der.push(0);
    }
    der.extend_from_slice(digits);
    Some(der)
}

#[cfg(test)]
mod tests {
    use ring::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED_SIGNING, UnparsedPublicKey};

    use super::*;

    #[test]
    fn ids_are_eight_hex_digits() {
        let id = InstallId::random().unwrap();
        assert_eq!(InstallId::parse(id.as_str()), Some(id.clone()));
        assert_eq!(id.as_str().len(), 8);
        assert_ne!(InstallId::random().unwrap(), InstallId::random().unwrap());
        for bad in ["", "0123ABC", "0123ABCDE", "0123abcd", "0123ABC.", "../../x", "0123ABC\0"] {
            assert_eq!(InstallId::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn fixed_signatures_become_der_that_ring_accepts() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let public = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pair.public_key().as_ref().to_vec());
        // Enough signatures that some r and s start with a set top bit or a
        // zero byte.
        for n in 0u32..300 {
            let message = n.to_be_bytes();
            let fixed = pair.sign(&rng, &message).unwrap();
            let der = der_from_fixed(fixed.as_ref()).unwrap();
            public.verify(&message, &der).unwrap();
        }
    }

    #[test]
    fn der_integers_are_minimal() {
        let mut fixed = [0u8; 64];
        fixed[31] = 1; // r = 1
        fixed[32] = 0x80; // s has its top bit set
        let der = der_from_fixed(&fixed).unwrap();
        let mut expected = vec![0x30, 3 + 35, 0x02, 0x01, 0x01, 0x02, 33, 0x00, 0x80];
        expected.extend_from_slice(&[0u8; 31]);
        assert_eq!(der, expected);
        // Zero is one zero byte.
        assert_eq!(der_integer(&[0, 0, 0]).unwrap(), vec![0x02, 0x01, 0x00]);
        assert_eq!(der_from_fixed(&[0u8; 63]), None);
        assert_eq!(der_from_fixed(&[0u8; 65]), None);
    }

    #[test]
    fn the_memory_store_keeps_each_key_until_deleted() {
        let store = MemoryKeyStore::new();
        let id = InstallId::random().unwrap();
        assert!(matches!(store.open(&id).unwrap(), KeyLookup::Missing));
        let key = store.create(&id).unwrap();
        assert!(store.create(&id).is_err(), "never a second key for one id");
        let KeyLookup::Found(again) = store.open(&id).unwrap() else { panic!("the key is kept") };
        assert_eq!(again.public_point(), key.public_point());
        assert_eq!(key.public_point().len(), 65);

        let signature = again.sign(b"message").unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key.public_point()).verify(b"message", &signature).unwrap();

        store.delete_all().unwrap();
        assert!(matches!(store.open(&id).unwrap(), KeyLookup::Missing));
    }

    #[test]
    fn rcgen_learns_why_a_signature_failed() {
        #[derive(Debug)]
        struct Broken;
        impl CaKey for Broken {
            fn public_point(&self) -> &[u8] {
                &[4; 65]
            }
            fn sign(&self, _: &[u8]) -> Result<Vec<u8>, TlsError> {
                Err(TlsError::Key("the key is out to lunch".into()))
            }
        }
        let signer = CaSigner::new(Box::new(Broken));
        let err = rcgen::CertificateParams::default().self_signed(&signer).unwrap_err();
        assert_eq!(
            signer.explain(err).to_string(),
            "Captun could not use its HTTPS inspection key: the key is out to lunch"
        );
    }
}
