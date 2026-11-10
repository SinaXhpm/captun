//! This computer's certificate stores. The one-off certificate goes into
//! the machine's Root store (so its signature chains to something trusted)
//! and TrustedPublisher store (so Windows installs the driver without
//! asking), as the encoded certificate alone: no key, no other property.

use std::{ffi::OsStr, io, ptr};

use windows_sys::{
    Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_FIND_SHA1_HASH, CERT_FIND_SUBJECT_STR_W, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG,
        CERT_SHA1_HASH_PROP_ID, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_OPEN_EXISTING_FLAG,
        CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
        CertAddEncodedCertificateToStore, CertCloseStore, CertCreateCertificateContext, CertDeleteCertificateFromStore,
        CertDuplicateCertificateContext, CertFindCertificateInStore, CertFreeCertificateContext,
        CertGetCertificateContextProperty, CertGetNameStringW, CertOpenStore, HCERTSTORE, X509_ASN_ENCODING,
        szOID_COMMON_NAME,
    },
    core::{PCWSTR, w},
};

use super::system::{from_wide, wide};
use crate::package::CERTIFICATE_NAME;

/// The machine's stores the certificate goes in.
const STORES: [PCWSTR; 2] = [w!("Root"), w!("TrustedPublisher")];

/// Puts the certificate in both stores. Needs administrator rights.
pub(super) fn add(certificate: &[u8]) -> io::Result<()> {
    let len = u32::try_from(certificate.len()).map_err(io::Error::other)?;
    for name in STORES {
        let store = Store::open(name, false)?;
        // SAFETY: `certificate` is live for the call and Windows copies it;
        // no context is wanted back.
        let ok = unsafe {
            CertAddEncodedCertificateToStore(
                store.0,
                X509_ASN_ENCODING,
                certificate.as_ptr(),
                len,
                CERT_STORE_ADD_REPLACE_EXISTING,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Whether both stores hold Captun's certificate with this thumbprint.
pub(super) fn trusts(thumbprint: &[u8; 20]) -> io::Result<bool> {
    for name in STORES {
        let store = Store::open(name, true)?;
        if !store.find(thumbprint).is_some_and(|certificate| certificate.is_captuns()) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Takes the certificate with this thumbprint out of both stores, and
/// returns how many were removed. Only Captun's own certificate is removed:
/// one by that thumbprint under any other name is left where it is.
pub(super) fn remove(thumbprint: &[u8; 20]) -> io::Result<usize> {
    let mut removed = 0;
    for name in STORES {
        let store = Store::open(name, false)?;
        // A store is a collection of stores, so it may hold more than one.
        for _ in 0..8 {
            let Some(certificate) = store.find(thumbprint) else { break };
            if !certificate.is_captuns() {
                break;
            }
            certificate.delete()?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// The thumbprints of every certificate Captun made for its driver that
/// either store holds, noted or not: what an older version, or an install
/// stopped part way, may have left.
pub(super) fn captuns() -> io::Result<Vec<[u8; 20]>> {
    let name = wide(OsStr::new(CERTIFICATE_NAME))?;
    let mut found = Vec::new();
    for store_name in STORES {
        let store = Store::open(store_name, true)?;
        let mut matching = Vec::new();
        let mut previous: *const CERT_CONTEXT = ptr::null();
        loop {
            // SAFETY: the store is open; `name` is NUL-terminated and lives
            // through the loop; `previous` is null or the context the last
            // call returned, which this call frees.
            let next = unsafe {
                CertFindCertificateInStore(
                    store.0,
                    X509_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_STR_W,
                    name.as_ptr().cast(),
                    previous,
                )
            };
            if next.is_null() {
                break;
            }
            previous = next;
            // SAFETY: a context the store just handed out; the copy holds a
            // reference of its own, freed when it drops.
            matching.push(Certificate(unsafe { CertDuplicateCertificateContext(next) }));
        }
        // The name is matched as part of the subject: only an exact match,
        // issued by itself, is one of Captun's.
        for certificate in matching.iter().filter(|certificate| certificate.is_captuns()) {
            let thumbprint = certificate.sha1()?;
            if !found.contains(&thumbprint) {
                found.push(thumbprint);
            }
        }
    }
    Ok(found)
}

/// The certificate's SHA-1 thumbprint, as Windows works it out.
pub(super) fn thumbprint(certificate: &[u8]) -> io::Result<[u8; 20]> {
    Certificate::decode(certificate)?.sha1()
}

/// Room for a common name, in UTF-16 units: far more than Captun's needs.
const NAME_UNITS: usize = 256;

/// One of the machine's system stores, closed on drop.
struct Store(HCERTSTORE);

impl Store {
    fn open(name: PCWSTR, read_only: bool) -> io::Result<Self> {
        let flags = CERT_SYSTEM_STORE_LOCAL_MACHINE
            | if read_only { CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG } else { 0 };
        // SAFETY: the system-store provider takes the store's name as its
        // parameter, a static NUL-terminated string here.
        let store = unsafe { CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, name.cast()) };
        if store.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(store))
    }

    fn find(&self, thumbprint: &[u8; 20]) -> Option<Certificate> {
        let blob = CRYPT_INTEGER_BLOB { cbData: 20, pbData: thumbprint.as_ptr().cast_mut() };
        // SAFETY: `blob` points at the 20 bytes of the thumbprint, which
        // Windows only reads, for the call; the search starts from the top.
        let found = unsafe {
            CertFindCertificateInStore(
                self.0,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_SHA1_HASH,
                (&raw const blob).cast(),
                ptr::null(),
            )
        };
        (!found.is_null()).then_some(Certificate(found))
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: the store was opened by this module and is closed once;
        // contexts from it hold their own reference.
        unsafe { CertCloseStore(self.0, 0) };
    }
}

/// A certificate context, freed on drop.
struct Certificate(*mut CERT_CONTEXT);

impl Certificate {
    fn decode(der: &[u8]) -> io::Result<Self> {
        let len = u32::try_from(der.len()).map_err(io::Error::other)?;
        // SAFETY: `der` is live for the call; Windows copies it into the new
        // context.
        let context = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), len) };
        if context.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(context))
    }

    /// Its subject's (or, with `issuer`, its issuer's) common name.
    fn common_name(&self, issuer: bool) -> String {
        let mut buf = [0u16; NAME_UNITS];
        let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
        // SAFETY: the context is valid; the common name's OID is a static
        // NUL-terminated string; `buf` has room for its length in UTF-16
        // units, which the call does not exceed.
        let written = unsafe {
            CertGetNameStringW(
                self.0,
                CERT_NAME_ATTR_TYPE,
                flags,
                szOID_COMMON_NAME.cast(),
                buf.as_mut_ptr(),
                NAME_UNITS as u32,
            )
        };
        from_wide(&buf[..(written as usize).min(buf.len())])
    }

    /// Whether this is a certificate Captun made for its driver.
    fn is_captuns(&self) -> bool {
        self.common_name(false) == CERTIFICATE_NAME && self.common_name(true) == CERTIFICATE_NAME
    }

    /// Its SHA-1 thumbprint.
    fn sha1(&self) -> io::Result<[u8; 20]> {
        let mut hash = [0u8; 20];
        let mut size = 20u32;
        // SAFETY: the context is valid; `hash` has room for `size` bytes.
        let ok = unsafe {
            CertGetCertificateContextProperty(self.0, CERT_SHA1_HASH_PROP_ID, hash.as_mut_ptr().cast(), &mut size)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if size != 20 {
            return Err(io::Error::other("Windows gave a thumbprint of the wrong size"));
        }
        Ok(hash)
    }

    #[cfg(test)]
    fn der(&self) -> Vec<u8> {
        // SAFETY: the context stays valid while `self` lives, and Windows
        // keeps its encoded bytes at `pbCertEncoded` for `cbCertEncoded`.
        unsafe {
            let context = &*self.0;
            std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize).to_vec()
        }
    }

    /// Deletes it from the store it was found in.
    fn delete(self) -> io::Result<()> {
        let context = self.0;
        // Freed by the delete, whether or not it succeeds.
        std::mem::forget(self);
        // SAFETY: a context found in a store opened for writing; the call
        // frees it, and nothing uses it after.
        if unsafe { CertDeleteCertificateFromStore(context) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: the context is owned by this value and freed once.
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

/// What the tests check about a certificate.
#[cfg(test)]
#[derive(Debug)]
pub(super) struct Description {
    pub(super) subject: String,
    pub(super) issuer: String,
    /// What it may be used for (the OIDs of its extended key usage).
    pub(super) usages: Vec<String>,
    /// Whether a private key can be reached through it.
    pub(super) has_private_key: bool,
}

#[cfg(test)]
pub(super) fn describe(der: &[u8]) -> io::Result<Description> {
    use std::ffi::CStr;

    use windows_sys::Win32::Security::Cryptography::{
        CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, CRYPT_ACQUIRE_SILENT_FLAG,
        CTL_USAGE, CertGetEnhancedKeyUsage, CryptAcquireCertificatePrivateKey,
    };

    let certificate = Certificate::decode(der)?;
    assert_eq!(certificate.der(), der);
    let mut size = 0u32;
    // SAFETY: a null buffer asks only for the size.
    let ok = unsafe {
        CertGetEnhancedKeyUsage(certificate.0, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, ptr::null_mut(), &mut size)
    };
    let mut usages = Vec::new();
    if ok != 0 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buf` has room for `size` bytes, aligned for the structure
        // Windows writes at its start.
        let ok = unsafe {
            CertGetEnhancedKeyUsage(
                certificate.0,
                CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        assert_ne!(ok, 0);
        // SAFETY: Windows wrote a CTL_USAGE at the start of `buf`, whose
        // pointers point into `buf`, at NUL-terminated OIDs.
        unsafe {
            let usage = &*buf.as_ptr().cast::<CTL_USAGE>();
            for i in 0..usage.cUsageIdentifier as usize {
                let oid = *usage.rgpszUsageIdentifier.add(i);
                usages.push(CStr::from_ptr(oid.cast()).to_string_lossy().into_owned());
            }
        }
    }
    let (mut key, mut spec, mut free) = (0usize, 0u32, 0i32);
    // SAFETY: the context is valid; the out-pointers are valid places; no
    // window may be shown.
    let has_private_key = unsafe {
        CryptAcquireCertificatePrivateKey(
            certificate.0,
            CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
            ptr::null(),
            &mut key,
            &mut spec,
            &mut free,
        )
    } != 0;
    Ok(Description {
        subject: certificate.common_name(false),
        issuer: certificate.common_name(true),
        usages,
        has_private_key,
    })
}

/// What Windows' chain checks find wrong with the certificate as a code
/// signer once a computer trusts it: the chain's own problems (its
/// `CERT_TRUST_*` bits), then the code-signing (Authenticode) policy's and
/// the base policy's error. The chain is built in memory with the
/// certificate as the only trusted root, so no store of this computer is
/// touched, and no problem hides behind an untrusted root.
#[cfg(test)]
pub(super) fn problems_once_trusted(der: &[u8]) -> io::Result<(u32, u32, u32)> {
    use windows_sys::{
        Win32::Security::Cryptography::{
            CERT_CHAIN_CONTEXT, CERT_CHAIN_ENGINE_CONFIG, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_AUTHENTICODE,
            CERT_CHAIN_POLICY_BASE, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_STORE_ADD_ALWAYS,
            CERT_STORE_PROV_MEMORY, CERT_USAGE_MATCH, CTL_USAGE, CertAddCertificateContextToStore,
            CertCreateCertificateChainEngine, CertFreeCertificateChain, CertFreeCertificateChainEngine,
            CertGetCertificateChain, CertVerifyCertificateChainPolicy, HCERTCHAINENGINE, USAGE_MATCH_TYPE_AND,
            szOID_PKIX_KP_CODE_SIGNING,
        },
        core::{PCSTR, PSTR},
    };

    use super::system::size_u32;

    let certificate = Certificate::decode(der)?;
    // SAFETY: a new, empty store in memory; no parameter.
    let roots = unsafe { CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, ptr::null()) };
    if roots.is_null() {
        return Err(io::Error::last_os_error());
    }
    let roots = Store(roots);
    // SAFETY: both are valid; the store keeps a copy of its own.
    if unsafe { CertAddCertificateContextToStore(roots.0, certificate.0, CERT_STORE_ADD_ALWAYS, ptr::null_mut()) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: plain data, for which all zeroes means no restriction, extra
    // store, flag or limit.
    let mut config: CERT_CHAIN_ENGINE_CONFIG = unsafe { std::mem::zeroed() };
    config.cbSize = size_u32::<CERT_CHAIN_ENGINE_CONFIG>();
    config.hExclusiveRoot = roots.0;
    let mut engine: HCERTCHAINENGINE = 0;
    // SAFETY: `config` is valid, and the store it names outlives the engine.
    if unsafe { CertCreateCertificateChainEngine(&config, &mut engine) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut code_signing: PSTR = szOID_PKIX_KP_CODE_SIGNING.cast_mut();
    let para = CERT_CHAIN_PARA {
        cbSize: size_u32::<CERT_CHAIN_PARA>(),
        RequestedUsage: CERT_USAGE_MATCH {
            dwType: USAGE_MATCH_TYPE_AND,
            Usage: CTL_USAGE { cUsageIdentifier: 1, rgpszUsageIdentifier: &mut code_signing },
        },
    };
    let mut chain: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();
    // SAFETY: the engine, the certificate and `para` (and the OID it points
    // at) are valid; the time now, no extra store, no revocation check (the
    // certificate names no list to check).
    let ok = unsafe {
        CertGetCertificateChain(engine, certificate.0, ptr::null(), ptr::null_mut(), &para, 0, ptr::null(), &mut chain)
    };
    let found = if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        let policy = |oid: PCSTR| {
            let para = CERT_CHAIN_POLICY_PARA {
                cbSize: size_u32::<CERT_CHAIN_POLICY_PARA>(),
                dwFlags: 0,
                pvExtraPolicyPara: ptr::null_mut(),
            };
            let mut status = CERT_CHAIN_POLICY_STATUS {
                cbSize: size_u32::<CERT_CHAIN_POLICY_STATUS>(),
                dwError: 0,
                lChainIndex: 0,
                lElementIndex: 0,
                pvExtraPolicyStatus: ptr::null_mut(),
            };
            // SAFETY: the chain stays valid until it is freed below; both
            // structures are valid for the call.
            let checked = unsafe { CertVerifyCertificateChainPolicy(oid, chain, &para, &mut status) };
            if checked == 0 { u32::MAX } else { status.dwError }
        };
        // SAFETY: the chain CertGetCertificateChain returned.
        let problems = unsafe { (*chain).TrustStatus.dwErrorStatus };
        let found = (problems, policy(CERT_CHAIN_POLICY_AUTHENTICODE), policy(CERT_CHAIN_POLICY_BASE));
        // SAFETY: freed once, after its last use.
        unsafe { CertFreeCertificateChain(chain) };
        Ok(found)
    };
    // SAFETY: the engine made above, freed once, after the chain.
    unsafe { CertFreeCertificateChainEngine(engine) };
    found
}
