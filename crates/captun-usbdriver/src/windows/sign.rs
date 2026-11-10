//! Signing the catalog with a certificate made for it alone.
//!
//! The private key is a CNG key with no name, which Windows never writes
//! anywhere: it exists in memory for the one signature. Once the catalog is
//! signed it is destroyed, so the certificate, which this computer is about
//! to trust, can never sign anything else. The certificate itself is fit
//! for one thing (signing code), cannot vouch for other certificates, and
//! leaves here as its encoded bytes alone.

use std::{ffi::c_void, io, path::Path, ptr, slice};

use windows_sys::{
    Win32::{
        Foundation::{FILETIME, SYSTEMTIME},
        Security::Cryptography::{
            CALG_SHA_256, CERT_CONTEXT, CERT_CREATE_SELFSIGN_NO_KEY_INFO, CERT_EXTENSION, CERT_EXTENSIONS,
            CERT_KEY_CONTEXT_PROP_ID, CERT_NCRYPT_KEY_HANDLE_PROP_ID, CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG,
            CRYPT_ALGORITHM_IDENTIFIER, CRYPT_INTEGER_BLOB, CertCreateSelfSignCertificate, CertFreeCertificateContext,
            CertSetCertificateContextProperty, MS_KEY_STORAGE_PROVIDER, NCRYPT_ALLOW_SIGNING_FLAG,
            NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_LENGTH_PROPERTY,
            NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM, NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptFinalizeKey,
            NCryptFreeObject, NCryptOpenStorageProvider, NCryptSetProperty, SIGNER_CERT, SIGNER_CERT_0,
            SIGNER_CERT_POLICY_CHAIN, SIGNER_CERT_STORE, SIGNER_CERT_STORE_INFO, SIGNER_CONTEXT, SIGNER_FILE_INFO,
            SIGNER_NO_ATTR, SIGNER_SIGNATURE_INFO, SIGNER_SIGNATURE_INFO_0, SIGNER_SUBJECT_FILE, SIGNER_SUBJECT_INFO,
            SIGNER_SUBJECT_INFO_0, SignerFreeSignerContext, SignerSignEx2, szOID_BASIC_CONSTRAINTS2,
            szOID_ENHANCED_KEY_USAGE, szOID_KEY_USAGE, szOID_RSA_SHA256RSA,
        },
        System::{SystemInformation::GetSystemTimeAsFileTime, Time::FileTimeToSystemTime},
    },
    core::{HRESULT, PCWSTR},
};

use super::system::{size_u32, wide};
use crate::package::CERTIFICATE_NAME;

/// The key's size: beyond any attack for longer than the certificate lives.
const KEY_BITS: u32 = 3072;

/// How long the certificate is valid. Its key is gone, so a long life gives
/// no one anything to sign with, and the driver it vouches for stays good
/// for as long as the computer keeps it.
const VALID_YEARS: u16 = 30;

/// Extended key usage: code signing (1.3.6.1.5.5.7.3.3) and nothing else.
const CODE_SIGNING_ONLY: [u8; 12] = [0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
/// Key usage: digital signatures only (a bit string with bit 0 set).
const SIGNATURES_ONLY: [u8; 4] = [0x03, 0x02, 0x07, 0x80];
/// Basic constraints with no fields: not a certificate authority, so it can
/// vouch for no other certificate.
const NOT_AN_AUTHORITY: [u8; 2] = [0x30, 0x00];

/// Signs the catalog at `catalog` with a certificate made for it alone, and
/// returns that certificate (DER). The private key is destroyed before this
/// returns, whether signing worked or not.
pub(super) fn sign_once(catalog: &Path) -> io::Result<Vec<u8>> {
    let provider = Provider::open()?;
    let certificate = Certificate::self_signed(provider.new_signing_key()?)?;
    let der = certificate.der();
    let signed = sign(catalog, &certificate);
    let destroyed = certificate.destroy_key();
    drop(certificate);
    signed?;
    destroyed?;
    Ok(der)
}

/// Signs the file with SHA-256, the certificate taken as it is (its key is
/// the one attached to it), no time stamp.
fn sign(catalog: &Path, certificate: &Certificate) -> io::Result<()> {
    let path = wide(catalog.as_os_str())?;
    let mut file = SIGNER_FILE_INFO {
        cbSize: size_u32::<SIGNER_FILE_INFO>(),
        pwszFileName: path.as_ptr(),
        hFile: ptr::null_mut(),
    };
    let mut index = 0u32;
    let subject = SIGNER_SUBJECT_INFO {
        cbSize: size_u32::<SIGNER_SUBJECT_INFO>(),
        pdwIndex: &mut index,
        dwSubjectChoice: SIGNER_SUBJECT_FILE,
        Anonymous: SIGNER_SUBJECT_INFO_0 { pSignerFileInfo: &mut file },
    };
    let mut store = SIGNER_CERT_STORE_INFO {
        cbSize: size_u32::<SIGNER_CERT_STORE_INFO>(),
        pSigningCert: certificate.0,
        // The signature carries the certificate itself.
        dwCertPolicy: SIGNER_CERT_POLICY_CHAIN,
        hCertStore: ptr::null_mut(),
    };
    let signer = SIGNER_CERT {
        cbSize: size_u32::<SIGNER_CERT>(),
        dwCertChoice: SIGNER_CERT_STORE,
        Anonymous: SIGNER_CERT_0 { pCertStoreInfo: &mut store },
        hwnd: ptr::null_mut(),
    };
    let signature = SIGNER_SIGNATURE_INFO {
        cbSize: size_u32::<SIGNER_SIGNATURE_INFO>(),
        algidHash: CALG_SHA_256,
        dwAttrChoice: SIGNER_NO_ATTR,
        Anonymous: SIGNER_SIGNATURE_INFO_0 { pAttrAuthcode: ptr::null_mut() },
        psAuthenticated: ptr::null_mut(),
        psUnauthenticated: ptr::null_mut(),
    };
    let mut context: *mut SIGNER_CONTEXT = ptr::null_mut();
    // SAFETY: every structure, and the path they point at, is a local that
    // outlives the call; no key provider is named (the certificate carries
    // its key), no time stamp, attributes, SIP data or policy.
    let result = unsafe {
        SignerSignEx2(
            0,
            &subject,
            &signer,
            &signature,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &mut context,
            ptr::null(),
            ptr::null(),
        )
    };
    if !context.is_null() {
        // SAFETY: the context SignerSignEx2 handed back, freed once.
        unsafe { SignerFreeSignerContext(context) };
    }
    check(result)
}

/// Windows' software key storage provider, freed on drop.
struct Provider(NCRYPT_PROV_HANDLE);

impl Provider {
    fn open() -> io::Result<Self> {
        let mut provider: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: `provider` is a valid place for the handle written; the
        // provider's name is a static NUL-terminated string.
        check(unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) })?;
        Ok(Self(provider))
    }

    /// A new RSA key for signing, with no name, so it is kept in memory only
    /// and never written anywhere; it cannot be exported either.
    fn new_signing_key(&self) -> io::Result<Key> {
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: `key` is a valid place for the handle written; the
        // algorithm is a static NUL-terminated string, and a null name is
        // what makes the key ephemeral.
        check(unsafe { NCryptCreatePersistedKey(self.0, &mut key, NCRYPT_RSA_ALGORITHM, ptr::null(), 0, 0) })?;
        let key = Key(key);
        key.set(NCRYPT_LENGTH_PROPERTY, KEY_BITS)?;
        key.set(NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_SIGNING_FLAG)?;
        key.set(NCRYPT_EXPORT_POLICY_PROPERTY, 0)?;
        // SAFETY: a key made just above and not yet finalized.
        check(unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) })?;
        Ok(key)
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: the provider handle is owned by this value and freed once.
        unsafe { NCryptFreeObject(self.0) };
    }
}

/// A key handle owned here until a certificate takes it; freed (and the
/// key with it) on drop.
struct Key(NCRYPT_KEY_HANDLE);

impl Key {
    fn set(&self, property: PCWSTR, value: u32) -> io::Result<()> {
        let bytes = value.to_ne_bytes();
        // SAFETY: the property's name is a static NUL-terminated string, and
        // `bytes` holds the 4 bytes passed.
        check(unsafe { NCryptSetProperty(self.0, property, bytes.as_ptr(), 4, 0) })
    }

    /// The handle, for whoever takes it over; this value no longer frees it.
    fn into_raw(self) -> NCRYPT_KEY_HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key handle is owned by this value and freed once.
        unsafe { NCryptFreeObject(self.0) };
    }
}

/// A certificate context, freed on drop (with any key it holds).
struct Certificate(*const CERT_CONTEXT);

impl Certificate {
    /// A certificate named [`CERTIFICATE_NAME`], issued by itself and signed
    /// with `key`, which it takes over.
    fn self_signed(key: Key) -> io::Result<Self> {
        let mut name = name_der(CERTIFICATE_NAME);
        let subject = blob(&mut name)?;
        let algorithm = CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: szOID_RSA_SHA256RSA.cast_mut(),
            Parameters: CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() },
        };
        let (mut usage, mut key_usage, mut constraints) = (CODE_SIGNING_ONLY, SIGNATURES_ONLY, NOT_AN_AUTHORITY);
        let mut list = [
            CERT_EXTENSION { pszObjId: szOID_ENHANCED_KEY_USAGE.cast_mut(), fCritical: 0, Value: blob(&mut usage)? },
            CERT_EXTENSION { pszObjId: szOID_KEY_USAGE.cast_mut(), fCritical: 1, Value: blob(&mut key_usage)? },
            CERT_EXTENSION {
                pszObjId: szOID_BASIC_CONSTRAINTS2.cast_mut(),
                fCritical: 1,
                Value: blob(&mut constraints)?,
            },
        ];
        let extensions = CERT_EXTENSIONS {
            cExtension: u32::try_from(list.len()).map_err(io::Error::other)?,
            rgExtension: list.as_mut_ptr(),
        };
        let (start, end) = validity()?;
        // SAFETY: every pointer refers to a local that outlives the call;
        // the certificate is signed with `key` and, as asked, gets no
        // property naming a key container (there is none).
        let context = unsafe {
            CertCreateSelfSignCertificate(
                key.0,
                &subject,
                CERT_CREATE_SELFSIGN_NO_KEY_INFO,
                ptr::null(),
                &algorithm,
                &start,
                &end,
                &extensions,
            )
        };
        if context.is_null() {
            return Err(io::Error::last_os_error());
        }
        let certificate = Self(context);
        // The certificate takes the key: deleting this property, or freeing
        // the certificate, destroys it. Windows takes the handle itself as
        // the property's data, and keeps it in memory only.
        // SAFETY: the context is valid; the handle stays valid while the
        // certificate holds it.
        let ok = unsafe {
            CertSetCertificateContextProperty(
                certificate.0,
                CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG,
                ptr::without_provenance::<c_void>(key.0),
            )
        };
        if ok == 0 {
            // The key is still `key`'s, freed as it drops.
            return Err(io::Error::last_os_error());
        }
        let _ = key.into_raw();
        Ok(certificate)
    }

    fn der(&self) -> Vec<u8> {
        // SAFETY: the context stays valid while `self` lives, and Windows
        // keeps its encoded bytes at `pbCertEncoded` for `cbCertEncoded`.
        unsafe {
            let context = &*self.0;
            slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize).to_vec()
        }
    }

    /// Destroys the private key now. Deleting the key's property frees it,
    /// together with the key context Windows keeps for it (where signing
    /// finds the key); deleting that context as well leaves nothing behind
    /// should Windows ever keep the two apart.
    fn destroy_key(&self) -> io::Result<()> {
        // SAFETY: the context is valid; no data deletes the property, and
        // the certificate frees the key handle it held.
        let deleted =
            unsafe { CertSetCertificateContextProperty(self.0, CERT_NCRYPT_KEY_HANDLE_PROP_ID, 0, ptr::null()) };
        let error = (deleted == 0).then(io::Error::last_os_error);
        // SAFETY: as above, for the key context; gone already, this does
        // nothing.
        unsafe { CertSetCertificateContextProperty(self.0, CERT_KEY_CONTEXT_PROP_ID, 0, ptr::null()) };
        error.map_or(Ok(()), Err)
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: the context is owned by this value and freed once.
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

/// When the certificate is valid: from a day ago (a clock set back a little
/// must not make it new) for [`VALID_YEARS`].
fn validity() -> io::Result<(SYSTEMTIME, SYSTEMTIME)> {
    const DAY: u64 = 24 * 60 * 60 * 10_000_000;
    let mut now = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    // SAFETY: `now` is a valid place for the time written.
    unsafe { GetSystemTimeAsFileTime(&mut now) };
    let now = (u64::from(now.dwHighDateTime) << 32) | u64::from(now.dwLowDateTime);
    let start = system_time(now.saturating_sub(DAY))?;
    let mut end = system_time(now)?;
    end.wYear += VALID_YEARS;
    if end.wMonth == 2 && end.wDay == 29 {
        end.wDay = 28;
    }
    Ok((start, end))
}

/// A time in 100 ns steps since 1601, as a date and time.
fn system_time(ticks: u64) -> io::Result<SYSTEMTIME> {
    let time = FILETIME { dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32, dwHighDateTime: (ticks >> 32) as u32 };
    let mut out =
        SYSTEMTIME { wYear: 0, wMonth: 0, wDayOfWeek: 0, wDay: 0, wHour: 0, wMinute: 0, wSecond: 0, wMilliseconds: 0 };
    // SAFETY: both are valid structures for the call.
    if unsafe { FileTimeToSystemTime(&time, &mut out) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(out)
}

/// The DER of a name with one common name:
/// SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String } } }.
fn name_der(common_name: &str) -> Vec<u8> {
    let attribute = der(0x30, &[&[0x06, 0x03, 0x55, 0x04, 0x03][..], &der(0x0C, common_name.as_bytes())].concat());
    der(0x30, &der(0x31, &attribute))
}

/// One DER element, its length in the definite form.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn blob(bytes: &mut [u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB { cbData: u32::try_from(bytes.len()).map_err(io::Error::other)?, pbData: bytes.as_mut_ptr() })
}

fn check(result: HRESULT) -> io::Result<()> {
    if result < 0 { Err(io::Error::from_raw_os_error(result)) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use windows_sys::Win32::{
        Foundation::CRYPT_E_NOT_FOUND,
        Security::Cryptography::{CERT_KEY_PROV_INFO_PROP_ID, CertGetCertificateContextProperty},
    };

    use super::*;
    use crate::package::{CAT_NAME, CDF_NAME, INF_NAME, cdf_text, inf_text};

    impl Certificate {
        /// The size of one of the certificate's properties, or why it
        /// cannot be read.
        fn property(&self, property: u32) -> io::Result<u32> {
            let mut size = 0u32;
            // SAFETY: the context is valid; a null buffer asks only for the
            // size.
            if unsafe { CertGetCertificateContextProperty(self.0, property, ptr::null_mut(), &mut size) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(size)
        }
    }

    #[test]
    fn a_destroyed_key_is_gone_from_its_certificate_which_signs_nothing_more() {
        let dir = env::temp_dir().join(format!("captun-usbdriver-key-{}", std::process::id()));
        let Some(definition) = dir.to_str().and_then(cdf_text) else {
            eprintln!("skipped: the temp folder {} is not a plain ASCII path", dir.display());
            return;
        };
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(INF_NAME), inf_text()).unwrap();
        fs::write(dir.join(CDF_NAME), definition).unwrap();
        let catalog = dir.join(CAT_NAME);
        super::super::catalog::make(&dir.join(CDF_NAME), &catalog).unwrap();
        // A second catalog, not signed yet.
        let spare = dir.join("spare.cat");
        fs::copy(&catalog, &spare).unwrap();

        let provider = Provider::open().unwrap();
        let certificate = Certificate::self_signed(provider.new_signing_key().unwrap()).unwrap();
        assert!(certificate.property(CERT_NCRYPT_KEY_HANDLE_PROP_ID).is_ok(), "the key is attached to sign with");
        sign(&catalog, &certificate).unwrap();
        certificate.destroy_key().unwrap();
        // Nothing the certificate holds leads to a key any more: not the key
        // itself, not the context signing found it through, and never a
        // stored key's name.
        for property in [CERT_NCRYPT_KEY_HANDLE_PROP_ID, CERT_KEY_CONTEXT_PROP_ID, CERT_KEY_PROV_INFO_PROP_ID] {
            let error = certificate.property(property).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(CRYPT_E_NOT_FOUND), "property {property}: {error}");
        }
        assert!(sign(&spare, &certificate).is_err(), "it signs nothing more");

        // The spare catalog itself can be signed, by a certificate with a key.
        let other = Certificate::self_signed(provider.new_signing_key().unwrap()).unwrap();
        sign(&spare, &other).unwrap();
        other.destroy_key().unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn names_and_lengths_are_encoded_as_der_wants() {
        assert_eq!(der(0x04, &[1, 2]), [0x04, 0x02, 1, 2]);
        assert_eq!(der(0x04, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(der(0x04, &[0; 0x100])[..4], [0x04, 0x82, 0x01, 0x00]);
        let name = name_der("ab");
        assert_eq!(name, [0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x02, b'a', b'b']);
    }

    #[test]
    fn the_certificate_is_valid_from_yesterday_for_decades() {
        let (start, end) = validity().unwrap();
        let years = end.wYear - start.wYear;
        assert!(years == VALID_YEARS || years == VALID_YEARS + 1, "{years}");
        assert!(start.wYear >= 2026);
    }
}
