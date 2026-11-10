//! The catalog: made from the catalog definition with wintrust's catalog
//! definition calls, the way makecat does, and read back to check that it
//! lists the INF as Windows hashes it and is signed by the certificate made
//! for it, before this computer is asked to trust that certificate.

use std::{
    cell::Cell,
    ffi::{CStr, c_void},
    fs::{self, File},
    io,
    os::windows::io::AsRawHandle,
    path::Path,
    ptr, slice,
};

use windows_sys::{
    Win32::{
        Foundation::{BOOL, HANDLE, INVALID_HANDLE_VALUE},
        Security::Cryptography::{
            BCRYPT_SHA256_ALGORITHM, CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_COUNT_PARAM, CMSG_SIGNER_INFO,
            CMSG_SIGNER_INFO_PARAM,
            Catalog::{
                CRYPTCAT_OPEN_EXISTING, CRYPTCATATTRIBUTE, CRYPTCATCDF, CryptCATAdminAcquireContext2,
                CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminReleaseContext, CryptCATCDFClose,
                CryptCATCDFEnumCatAttributes, CryptCATCDFOpen, CryptCATClose, CryptCATEnumerateCatAttr,
                CryptCATEnumerateMember, CryptCATOpen, PFN_CDF_PARSE_ERROR_CALLBACK,
            },
            CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CryptMsgClose, CryptMsgGetParam,
            CryptQueryObject, HCERTSTORE,
        },
    },
    core::{PCWSTR, PWSTR},
};

use super::{
    hex,
    system::{from_wide, wide},
};
use crate::package::OS_ATTRIBUTE;

/// The OID of SHA-256, the hash the catalog must be signed with.
pub(super) const SHA256: &str = "2.16.840.1.101.3.4.2.1";

// Two catalog definition calls windows-sys 0.59 does not declare. Both are
// in wintrust.dll on every Windows version Captun runs on (mscat.h).
#[cfg_attr(target_arch = "x86", link(name = "wintrust", kind = "raw-dylib", import_name_type = "undecorated"))]
#[cfg_attr(not(target_arch = "x86"), link(name = "wintrust", kind = "raw-dylib"))]
unsafe extern "system" {
    /// The next file of the definition, hashed and added as it is read, or
    /// null at the end. The member is written to `member`.
    fn CryptCATCDFEnumMembersByCDFTagEx(
        cdf: *mut CRYPTCATCDF,
        previous_tag: PWSTR,
        on_error: PFN_CDF_PARSE_ERROR_CALLBACK,
        member: *mut *mut c_void,
        continue_on_error: BOOL,
        reserved: *mut c_void,
    ) -> PWSTR;

    /// The next attribute of that file, added as it is read, or null.
    fn CryptCATCDFEnumAttributesWithCDFTag(
        cdf: *mut CRYPTCATCDF,
        member_tag: PWSTR,
        member: *mut c_void,
        previous: *mut CRYPTCATATTRIBUTE,
        on_error: PFN_CDF_PARSE_ERROR_CALLBACK,
    ) -> *mut CRYPTCATATTRIBUTE;
}

thread_local! {
    /// The first problem wintrust reported in the definition on this thread.
    static PARSE_ERROR: Cell<Option<(u32, u32)>> = const { Cell::new(None) };
}

/// Called by wintrust, on the calling thread, for a line of the definition
/// it cannot use. Notes the first; never unwinds into wintrust.
extern "system" fn on_parse_error(area: u32, error: u32, _line: PCWSTR) {
    let _ = PARSE_ERROR.try_with(|first| {
        if first.get().is_none() {
            first.set(Some((area, error)));
        }
    });
}

const ON_ERROR: PFN_CDF_PARSE_ERROR_CALLBACK = Some(on_parse_error);

fn parse_error() -> Option<io::Error> {
    PARSE_ERROR.with(Cell::take).map(|(area, error)| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Windows did not take the catalog definition (part {area:#x}, problem {error:#x})"),
        )
    })
}

/// Makes the catalog `catalog` from the definition at `cdf`, which names it.
pub(super) fn make(cdf: &Path, catalog: &Path) -> io::Result<()> {
    let path = wide(cdf.as_os_str())?;
    PARSE_ERROR.with(|first| first.set(None));
    // SAFETY: `path` is a NUL-terminated UTF-16 string that outlives the
    // call; the callback is a plain function that does not unwind.
    let definition = unsafe { CryptCATCDFOpen(path.as_ptr(), ON_ERROR) };
    if definition.is_null() {
        return Err(parse_error().unwrap_or_else(io::Error::last_os_error));
    }
    // The catalog's own attribute (the Windows versions) goes in as it is read.
    let mut attribute: *mut CRYPTCATATTRIBUTE = ptr::null_mut();
    loop {
        // SAFETY: `definition` is open; `attribute` is null or the attribute
        // this call returned last.
        attribute = unsafe { CryptCATCDFEnumCatAttributes(definition, attribute, ON_ERROR) };
        if attribute.is_null() {
            break;
        }
    }
    // Then each file, hashed as it is read, with its attributes.
    let mut files = 0;
    let mut tag: PWSTR = ptr::null_mut();
    loop {
        let mut member: *mut c_void = ptr::null_mut();
        // SAFETY: `definition` is open; `tag` is null or the tag this call
        // returned last, which stays valid while the definition is open;
        // `member` is a valid place for the pointer written. It stops at the
        // first problem.
        tag = unsafe { CryptCATCDFEnumMembersByCDFTagEx(definition, tag, ON_ERROR, &mut member, 0, ptr::null_mut()) };
        if tag.is_null() {
            break;
        }
        files += 1;
        let mut attribute: *mut CRYPTCATATTRIBUTE = ptr::null_mut();
        loop {
            // SAFETY: `tag` and `member` are what the call above returned for
            // this file; `attribute` is null or the one returned last.
            attribute = unsafe { CryptCATCDFEnumAttributesWithCDFTag(definition, tag, member, attribute, ON_ERROR) };
            if attribute.is_null() {
                break;
            }
        }
    }
    // Writes the catalog and frees the definition.
    // SAFETY: `definition` is open, and not used after this.
    let closed = unsafe { CryptCATCDFClose(definition) } != 0;
    let close_error = (!closed).then(io::Error::last_os_error);
    let problem = parse_error().or(close_error).or_else(|| {
        if files != 1 {
            Some(io::Error::other(format!("the catalog lists {files} files, not the INF alone")))
        } else if !catalog.is_file() {
            Some(io::Error::new(io::ErrorKind::NotFound, "Windows wrote no catalog"))
        } else {
            None
        }
    });
    match problem {
        Some(problem) => {
            let _ = fs::remove_file(catalog);
            Err(problem)
        }
        None => Ok(()),
    }
}

/// What a catalog holds that matters here.
#[derive(Debug)]
pub(super) struct Facts {
    /// Its members' tags: the hashes of the files it lists, in hex.
    pub(super) members: Vec<String>,
    /// The catalog's own `OSAttr` attribute.
    pub(super) os_attribute: Option<String>,
    /// Its signers: each one's certificate (DER) and hash algorithm (OID).
    pub(super) signers: Vec<(Vec<u8>, String)>,
}

/// Checks that the catalog lists the INF as Windows hashes it, names the
/// Windows versions, and is signed by `certificate` alone, with SHA-256.
pub(super) fn check(inf: &Path, catalog: &Path, certificate: &[u8]) -> io::Result<()> {
    let facts = read(catalog)?;
    let hash = windows_hash(inf)?;
    if !facts.members.iter().any(|member| member.eq_ignore_ascii_case(&hash)) {
        return Err(invalid("the catalog does not list the driver's INF"));
    }
    if facts.os_attribute.as_deref() != Some(OS_ATTRIBUTE) {
        return Err(invalid("the catalog does not name the Windows versions"));
    }
    match facts.signers.as_slice() {
        [(signer, hash)] if signer == certificate && hash == SHA256 => Ok(()),
        signers => {
            let found: Vec<String> = signers
                .iter()
                .map(|(signer, hash)| {
                    let whose = if signer == certificate { "the one made for it" } else { "another certificate" };
                    format!("{whose} with hash {hash}")
                })
                .collect();
            Err(invalid(&format!(
                "the catalog is not signed by the certificate made for it alone, with SHA-256 (signed by: {})",
                if found.is_empty() { "no one".to_owned() } else { found.join(", ") }
            )))
        }
    }
}

pub(super) fn read(catalog: &Path) -> io::Result<Facts> {
    let path = wide(catalog.as_os_str())?;
    let opened = Catalog::open(&path)?;
    Ok(Facts { members: opened.members(), os_attribute: opened.attribute("OSAttr"), signers: signers(&path)? })
}

/// The file's hash as Windows works it out to find the file in a catalog
/// (SHA-256, as version 2 catalogs use), in hex.
pub(super) fn windows_hash(file: &Path) -> io::Result<String> {
    let file = File::open(file)?;
    let mut admin: isize = 0;
    // SAFETY: `admin` is a valid place for the handle written; the default
    // subsystem, SHA-256 by its static NUL-terminated name, no hash policy.
    let ok = unsafe { CryptCATAdminAcquireContext2(&mut admin, ptr::null(), BCRYPT_SHA256_ALGORITHM, ptr::null(), 0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let admin = Admin(admin);
    let mut hash = [0u8; 64];
    let mut len = u32::try_from(hash.len()).map_err(io::Error::other)?;
    // SAFETY: `file` stays open for the call; `hash` has room for `len` bytes.
    let ok =
        unsafe { CryptCATAdminCalcHashFromFileHandle2(admin.0, file.as_raw_handle(), &mut len, hash.as_mut_ptr(), 0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(hex(&hash[..(len as usize).min(hash.len())]))
}

/// The signers of the signed file at `path` (NUL-terminated UTF-16). A
/// catalog is read as the signed message it is, not as the trust list it
/// carries, which would hide its signers.
fn signers(path: &[u16]) -> io::Result<Vec<(Vec<u8>, String)>> {
    let (mut encoding, mut content, mut format) = (0u32, 0u32, 0u32);
    let mut store: HCERTSTORE = ptr::null_mut();
    let mut message: *mut c_void = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated; every out-pointer is a valid place
    // for what is written; no context is wanted.
    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path.as_ptr().cast(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &mut encoding,
            &mut content,
            &mut format,
            &mut store,
            &mut message,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let store = Store(store);
    let message = Message(message);
    if message.0.is_null() || store.0.is_null() {
        return Ok(Vec::new());
    }
    let mut count = 0u32;
    let mut size = 4u32;
    // SAFETY: `count` has room for the 4 bytes of the count.
    let ok = unsafe { CryptMsgGetParam(message.0, CMSG_SIGNER_COUNT_PARAM, 0, (&raw mut count).cast(), &mut size) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    for index in 0..count {
        let info = message.signer_info(index)?;
        // SAFETY: `info` holds the CMSG_SIGNER_INFO Windows wrote at its
        // start (checked to fit), aligned for it, with what its pointers
        // point at after it.
        let signer = unsafe { &*info.as_ptr().cast::<CMSG_SIGNER_INFO>() };
        let hash = if signer.HashAlgorithm.pszObjId.is_null() {
            String::new()
        } else {
            // SAFETY: a non-null OID Windows wrote into `info`, NUL-terminated.
            unsafe { CStr::from_ptr(signer.HashAlgorithm.pszObjId.cast()) }.to_string_lossy().into_owned()
        };
        // The signer's certificate, found by its issuer and serial number
        // among the certificates the signature carries.
        // SAFETY: CERT_INFO is plain data, for which all zeroes is a value.
        let mut id: CERT_INFO = unsafe { std::mem::zeroed() };
        id.Issuer = signer.Issuer;
        id.SerialNumber = signer.SerialNumber;
        // SAFETY: the store is open; `id` names the signer, pointing into
        // `info`, both alive for the call; the search starts from the top.
        let found = unsafe {
            CertFindCertificateInStore(
                store.0,
                encoding,
                0,
                CERT_FIND_SUBJECT_CERT,
                (&raw const id).cast(),
                ptr::null(),
            )
        };
        if found.is_null() {
            return Err(invalid("the signature does not carry its signer's certificate"));
        }
        // SAFETY: a context Windows returned, valid until freed just below;
        // its encoded bytes are `cbCertEncoded` at `pbCertEncoded`.
        let der = unsafe { slice::from_raw_parts((*found).pbCertEncoded, (*found).cbCertEncoded as usize).to_vec() };
        // SAFETY: the context found above, freed once.
        unsafe { CertFreeCertificateContext(found) };
        out.push((der, hash));
    }
    Ok(out)
}

/// An open catalog, closed on drop.
struct Catalog(HANDLE);

impl Catalog {
    fn open(path: &[u16]) -> io::Result<Self> {
        // SAFETY: `path` is NUL-terminated; no provider; the version and
        // encoding the file says.
        let handle = unsafe { CryptCATOpen(path.as_ptr(), CRYPTCAT_OPEN_EXISTING, 0, 0, 0) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }

    fn members(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut member = ptr::null_mut();
        loop {
            // SAFETY: the catalog is open; `member` is null or the member this
            // call returned last.
            member = unsafe { CryptCATEnumerateMember(self.0, member) };
            if member.is_null() {
                return out;
            }
            // SAFETY: a member Windows returned stays valid while the catalog
            // is open; its tag is null or NUL-terminated.
            out.push(unsafe { text_at((*member).pwszReferenceTag) });
        }
    }

    /// The value of the catalog's own attribute `name`.
    fn attribute(&self, name: &str) -> Option<String> {
        let mut attribute = ptr::null_mut();
        loop {
            // SAFETY: the catalog is open; `attribute` is null or the one this
            // call returned last.
            attribute = unsafe { CryptCATEnumerateCatAttr(self.0, attribute) };
            if attribute.is_null() {
                return None;
            }
            // SAFETY: an attribute Windows returned stays valid while the
            // catalog is open; its tag is NUL-terminated and its value is
            // `cbValue` bytes of UTF-16 at `pbValue`.
            let (tag, value) = unsafe {
                let attribute = &*attribute;
                let units = if attribute.pbValue.is_null() {
                    &[][..]
                } else {
                    slice::from_raw_parts(attribute.pbValue.cast::<u16>(), attribute.cbValue as usize / 2)
                };
                (text_at(attribute.pwszReferenceTag), from_wide(units))
            };
            if tag == name {
                return Some(value);
            }
        }
    }
}

impl Drop for Catalog {
    fn drop(&mut self) {
        // SAFETY: the catalog was opened by this module and is closed once.
        unsafe { CryptCATClose(self.0) };
    }
}

/// A catalog administrator context, released on drop.
struct Admin(isize);

impl Drop for Admin {
    fn drop(&mut self) {
        // SAFETY: the context was acquired by this module and released once.
        unsafe { CryptCATAdminReleaseContext(self.0, 0) };
    }
}

/// A certificate store handed out by CryptQueryObject, closed on drop.
struct Store(HCERTSTORE);

impl Drop for Store {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the store CryptQueryObject opened, closed once.
            unsafe { CertCloseStore(self.0, 0) };
        }
    }
}

/// A signed message handed out by CryptQueryObject, closed on drop.
struct Message(*mut c_void);

impl Message {
    /// Signer `index`'s CMSG_SIGNER_INFO, in a buffer aligned for it.
    fn signer_info(&self, index: u32) -> io::Result<Vec<u64>> {
        let mut size = 0u32;
        // SAFETY: the message is open; a null buffer asks only for the size.
        if unsafe { CryptMsgGetParam(self.0, CMSG_SIGNER_INFO_PARAM, index, ptr::null_mut(), &mut size) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buf` has room for `size` bytes, as `size` says.
        let ok = unsafe { CryptMsgGetParam(self.0, CMSG_SIGNER_INFO_PARAM, index, buf.as_mut_ptr().cast(), &mut size) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if (size as usize) < size_of::<CMSG_SIGNER_INFO>() {
            return Err(invalid("Windows gave too little about a signer"));
        }
        Ok(buf)
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the message CryptQueryObject opened, closed once.
            unsafe { CryptMsgClose(self.0) };
        }
    }
}

/// The NUL-terminated UTF-16 text at `text`, or nothing for null.
///
/// # Safety
///
/// `text` must be null or point at NUL-terminated UTF-16 that stays valid
/// for the call.
unsafe fn text_at(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: the caller promises NUL-terminated text, so every unit up to
    // and including the NUL can be read.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the NUL were just read.
    String::from_utf16_lossy(unsafe { slice::from_raw_parts(text, len) })
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}
