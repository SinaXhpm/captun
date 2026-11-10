//! The CA key on Windows: a machine key in CNG (the Microsoft Software Key
//! Storage Provider) that cannot be exported.
//!
//! - It is made by the elevated service only, named
//!   `Captun-HTTPS-inspection-CA-<id>`, as an ECDSA P-256 machine key whose
//!   export policy has no export flag at all (no plain or wrapped export, no
//!   archiving), owned by Administrators, and whose permissions let only
//!   SYSTEM and Administrators use it, cut off from the permissions of the
//!   folder Windows keeps machine keys in. All of this is set before the key
//!   is finalized, so it is never stored any other way.
//! - Windows keeps keys of this provider in its key isolation service
//!   (KeyIso) and signs there: Captun sends the SHA-256 hash of what is to be
//!   signed and gets the signature back (`NCryptSignHash`). The private key
//!   never enters Captun's process.
//! - Each time a key is made or opened, it is checked again the way Windows
//!   reports it: P-256, the export policy still zero, owned by SYSTEM or
//!   Administrators, and no one else let in. A key that fails is not used: a
//!   new one is refused (and deleted), and an existing one makes the CA be
//!   replaced. So a key someone else made under Captun's name is never used.
//!   A question Windows could not answer (or answered in a form Captun does
//!   not know) is an error instead: it never counts as a failed check, so a
//!   passing fault never replaces the CA every device trusts.
//! - An ordinary (not elevated) program is refused before anything is asked
//!   of Windows, so "access denied" is never taken for "no key".
//! - The folder for the CA's public files is made with its own protected
//!   permissions (SYSTEM and Administrators only), so ordinary users cannot
//!   plant or damage files there, which could stop HTTPS inspection or make
//!   the CA be replaced.
//! - Windows' documentation says a service must not open the key storage
//!   from its start-up routine; Captun's callers run after start-up, on a
//!   worker thread (see `CertAuthority::open_or_create`).

use std::{
    fmt, fs,
    path::Path,
    sync::{Mutex, PoisonError},
};

use ring::digest;
use tracing::warn;

use crate::{
    TlsError,
    error::file_error,
    key::{CaKey, InstallId, KeyLookup, KeyStore, der_from_fixed},
    sddl,
};

/// Every CA key's name starts with this; the install id follows.
const PREFIX: &str = "Captun-HTTPS-inspection-CA-";
/// A new key's owner and permissions: Administrators own it (set here, not
/// left to the account's default owner, which a policy can change), only
/// SYSTEM and Administrators may use it, and nothing comes from the folder it
/// is kept in (`P`).
const KEY_SDDL: &str = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)";
/// The CA folder's owner and permissions: Administrators own it, only SYSTEM
/// and Administrators get in (files and subfolders inherit that), and nothing
/// comes from the folders above (`P`): ProgramData lets every user add files.
const FOLDER_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

const NOT_ELEVATED: &str = "HTTPS inspection keeps its key where only the Captun service can use it, and only the service, which runs with administrator rights, can make or open it.";

/// CA keys as non-exportable CNG machine keys (see the module docs).
#[derive(Debug)]
pub struct CngKeyStore {
    /// What every key name starts with: [`PREFIX`], but for tests, so they
    /// never touch the keys of a Captun installed on the same computer.
    prefix: &'static str,
}

impl Default for CngKeyStore {
    fn default() -> Self {
        Self { prefix: PREFIX }
    }
}

impl CngKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn for_tests() -> Self {
        Self { prefix: "Captun-HTTPS-inspection-CA-test-" }
    }

    fn key_name(&self, id: &InstallId) -> String {
        format!("{}{id}", self.prefix)
    }
}

/// Fails, in plain words, unless this is the elevated service.
fn require_service() -> Result<(), TlsError> {
    match ffi::is_elevated() {
        Ok(true) => Ok(()),
        Ok(false) => Err(TlsError::NeedsService(NOT_ELEVATED)),
        Err(e) => {
            Err(TlsError::Key(format!("Windows could not say whether Captun runs with administrator rights ({e})")))
        }
    }
}

fn windows_error(what: &'static str) -> impl FnOnce(ffi::Status) -> TlsError {
    move |status| {
        if status.is_denied() {
            TlsError::NeedsService(NOT_ELEVATED)
        } else {
            TlsError::Key(format!("Windows could not {what} ({status})"))
        }
    }
}

impl KeyStore for CngKeyStore {
    fn kind(&self) -> &'static str {
        "windows-machine-key"
    }

    fn prepare_folder(&self, dir: &Path) -> Result<(), TlsError> {
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent).map_err(file_error("make the folder", parent))?;
        }
        // Twice at most: a folder someone else made is moved aside once; if it
        // is there again right away, someone keeps making it.
        for _ in 0..2 {
            if ffi::create_folder(dir, FOLDER_SDDL).map_err(file_error("make the folder", dir))? {
                return Ok(());
            }
            let why = match ffi::folder_security(dir).map_err(file_error("read who may change", dir))? {
                ffi::Folder::Security(text) => match sddl::check_private(&text) {
                    Ok(()) => return Ok(()),
                    Err(sddl::Refusal::Finding(why)) => why,
                    Err(refusal @ sddl::Refusal::Unreadable) => {
                        return Err(TlsError::UnsafeFolder { path: dir.to_path_buf(), why: refusal.why() });
                    }
                },
                ffi::Folder::NotOwn => "it is a link, not a folder of its own",
            };
            // Only public files live here (the key is in Windows' key
            // storage), so a folder that is not Captun's alone is moved aside
            // and made again, rather than refused for good: refusing would let
            // any account switch HTTPS inspection off.
            let aside = set_aside_path(dir);
            warn!("moved the HTTPS inspection folder aside because {why}: {} -> {}", dir.display(), aside.display());
            fs::rename(dir, &aside).map_err(file_error("move aside", dir))?;
        }
        Err(TlsError::UnsafeFolder { path: dir.to_path_buf(), why: "another account keeps making it again" })
    }

    fn create(&self, id: &InstallId) -> Result<Box<dyn CaKey>, TlsError> {
        require_service()?;
        let provider = ffi::Provider::open().map_err(windows_error("open its key storage"))?;
        let name = self.key_name(id);
        let key = provider.create_key(&name, KEY_SDDL, ffi::Scope::Machine).map_err(windows_error("make the key"))?;
        // A new key nothing depends on yet: whether it was kept wrongly or
        // could not be checked, it is deleted and making the CA fails.
        let failure = match inspect(&key) {
            Ok(Inspection::Good(point)) => {
                return Ok(Box::new(CngKey { key: Mutex::new(key), _provider: provider, point, name }));
            }
            Ok(Inspection::Wrong(why)) => {
                TlsError::Key(format!("Windows did not keep the new key the way Captun asked: {why}"))
            }
            Err(error) => error,
        };
        if let Err(status) = key.delete() {
            warn!("could not delete the HTTPS inspection key {name}, which could not be confirmed safe ({status})");
        }
        Err(failure)
    }

    fn open(&self, id: &InstallId) -> Result<KeyLookup, TlsError> {
        require_service()?;
        let provider = ffi::Provider::open().map_err(windows_error("open its key storage"))?;
        let name = self.key_name(id);
        let key = match provider.open_key(&name, ffi::Scope::Machine) {
            Ok(key) => key,
            Err(status) if status.is_missing() => return Ok(KeyLookup::Missing),
            Err(status) => return Err(windows_error("open the key")(status)),
        };
        // `?`: a question Windows could not answer leaves the CA alone.
        Ok(match inspect(&key)? {
            Inspection::Good(point) => {
                KeyLookup::Found(Box::new(CngKey { key: Mutex::new(key), _provider: provider, point, name }))
            }
            Inspection::Wrong(why) => KeyLookup::Unusable(why),
        })
    }

    fn delete_all(&self) -> Result<(), TlsError> {
        require_service()?;
        let provider = ffi::Provider::open().map_err(windows_error("open its key storage"))?;
        let names = provider.key_names(ffi::Scope::Machine).map_err(windows_error("list its keys"))?;
        for name in names.iter().filter(|name| name.starts_with(self.prefix)) {
            match provider.open_key(name, ffi::Scope::Machine) {
                Ok(key) => key.delete().map_err(windows_error("delete the key"))?,
                // Captun's own keys always let Administrators in, so one the
                // service cannot open (which Windows may also report as "no
                // such key") was made by someone else, and it is refused when
                // opened.
                Err(status) if status.is_missing() => {}
                Err(status) if status.is_denied() => {
                    warn!("left the key {name} alone: it is not Captun's and Captun may not open it ({status})");
                }
                Err(status) => return Err(windows_error("open the key")(status)),
            }
        }
        Ok(())
    }
}

/// What a look at a key found.
enum Inspection {
    /// P-256, impossible to export, usable by SYSTEM and Administrators only:
    /// its public point.
    Good(Vec<u8>),
    /// Really not as Captun keeps its keys, with why in plain words.
    Wrong(String),
}

/// Looks at a key. A question Windows could not answer, or answered in a
/// form Captun does not know, is an `Err`, kept apart from a real finding
/// (`Wrong`): only a finding may make the CA be replaced.
fn inspect(key: &ffi::Key) -> Result<Inspection, TlsError> {
    let policy = key
        .export_policy()
        .map_err(|s| TlsError::Key(format!("Windows could not say whether the key can be exported ({s})")))?;
    if policy != 0 {
        return Ok(Inspection::Wrong("Windows would let the key be copied out".into()));
    }
    let text =
        key.security_sddl().map_err(|s| TlsError::Key(format!("Windows could not say who may use the key ({s})")))?;
    match sddl::check_private(&text) {
        Ok(()) => {}
        Err(refusal @ sddl::Refusal::Unreadable) => return Err(TlsError::Key(format!("{} ({text})", refusal.why()))),
        Err(sddl::Refusal::Finding(why)) => {
            return Ok(Inspection::Wrong(format!("the key's permissions are not Captun's: {why}")));
        }
    }
    let blob = key
        .public_blob()
        .map_err(|s| TlsError::Key(format!("Windows could not give the key's public half ({s})")))?;
    Ok(match point_from_blob(&blob) {
        Some(point) => Inspection::Good(point),
        None => Inspection::Wrong("it is not an ECDSA P-256 key".into()),
    })
}

/// Where a folder that is not Captun's alone is moved: beside it, named for
/// the time, so nothing is ever deleted that another account put there.
fn set_aside_path(dir: &Path) -> std::path::PathBuf {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    dir.with_file_name(format!("{name}.untrusted-{secs}"))
}

/// The uncompressed point in a `BCRYPT_ECCPUBLIC_BLOB` of a P-256 ECDSA key:
/// the magic `ECS1`, the coordinate size 32, then X and Y.
fn point_from_blob(blob: &[u8]) -> Option<Vec<u8>> {
    /// `BCRYPT_ECDSA_PUBLIC_P256_MAGIC`.
    const MAGIC: [u8; 4] = *b"ECS1";
    let (header, xy) = blob.split_at_checked(8)?;
    if header[..4] != MAGIC || header[4..] != 32u32.to_le_bytes() || xy.len() != 64 {
        return None;
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(xy);
    Some(point)
}

/// A CA key in CNG. Each signature is one call into Windows' key isolation
/// service; they are made one at a time.
struct CngKey {
    key: Mutex<ffi::Key>,
    /// The provider the key was opened from, kept open as long as the key
    /// (and closed after it: fields drop in this order).
    _provider: ffi::Provider,
    point: Vec<u8>,
    name: String,
}

impl CaKey for CngKey {
    fn public_point(&self) -> &[u8] {
        &self.point
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        let hash = digest::digest(&digest::SHA256, message);
        let fixed = self
            .key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sign_hash(hash.as_ref())
            .map_err(windows_error("sign with the key"))?;
        der_from_fixed(&fixed).ok_or_else(|| TlsError::Key("Windows gave a signature of the wrong size".into()))
    }
}

impl fmt::Debug for CngKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CngKey").field("name", &self.name).finish_non_exhaustive()
    }
}

/// Windows' CNG (NCrypt), the token's elevation and a folder's owner.
#[allow(unsafe_code)]
mod ffi {
    use std::{
        ffi::c_void,
        fmt,
        fs::OpenOptions,
        io,
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::Path,
        ptr, slice,
    };

    use windows_sys::{
        Win32::{
            Foundation::{
                E_ACCESSDENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, LocalFree, NTE_BAD_KEYSET, NTE_BAD_LEN,
                NTE_NO_KEY, NTE_NO_MORE_ITEMS, NTE_PERM,
            },
            Security::{
                Authorization::{
                    ConvertSecurityDescriptorToStringSecurityDescriptorW,
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
                    SE_FILE_OBJECT,
                },
                Cryptography::{
                    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, MS_KEY_STORAGE_PROVIDER,
                    NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PERSIST_FLAG,
                    NCRYPT_PROV_HANDLE, NCRYPT_SECURITY_DESCR_PROPERTY, NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey,
                    NCryptDeleteKey, NCryptEnumKeys, NCryptExportKey, NCryptFinalizeKey, NCryptFreeBuffer,
                    NCryptFreeObject, NCryptGetProperty, NCryptKeyName, NCryptOpenKey, NCryptOpenStorageProvider,
                    NCryptSetProperty, NCryptSignHash,
                },
                DACL_SECURITY_INFORMATION, GetTokenInformation, OBJECT_SECURITY_INFORMATION,
                OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
                TokenElevation,
            },
            Storage::FileSystem::{
                CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
                FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
            },
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        },
        core::{HRESULT, PCWSTR},
    };

    /// What a CNG call returned when it failed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Status(HRESULT);

    impl Status {
        /// There is no key by that name. (Windows says the same, "keyset
        /// does not exist", when a key's permissions keep the caller out;
        /// Captun's own keys always let the elevated service in.)
        pub(super) fn is_missing(self) -> bool {
            matches!(self.0, NTE_BAD_KEYSET | NTE_NO_KEY)
        }

        pub(super) fn is_denied(self) -> bool {
            matches!(self.0, NTE_PERM | E_ACCESSDENIED)
        }

        /// The last Windows error of this thread, as an HRESULT.
        fn last() -> Self {
            let code = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            // HRESULT_FROM_WIN32.
            Self(if code <= 0 { code } else { ((code.cast_unsigned() & 0xFFFF) | 0x8007_0000).cast_signed() })
        }
    }

    impl fmt::Display for Status {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "error 0x{:08X}", self.0.cast_unsigned())
        }
    }

    fn check(status: HRESULT) -> Result<(), Status> {
        if status == 0 { Ok(()) } else { Err(Status(status)) }
    }

    /// `text` as a null-terminated UTF-16 string. Callers pass only names
    /// Captun makes, which hold no null character.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    /// Which keys: the computer's (what Captun uses), or, for a test that
    /// cannot run elevated, the user's own.
    #[derive(Clone, Copy)]
    pub(super) enum Scope {
        Machine,
        #[cfg(test)]
        User,
    }

    impl Scope {
        fn flag(self) -> u32 {
            match self {
                Self::Machine => NCRYPT_MACHINE_KEY_FLAG,
                #[cfg(test)]
                Self::User => 0,
            }
        }
    }

    /// The Microsoft Software Key Storage Provider, open.
    pub(super) struct Provider(NCRYPT_PROV_HANDLE);

    impl Drop for Provider {
        fn drop(&mut self) {
            // SAFETY: the handle came from NCryptOpenStorageProvider, belongs
            // to this value alone and is freed once, here.
            unsafe { NCryptFreeObject(self.0) };
        }
    }

    /// A key, open.
    pub(super) struct Key(NCRYPT_KEY_HANDLE);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from NCryptCreatePersistedKey or
            // NCryptOpenKey, belongs to this value alone and is freed once,
            // here (`delete` forgets the value when Windows freed it).
            unsafe { NCryptFreeObject(self.0) };
        }
    }

    impl Provider {
        pub(super) fn open() -> Result<Self, Status> {
            let mut handle: NCRYPT_PROV_HANDLE = 0;
            // SAFETY: `handle` is a valid place for the handle written; the
            // provider name is a constant null-terminated string.
            check(unsafe { NCryptOpenStorageProvider(&mut handle, MS_KEY_STORAGE_PROVIDER, 0) })?;
            Ok(Self(handle))
        }

        /// Makes the key `name`: ECDSA P-256, no export flag, the permissions
        /// (and the owner, if it names one) in `sddl`. Fails if a key by that
        /// name exists.
        pub(super) fn create_key(&self, name: &str, sddl: &str, scope: Scope) -> Result<Key, Status> {
            let name = wide(name);
            let mut handle: NCRYPT_KEY_HANDLE = 0;
            // SAFETY: the provider is open for the call; `name` is a
            // null-terminated UTF-16 string that outlives it; the algorithm is
            // a constant null-terminated string; `handle` is a valid place for
            // the handle written. Without NCRYPT_OVERWRITE_KEY_FLAG a key that
            // exists is never replaced.
            check(unsafe {
                NCryptCreatePersistedKey(
                    self.0,
                    &mut handle,
                    BCRYPT_ECDSA_P256_ALGORITHM,
                    name.as_ptr(),
                    0,
                    scope.flag(),
                )
            })?;
            let key = Key(handle);
            // No NCRYPT_ALLOW_EXPORT_FLAG, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
            // or archiving flag: the private key can never be exported.
            key.set_property(NCRYPT_EXPORT_POLICY_PROPERTY, &0u32.to_ne_bytes(), NCRYPT_PERSIST_FLAG)?;
            let descriptor = Descriptor::from_sddl(sddl)?;
            let parts = if sddl.starts_with("O:") {
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
            } else {
                DACL_SECURITY_INFORMATION
            };
            key.set_property(NCRYPT_SECURITY_DESCR_PROPERTY, descriptor.bytes(), NCRYPT_PERSIST_FLAG | parts)?;
            // SAFETY: the key handle is open for the call.
            check(unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) })?;
            Ok(key)
        }

        pub(super) fn open_key(&self, name: &str, scope: Scope) -> Result<Key, Status> {
            let name = wide(name);
            let mut handle: NCRYPT_KEY_HANDLE = 0;
            // SAFETY: the provider is open for the call; `name` is a
            // null-terminated UTF-16 string that outlives it; `handle` is a
            // valid place for the handle written.
            check(unsafe { NCryptOpenKey(self.0, &mut handle, name.as_ptr(), 0, scope.flag() | NCRYPT_SILENT_FLAG) })?;
            Ok(Key(handle))
        }

        /// The names of all keys of this provider in `scope`.
        pub(super) fn key_names(&self, scope: Scope) -> Result<Vec<String>, Status> {
            let mut names = Vec::new();
            let mut state: *mut c_void = ptr::null_mut();
            let outcome = loop {
                let mut item: *mut NCryptKeyName = ptr::null_mut();
                // SAFETY: the provider is open for the call; `item` and `state`
                // are valid places for what is written, and `state` carries the
                // enumeration from one call to the next.
                let status = unsafe {
                    NCryptEnumKeys(self.0, ptr::null(), &mut item, &mut state, scope.flag() | NCRYPT_SILENT_FLAG)
                };
                if status == NTE_NO_MORE_ITEMS {
                    break Ok(());
                }
                if let Err(status) = check(status) {
                    break Err(status);
                }
                if item.is_null() {
                    break Err(Status(NTE_BAD_LEN));
                }
                let item = Buffer(item.cast());
                // SAFETY: on success `item` points to a key name Windows filled
                // in, whose name is a null-terminated UTF-16 string; both stay
                // valid until `item` is dropped, after the copy.
                names.push(unsafe { from_wide((*item.0.cast::<NCryptKeyName>()).pszName) });
            };
            if !state.is_null() {
                // SAFETY: the enumeration state came from NCryptEnumKeys and is
                // freed once, here.
                unsafe { NCryptFreeBuffer(state) };
            }
            outcome.map(|()| names)
        }
    }

    impl Key {
        fn set_property(&self, name: PCWSTR, value: &[u8], flags: u32) -> Result<(), Status> {
            let len = u32::try_from(value.len()).map_err(|_| Status(NTE_BAD_LEN))?;
            // SAFETY: the key handle is open; `name` is a constant
            // null-terminated string; `value` is valid for `len` bytes for the
            // call, which only reads it.
            check(unsafe { NCryptSetProperty(self.0, name, value.as_ptr(), len, flags) })
        }

        /// The export policy flags; zero is "never".
        pub(super) fn export_policy(&self) -> Result<u32, Status> {
            let mut value = [0u8; 4];
            let mut len = 0u32;
            // SAFETY: the key handle is open; `value` is valid for the 4 bytes
            // given and `len` for the size written.
            check(unsafe {
                NCryptGetProperty(self.0, NCRYPT_EXPORT_POLICY_PROPERTY, value.as_mut_ptr(), 4, &mut len, 0)
            })?;
            if len != 4 {
                return Err(Status(NTE_BAD_LEN));
            }
            Ok(u32::from_ne_bytes(value))
        }

        /// The key's owner and permissions, as SDDL.
        pub(super) fn security_sddl(&self) -> Result<String, Status> {
            const WHAT: OBJECT_SECURITY_INFORMATION = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            let mut len = 0u32;
            // SAFETY: the key handle is open; with no buffer Windows only
            // writes the size needed to `len`.
            check(unsafe {
                NCryptGetProperty(self.0, NCRYPT_SECURITY_DESCR_PROPERTY, ptr::null_mut(), 0, &mut len, WHAT)
            })?;
            // In u32s: a security descriptor is read 4 bytes at a time.
            let mut buffer = vec![0u32; (len as usize).div_ceil(4)];
            // SAFETY: `buffer` holds at least `len` bytes, valid for the call;
            // `len` is a valid place for the size written.
            check(unsafe {
                NCryptGetProperty(
                    self.0,
                    NCRYPT_SECURITY_DESCR_PROPERTY,
                    buffer.as_mut_ptr().cast(),
                    len,
                    &mut len,
                    WHAT,
                )
            })?;
            // SAFETY: Windows filled `buffer`, which outlives the call, with a
            // self-relative security descriptor.
            unsafe { sddl_of(buffer.as_mut_ptr().cast(), WHAT) }
        }

        /// The public key as a `BCRYPT_ECCPUBLIC_BLOB` (exporting the public
        /// half is allowed whatever the export policy).
        pub(super) fn public_blob(&self) -> Result<Vec<u8>, Status> {
            let mut blob = [0u8; 8 + 64];
            let mut len = 0u32;
            // SAFETY: the key handle is open; there is no export key and no
            // parameter list; `blob` is valid for the 72 bytes given and `len`
            // for the size written.
            check(unsafe {
                NCryptExportKey(self.0, 0, BCRYPT_ECCPUBLIC_BLOB, ptr::null(), blob.as_mut_ptr(), 72, &mut len, 0)
            })?;
            blob.get(..len as usize).map(<[u8]>::to_vec).ok_or(Status(NTE_BAD_LEN))
        }

        /// Signs `hash` (ECDSA, so no padding information): r ‖ s.
        pub(super) fn sign_hash(&self, hash: &[u8]) -> Result<Vec<u8>, Status> {
            let hash_len = u32::try_from(hash.len()).map_err(|_| Status(NTE_BAD_LEN))?;
            let mut signature = [0u8; 64];
            let mut len = 0u32;
            // SAFETY: the key handle is open; `hash` is valid for `hash_len`
            // bytes and `signature` for the 64 given; `len` is a valid place
            // for the size written.
            check(unsafe {
                NCryptSignHash(
                    self.0,
                    ptr::null(),
                    hash.as_ptr(),
                    hash_len,
                    signature.as_mut_ptr(),
                    64,
                    &mut len,
                    NCRYPT_SILENT_FLAG,
                )
            })?;
            signature.get(..len as usize).map(<[u8]>::to_vec).ok_or(Status(NTE_BAD_LEN))
        }

        /// Asks Windows for the private key in the form `blob`; for the test
        /// that it refuses.
        #[cfg(test)]
        pub(super) fn export_private(&self, blob: PCWSTR) -> Result<u32, Status> {
            let mut out = vec![0u8; 4096];
            let mut len = 0u32;
            // SAFETY: the key handle is open; `blob` is a constant
            // null-terminated string; `out` is valid for the 4096 bytes given
            // and `len` for the size written.
            check(unsafe {
                NCryptExportKey(self.0, 0, blob, ptr::null(), out.as_mut_ptr(), 4096, &mut len, NCRYPT_SILENT_FLAG)
            })?;
            Ok(len)
        }

        /// Deletes the key from storage.
        pub(super) fn delete(self) -> Result<(), Status> {
            // SAFETY: the key handle is open for the call.
            let status = unsafe { NCryptDeleteKey(self.0, NCRYPT_SILENT_FLAG) };
            if status == 0 {
                // Windows freed the handle; it must not be freed again.
                std::mem::forget(self);
            }
            check(status)
        }
    }

    /// Memory from NCryptEnumKeys, freed with NCryptFreeBuffer on drop.
    struct Buffer(*mut c_void);

    impl Drop for Buffer {
        fn drop(&mut self) {
            // SAFETY: the pointer came from NCryptEnumKeys, belongs to this
            // value alone and is freed once, here.
            unsafe { NCryptFreeBuffer(self.0) };
        }
    }

    /// Memory Windows handed out to be freed with LocalFree; freed on drop.
    struct Local(*mut c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a Windows call whose result is
                // freed with LocalFree, and this is the only place it is freed.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// A security descriptor made from SDDL.
    struct Descriptor {
        memory: Local,
        len: usize,
    }

    impl Descriptor {
        fn from_sddl(sddl: &str) -> Result<Self, Status> {
            let text = wide(sddl);
            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            let mut len = 0u32;
            // SAFETY: `text` is a null-terminated UTF-16 string that outlives
            // the call; `descriptor` and `len` are valid places for what is
            // written.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    &mut len,
                )
            };
            if ok == 0 || descriptor.is_null() {
                return Err(Status::last());
            }
            Ok(Self { memory: Local(descriptor), len: len as usize })
        }

        fn bytes(&self) -> &[u8] {
            // SAFETY: Windows made `len` bytes of self-relative descriptor at
            // the pointer, which stay valid while `memory` is alive (as long
            // as `self`, which the slice borrows).
            unsafe { slice::from_raw_parts(self.memory.0.cast::<u8>(), self.len) }
        }
    }

    /// The parts `what` of the security descriptor at `descriptor`, as SDDL.
    ///
    /// # Safety
    ///
    /// `descriptor` must point to a valid security descriptor, alive for the
    /// call.
    unsafe fn sddl_of(descriptor: PSECURITY_DESCRIPTOR, what: OBJECT_SECURITY_INFORMATION) -> Result<String, Status> {
        let mut text: *mut u16 = ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: the caller vouches for `descriptor`; `text` and `len` are
        // valid places for what is written.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, what, &mut text, &mut len)
        };
        if ok == 0 || text.is_null() {
            return Err(Status::last());
        }
        let text = Local(text.cast());
        // SAFETY: Windows wrote `len` UTF-16 units at `text` (the closing null
        // included), which stay valid until `text` is dropped, after the copy.
        let units = unsafe { slice::from_raw_parts(text.0.cast::<u16>(), len as usize) };
        let end = units.iter().position(|&unit| unit == 0).unwrap_or(units.len());
        Ok(String::from_utf16_lossy(&units[..end]))
    }

    /// The null-terminated UTF-16 string at `text`.
    ///
    /// # Safety
    ///
    /// `text` must be null or point to a null-terminated UTF-16 string, valid
    /// for the call.
    unsafe fn from_wide(text: *const u16) -> String {
        if text.is_null() {
            return String::new();
        }
        let mut len = 0;
        // SAFETY: the caller vouches that the string ends with a null, so
        // every unit up to it can be read.
        while unsafe { *text.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: the `len` units before the null were just read.
        String::from_utf16_lossy(unsafe { slice::from_raw_parts(text, len) })
    }

    /// Whether this process runs elevated (as the service does).
    pub(super) fn is_elevated() -> io::Result<bool> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess gives a pseudo handle that needs no
        // closing; `token` is a valid place for the handle written.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `token` was just opened here and belongs to nothing else;
        // the OwnedHandle closes it.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let size = u32::try_from(size_of::<TOKEN_ELEVATION>()).map_err(io::Error::other)?;
        // SAFETY: `token` is open with query access; `elevation` is valid for
        // the `size` bytes given and `len` for the size written.
        let ok = unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenElevation, (&raw mut elevation).cast(), size, &mut len)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    /// Makes the folder `dir` with the owner and permissions in `sddl`, in one
    /// step, so it never exists with any others. `Ok(false)` when something is
    /// already there (made by Captun before, or by someone else).
    pub(super) fn create_folder(dir: &Path, sddl: &str) -> io::Result<bool> {
        let descriptor = Descriptor::from_sddl(sddl).map_err(|status| io::Error::other(status.to_string()))?;
        let path: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
            lpSecurityDescriptor: descriptor.memory.0,
            bInheritHandle: 0,
        };
        // SAFETY: `path` is a null-terminated UTF-16 string and `attributes`
        // points to a valid security descriptor (kept alive by `descriptor`);
        // both outlive the call, which only reads them.
        if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } != 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS.cast_signed()) { Ok(false) } else { Err(error) }
    }

    /// Who owns a folder and who may use it, as Windows reports it for the
    /// very folder held open.
    pub(super) enum Folder {
        /// The owner and permissions, as SDDL.
        Security(String),
        /// Not a folder of its own: a link, a junction or a file.
        NotOwn,
    }

    pub(super) fn folder_security(dir: &Path) -> io::Result<Folder> {
        const WHAT: OBJECT_SECURITY_INFORMATION = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let folder = OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir)?;
        let meta = folder.metadata()?;
        if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(Folder::NotOwn);
        }
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `folder` keeps the handle open, with read-control access,
        // for the call; the owner, group and list out-pointers may be null
        // (only the whole descriptor is wanted); `descriptor` is a valid place
        // for the pointer written.
        let status = unsafe {
            GetSecurityInfo(
                folder.as_raw_handle(),
                SE_FILE_OBJECT,
                WHAT,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status.cast_signed()));
        }
        let descriptor = Local(descriptor);
        // SAFETY: `descriptor` is the valid descriptor just returned, alive
        // until it is dropped after the call.
        unsafe { sddl_of(descriptor.0, WHAT) }
            .map(Folder::Security)
            .map_err(|status| io::Error::other(status.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_ECCPRIVATE_BLOB, NCRYPT_PKCS8_PRIVATE_KEY_BLOB};

    use super::*;

    /// The test CA keys Windows holds now (never those of an installed
    /// Captun, whose names do not start with the test prefix).
    fn test_keys() -> Vec<String> {
        let prefix = CngKeyStore::for_tests().prefix;
        let names = ffi::Provider::open().unwrap().key_names(ffi::Scope::Machine).unwrap();
        names.into_iter().filter(|name| name.starts_with(prefix)).collect()
    }

    /// Deletes the user key `name` when dropped, so a failing test leaves
    /// none behind.
    struct UserKeyCleanup(String);

    impl Drop for UserKeyCleanup {
        fn drop(&mut self) {
            if let Ok(provider) = ffi::Provider::open()
                && let Ok(key) = provider.open_key(&self.0, ffi::Scope::User)
            {
                let _ = key.delete();
            }
        }
    }

    /// The same calls into Windows as for the CA's machine key, on a key of
    /// the user running the tests (a machine key needs an elevated prompt):
    /// made with no export flag and its own permissions, it signs, refuses
    /// to be exported, is listed, reports its permissions, and is deleted.
    #[test]
    fn a_key_made_this_way_signs_and_cannot_be_exported() {
        let provider = ffi::Provider::open().unwrap();
        let user_key = || format!("Captun-HTTPS-inspection-CA-test-user-{}", InstallId::random().unwrap());
        // OW: the owner (this user) may use it; SYSTEM and Administrators as
        // for the CA's key.
        let entries = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";

        // This account's SID, from a key that leaves the owner to Windows.
        let probe = user_key();
        let _cleanup_probe = UserKeyCleanup(probe.clone());
        let text = provider.create_key(&probe, entries, ffi::Scope::User).unwrap().security_sddl().unwrap();
        let me = text.strip_prefix("O:").and_then(|rest| rest.split("D:").next()).unwrap().to_owned();
        assert!(me.starts_with("S-1-5-"), "{text}");

        // The owner set the way the CA's key sets Administrators.
        let name = user_key();
        let _cleanup = UserKeyCleanup(name.clone());
        let sddl = format!("O:{me}{entries}");
        let key = provider.create_key(&name, &sddl, ffi::Scope::User).unwrap();
        assert!(provider.create_key(&name, &sddl, ffi::Scope::User).is_err(), "never a second key by that name");

        assert_eq!(key.export_policy().unwrap(), 0);
        assert!(key.export_private(NCRYPT_PKCS8_PRIVATE_KEY_BLOB).is_err());
        assert!(key.export_private(BCRYPT_ECCPRIVATE_BLOB).is_err());

        let point = point_from_blob(&key.public_blob().unwrap()).unwrap();
        let hash = digest::digest(&digest::SHA256, b"message");
        let signature = der_from_fixed(&key.sign_hash(hash.as_ref()).unwrap()).unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point).verify(b"message", &signature).unwrap();

        // As Windows reports them: the list given, owned by this account,
        // which is not SYSTEM or Administrators, so the check refuses it.
        let text = key.security_sddl().unwrap();
        println!("as Windows reports the key's owner and permissions: {text}");
        assert!(text.starts_with(&format!("O:{me}D:P")), "the owner given: {text}");
        assert!(text.contains(";;;SY)") && text.contains(";;;BA)"), "{text}");
        assert_eq!(text.matches('(').count(), 3, "only the entries given: {text}");
        assert_eq!(
            sddl::check_private(&text),
            Err(sddl::Refusal::Finding("it belongs to an account other than SYSTEM or Administrators"))
        );
        // Captun's own key, written the way Windows writes the rights, passes.
        let rights = text.split("(A;;").nth(1).and_then(|entry| entry.split(';').next()).unwrap();
        let captuns = format!("O:BAD:P(A;;{rights};;;SY)(A;;{rights};;;BA)");
        assert_eq!(sddl::check_private(&captuns), Ok(()), "{captuns}");

        assert!(provider.key_names(ffi::Scope::User).unwrap().contains(&name));
        drop(key);
        let opened = provider.open_key(&name, ffi::Scope::User).unwrap();
        assert_eq!(point_from_blob(&opened.public_blob().unwrap()).unwrap(), point, "the same key, opened again");
        opened.delete().unwrap();
        assert!(provider.open_key(&name, ffi::Scope::User).err().is_some_and(|status| status.is_missing()));
        assert!(!provider.key_names(ffi::Scope::User).unwrap().contains(&name));
    }

    #[test]
    fn test_keys_never_share_names_with_real_ones() {
        let id = InstallId::parse("0123ABCD").unwrap();
        assert_eq!(CngKeyStore::new().key_name(&id), "Captun-HTTPS-inspection-CA-0123ABCD");
        assert!(!CngKeyStore::for_tests().key_name(&id).starts_with(&CngKeyStore::new().key_name(&id)));
        // A real id is eight characters 0-9 and A-F, so no real name starts
        // with the test prefix.
        assert!(InstallId::parse("test-012").is_none());
    }

    #[test]
    fn public_blobs_are_read_only_when_they_are_p256() {
        let mut blob = b"ECS1".to_vec();
        blob.extend_from_slice(&32u32.to_le_bytes());
        blob.extend((0u8..64).map(|n| n + 1));
        let point = point_from_blob(&blob).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        assert_eq!(&point[1..], &blob[8..]);

        let mut p384 = b"ECS3".to_vec();
        p384.extend_from_slice(&48u32.to_le_bytes());
        p384.extend([1u8; 96]);
        assert_eq!(point_from_blob(&p384), None);
        assert_eq!(point_from_blob(&blob[..71]), None);
        assert_eq!(point_from_blob(b"ECS1"), None);
    }

    #[test]
    fn an_ordinary_program_is_refused_in_plain_words() {
        if ffi::is_elevated().unwrap() {
            return; // The ignored tests below cover an elevated run.
        }
        let store = CngKeyStore::for_tests();
        let id = InstallId::random().unwrap();
        for result in [store.create(&id).map(|_| ()), store.open(&id).map(|_| ()), store.delete_all()] {
            let err = result.unwrap_err();
            assert!(matches!(err, TlsError::NeedsService(_)), "{err}");
            assert!(err.to_string().contains("administrator rights"), "{err}");
        }
    }

    /// Windows itself, end to end. Making a machine key needs an elevated
    /// prompt, so this runs only when asked:
    /// `cargo test -p captun-tls -- --ignored`, from an elevated PowerShell
    /// or Command Prompt.
    #[test]
    #[ignore = "needs an elevated prompt: makes a Windows machine key"]
    fn a_machine_key_signs_and_cannot_be_exported() {
        let store = CngKeyStore::for_tests();
        let id = InstallId::random().unwrap();
        let key = store.create(&id).unwrap();
        let signature = key.sign(b"message").unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key.public_point()).verify(b"message", &signature).unwrap();

        // Windows refuses to hand out the private key, in either form.
        let provider = ffi::Provider::open().unwrap();
        let raw = provider.open_key(&store.key_name(&id), ffi::Scope::Machine).unwrap();
        assert_eq!(raw.export_policy().unwrap(), 0);
        assert!(raw.export_private(NCRYPT_PKCS8_PRIVATE_KEY_BLOB).is_err());
        assert!(raw.export_private(BCRYPT_ECCPRIVATE_BLOB).is_err());
        let text = raw.security_sddl().unwrap();
        assert_eq!(sddl::check_private(&text), Ok(()), "{text}");
        drop(raw);

        // Opened again, it is the same key, checked again.
        let KeyLookup::Found(again) = store.open(&id).unwrap() else { panic!("the key is kept") };
        assert_eq!(again.public_point(), key.public_point());
        // A second key under the same name is refused.
        assert!(store.create(&id).is_err());

        drop((key, again));
        store.delete_all().unwrap();
        assert!(matches!(store.open(&id).unwrap(), KeyLookup::Missing));
        assert!(test_keys().is_empty(), "{:?}", test_keys());
    }

    /// A whole CA on a Windows machine key: made, reloaded, signing site
    /// certificates that rustls accepts, and reset.
    #[test]
    #[ignore = "needs an elevated prompt: makes a Windows machine key"]
    fn a_ca_on_a_machine_key_works_and_resets() {
        let dir = std::env::temp_dir().join(format!("captun-tls-cng-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = CngKeyStore::for_tests();
        let (ca, status) = crate::CertAuthority::open_or_create(&dir, &store).unwrap();
        assert_eq!(status, crate::CaStatus::Created);
        let (again, status) = crate::CertAuthority::open_or_create(&dir, &store).unwrap();
        assert_eq!(status, crate::CaStatus::Loaded);
        assert_eq!(again.fingerprint(), ca.fingerprint());
        let leaf = again.issue(&crate::SiteName::parse("example.com").unwrap()).unwrap();
        crate::tests::verify_leaf(&again, &leaf, "example.com").unwrap();
        drop((ca, again));

        crate::reset(&dir, &store).unwrap();
        assert!(!dir.join("ca.pem").exists() && !dir.join("ca.json").exists());
        assert!(test_keys().is_empty(), "{:?}", test_keys());
        let (_, status) = crate::CertAuthority::open_or_create(&dir, &store).unwrap();
        assert_eq!(status, crate::CaStatus::Created);
        assert_eq!(test_keys().len(), 1);

        // Half there: the record gone, the key and certificate left behind.
        fs::remove_file(dir.join("ca.json")).unwrap();
        crate::reset(&dir, &store).unwrap();
        assert!(test_keys().is_empty(), "{:?}", test_keys());
        let _ = fs::remove_dir_all(&dir);
    }
}
