//! Captun's phone key: the RSA key the built-in adb shows a phone. Once the
//! user taps "Allow USB debugging", the phone trusts whoever holds that key,
//! so it must be one Captun made, and no one else may read it.
//!
//! On Windows it lives in `%ProgramData%\Captun`. Nothing is checked, moved,
//! deleted or made there unless SYSTEM or Administrators own that folder (its
//! owner can change who may do what in it), and the folder is held open
//! meanwhile, so it cannot be renamed or swapped. A key found there is used
//! only if SYSTEM or Administrators own it and its permissions, cut off from
//! the folder's, let only them in; Windows reports both for the very file
//! held open. Anything else is moved out of the way and a new key is made,
//! with its owner and permissions given in the call that creates it, so it is
//! never open to anyone else, not even for a moment. On Linux and macOS the
//! key's folder is root's alone and the key is created `0600`.
//!
//! Captun was called OmniHub before, and phones may have allowed the key
//! OmniHub made. [`take_over_key`] copies that key into place once, while
//! Captun has none, but only if it passes the same checks; it never moves or
//! deletes anything of OmniHub's.

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex, MutexGuard, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use rsa::{
    RsaPrivateKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding, der::zeroize::Zeroizing},
    rand_core::{OsRng, RngCore},
};
use tracing::{info, warn};

use crate::runner::AdbError;

/// RSA key size adb uses.
const KEY_BITS: usize = 2048;
/// A 2048-bit key in PEM is under 2 KiB; a larger file is not one.
const MAX_KEY_FILE: u64 = 16 * 1024;
/// How long a phone command waits while another one checks or makes the key.
/// That takes a second or two; a check stuck on a file someone else holds
/// must not keep every later command waiting with it.
const MEMORY_WAIT: Duration = Duration::from_secs(20);

/// A new key's owner and permissions: Administrators own it, only SYSTEM and
/// Administrators may read it, nothing comes from the folder (`P`).
#[cfg(windows)]
const KEY_SDDL: &str = "O:BAD:P(A;;FR;;;SY)(A;;FR;;;BA)";

/// What the user is told when the key cannot be made private.
const NOT_PRIVATE: &str = "Captun could not keep its phone key private, so USB to phone did not start.";
/// ... when it cannot be told whether the key is private.
const NOT_CHECKED: &str = "Captun could not check that its phone key is private, so USB to phone did not start.";
/// ... when a key Captun did not make cannot be moved away.
const NOT_MOVED: &str =
    "Captun found a phone key it did not make and could not move it away, so USB to phone did not start.";
/// ... when a new key cannot be made or written.
const NOT_MADE: &str = "Captun could not make its phone key, so USB to phone did not start.";
/// What the user should know after [`KeyStatus::Replaced`].
const REPLACED_NOTE: &str = "Captun found a phone key it did not make and replaced it. If you allowed USB debugging for Captun before, open Developer options on the phone, tap Revoke USB debugging authorizations, then allow Captun again.";

/// What Captun found where its phone key belongs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    /// Its own private key was there.
    Existing,
    /// There was none (or only an unfinished one of its own); a new one was made.
    Created,
    /// There was a key Captun did not make, or one others could read. It was
    /// moved out of the way and a new key made; a phone that trusted the old
    /// key should forget it (see [`KeyStatus::note`]).
    Replaced,
}

impl KeyStatus {
    /// What to tell the user, if anything.
    pub fn note(self) -> Option<&'static str> {
        (self == Self::Replaced).then_some(REPLACED_NOTE)
    }
}

/// The steps that tell who controls the key and its folder, and make a new
/// key private. On Windows they ask Windows itself, and making a key owned by
/// Administrators needs the elevated service; tests stand in for them.
pub(crate) trait KeyGuard {
    /// Whether SYSTEM or Administrators own the folder held open as `dir`.
    /// An error means it could not be told.
    fn owns_folder(&self, dir: &File) -> Result<bool, String>;

    /// Whether the plain file held open as `file` is a key only Captun can
    /// have made and no one else can read. An error means it could not be told.
    fn is_private(&self, file: &File) -> Result<bool, String>;

    /// Creates the new key file at `path`, private from the moment it exists,
    /// and returns it open for writing. Fails if anything is there already,
    /// a link included.
    fn create_private(&self, path: &Path) -> io::Result<File>;

    /// A new key, as PKCS#8 PEM (the format `adb_client` reads).
    fn new_key(&self) -> Result<Zeroizing<String>, String> {
        generate()
    }
}

fn generate() -> Result<Zeroizing<String>, String> {
    let key = RsaPrivateKey::new(&mut OsRng, KEY_BITS).map_err(|e| format!("cannot generate it: {e}"))?;
    key.to_pkcs8_pem(LineEnding::LF).map_err(|e| format!("cannot encode it: {e}"))
}

/// The key checked or made in this run, held open: on Windows no one else can
/// then write, rename or delete it, so it is checked once per run rather than
/// before every phone command.
#[derive(Debug)]
pub(crate) struct KeyMemory {
    held: Mutex<Option<(PathBuf, File)>>,
    /// How long a command waits for another one's check.
    wait: Duration,
}

impl KeyMemory {
    const fn new(wait: Duration) -> Self {
        Self { held: Mutex::new(None), wait }
    }

    /// The memory, once no other command is checking the key. A check that
    /// takes longer than [`KeyMemory::wait`] is given up on: it is stuck.
    fn take(&self) -> Result<MutexGuard<'_, Option<(PathBuf, File)>>, AdbError> {
        let deadline = Instant::now() + self.wait;
        loop {
            match self.held.try_lock() {
                Ok(held) => return Ok(held),
                Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Err(TryLockError::WouldBlock) => {
                    return Err(key_error(NOT_CHECKED, "another phone command is still checking the key"));
                }
            }
        }
    }
}

impl Default for KeyMemory {
    fn default() -> Self {
        Self::new(MEMORY_WAIT)
    }
}

static MEMORY: KeyMemory = KeyMemory::new(MEMORY_WAIT);
/// Set when a key was replaced and [`prepare_key`] has not reported it yet.
static UNREPORTED_REPLACEMENT: AtomicBool = AtomicBool::new(false);

/// Makes sure Captun's phone key at `path` exists and is private (see the
/// module docs), making or replacing it as needed.
pub(crate) fn ensure_key(path: &Path) -> Result<KeyStatus, AdbError> {
    let status = ensure_key_with(path, &SystemGuard, &MEMORY)?;
    if status == KeyStatus::Replaced {
        UNREPORTED_REPLACEMENT.store(true, Ordering::Relaxed);
    }
    Ok(status)
}

/// [`ensure_key`] for the start of a session: also reports, once, a
/// replacement that an earlier phone command of this run made unannounced.
pub(crate) fn prepare_key(path: &Path) -> Result<KeyStatus, AdbError> {
    let status = ensure_key(path)?;
    let unreported = UNREPORTED_REPLACEMENT.swap(false, Ordering::Relaxed);
    Ok(if unreported { KeyStatus::Replaced } else { status })
}

pub(crate) fn ensure_key_with(path: &Path, guard: &dyn KeyGuard, memory: &KeyMemory) -> Result<KeyStatus, AdbError> {
    // Held for the whole check, so two phone commands never make two keys.
    let mut held = memory.take()?;
    if held.as_ref().is_some_and(|(known, _)| known == path) {
        return Ok(KeyStatus::Existing);
    }
    // Held open to the end, so the folder stays the one that was checked.
    let _folder = trusted_folder(path, guard).map_err(reported)?;
    let status = match examine(path, guard).map_err(reported)? {
        Found::Good(file) => {
            *held = Some((path.to_path_buf(), file));
            return Ok(KeyStatus::Existing);
        }
        Found::Nothing => KeyStatus::Created,
        Found::Unfinished => {
            // Made by Captun but cut short (a crash while it was written, say):
            // no phone can have trusted it.
            move_aside(path)?;
            info!("the phone key {} was unfinished; making a new one", path.display());
            KeyStatus::Created
        }
        Found::Foreign(why) => {
            let gone = move_aside(path)?;
            warn!("the phone key {} was not Captun's own ({why}); {gone}, and a new key is made", path.display());
            KeyStatus::Replaced
        }
    };
    create(path, guard)?;
    // Not holding it only costs a check on the next command.
    *held = hold(path).ok().map(|file| (path.to_path_buf(), file));
    Ok(status)
}

/// What [`take_over_key`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyTakeover {
    /// The earlier key passed every check and was copied into place.
    Copied,
    /// There is a key where it belongs already, or none to take over.
    NotNeeded,
    /// The earlier key was not taken, with why (for the log). It was left as
    /// it is, and a new key is made when one is needed.
    Refused(String),
}

/// Takes over the phone key OmniHub, as this program was called before, made
/// at `earlier`, so phones that allowed it keep allowing this one: only while
/// there is no key at `path` yet. The earlier key is used only if it passes
/// the checks a key found at `path` must pass (see the module docs), on the
/// very file held open, and it is then copied into a new key file made the way
/// every new key is, private from the moment it exists. The earlier key and
/// its folder are only read: never moved, changed or deleted, whatever is found.
pub fn take_over_key(earlier: &Path, path: &Path) -> KeyTakeover {
    take_over_key_with(earlier, path, &SystemGuard, &MEMORY)
}

pub(crate) fn take_over_key_with(earlier: &Path, path: &Path, guard: &dyn KeyGuard, memory: &KeyMemory) -> KeyTakeover {
    // The reasons are the details for the log, not the sentences a phone
    // command shows the user: no phone command is running.
    let refused = KeyTakeover::Refused;
    // Held for the whole takeover, so no phone command makes a key meanwhile.
    let Ok(_held) = memory.take() else {
        return refused("another phone command is checking the key".into());
    };
    // Anything where the key belongs, a link included, is left to `ensure_key`.
    match fs::symlink_metadata(path) {
        Ok(_) => return KeyTakeover::NotNeeded,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return refused(format!("cannot look at {}: {e}", path.display())),
    }
    match fs::symlink_metadata(earlier) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return KeyTakeover::NotNeeded,
        Err(e) => return refused(format!("cannot look at {}: {e}", earlier.display())),
    }
    // Held open to the end, like the key: what is checked is what is read.
    let _earlier_folder = match check_folder(folder_of(earlier), guard) {
        Ok(folder) => folder,
        Err((_, why)) => return refused(why),
    };
    let pem = match examine(earlier, guard) {
        Ok(Found::Good(mut file)) => match read_pem(&mut file) {
            Ok(pem) => pem,
            Err(e) => return refused(format!("cannot read it: {e}")),
        },
        Ok(Found::Nothing) => return KeyTakeover::NotNeeded,
        Ok(Found::Unfinished) => return refused("it is empty or cut short".into()),
        Ok(Found::Foreign(why)) => return refused(why.into()),
        Err((_, why)) => return refused(format!("it could not be checked: {why}")),
    };
    let _folder = match trusted_folder(path, guard) {
        Ok(folder) => folder,
        Err((_, why)) => return refused(format!("the folder for the new key is not safe to use: {why}")),
    };
    match write_new(path, guard, &pem) {
        Ok(()) => KeyTakeover::Copied,
        Err((_, why)) => refused(format!("it could not be copied: {why}")),
    }
}

/// The folder `path` is in.
fn folder_of(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// The whole key in the file held open, from its start.
fn read_pem(file: &mut File) -> io::Result<Zeroizing<String>> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut pem = Zeroizing::new(String::new());
    file.take(MAX_KEY_FILE).read_to_string(&mut pem)?;
    Ok(pem)
}

/// Why a step failed: the plain sentence a phone command shows the user, and
/// the detail for the log.
type Failure = (&'static str, String);

/// A [`Failure`] as a phone command reports it: the detail logged, the plain
/// sentence for the user.
fn reported((plain, detail): Failure) -> AdbError {
    key_error(plain, detail)
}

/// Opens the key's folder (making it first if there is none) and makes sure
/// only SYSTEM or Administrators control it. In a folder someone else owns,
/// or one that is a link, nothing is touched: they could swap what is in it,
/// or the folder itself, between the check and a move or delete.
fn trusted_folder(path: &Path, guard: &dyn KeyGuard) -> Result<File, Failure> {
    let dir = folder_of(path);
    fs::create_dir_all(dir).map_err(|e| (NOT_MADE, format!("cannot create {}: {e}", dir.display())))?;
    check_folder(dir, guard)
}

/// Opens the folder `dir`, which must be there, and makes sure it is a folder
/// of its own (not a link) that only SYSTEM or Administrators control.
fn check_folder(dir: &Path, guard: &dyn KeyGuard) -> Result<File, Failure> {
    let folder = hold_folder(dir).map_err(|e| (NOT_CHECKED, format!("cannot open {}: {e}", dir.display())))?;
    let meta = folder.metadata().map_err(|e| (NOT_CHECKED, format!("cannot look at {}: {e}", dir.display())))?;
    if !meta.is_dir() || is_link(&meta) {
        return Err((NOT_PRIVATE, format!("{} is a link, not a folder of its own; nothing in it was touched", dir.display())));
    }
    match guard.owns_folder(&folder) {
        Ok(true) => Ok(folder),
        Ok(false) => Err((
            NOT_PRIVATE,
            format!(
                "{} is owned by an account other than SYSTEM or Administrators; nothing in it was touched",
                dir.display()
            ),
        )),
        Err(why) => Err((NOT_CHECKED, why)),
    }
}

/// Opens a folder to read its owner. On Windows it can then not be renamed or
/// deleted while it stays open (others may still add files to it, as moving
/// the key aside does), and a link is opened as itself, not followed.
fn hold_folder(dir: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        };
        // Windows applies a handle's sharing only when it was opened for
        // data (listing, for a folder); without that, not sharing delete
        // would stop no one.
        options
            .access_mode(FILE_LIST_DIRECTORY | READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(windows))]
    {
        options.read(true);
    }
    options.open(dir)
}

/// What is where the key belongs.
enum Found {
    Nothing,
    /// Captun's own private key, held open.
    Good(File),
    /// Captun's own private key, but empty or cut short.
    Unfinished,
    /// Anything Captun did not make, with why it is refused (for the log).
    Foreign(&'static str),
}

fn examine(path: &Path, guard: &dyn KeyGuard) -> Result<Found, Failure> {
    const NOT_A_FILE: &str = "it is a link or a folder, not a file";
    match fs::symlink_metadata(path) {
        Ok(meta) if is_link_or_folder(&meta) => return Ok(Found::Foreign(NOT_A_FILE)),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Found::Nothing),
        Err(e) => return Err((NOT_CHECKED, format!("cannot look at {}: {e}", path.display()))),
    }
    // Held open from here on, so what is checked is what the phone is shown.
    let mut file = match hold(path) {
        Ok(file) => file,
        // Captun's own key always lets the service read it (and its
        // permissions: reading asks for both). A file planted to shut the
        // service out would otherwise stop USB to phone for good.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(Found::Foreign("the service is not allowed to read it"));
        }
        Err(e) => return Err((NOT_CHECKED, format!("cannot open {}: {e}", path.display()))),
    };
    let meta = file.metadata().map_err(|e| (NOT_CHECKED, format!("cannot look at {}: {e}", path.display())))?;
    // Swapped for a link or a folder since the look above.
    if is_link_or_folder(&meta) || !meta.is_file() {
        return Ok(Found::Foreign(NOT_A_FILE));
    }
    match guard.is_private(&file) {
        Ok(true) => {}
        Ok(false) => return Ok(Found::Foreign("its owner or permissions are not the ones Captun sets")),
        Err(why) => return Err((NOT_CHECKED, why)),
    }
    Ok(if is_whole_key(&mut file, meta.len()) { Found::Good(file) } else { Found::Unfinished })
}

/// Whether the file holds a whole key `adb_client` can read.
fn is_whole_key(file: &mut File, len: u64) -> bool {
    if len == 0 || len > MAX_KEY_FILE {
        return false;
    }
    let mut pem = Zeroizing::new(String::new());
    file.take(MAX_KEY_FILE).read_to_string(&mut pem).is_ok() && RsaPrivateKey::from_pkcs8_pem(&pem).is_ok()
}

/// Opens the key for reading (on Windows its owner and permissions too). On
/// Windows no one else may then write, rename or delete it while it stays
/// open, and a link is opened as itself, not followed.
fn hold(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
        options.share_mode(FILE_SHARE_READ).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn is_link_or_folder(meta: &fs::Metadata) -> bool {
    meta.is_dir() || is_link(meta)
}

/// A symbolic link, or on Windows any reparse point (a junction included).
fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// Gets whatever is at `path` out of the way: moved to a new, unguessable
/// name beside it (a fixed name could be taken by something planted there
/// first), then deleted if it is a plain file; a link or a folder is left
/// under its new name. Says where it went, for the log.
fn move_aside(path: &Path) -> Result<String, AdbError> {
    let name = path.file_name().map_or_else(|| "adbkey".into(), |name| name.to_string_lossy().into_owned());
    let aside = path.with_file_name(format!("{name}.untrusted-{:016x}", OsRng.next_u64()));
    if let Err(e) = fs::rename(path, &aside) {
        // A planted file's permissions can refuse even renaming it, while
        // deleting it needs only the folder's, which the service has.
        // Deleting a link by its name never touches what it points to.
        if is_plain_file(path) && fs::remove_file(path).is_ok() {
            return Ok("it was deleted".to_owned());
        }
        return Err(key_error(NOT_MOVED, format!("cannot move {} to {}: {e}", path.display(), aside.display())));
    }
    if is_plain_file(&aside) {
        match fs::remove_file(&aside) {
            Ok(()) => return Ok("it was deleted".to_owned()),
            Err(e) => warn!("could not delete {}: {e}", aside.display()),
        }
    }
    Ok(format!("it was moved to {}", aside.display()))
}

fn is_plain_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && !is_link_or_folder(&meta))
}

/// Makes a new key at `path`: created exclusively (a file or link planted
/// meanwhile is never adopted) and private from the start, then written. On
/// any failure nothing stays.
fn create(path: &Path, guard: &dyn KeyGuard) -> Result<(), AdbError> {
    let pem = guard.new_key().map_err(|why| key_error(NOT_MADE, why))?;
    write_new(path, guard, &pem).map_err(reported)
}

/// Writes `pem` to a new key file at `path`, made as [`create`] makes one.
fn write_new(path: &Path, guard: &dyn KeyGuard, pem: &str) -> Result<(), Failure> {
    let mut file = guard
        .create_private(path)
        .map_err(|e| (NOT_PRIVATE, format!("cannot create {} as a private file: {e}", path.display())))?;
    let done = file
        .write_all(pem.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| (NOT_MADE, format!("cannot write {}: {e}", path.display())));
    drop(file);
    if done.is_err()
        && let Err(e) = fs::remove_file(path)
    {
        warn!("could not delete the unfinished phone key {}: {e}", path.display());
    }
    done
}

/// A new file, open for writing, that no one else may open while it is (on
/// Linux and macOS readable by its owner only).
#[cfg(any(not(windows), test))]
fn create_new_plain(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    options.open(path)
}

/// Logs what went wrong in detail and gives the user the plain sentence.
fn key_error(plain: &'static str, detail: impl std::fmt::Display) -> AdbError {
    warn!("phone key: {detail}");
    AdbError::Key(plain.to_owned())
}

/// The real checks. On Linux and macOS there is nothing to check: the key's
/// folder is root's alone and the key is created `0600`.
struct SystemGuard;

#[cfg(windows)]
impl KeyGuard for SystemGuard {
    fn owns_folder(&self, dir: &File) -> Result<bool, String> {
        ffi::sddl_of(dir, ffi::OWNER)
            .map(|text| sddl::owner_is_admin(&text))
            .map_err(|e| format!("cannot read who owns the key's folder: {e}"))
    }

    fn is_private(&self, file: &File) -> Result<bool, String> {
        ffi::sddl_of(file, ffi::OWNER | ffi::DACL)
            .map(|text| sddl::is_private(&text))
            .map_err(|e| format!("cannot read who may use the key: {e}"))
    }

    fn create_private(&self, path: &Path) -> io::Result<File> {
        ffi::create_new_with(path, KEY_SDDL)
    }
}

#[cfg(not(windows))]
impl KeyGuard for SystemGuard {
    fn owns_folder(&self, _dir: &File) -> Result<bool, String> {
        Ok(true)
    }

    fn is_private(&self, _file: &File) -> Result<bool, String> {
        Ok(true)
    }

    fn create_private(&self, path: &Path) -> io::Result<File> {
        create_new_plain(path)
    }
}

/// Owner and permissions in SDDL, the text Windows itself writes them as.
/// Unlike icacls' output it is the same in every Windows language.
#[cfg(any(windows, test))]
mod sddl {
    /// SYSTEM and Administrators, as aliases and as SIDs.
    const ADMINS: [&str; 4] = ["SY", "BA", "S-1-5-18", "S-1-5-32-544"];
    /// "Owner rights", which earlier versions of Captun granted on the key.
    /// It stands for the owner, who must be one of [`ADMINS`].
    const OWNER_RIGHTS: [&str; 2] = ["OW", "S-1-3-4"];

    /// Whether `text` (owner and permissions) describes a key that only
    /// SYSTEM and Administrators can use: one of them owns it, its permissions
    /// are cut off from the folder's (`D:P`), and every entry lets in only
    /// SYSTEM, Administrators or the owner. Anything else, entries this does
    /// not understand included, is refused.
    pub(super) fn is_private(text: &str) -> bool {
        let Some(parts) = split(text) else { return false };
        let part = |tag| parts.iter().find(|(t, _)| *t == tag).map(|(_, body)| *body);
        match (part('O'), part('D')) {
            (Some(owner), Some(dacl)) => ADMINS.contains(&owner) && dacl_is_private(dacl),
            _ => false,
        }
    }

    /// Whether `text` names SYSTEM or Administrators as the owner.
    pub(super) fn owner_is_admin(text: &str) -> bool {
        split(text).is_some_and(|parts| parts.iter().any(|(tag, owner)| *tag == 'O' && ADMINS.contains(owner)))
    }

    /// Splits `O:…G:…D:…S:…` into its parts, each tag at most once.
    fn split(text: &str) -> Option<Vec<(char, &str)>> {
        let bytes = text.as_bytes();
        let mut starts = Vec::new();
        let mut depth = 0usize;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'(' => depth += 1,
                b')' => depth = depth.checked_sub(1)?,
                b':' if depth == 0 && i > 0 && matches!(bytes[i - 1], b'O' | b'G' | b'D' | b'S') => starts.push(i - 1),
                _ => {}
            }
        }
        if depth != 0 || starts.first() != Some(&0) {
            return None;
        }
        let mut parts: Vec<(char, &str)> = Vec::with_capacity(starts.len());
        for (n, &start) in starts.iter().enumerate() {
            let end = starts.get(n + 1).copied().unwrap_or(bytes.len());
            let tag = char::from(bytes[start]);
            if parts.iter().any(|(t, _)| *t == tag) {
                return None;
            }
            parts.push((tag, text.get(start + 2..end)?));
        }
        Some(parts)
    }

    pub(super) fn dacl_is_private(dacl: &str) -> bool {
        let (flags, mut rest) = dacl.split_at(dacl.find('(').unwrap_or(dacl.len()));
        if !is_protected(flags) {
            return false;
        }
        let mut entries = 0;
        while !rest.is_empty() {
            let Some(end) = rest.find(')') else { return false };
            let Some(entry) = rest.get(..end).and_then(|e| e.strip_prefix('(')) else { return false };
            if !lets_in_only_admins(entry) {
                return false;
            }
            entries += 1;
            rest = &rest[end + 1..];
        }
        entries > 0
    }

    /// `P` must be among the flags; `AI` and `AR` may be. `NO_ACCESS_CONTROL`
    /// (everyone may do anything) or anything unknown fails.
    fn is_protected(mut flags: &str) -> bool {
        let mut protected = false;
        while !flags.is_empty() {
            if let Some(rest) = flags.strip_prefix("AI").or_else(|| flags.strip_prefix("AR")) {
                flags = rest;
            } else if let Some(rest) = flags.strip_prefix('P') {
                protected = true;
                flags = rest;
            } else {
                return false;
            }
        }
        protected
    }

    /// `type;flags;rights;object;inherited object;account`: an allow entry
    /// for SYSTEM, Administrators or the owner. Conditional entries carry a
    /// seventh field and are refused like every other kind.
    fn lets_in_only_admins(entry: &str) -> bool {
        let fields: Vec<&str> = entry.split(';').collect();
        fields.len() == 6
            && fields[0] == "A"
            && (ADMINS.contains(&fields[5]) || OWNER_RIGHTS.contains(&fields[5]))
    }
}

/// Asks Windows itself, on handles already open: no program is started, so
/// nothing depends on the service's environment or on what PowerShell may
/// run, and what is checked is the very file or folder held.
#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    use std::{
        ffi::{OsStr, c_void},
        fs::File,
        io,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::Path,
        ptr, slice,
    };

    use windows_sys::Win32::{
        Foundation::{ERROR_SUCCESS, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
                SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT},
    };

    pub(super) const OWNER: OBJECT_SECURITY_INFORMATION = OWNER_SECURITY_INFORMATION;
    pub(super) const DACL: OBJECT_SECURITY_INFORMATION = DACL_SECURITY_INFORMATION;

    /// Memory Windows handed out to be freed with `LocalFree`; freed on drop.
    struct Local(*mut c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a Windows call whose result is
                // to be freed with LocalFree, and this is the only place it is
                // freed, once.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// The parts `what` of the security descriptor of the file or folder held
    /// open as `file` (opened with read-control access), as SDDL.
    pub(super) fn sddl_of(file: &File, what: OBJECT_SECURITY_INFORMATION) -> io::Result<String> {
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `file` keeps the handle open for the call. The owner, group
        // and list out-pointers may be null (only the whole descriptor is
        // wanted), and `descriptor` is a valid place for the pointer written.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                what,
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
        let mut text: *mut u16 = ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: `descriptor` is the valid descriptor just returned; `text`
        // and `len` are valid places for what is written.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor.0, SDDL_REVISION_1, what, &mut text, &mut len)
        };
        if ok == 0 || text.is_null() {
            return Err(io::Error::last_os_error());
        }
        let text = Local(text.cast());
        // SAFETY: Windows wrote `len` UTF-16 units at `text` (the closing null
        // included), which stay valid until `text` is dropped, after the copy.
        let units = unsafe { slice::from_raw_parts(text.0.cast::<u16>(), len as usize) };
        let end = units.iter().position(|&unit| unit == 0).unwrap_or(units.len());
        Ok(String::from_utf16_lossy(&units[..end]))
    }

    /// Creates a new file at `path` with the owner and permissions in `sddl`
    /// from the start, open for writing and shared with no one. Fails if
    /// anything is there, a link included. Whoever creates a file may write
    /// it through this handle whatever the permissions say.
    pub(super) fn create_new_with(path: &Path, sddl: &str) -> io::Result<File> {
        let path = wide(path.as_os_str())?;
        let sddl = wide(OsStr::new(sddl))?;
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl` is a null-terminated UTF-16 string that outlives the
        // call; `descriptor` is a valid place for the pointer written; the
        // size out-pointer may be null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = Local(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: `path` is a null-terminated UTF-16 string; `attributes` and
        // the descriptor it points to stay alive for the call; there is no
        // template file.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_WRITE,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is a valid file handle just opened here and owned
        // by nothing else; the `File` closes it.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    /// `text` as a null-terminated UTF-16 string; one with a null inside
    /// would name something else.
    fn wide(text: &OsStr) -> io::Result<Vec<u16>> {
        let mut units: Vec<u16> = text.encode_wide().collect();
        if units.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a name with a null character in it"));
        }
        units.push(0);
        Ok(units)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    /// Captun's own key: owned by Administrators, readable by SYSTEM and
    /// Administrators only, nothing taken from the folder.
    const OURS: &str = "O:BAG:SYD:PAI(A;;FR;;;SY)(A;;FR;;;BA)";
    /// Planted by another local user: their own account owns it.
    const FOREIGN_OWNER: &str = "O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-513D:PAI(A;;FR;;;SY)(A;;FR;;;BA)";
    /// Made with the folder's permissions, which let every user read it.
    const USERS_CAN_READ: &str = "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)";

    /// One real key for the tests that need a whole one; making a key takes
    /// seconds in a debug build.
    fn test_pem() -> Zeroizing<String> {
        static PEM: OnceLock<String> = OnceLock::new();
        Zeroizing::new(PEM.get_or_init(|| generate().unwrap().to_string()).clone())
    }

    /// Stands in for Windows, whose answers depend on the account the tests
    /// run as: answers the key check from a fixed SDDL (`None`: the check
    /// cannot run), says whether the folder is owned by Administrators, and
    /// creates the key plainly or fails to.
    struct Stub {
        sddl: Option<&'static str>,
        folder_owned: bool,
        create_works: bool,
        real_keys: bool,
        checks: AtomicUsize,
        creates: AtomicUsize,
    }

    impl Stub {
        fn new(sddl: Option<&'static str>, create_works: bool) -> Self {
            Self {
                sddl,
                folder_owned: true,
                create_works,
                real_keys: false,
                checks: AtomicUsize::new(0),
                creates: AtomicUsize::new(0),
            }
        }
    }

    impl KeyGuard for Stub {
        fn owns_folder(&self, _dir: &File) -> Result<bool, String> {
            Ok(self.folder_owned)
        }

        fn is_private(&self, _file: &File) -> Result<bool, String> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            self.sddl.map(sddl::is_private).ok_or_else(|| "cannot tell".to_owned())
        }

        fn create_private(&self, path: &Path) -> io::Result<File> {
            self.creates.fetch_add(1, Ordering::SeqCst);
            if self.create_works { create_new_plain(path) } else { Err(io::ErrorKind::PermissionDenied.into()) }
        }

        fn new_key(&self) -> Result<Zeroizing<String>, String> {
            if self.real_keys { generate() } else { Ok(test_pem()) }
        }
    }

    /// A key path in a fresh folder of its own.
    fn key_path(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("captun-key-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("adbkey")
    }

    /// Everything beside the key that was moved out of its way.
    fn set_aside(path: &Path) -> Vec<PathBuf> {
        let dir = path.parent().unwrap();
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("adbkey.untrusted-"))
            .collect()
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_new_key_is_created_written_and_then_kept() {
        let path = key_path("new");
        let mut stub = Stub::new(Some(OURS), true);
        stub.real_keys = true;
        let memory = KeyMemory::default();

        assert_eq!(ensure_key_with(&path, &stub, &memory).unwrap(), KeyStatus::Created);
        let pem = fs::read_to_string(&path).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"), "should be PKCS#8 PEM");
        assert_eq!(stub.creates.load(Ordering::SeqCst), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "key must be owner-only");
        }

        // Remembered for the run: no second check, the same key.
        assert_eq!(ensure_key_with(&path, &stub, &memory).unwrap(), KeyStatus::Existing);
        assert_eq!(stub.checks.load(Ordering::SeqCst), 0);
        drop(memory);

        // A new run checks it once, finds it Captun's own, and keeps it.
        let memory = KeyMemory::default();
        assert_eq!(ensure_key_with(&path, &stub, &memory).unwrap(), KeyStatus::Existing);
        assert_eq!(stub.checks.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_to_string(&path).unwrap(), pem, "key must not change");
        drop(memory);
        cleanup(&path);
    }

    #[test]
    fn a_missing_folder_is_made() {
        let path = key_path("no-folder").with_file_name("inner").join("adbkey");
        let stub = Stub::new(Some(OURS), true);
        assert_eq!(ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap(), KeyStatus::Created);
        assert!(path.is_file());
        cleanup(path.parent().unwrap());
    }

    #[test]
    fn a_key_with_another_owner_is_replaced() {
        let path = key_path("foreign");
        fs::write(&path, "planted").unwrap();
        let stub = Stub::new(Some(FOREIGN_OWNER), true);

        let status = ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap();
        assert_eq!(status, KeyStatus::Replaced);
        assert!(status.note().is_some_and(|note| note.contains("Revoke USB debugging authorizations")));
        let pem = fs::read_to_string(&path).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"), "a new key took its place");
        assert_eq!(stub.creates.load(Ordering::SeqCst), 1, "a new key was made private");
        assert!(set_aside(&path).is_empty(), "a planted plain file is deleted");
        cleanup(&path);
    }

    #[test]
    fn a_key_others_can_read_is_replaced() {
        let path = key_path("readable");
        fs::write(&path, test_pem().as_bytes()).unwrap();
        let stub = Stub::new(Some(USERS_CAN_READ), true);

        assert_eq!(ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap(), KeyStatus::Replaced);
        assert_eq!(stub.creates.load(Ordering::SeqCst), 1);
        cleanup(&path);
    }

    #[test]
    fn a_key_that_cannot_be_made_private_leaves_no_file() {
        let path = key_path("create-fails");
        let stub = Stub::new(Some(OURS), false);
        let err = ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap_err();
        assert_eq!(err.to_string(), NOT_PRIVATE);
        assert!(!path.exists(), "no key may stay behind");

        // Also when it was replacing a planted key.
        fs::write(&path, "planted").unwrap();
        let stub = Stub::new(Some(FOREIGN_OWNER), false);
        assert!(ensure_key_with(&path, &stub, &KeyMemory::default()).is_err());
        assert!(!path.exists());
        assert!(set_aside(&path).is_empty());
        cleanup(&path);
    }

    #[test]
    fn nothing_is_touched_in_a_folder_another_account_owns() {
        let path = key_path("foreign-folder");
        let theirs = path.with_file_name("theirs.txt");
        fs::write(&path, "planted").unwrap();
        fs::write(&theirs, "their own file").unwrap();
        let mut stub = Stub::new(Some(FOREIGN_OWNER), true);
        stub.folder_owned = false;

        let err = ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap_err();
        assert_eq!(err.to_string(), NOT_PRIVATE);
        assert_eq!(fs::read_to_string(&path).unwrap(), "planted", "neither moved nor deleted");
        assert_eq!(fs::read_to_string(&theirs).unwrap(), "their own file");
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2, "nothing added");
        assert_eq!(stub.checks.load(Ordering::SeqCst), 0);
        assert_eq!(stub.creates.load(Ordering::SeqCst), 0);

        // With no key there yet, none is made.
        fs::remove_file(&path).unwrap();
        assert!(ensure_key_with(&path, &stub, &KeyMemory::default()).is_err());
        assert!(!path.exists());
        assert_eq!(stub.creates.load(Ordering::SeqCst), 0);
        cleanup(&path);
    }

    /// Making a link to a folder needs a right not every account has; the
    /// test runs only where it can.
    #[cfg(windows)]
    #[test]
    fn a_folder_that_is_a_link_is_refused() {
        let path = key_path("linked-folder");
        let real = path.parent().unwrap().join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("adbkey"), "planted").unwrap();
        let link = path.parent().unwrap().join("link");
        if std::os::windows::fs::symlink_dir(&real, &link).is_ok() {
            let stub = Stub::new(Some(FOREIGN_OWNER), true);
            let err = ensure_key_with(&link.join("adbkey"), &stub, &KeyMemory::default()).unwrap_err();
            assert_eq!(err.to_string(), NOT_PRIVATE);
            assert_eq!(fs::read_to_string(real.join("adbkey")).unwrap(), "planted");
            assert_eq!(stub.creates.load(Ordering::SeqCst), 0);
        }
        cleanup(&path);
    }

    #[test]
    fn a_folder_in_the_keys_place_is_moved_aside() {
        let path = key_path("folder");
        fs::create_dir_all(path.join("inside")).unwrap();
        let stub = Stub::new(Some(OURS), true);

        assert_eq!(ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap(), KeyStatus::Replaced);
        assert!(path.is_file());
        let aside = set_aside(&path);
        assert_eq!(aside.len(), 1, "the folder is kept under a new name");
        assert!(aside[0].join("inside").is_dir());
        assert_eq!(stub.checks.load(Ordering::SeqCst), 0, "a folder is never taken for a key");
        cleanup(&path);
    }

    #[test]
    fn a_key_that_cannot_be_checked_is_neither_used_nor_replaced() {
        let path = key_path("unknown");
        fs::write(&path, test_pem().as_bytes()).unwrap();
        let stub = Stub::new(None, true);

        let err = ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap_err();
        assert_eq!(err.to_string(), NOT_CHECKED);
        assert_eq!(fs::read_to_string(&path).unwrap(), *test_pem(), "left as it was");
        assert_eq!(stub.creates.load(Ordering::SeqCst), 0);
        cleanup(&path);
    }

    #[test]
    fn a_key_the_service_may_not_read_is_replaced() {
        let path = key_path("unreadable");
        // Planted so that no one may read it (moving it away still works).
        #[cfg(windows)]
        let shut_out = {
            let mut planted = ffi::create_new_with(&path, "D:P").unwrap();
            planted.write_all(b"planted").unwrap();
            drop(planted);
            assert_eq!(hold(&path).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            true
        };
        #[cfg(unix)]
        let shut_out = {
            use std::os::unix::fs::PermissionsExt;
            fs::write(&path, "planted").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
            // root reads it anyway; then there is nothing to test.
            fs::File::open(&path).is_err()
        };
        if shut_out {
            let stub = Stub::new(Some(OURS), true);
            assert_eq!(ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap(), KeyStatus::Replaced);
            assert_eq!(stub.checks.load(Ordering::SeqCst), 0, "nothing to check on a file it cannot open");
            assert!(fs::read_to_string(&path).unwrap().starts_with("-----BEGIN PRIVATE KEY-----"));
            assert!(set_aside(&path).is_empty(), "the planted file is deleted");
        }
        cleanup(&path);
    }

    #[test]
    fn an_unfinished_key_of_ours_is_made_again_without_a_warning() {
        let path = key_path("unfinished");
        fs::write(&path, "").unwrap();
        let stub = Stub::new(Some(OURS), true);

        assert_eq!(ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap(), KeyStatus::Created);
        assert!(fs::read_to_string(&path).unwrap().starts_with("-----BEGIN PRIVATE KEY-----"));
        cleanup(&path);
    }

    #[test]
    fn a_check_stuck_elsewhere_is_not_waited_for_forever() {
        let path = key_path("stuck");
        let memory = KeyMemory::new(Duration::from_millis(100));
        let stuck = memory.held.lock().unwrap();
        let stub = Stub::new(Some(OURS), true);

        let started = Instant::now();
        let err = ensure_key_with(&path, &stub, &memory).unwrap_err();
        assert_eq!(err.to_string(), NOT_CHECKED);
        assert!(started.elapsed() < Duration::from_secs(5), "it must give up");
        assert_eq!(stub.creates.load(Ordering::SeqCst), 0);

        // Once the other check is done, the next command goes ahead.
        drop(stuck);
        assert_eq!(ensure_key_with(&path, &stub, &memory).unwrap(), KeyStatus::Created);
        cleanup(&path);
    }

    /// Windows makes a file with the given permissions in the creating call
    /// itself: nothing from the folder (which lets this account in) is added,
    /// and its maker may still write it. Works without elevation, since no
    /// owner is given.
    #[cfg(windows)]
    #[test]
    fn windows_creates_a_file_with_its_permissions_in_place() {
        use std::os::windows::fs::OpenOptionsExt;

        use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;

        let path = key_path("create-with");
        let mut file = ffi::create_new_with(&path, "D:P(A;;FR;;;SY)(A;;FR;;;BA)").unwrap();
        file.write_all(b"written by its maker").unwrap();
        drop(file);
        let again = ffi::create_new_with(&path, "D:P(A;;FR;;;SY)(A;;FR;;;BA)").unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists, "never opens what is there");

        // Its owner may always read its permissions.
        let view = fs::OpenOptions::new().access_mode(READ_CONTROL).open(&path).unwrap();
        let text = ffi::sddl_of(&view, ffi::OWNER | ffi::DACL).unwrap();
        let dacl = text.split_once("D:").unwrap().1;
        assert!(sddl::dacl_is_private(dacl), "{text}");
        assert!(dacl.ends_with("(A;;FR;;;SY)(A;;FR;;;BA)"), "{text}");
        drop(view);
        cleanup(&path);
    }

    /// While the key's folder is held it cannot be renamed (and something
    /// else put in its place), but files in it can still be added and moved.
    #[cfg(windows)]
    #[test]
    fn a_held_folder_cannot_be_renamed() {
        /// Refused because the folder is held, not for want of rights.
        const ERROR_SHARING_VIOLATION: i32 = 32;
        let path = key_path("held-folder");
        let dir = path.parent().unwrap().to_path_buf();

        let held = hold_folder(&dir).unwrap();
        let renamed = fs::rename(&dir, dir.with_extension("moved")).unwrap_err();
        assert_eq!(renamed.raw_os_error(), Some(ERROR_SHARING_VIOLATION), "{renamed}");
        let deleted = fs::remove_dir(&dir).unwrap_err();
        assert_eq!(deleted.raw_os_error(), Some(ERROR_SHARING_VIOLATION), "{deleted}");
        fs::write(&path, "planted").unwrap();
        let aside = path.with_file_name("adbkey.untrusted-0");
        fs::rename(&path, &aside).unwrap();
        fs::remove_file(&aside).unwrap();
        drop(held);

        // Once let go, it can be deleted (a virus scanner may still be
        // looking at the file that was in it for a moment).
        let deadline = Instant::now() + Duration::from_secs(10);
        while let Err(e) = fs::remove_dir(&dir) {
            assert!(Instant::now() < deadline, "still cannot delete it: {e}");
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// Windows' own folders: `%ProgramData%` belongs to SYSTEM, the Windows
    /// folder to TrustedInstaller (neither SYSTEM nor Administrators).
    #[cfg(windows)]
    #[test]
    fn windows_tells_who_owns_a_folder() {
        let data = PathBuf::from(std::env::var_os("ProgramData").unwrap());
        assert!(SystemGuard.owns_folder(&hold_folder(&data).unwrap()).unwrap());
        let windows = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        let text = ffi::sddl_of(&hold_folder(&windows).unwrap(), ffi::OWNER).unwrap();
        assert!(text.starts_with("O:S-1-5-80-"), "{text}");
        assert!(!SystemGuard.owns_folder(&hold_folder(&windows).unwrap()).unwrap());
    }

    /// Windows itself, end to end. Giving a file to Administrators needs an
    /// elevated prompt, so this runs only when asked:
    /// `cargo test -p captun-adb -- --ignored`. Use PowerShell or the
    /// Command Prompt: Git Bash (Cygwin) makes the user, not Administrators,
    /// own the folders it creates, and the test folder is then refused.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs an elevated prompt"]
    fn windows_makes_a_new_key_private_and_recognises_it() {
        let path = key_path("windows");
        assert_eq!(ensure_key_with(&path, &SystemGuard, &KeyMemory::default()).unwrap(), KeyStatus::Created);
        let text = ffi::sddl_of(&hold(&path).unwrap(), ffi::OWNER | ffi::DACL).unwrap();
        assert!(text.starts_with("O:BA") && text.contains("D:P"), "{text}");
        assert!(sddl::is_private(&text), "{text}");
        // A new run checks it and keeps it.
        assert_eq!(ensure_key_with(&path, &SystemGuard, &KeyMemory::default()).unwrap(), KeyStatus::Existing);

        // A file made the ordinary way (permissions from the folder) is not
        // taken for one.
        fs::rename(&path, path.with_file_name("old")).unwrap();
        fs::write(&path, test_pem().as_bytes()).unwrap();
        assert!(!SystemGuard.is_private(&hold(&path).unwrap()).unwrap());
        assert_eq!(ensure_key_with(&path, &SystemGuard, &KeyMemory::default()).unwrap(), KeyStatus::Replaced);
        cleanup(&path);
    }

    #[test]
    fn only_a_replacement_has_a_note() {
        assert!(KeyStatus::Existing.note().is_none());
        assert!(KeyStatus::Created.note().is_none());
        assert!(KeyStatus::Replaced.note().is_some());
    }

    #[test]
    fn sddl_of_captuns_own_keys_passes() {
        assert!(sddl::is_private(OURS));
        // As Windows reports a key made with Captun's owner and permissions.
        assert!(sddl::is_private("O:BAD:PAI(A;;FR;;;SY)(A;;FR;;;BA)"));
        // Keys made by earlier versions also granted "owner rights".
        assert!(sddl::is_private("O:BAG:DUD:PAI(A;;FR;;;SY)(A;;FR;;;BA)(A;;FR;;;OW)"));
        // SIDs instead of aliases, owner SYSTEM, a SACL after the DACL.
        assert!(sddl::is_private("O:S-1-5-18D:P(A;;FA;;;S-1-5-18)(A;;FR;;;S-1-5-32-544)S:(ML;;NW;;;LW)"));
    }

    #[test]
    fn sddl_of_anything_else_fails() {
        for text in [
            FOREIGN_OWNER,
            USERS_CAN_READ,
            // Not cut off from the folder's permissions.
            "O:BAD:AI(A;;FR;;;SY)(A;;FR;;;BA)",
            // Another account may read it.
            "O:BAD:PAI(A;;FR;;;SY)(A;;FR;;;BA)(A;;FR;;;S-1-5-21-1-2-3-1001)",
            "O:BAD:P(A;;FR;;;BA)(A;;FR;;;WD)",
            // Everyone may do anything.
            "O:BAD:NO_ACCESS_CONTROL",
            // No entries at all, deny entries, conditional entries.
            "O:BAD:P",
            "O:BAD:P(D;;FA;;;WD)(A;;FR;;;BA)",
            "O:BAD:P(XA;;FR;;;BA;(Member_of {SID(BA)}))",
            // Owned by "owner rights" itself, or by no one known.
            "O:OWD:P(A;;FR;;;BA)",
            "D:P(A;;FR;;;BA)",
            // Malformed or empty.
            "",
            "O:BAD:P(A;;FR;;;BA",
            "O:BAD:P(A;;FR;;;BA))",
            "O:BAD:P(A;;FR;;;BA)junk",
            "O:BAO:SYD:P(A;;FR;;;BA)",
        ] {
            assert!(!sddl::is_private(text), "{text:?} must not pass");
        }
    }

    #[test]
    fn folder_owners_are_read_from_sddl() {
        for text in ["O:BA", "O:SY", "O:S-1-5-18", "O:S-1-5-32-544", "O:BAG:SYD:PAI(A;OICI;FA;;;BU)"] {
            assert!(sddl::owner_is_admin(text), "{text:?} must pass");
        }
        for text in [
            "O:S-1-5-21-1-2-3-1001",
            // TrustedInstaller, which owns Windows' own folders.
            "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            "O:BU",
            "O:OW",
            "G:BA",
            "",
            "O:BAO:BA",
            "O:BA(",
        ] {
            assert!(!sddl::owner_is_admin(text), "{text:?} must not pass");
        }
    }

    #[test]
    fn omnihubs_own_key_is_taken_over_and_left_where_it_was() {
        let path = key_path("takeover");
        let earlier = path.with_file_name("omnihub").join("adbkey");
        fs::create_dir_all(earlier.parent().unwrap()).unwrap();
        fs::write(&earlier, test_pem().as_bytes()).unwrap();
        let stub = Stub::new(Some(OURS), true);

        assert_eq!(take_over_key_with(&earlier, &path, &stub, &KeyMemory::default()), KeyTakeover::Copied);
        assert_eq!(fs::read_to_string(&path).unwrap(), *test_pem(), "the same key, so phones keep allowing it");
        assert_eq!(stub.creates.load(Ordering::SeqCst), 1, "made the way a new key is");
        assert_eq!(fs::read_to_string(&earlier).unwrap(), *test_pem(), "OmniHub's key stays");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Captun has one now: nothing more to take over, and it is its own.
        assert_eq!(take_over_key_with(&earlier, &path, &stub, &KeyMemory::default()), KeyTakeover::NotNeeded);
        assert_eq!(ensure_key_with(&path, &stub, &KeyMemory::default()).unwrap(), KeyStatus::Existing);
        cleanup(&path);
    }

    #[test]
    fn an_earlier_key_that_fails_the_checks_is_never_taken_or_touched() {
        let path = key_path("takeover-refused");
        let earlier = path.with_file_name("omnihub").join("adbkey");
        fs::create_dir_all(earlier.parent().unwrap()).unwrap();
        fs::write(&earlier, test_pem().as_bytes()).unwrap();
        let mut not_their_folder = Stub::new(Some(OURS), true);
        not_their_folder.folder_owned = false;
        // The reason is the detail for the log: no phone command was running,
        // so it never says USB to phone did not start.
        let refused_for_its_own_reason = |taken: &KeyTakeover| match taken {
            KeyTakeover::Refused(why) => !why.is_empty() && !why.contains("USB to phone"),
            _ => false,
        };
        for stub in [
            Stub::new(Some(FOREIGN_OWNER), true),
            Stub::new(Some(USERS_CAN_READ), true),
            Stub::new(None, true),
            not_their_folder,
        ] {
            let taken = take_over_key_with(&earlier, &path, &stub, &KeyMemory::default());
            assert!(refused_for_its_own_reason(&taken), "{taken:?}");
            assert!(!path.exists(), "no key is made from it");
            assert_eq!(stub.creates.load(Ordering::SeqCst), 0);
            assert_eq!(fs::read_to_string(&earlier).unwrap(), *test_pem(), "never moved or changed");
            assert!(set_aside(&earlier).is_empty());
        }

        // A key of its own, but cut short.
        fs::write(&earlier, "-----BEGIN PRIVATE KEY-----").unwrap();
        let taken = take_over_key_with(&earlier, &path, &Stub::new(Some(OURS), true), &KeyMemory::default());
        assert!(refused_for_its_own_reason(&taken), "{taken:?}");
        assert!(!path.exists() && earlier.exists());

        // A key that cannot be made private leaves nothing behind.
        fs::write(&earlier, test_pem().as_bytes()).unwrap();
        let taken = take_over_key_with(&earlier, &path, &Stub::new(Some(OURS), false), &KeyMemory::default());
        assert!(refused_for_its_own_reason(&taken), "{taken:?}");
        assert!(!path.exists());
        cleanup(&path);
    }

    #[test]
    fn nothing_is_taken_over_without_an_earlier_key_or_with_a_key_already_there() {
        let path = key_path("takeover-none");
        let earlier = path.with_file_name("omnihub").join("adbkey");
        let stub = Stub::new(Some(OURS), true);
        assert_eq!(take_over_key_with(&earlier, &path, &stub, &KeyMemory::default()), KeyTakeover::NotNeeded);
        assert!(!path.exists());

        fs::create_dir_all(earlier.parent().unwrap()).unwrap();
        fs::write(&earlier, test_pem().as_bytes()).unwrap();
        fs::write(&path, "Captun's own").unwrap();
        assert_eq!(take_over_key_with(&earlier, &path, &stub, &KeyMemory::default()), KeyTakeover::NotNeeded);
        assert_eq!(fs::read_to_string(&path).unwrap(), "Captun's own");
        assert_eq!(stub.checks.load(Ordering::SeqCst), 0, "the earlier key was not even looked at");
        cleanup(&path);
    }
}
