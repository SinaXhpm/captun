//! The settings, saved next to the app and encrypted so that only this user
//! on this computer can open them. The GUI owns them: the service keeps its
//! copy in memory and is handed this one each time it starts (`state.rs`).
//!
//! Next to the program, a copy of Captun carries its settings along. A
//! second encrypted copy in the user's profile lets a new copy or version
//! start with the same settings, and is the only one where the program's
//! folder cannot be written (Program Files, a macOS app bundle, an AppImage).
//!
//! Captun was called OmniHub before. The first time it starts with no
//! settings of its own, it copies the ones OmniHub saved for this user into
//! its own profile folder and uses that copy from then on
//! ([`Settings::taking_over`]). OmniHub's files are only ever read.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use captun_core::{Config, config::ConfigError};
use zeroize::Zeroizing;

use crate::paths;

pub(crate) const FILE_NAME: &str = "captun.settings";
/// What an unreadable settings file is renamed to, so it is never overwritten.
const SET_ASIDE_NAME: &str = "captun.settings.unreadable";
/// What OmniHub called its settings file, in its profile folder and next to
/// the program.
const EARLIER_FILE_NAME: &str = "omnihub.settings";
/// The plain-text settings early OmniHub versions kept in its profile folder.
const EARLIER_PLAIN_NAME: &str = "omnihub.toml";
/// On macOS and Linux, the key the settings are sealed with, kept in the
/// profile folder (OmniHub kept its own the same way).
const KEY_FILE_NAME: &str = "settings.key";
/// Far more than any settings file holds: a bigger file where OmniHub kept
/// its settings is not one.
const MAX_EARLIER_BYTES: u64 = 16 * 1024 * 1024;

/// What [`Settings::load`] found.
#[derive(Debug)]
pub(crate) enum Loaded {
    Saved(Box<Config>),
    /// Nothing has been saved yet.
    Missing,
    /// Settings exist but cannot be opened here (saved by another account or
    /// computer, or damaged). They were renamed out of the way.
    Unreadable(String),
    /// Nothing has been saved yet, and the settings OmniHub saved could not
    /// be brought over, with why (shown to the user). They stay where they
    /// are, and are tried again at the next start until Captun saves its own.
    NotTakenOver(String),
}

#[derive(Debug)]
pub(crate) struct Settings {
    /// Written on every save; the first is the main copy.
    write_to: Vec<PathBuf>,
    /// Tried in this order when loading.
    read_from: Vec<PathBuf>,
    /// The profile copy, where settings taken over from OmniHub are put.
    in_profile: PathBuf,
    /// The folder the program runs from, where OmniHub may have kept a copy.
    app_dir: Option<PathBuf>,
    /// OmniHub's profile folder, when its settings may be taken over.
    earlier: Option<PathBuf>,
    sealer: seal::Sealer,
}

impl Settings {
    pub(crate) fn new() -> Self {
        let profile = paths::settings_dir();
        Self::at(paths::app_dir().as_deref(), &profile).taking_over(&paths::earlier_settings_dir())
    }

    /// Settings next to `app_dir` (when it can be written) and in `profile`.
    pub(crate) fn at(app_dir: Option<&Path>, profile: &Path) -> Self {
        let in_profile = profile.join(FILE_NAME);
        let beside_app = app_dir.map(|dir| dir.join(FILE_NAME));
        let (write_to, read_from) = match beside_app {
            Some(app) if can_write(&app) => (vec![app.clone(), in_profile.clone()], vec![app, in_profile.clone()]),
            // Not writable: an older copy there may still be read.
            Some(app) => (vec![in_profile.clone()], vec![in_profile.clone(), app]),
            None => (vec![in_profile.clone()], vec![in_profile.clone()]),
        };
        Self {
            write_to,
            read_from,
            in_profile,
            app_dir: app_dir.map(Path::to_path_buf),
            earlier: None,
            sealer: seal::Sealer::new(profile),
        }
    }

    /// Also takes over, once, the settings OmniHub saved with `profile` as its
    /// profile folder (see [`Settings::load`]).
    pub(crate) fn taking_over(mut self, profile: &Path) -> Self {
        self.earlier = Some(profile.to_path_buf());
        self
    }

    /// The main copy, the one the user would look for.
    pub(crate) fn location(&self) -> &Path {
        &self.write_to[0]
    }

    pub(crate) fn load(&self) -> Loaded {
        let not_taken_over = match self.take_over_earlier() {
            Ok(Some(config)) => return Loaded::Saved(Box::new(config)),
            Ok(None) => None,
            Err(why) => Some(why),
        };
        let mut unreadable = None;
        for path in &self.read_from {
            let sealed = match fs::read(path) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => {
                    unreadable.get_or_insert_with(|| format!("{} cannot be read: {e}", path.display()));
                    continue;
                }
            };
            match self.open(&sealed) {
                Ok(config) => return Loaded::Saved(Box::new(config)),
                Err(why) => {
                    tracing::warn!("cannot open the settings in {}: {why}", path.display());
                    set_aside(path);
                    unreadable.get_or_insert(why);
                }
            }
        }
        match (unreadable, not_taken_over) {
            (Some(why), _) => Loaded::Unreadable(why),
            (None, Some(why)) => Loaded::NotTakenOver(why),
            (None, None) => Loaded::Missing,
        }
    }

    /// Validates, encrypts and writes every copy. Only a failure of the main
    /// copy is an error; the profile copy is a convenience.
    pub(crate) fn save(&self, config: &Config) -> Result<(), ConfigError> {
        config.validate()?;
        let text = Zeroizing::new(config.to_toml()?);
        let sealed = self.sealer.seal(text.as_bytes())?;
        let mut result = Ok(());
        for (i, path) in self.write_to.iter().enumerate() {
            if let Err(e) = write_atomically(path, &sealed) {
                if i == 0 {
                    result = Err(io::Error::new(e.kind(), format!("cannot save {}: {e}", path.display())).into());
                } else {
                    tracing::warn!("cannot save the profile copy of the settings at {}: {e}", path.display());
                }
            }
        }
        result
    }

    fn open(&self, sealed: &[u8]) -> Result<Config, String> {
        let text = self.sealer.open(sealed).map_err(|e| e.to_string())?;
        let text = std::str::from_utf8(&text).map_err(|_| "the settings are damaged".to_owned())?;
        Config::from_toml(text).map_err(|e| format!("the settings are damaged: {e}"))
    }

    /// The first time Captun starts with no settings of its own (none saved,
    /// none set aside as unreadable), copies the ones OmniHub saved for this
    /// user to the profile copy, which [`Settings::load`] then opens like any
    /// other. Settings early OmniHub versions kept in plain text are read,
    /// saved encrypted and returned. OmniHub's files stay as they are. An
    /// error says, for the user, why OmniHub's settings were not taken over.
    fn take_over_earlier(&self) -> Result<Option<Config>, String> {
        let Some(earlier) = self.earlier.as_deref() else { return Ok(None) };
        let mut ours = self.read_from.iter().flat_map(|path| [path.clone(), path.with_file_name(SET_ASIDE_NAME)]);
        // Anything there, a link included, means Captun has been here.
        if ours.any(|path| fs::symlink_metadata(path).is_ok()) {
            return Ok(None);
        }
        let copies = [Some(earlier.join(EARLIER_FILE_NAME)), self.app_dir.as_ref().map(|dir| dir.join(EARLIER_FILE_NAME))];
        // The first copy refused, unless another can be taken.
        let mut refused = None;
        for old in copies.into_iter().flatten() {
            let sealed = match read_earlier(&old) {
                Ok(Some(sealed)) => sealed,
                Ok(None) => continue,
                Err(why) => {
                    tracing::warn!("did not take over the settings OmniHub kept in {}: {why}", old.display());
                    refused.get_or_insert_with(|| not_taken_over(&old, &why));
                    continue;
                }
            };
            return match self.copy_earlier(earlier, &sealed) {
                Ok(()) => {
                    tracing::info!("copied the settings OmniHub saved in {} to {}", old.display(), self.in_profile.display());
                    Ok(None)
                }
                Err(why) => {
                    tracing::warn!("did not take over the settings OmniHub saved in {}: {why}", old.display());
                    Err(not_taken_over(&old, &why))
                }
            };
        }
        match self.take_earlier_plain(&earlier.join(EARLIER_PLAIN_NAME)) {
            Ok(Some(config)) => Ok(Some(config)),
            Ok(None) => refused.map_or(Ok(None), Err),
            Err(why) => Err(refused.unwrap_or(why)),
        }
    }

    /// Puts OmniHub's sealed settings where Captun keeps its profile copy. On
    /// macOS and Linux they open only with the key they were sealed with,
    /// which comes along.
    fn copy_earlier(&self, earlier: &Path, sealed: &[u8]) -> Result<(), String> {
        if let Some(our_key) = self.sealer.key_file() {
            take_over_key(&earlier.join(KEY_FILE_NAME), &our_key)?;
        }
        write_atomically(&self.in_profile, sealed).map_err(|e| format!("cannot copy them: {e}"))
    }

    /// Takes over the plain-text settings an early OmniHub kept at `path`
    /// and saves them encrypted. The plain file is OmniHub's and stays. An
    /// error says, for the user, why they were not taken over.
    fn take_earlier_plain(&self, path: &Path) -> Result<Option<Config>, String> {
        let text = match read_earlier(path) {
            Ok(Some(bytes)) => Zeroizing::new(bytes),
            Ok(None) => return Ok(None),
            Err(why) => {
                tracing::warn!("did not take over the old settings {}: {why}", path.display());
                return Err(not_taken_over(path, &why));
            }
        };
        let parsed = std::str::from_utf8(&text).map_err(|e| e.to_string());
        let config = match parsed.and_then(|text| Config::from_toml(text).map_err(|e| e.to_string())) {
            Ok(config) => config,
            Err(e) => {
                tracing::warn!("ignoring the old settings {}: {e}", path.display());
                return Err(not_taken_over(path, &format!("they are damaged ({e})")));
            }
        };
        match self.save(&config) {
            Ok(()) => tracing::info!(
                "took over the plain-text settings OmniHub kept in {} and saved them encrypted",
                path.display()
            ),
            Err(e) => tracing::warn!("cannot store the old settings encrypted yet: {e}"),
        }
        Ok(Some(config))
    }
}

/// What the user is told when the settings OmniHub kept at `path` were not
/// taken over, and `why`.
fn not_taken_over(path: &Path, why: &str) -> String {
    format!("Captun could not bring over the settings OmniHub saved in {}: {why}", path.display())
}

/// The bytes of a file OmniHub saved at `path`, or `None` if there is none.
/// Only a plain file is read, never a link or any other reparse point, so
/// nothing is ever taken from somewhere else.
fn read_earlier(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot look at it: {e}")),
    };
    if !is_plain_file(&meta) {
        return Err("it is a link or a folder, not a file".to_owned());
    }
    if meta.len() > MAX_EARLIER_BYTES {
        return Err("it is too large to be settings".to_owned());
    }
    fs::read(path).map(Some).map_err(|e| format!("cannot read it: {e}"))
}

/// A file that is neither a link nor, on Windows, any reparse point.
fn is_plain_file(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    let link = {
        use std::os::windows::fs::MetadataExt;
        /// `FILE_ATTRIBUTE_REPARSE_POINT`: links, junctions and the like.
        const REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & REPARSE_POINT != 0
    };
    #[cfg(not(windows))]
    let link = meta.file_type().is_symlink();
    meta.is_file() && !link
}

/// Copies the key OmniHub sealed its settings with (macOS and Linux) to
/// `ours`, owner-only like Captun's own. A key Captun already made is kept,
/// and unless it is the same one the settings cannot come along.
fn take_over_key(earlier: &Path, ours: &Path) -> Result<(), String> {
    let key = Zeroizing::new(read_earlier(earlier)?.ok_or_else(|| "the key they were saved with is gone".to_owned())?);
    match fs::symlink_metadata(ours) {
        Ok(_) if fs::read(ours).is_ok_and(|own| Zeroizing::new(own) == key) => return Ok(()),
        Ok(_) => return Err(format!("{} holds another key already, which cannot open them", ours.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot look at {}: {e}", ours.display())),
    }
    write_atomically(ours, &key).map_err(|e| format!("cannot copy their key: {e}"))
}

/// Whether the settings can be saved at `file`: its folder takes new files
/// (needed to replace it safely) and the file, if any, can be written.
fn can_write(file: &Path) -> bool {
    let Some(dir) = file.parent() else { return false };
    let probe = dir.join(format!(".captun-write-test-{}", std::process::id()));
    let dir_ok = fs::OpenOptions::new().write(true).create_new(true).open(&probe).is_ok();
    if dir_ok {
        let _ = fs::remove_file(&probe);
    }
    dir_ok && (!file.exists() || fs::OpenOptions::new().append(true).open(file).is_ok())
}

/// Renames an unreadable settings file so a later save cannot destroy it.
fn set_aside(path: &Path) {
    let target = path.with_file_name(SET_ASIDE_NAME);
    match fs::rename(path, &target) {
        Ok(()) => tracing::warn!("kept the unreadable settings as {}", target.display()),
        Err(e) => tracing::warn!("cannot rename the unreadable settings {}: {e}", path.display()),
    }
}

/// Writes through a temporary file and a rename, so a crash never leaves a
/// half-written file. On Unix the file is owner-only.
fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let name = path.file_name().map_or_else(|| FILE_NAME.into(), |name| name.to_string_lossy());
    let tmp = path.with_file_name(format!("{name}.tmp"));
    {
        use std::io::Write;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Every sealed file starts with this, then a byte naming how it was sealed.
const MAGIC: &[u8] = b"CAPTUN";
/// What the files OmniHub sealed start with instead. They are still opened,
/// so the settings taken over from it open; nothing is sealed this way now.
const EARLIER_MAGIC: &[u8] = b"OMNIHUB";

/// A sealed file, split up.
#[derive(Debug)]
struct Sealed<'a> {
    /// Its magic and scheme byte, as they are in the file (checked along
    /// with the text on macOS and Linux).
    #[cfg_attr(all(windows, not(test)), allow(dead_code))]
    header: &'a [u8],
    /// Whether OmniHub sealed it.
    earlier: bool,
    body: &'a [u8],
}

fn check_header(sealed: &[u8], scheme: u8) -> io::Result<Sealed<'_>> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_owned());
    let (magic, earlier) = if sealed.starts_with(MAGIC) {
        (MAGIC, false)
    } else if sealed.starts_with(EARLIER_MAGIC) {
        (EARLIER_MAGIC, true)
    } else {
        return Err(bad("this is not a Captun settings file"));
    };
    match sealed.split_at_checked(magic.len() + 1) {
        Some((header, body)) if header[magic.len()] == scheme => Ok(Sealed { header, earlier, body }),
        Some(_) => Err(bad("these settings were saved on another kind of computer")),
        None => Err(bad("this is not a Captun settings file")),
    }
}

/// Windows: DPAPI bound to the user's account, the way Windows itself keeps
/// saved passwords. Nothing else to keep: Windows holds the key.
#[cfg(windows)]
mod seal {
    use std::{
        io,
        path::{Path, PathBuf},
    };

    use zeroize::Zeroizing;

    const SCHEME: u8 = 1;

    #[derive(Debug)]
    pub(crate) struct Sealer;

    impl Sealer {
        pub(crate) fn new(_profile: &Path) -> Self {
            Self
        }

        /// The key file the settings need, if any: none, Windows holds the key.
        pub(crate) fn key_file(&self) -> Option<PathBuf> {
            None
        }

        pub(crate) fn seal(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            let blob = dpapi::protect(plain, dpapi::ENTROPY)?;
            let parts: [&[u8]; 3] = [super::MAGIC, &[SCHEME], &blob];
            Ok(parts.concat())
        }

        /// Sealed as OmniHub sealed its settings, to check they still open.
        #[cfg(test)]
        pub(crate) fn seal_as_earlier(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            let blob = dpapi::protect(plain, dpapi::EARLIER_ENTROPY)?;
            let parts: [&[u8]; 3] = [super::EARLIER_MAGIC, &[SCHEME], &blob];
            Ok(parts.concat())
        }

        pub(crate) fn open(&self, sealed: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
            let sealed = super::check_header(sealed, SCHEME)?;
            let entropy = if sealed.earlier { dpapi::EARLIER_ENTROPY } else { dpapi::ENTROPY };
            dpapi::unprotect(sealed.body, entropy).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "these settings were saved by another Windows account or on another computer")
            })
        }
    }

    #[allow(unsafe_code)]
    mod dpapi {
        use std::{io, ptr};

        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData},
        };
        use zeroize::Zeroizing;

        /// Mixed into the encryption so other programs using DPAPI for the
        /// same user cannot open these blobs by accident.
        pub(super) const ENTROPY: &[u8] = b"Captun settings v1";
        /// What OmniHub mixed in, to open the settings taken over from it.
        pub(super) const EARLIER_ENTROPY: &[u8] = b"OmniHub settings v1";

        fn blob(data: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
            let len = u32::try_from(data.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "settings too large"))?;
            // DPAPI only reads input blobs; the cast to *mut is what the C API spells.
            Ok(CRYPT_INTEGER_BLOB { cbData: len, pbData: data.as_ptr().cast_mut() })
        }

        /// Copies DPAPI's output out of its LocalAlloc'ed buffer and frees it,
        /// wiping it first when it held plain text.
        ///
        /// SAFETY: `out` must be a blob DPAPI filled on success.
        unsafe fn take(out: CRYPT_INTEGER_BLOB, wipe: bool) -> Vec<u8> {
            // SAFETY: on success DPAPI points `pbData` at `cbData` bytes it allocated.
            let slice = unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) };
            let copy = slice.to_vec();
            if wipe {
                use zeroize::Zeroize;
                slice.zeroize();
            }
            // SAFETY: the buffer came from DPAPI's LocalAlloc and is freed once.
            unsafe { LocalFree(out.pbData.cast()) };
            copy
        }

        pub(super) fn protect(plain: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
            let input = blob(plain)?;
            let entropy = blob(entropy)?;
            let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
            // SAFETY: the input blobs point at live slices for the whole call,
            // no prompt is requested, and `out` receives a buffer we free.
            let ok = unsafe { CryptProtectData(&input, ptr::null(), &entropy, ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: CryptProtectData succeeded and filled `out`.
            Ok(unsafe { take(out, false) })
        }

        pub(super) fn unprotect(sealed: &[u8], entropy: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
            let input = blob(sealed)?;
            let entropy = blob(entropy)?;
            let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
            // SAFETY: as in `protect`; the description out-pointer is not requested.
            let ok = unsafe { CryptUnprotectData(&input, ptr::null_mut(), &entropy, ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: CryptUnprotectData succeeded and filled `out`.
            Ok(Zeroizing::new(unsafe { take(out, true) }))
        }
    }
}

#[cfg(not(windows))]
mod seal {
    pub(crate) use super::keyfile::Sealer;
}

/// macOS and Linux: AES-256-GCM with a random key kept owner-only in the
/// user's profile, so the settings next to the app are useless without it.
/// (Also built for tests on Windows, where the real sealer is DPAPI.)
#[cfg(any(not(windows), test))]
mod keyfile {
    use std::{
        fs, io,
        path::{Path, PathBuf},
    };

    use ring::{
        aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
        rand::{SecureRandom, SystemRandom},
    };
    use zeroize::Zeroizing;

    const SCHEME: u8 = 2;
    const KEY_LEN: usize = 32;

    #[derive(Debug)]
    pub(crate) struct Sealer {
        key_file: PathBuf,
    }

    fn crypto_error(_: ring::error::Unspecified) -> io::Error {
        io::Error::other("encryption failed")
    }

    impl Sealer {
        pub(crate) fn new(profile: &Path) -> Self {
            Self { key_file: profile.join(super::KEY_FILE_NAME) }
        }

        /// The key file the settings need.
        pub(crate) fn key_file(&self) -> Option<PathBuf> {
            Some(self.key_file.clone())
        }

        fn read_key(&self) -> io::Result<Zeroizing<[u8; KEY_LEN]>> {
            let bytes = Zeroizing::new(fs::read(&self.key_file)?);
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            if bytes.len() != KEY_LEN {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "the settings key is damaged"));
            }
            key.copy_from_slice(&bytes);
            Ok(key)
        }

        /// The key, made the first time. Written to a temporary name and
        /// linked into place, so two Captun windows can never end up with
        /// different keys.
        fn key(&self) -> io::Result<Zeroizing<[u8; KEY_LEN]>> {
            match self.read_key() {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                other => return other,
            }
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            SystemRandom::new().fill(&mut key[..]).map_err(crypto_error)?;
            if let Some(dir) = self.key_file.parent() {
                fs::create_dir_all(dir)?;
            }
            let tmp = self.key_file.with_file_name(format!("{}.{}", super::KEY_FILE_NAME, std::process::id()));
            {
                use std::io::Write;
                let mut options = fs::OpenOptions::new();
                options.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(&tmp)?;
                file.write_all(&key[..])?;
                file.sync_all()?;
            }
            let linked = fs::hard_link(&tmp, &self.key_file);
            let _ = fs::remove_file(&tmp);
            match linked {
                Ok(()) => Ok(key),
                // Someone else made it first: use theirs.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => self.read_key(),
                Err(e) => Err(e),
            }
        }

        pub(crate) fn seal(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            self.seal_with(super::MAGIC, plain)
        }

        /// Sealed as OmniHub sealed its settings, to check they still open.
        #[cfg(test)]
        pub(crate) fn seal_as_earlier(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            self.seal_with(super::EARLIER_MAGIC, plain)
        }

        /// `magic` and the scheme byte, then a nonce and the sealed text; the
        /// header is authenticated with it.
        fn seal_with(&self, magic: &[u8], plain: &[u8]) -> io::Result<Vec<u8>> {
            let key = self.key()?;
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key[..]).map_err(crypto_error)?);
            let mut nonce = [0u8; NONCE_LEN];
            SystemRandom::new().fill(&mut nonce).map_err(crypto_error)?;
            let header: [&[u8]; 2] = [magic, &[SCHEME]];
            let header = header.concat();
            let mut body = plain.to_vec();
            key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(header.as_slice()), &mut body)
                .map_err(crypto_error)?;
            let parts: [&[u8]; 3] = [&header, &nonce, &body];
            Ok(parts.concat())
        }

        pub(crate) fn open(&self, sealed: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
            let sealed = super::check_header(sealed, SCHEME)?;
            let gone = || io::Error::new(io::ErrorKind::InvalidData, "these settings were saved on another computer, or their key is gone");
            let key = match self.read_key() {
                Ok(key) => key,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(gone()),
                Err(e) => return Err(e),
            };
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key[..]).map_err(crypto_error)?);
            let (nonce, cipher) = sealed.body.split_at_checked(NONCE_LEN).ok_or_else(gone)?;
            let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| gone())?;
            let mut buf = Zeroizing::new(cipher.to_vec());
            let plain_len = key.open_in_place(nonce, Aad::from(sealed.header), &mut buf[..]).map_err(|_| gone())?.len();
            buf.truncate(plain_len);
            Ok(buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("captun-settings-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample() -> Config {
        let mut config = Config::default();
        config.hotspot.ssid = "Test net".into();
        config.hotspot.passphrase = "correct horse battery".into();
        config
    }

    fn other() -> Config {
        let mut config = sample();
        config.hotspot.ssid = "Changed since".into();
        config
    }

    /// OmniHub's profile folder holding `config`, sealed as OmniHub sealed it.
    fn omnihub_profile(dir: &Path, config: &Config) -> PathBuf {
        let earlier = dir.join("omnihub");
        fs::create_dir_all(&earlier).unwrap();
        let sealed = seal::Sealer::new(&earlier).seal_as_earlier(config.to_toml().unwrap().as_bytes()).unwrap();
        assert!(sealed.starts_with(EARLIER_MAGIC));
        fs::write(earlier.join(EARLIER_FILE_NAME), sealed).unwrap();
        earlier
    }

    #[test]
    fn saved_settings_are_encrypted_and_come_back() {
        let dir = temp_dir("roundtrip");
        let (app, profile) = (dir.join("app"), dir.join("profile"));
        fs::create_dir_all(&app).unwrap();
        let settings = Settings::at(Some(&app), &profile);
        assert!(matches!(settings.load(), Loaded::Missing));

        settings.save(&sample()).unwrap();
        assert_eq!(settings.location(), app.join(FILE_NAME));
        for copy in [app.join(FILE_NAME), profile.join(FILE_NAME)] {
            let bytes = fs::read(&copy).unwrap();
            assert!(bytes.starts_with(MAGIC));
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("correct horse") && !text.contains("Test net"), "plain text in {}", copy.display());
        }
        // The files, and on macOS/Linux the key, are owner-only.
        #[cfg(unix)]
        for file in [app.join(FILE_NAME), profile.join(FILE_NAME), profile.join(KEY_FILE_NAME)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600, "{}", file.display());
        }
        match Settings::at(Some(&app), &profile).load() {
            Loaded::Saved(config) => assert_eq!(*config, sample()),
            other => panic!("expected saved settings, got {other:?}"),
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_new_copy_of_the_app_starts_from_the_profile_copy() {
        let dir = temp_dir("newcopy");
        let (old_app, new_app, profile) = (dir.join("v1"), dir.join("v2"), dir.join("profile"));
        fs::create_dir_all(&old_app).unwrap();
        fs::create_dir_all(&new_app).unwrap();
        Settings::at(Some(&old_app), &profile).save(&sample()).unwrap();
        assert!(matches!(Settings::at(Some(&new_app), &profile).load(), Loaded::Saved(c) if *c == sample()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unreadable_settings_are_kept_aside_not_overwritten() {
        let dir = temp_dir("unreadable");
        let profile = dir.join("profile");
        fs::create_dir_all(&profile).unwrap();
        let file = profile.join(FILE_NAME);
        fs::write(&file, b"CAPTUN\x01not really a blob").unwrap();
        let settings = Settings::at(None, &profile);
        assert!(matches!(settings.load(), Loaded::Unreadable(_)));
        assert!(!file.exists());
        assert_eq!(fs::read(profile.join(SET_ASIDE_NAME)).unwrap(), b"CAPTUN\x01not really a blob");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn omnihubs_settings_are_copied_once_and_left_as_they_were() {
        let dir = temp_dir("earlier");
        let earlier = omnihub_profile(&dir, &sample());
        let before = fs::read(earlier.join(EARLIER_FILE_NAME)).unwrap();
        let profile = dir.join("captun");

        let settings = Settings::at(None, &profile).taking_over(&earlier);
        assert!(matches!(settings.load(), Loaded::Saved(c) if *c == sample()));
        assert!(profile.join(FILE_NAME).exists(), "copied to Captun's own folder");
        assert_eq!(fs::read(earlier.join(EARLIER_FILE_NAME)).unwrap(), before, "OmniHub's file is left as it was");

        // From now on Captun's own copy is the one used, in Captun's format.
        settings.save(&other()).unwrap();
        assert!(fs::read(profile.join(FILE_NAME)).unwrap().starts_with(MAGIC));
        assert!(matches!(Settings::at(None, &profile).taking_over(&earlier).load(), Loaded::Saved(c) if *c == other()));
        assert_eq!(fs::read(earlier.join(EARLIER_FILE_NAME)).unwrap(), before);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_copy_omnihub_kept_next_to_the_program_is_taken_over_too() {
        let dir = temp_dir("earlier-app");
        let earlier = omnihub_profile(&dir, &sample());
        let app = dir.join("app");
        fs::create_dir_all(&app).unwrap();
        fs::rename(earlier.join(EARLIER_FILE_NAME), app.join(EARLIER_FILE_NAME)).unwrap();
        let profile = dir.join("captun");
        assert!(matches!(Settings::at(Some(&app), &profile).taking_over(&earlier).load(), Loaded::Saved(c) if *c == sample()));
        assert!(app.join(EARLIER_FILE_NAME).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn nothing_is_taken_over_once_captun_has_had_settings() {
        let dir = temp_dir("earlier-not-again");
        let earlier = omnihub_profile(&dir, &other());
        let profile = dir.join("captun");
        Settings::at(None, &profile).save(&sample()).unwrap();
        assert!(matches!(Settings::at(None, &profile).taking_over(&earlier).load(), Loaded::Saved(c) if *c == sample()));

        // Settings Captun set aside as unreadable count as its own too.
        fs::rename(profile.join(FILE_NAME), profile.join(SET_ASIDE_NAME)).unwrap();
        assert!(matches!(Settings::at(None, &profile).taking_over(&earlier).load(), Loaded::Missing));
        assert!(!profile.join(FILE_NAME).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn something_other_than_a_file_where_omnihub_kept_its_settings_is_not_taken() {
        let dir = temp_dir("earlier-folder");
        let earlier = dir.join("omnihub");
        fs::create_dir_all(earlier.join(EARLIER_FILE_NAME)).unwrap();
        let profile = dir.join("captun");
        // The user is told why, and where OmniHub's settings still are.
        match Settings::at(None, &profile).taking_over(&earlier).load() {
            Loaded::NotTakenOver(why) => {
                assert!(why.contains("a link or a folder") && why.contains(&*earlier.to_string_lossy()), "{why}");
            }
            other => panic!("expected the takeover to be refused, got {other:?}"),
        }
        assert!(!profile.join(FILE_NAME).exists());

        // A copy OmniHub kept next to the program is still taken, and then
        // there is nothing to tell.
        let app = dir.join("app");
        let sealed = seal::Sealer::new(&earlier).seal_as_earlier(sample().to_toml().unwrap().as_bytes()).unwrap();
        fs::create_dir_all(&app).unwrap();
        fs::write(app.join(EARLIER_FILE_NAME), sealed).unwrap();
        assert!(matches!(Settings::at(Some(&app), &profile).taking_over(&earlier).load(), Loaded::Saved(c) if *c == sample()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn damaged_plain_settings_from_omnihub_are_named_and_left_alone() {
        let dir = temp_dir("legacy-damaged");
        let earlier = dir.join("omnihub");
        fs::create_dir_all(&earlier).unwrap();
        fs::write(earlier.join(EARLIER_PLAIN_NAME), "not = [valid").unwrap();
        let profile = dir.join("captun");
        let settings = Settings::at(None, &profile).taking_over(&earlier);
        assert!(matches!(settings.load(), Loaded::NotTakenOver(why) if why.contains("damaged")));
        assert_eq!(fs::read_to_string(earlier.join(EARLIER_PLAIN_NAME)).unwrap(), "not = [valid");

        // Once Captun has saved its own, there is nothing more to tell.
        settings.save(&sample()).unwrap();
        assert!(matches!(settings.load(), Loaded::Saved(c) if *c == sample()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn plain_settings_from_early_omnihub_versions_are_taken_over_and_left_in_place() {
        let dir = temp_dir("legacy");
        let earlier = dir.join("omnihub");
        fs::create_dir_all(&earlier).unwrap();
        fs::write(earlier.join(EARLIER_PLAIN_NAME), sample().to_toml().unwrap()).unwrap();
        let profile = dir.join("captun");
        let settings = Settings::at(None, &profile).taking_over(&earlier);
        assert!(matches!(settings.load(), Loaded::Saved(c) if *c == sample()));
        assert!(earlier.join(EARLIER_PLAIN_NAME).exists(), "OmniHub's file stays");
        assert!(fs::read(profile.join(FILE_NAME)).unwrap().starts_with(MAGIC), "saved encrypted");
        // Captun's own copy from now on.
        fs::write(earlier.join(EARLIER_PLAIN_NAME), other().to_toml().unwrap()).unwrap();
        assert!(matches!(Settings::at(None, &profile).taking_over(&earlier).load(), Loaded::Saved(c) if *c == sample()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_settings_are_refused() {
        let dir = temp_dir("invalid");
        let settings = Settings::at(None, &dir);
        let mut config = Config::default();
        config.hotspot.ssid = String::new();
        assert!(settings.save(&config).is_err());
        assert!(!dir.join(FILE_NAME).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn key_file_sealing_detects_tampering_and_a_lost_key() {
        let dir = temp_dir("keyfile");
        let sealer = keyfile::Sealer::new(&dir);
        assert_eq!(sealer.key_file(), Some(dir.join(KEY_FILE_NAME)));
        let sealed = sealer.seal(b"secret settings").unwrap();
        assert!(sealed.starts_with(MAGIC));
        assert_eq!(&**sealer.open(&sealed).unwrap(), b"secret settings");
        assert!(!String::from_utf8_lossy(&sealed).contains("secret"));

        let mut tampered = sealed.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert!(sealer.open(&tampered).is_err());

        fs::remove_file(dir.join(KEY_FILE_NAME)).unwrap();
        assert!(sealer.open(&sealed).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn key_file_sealing_opens_what_omnihub_sealed() {
        let dir = temp_dir("keyfile-earlier");
        let sealer = keyfile::Sealer::new(&dir);
        let sealed = sealer.seal_as_earlier(b"old settings").unwrap();
        assert!(sealed.starts_with(EARLIER_MAGIC));
        assert_eq!(&**sealer.open(&sealed).unwrap(), b"old settings");
        // The header is part of what is checked: the same body under the new
        // name does not open.
        let renamed = [MAGIC, &sealed[EARLIER_MAGIC.len()..]].concat();
        assert!(sealer.open(&renamed).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn omnihubs_settings_key_comes_along_unless_captun_has_another() {
        let dir = temp_dir("key-takeover");
        let (earlier, ours) = (dir.join("omnihub.key"), dir.join("captun").join(KEY_FILE_NAME));
        assert!(take_over_key(&earlier, &ours).is_err(), "no key to bring");
        fs::write(&earlier, [7u8; 32]).unwrap();
        take_over_key(&earlier, &ours).unwrap();
        assert_eq!(fs::read(&ours).unwrap(), [7u8; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&ours).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // The same key again is fine; another one is never replaced.
        take_over_key(&earlier, &ours).unwrap();
        fs::write(&ours, [8u8; 32]).unwrap();
        assert!(take_over_key(&earlier, &ours).is_err());
        assert_eq!(fs::read(&ours).unwrap(), [8u8; 32]);
        assert!(earlier.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn files_from_another_kind_of_computer_are_named_as_such() {
        let err = check_header(b"CAPTUN\x09rest", 1).unwrap_err();
        assert!(err.to_string().contains("another kind of computer"));
        assert!(check_header(b"something else", 1).is_err());
        assert!(check_header(b"CAPTUN", 1).is_err());
        let ours = check_header(b"CAPTUN\x01rest", 1).unwrap();
        assert_eq!((ours.header, ours.earlier, ours.body), (&b"CAPTUN\x01"[..], false, &b"rest"[..]));
        let omnihubs = check_header(b"OMNIHUB\x01rest", 1).unwrap();
        assert_eq!((omnihubs.header, omnihubs.earlier, omnihubs.body), (&b"OMNIHUB\x01"[..], true, &b"rest"[..]));
    }
}
