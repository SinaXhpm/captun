//! The settings, saved next to the app and encrypted so that only this user
//! on this computer can open them. The GUI owns them: the service keeps its
//! copy in memory and is handed this one each time it starts (`state.rs`).
//!
//! Next to the program, a copy of Captun carries its settings along. A
//! second encrypted copy in the user's profile lets a new copy or version
//! start with the same settings, and is the only one where the program's
//! folder cannot be written (Program Files, a macOS app bundle, an AppImage).

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
/// On macOS and Linux, the key the settings are sealed with, kept in the
/// profile folder.
#[cfg(any(not(windows), test))]
const KEY_FILE_NAME: &str = "settings.key";

/// What [`Settings::load`] found.
#[derive(Debug)]
pub(crate) enum Loaded {
    Saved(Box<Config>),
    /// Nothing has been saved yet.
    Missing,
    /// Settings exist but cannot be opened here (saved by another account or
    /// computer, or damaged). They were renamed out of the way.
    Unreadable(String),
}

#[derive(Debug)]
pub(crate) struct Settings {
    /// Written on every save; the first is the main copy.
    write_to: Vec<PathBuf>,
    /// Tried in this order when loading.
    read_from: Vec<PathBuf>,
    sealer: seal::Sealer,
}

impl Settings {
    pub(crate) fn new() -> Self {
        let profile = paths::settings_dir();
        Self::at(paths::app_dir().as_deref(), &profile)
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
        Self { write_to, read_from, sealer: seal::Sealer::new(profile) }
    }

    /// The main copy, the one the user would look for.
    pub(crate) fn location(&self) -> &Path {
        &self.write_to[0]
    }

    pub(crate) fn load(&self) -> Loaded {
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
        match unreadable {
            Some(why) => Loaded::Unreadable(why),
            None => Loaded::Missing,
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

/// A sealed file, split up.
#[derive(Debug)]
struct Sealed<'a> {
    /// Its magic and scheme byte, as they are in the file (checked along
    /// with the text on macOS and Linux).
    #[cfg_attr(all(windows, not(test)), allow(dead_code))]
    header: &'a [u8],
    body: &'a [u8],
}

fn check_header(sealed: &[u8], scheme: u8) -> io::Result<Sealed<'_>> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_owned());
    if !sealed.starts_with(MAGIC) {
        return Err(bad("this is not a Captun settings file"));
    }
    match sealed.split_at_checked(MAGIC.len() + 1) {
        Some((header, body)) if header[MAGIC.len()] == scheme => Ok(Sealed { header, body }),
        Some(_) => Err(bad("these settings were saved on another kind of computer")),
        None => Err(bad("this is not a Captun settings file")),
    }
}

/// Windows: DPAPI bound to the user's account, the way Windows itself keeps
/// saved passwords. Nothing else to keep: Windows holds the key.
#[cfg(windows)]
mod seal {
    use std::{io, path::Path};

    use zeroize::Zeroizing;

    const SCHEME: u8 = 1;

    #[derive(Debug)]
    pub(crate) struct Sealer;

    impl Sealer {
        pub(crate) fn new(_profile: &Path) -> Self {
            Self
        }

        pub(crate) fn seal(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            let blob = dpapi::protect(plain, dpapi::ENTROPY)?;
            let parts: [&[u8]; 3] = [super::MAGIC, &[SCHEME], &blob];
            Ok(parts.concat())
        }

        pub(crate) fn open(&self, sealed: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
            let sealed = super::check_header(sealed, SCHEME)?;
            dpapi::unprotect(sealed.body, dpapi::ENTROPY).map_err(|_| {
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

        /// The magic and the scheme byte, then a nonce and the sealed text;
        /// the header is authenticated with it.
        pub(crate) fn seal(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            let key = self.key()?;
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key[..]).map_err(crypto_error)?);
            let mut nonce = [0u8; NONCE_LEN];
            SystemRandom::new().fill(&mut nonce).map_err(crypto_error)?;
            let header: [&[u8]; 2] = [super::MAGIC, &[SCHEME]];
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
    fn files_from_another_kind_of_computer_are_named_as_such() {
        let err = check_header(b"CAPTUN\x09rest", 1).unwrap_err();
        assert!(err.to_string().contains("another kind of computer"));
        assert!(check_header(b"something else", 1).is_err());
        assert!(check_header(b"CAPTUN", 1).is_err());
        let ours = check_header(b"CAPTUN\x01rest", 1).unwrap();
        assert_eq!((ours.header, ours.body), (&b"CAPTUN\x01"[..], &b"rest"[..]));
        // Nothing else is a Captun settings file, whatever it starts with.
        assert!(check_header(b"OTHER\x01rest", 1).is_err());
    }
}
