//! The CA key as a key file: what Linux and macOS use until a keychain
//! backend exists.
//!
//! The key is a PKCS#8 file `ca-key-<id>.pk8` in the CA's folder. Only the
//! service, running as root, makes or reads it. It is created exclusively (a
//! file or link already there is never written through or adopted) and mode
//! `0600`, and its owner is checked before the key is written into it. The
//! folder must belong to root and let no one else add, remove or rename
//! files in it. A key file is used only if it is a plain file (never a
//! link), belongs to root and lets no one else in; otherwise the CA is
//! replaced. The bytes read from it are wiped once the key is loaded.
//!
//! On Windows this store exists only in tests: the service keeps its key in
//! CNG ([`crate::CngKeyStore`]).

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

use crate::{
    TlsError,
    error::file_error,
    fsutil::remove_if_there,
    key::{CaKey, InstallId, KeyLookup, KeyStore, SoftKey},
};

const PREFIX: &str = "ca-key-";
const SUFFIX: &str = ".pk8";
/// A P-256 key in PKCS#8 is under 200 bytes; a larger file is not one.
const MAX_KEY_FILE: u64 = 4096;

#[cfg(unix)]
const NOT_ROOT: &str = "HTTPS inspection keeps its key in a file only the Captun service can read, and only the service, which runs as root, can make or open it.";

/// CA keys as files in one folder (see the module docs).
#[derive(Debug)]
pub struct FileKeyStore {
    dir: PathBuf,
    /// Who the folder and the keys belong to, and who must be making and
    /// reading them: root, but for tests.
    #[cfg(unix)]
    owner: u32,
}

impl FileKeyStore {
    /// Keys in `dir`, which (like the keys) must belong to root.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            #[cfg(unix)]
            owner: 0,
        }
    }

    /// For tests, which do not run as root: whoever runs them stands in for
    /// root.
    #[cfg(test)]
    pub(crate) fn for_this_user(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            #[cfg(unix)]
            owner: sys::effective_uid(),
        }
    }

    fn path(&self, id: &InstallId) -> PathBuf {
        self.dir.join(format!("{PREFIX}{id}{SUFFIX}"))
    }

    /// Reads the key in `file` (at `path`), if it may be used.
    fn load(&self, mut file: File, path: &Path) -> Result<KeyLookup, TlsError> {
        let meta = file.metadata().map_err(file_error("look at", path))?;
        if !meta.is_file() {
            return Ok(KeyLookup::Unusable("the key is not a plain file".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != self.owner {
                return Ok(KeyLookup::Unusable("the key file belongs to another user".into()));
            }
            if meta.mode() & 0o077 != 0 {
                return Ok(KeyLookup::Unusable("other users may read or change the key file".into()));
            }
        }
        let Some(len) = usize::try_from(meta.len()).ok().filter(|&len| len > 0 && meta.len() <= MAX_KEY_FILE) else {
            return Ok(KeyLookup::Unusable("the key file is damaged".into()));
        };
        // Read at its final size, so no partial copy is left behind unwiped.
        let mut pkcs8 = Zeroizing::new(vec![0u8; len]);
        file.read_exact(&mut pkcs8).map_err(file_error("read", path))?;
        Ok(match SoftKey::from_pkcs8(&pkcs8) {
            Some(key) => KeyLookup::Found(Box::new(key)),
            None => KeyLookup::Unusable("the key file is damaged".into()),
        })
    }

    /// Makes the key file at `path` and writes a new key into it.
    fn write_new(&self, path: &Path) -> Result<(), TlsError> {
        let mut file = new_private_file(path).map_err(file_error("create the key file", path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // Checked before the key is in it: a file that would belong to
            // anyone else (a file system that maps root to another user, say)
            // never holds it.
            let meta = file.metadata().map_err(file_error("look at", path))?;
            if meta.uid() != self.owner {
                return Err(TlsError::Key("its new file would belong to another user".into()));
            }
        }
        let pkcs8 = SoftKey::generate_pkcs8()?;
        file.write_all(&pkcs8).and_then(|()| file.sync_all()).map_err(file_error("write the key file", path))
    }
}

impl KeyStore for FileKeyStore {
    fn kind(&self) -> &'static str {
        "file"
    }

    fn prepare_folder(&self, dir: &Path) -> Result<(), TlsError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};

            if sys::effective_uid() != self.owner {
                return Err(TlsError::NeedsService(NOT_ROOT));
            }
            if let Some(parent) = dir.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                fs::create_dir_all(parent).map_err(file_error("make the folder", parent))?;
            }
            if let Err(e) = fs::DirBuilder::new().mode(0o700).create(dir)
                && e.kind() != io::ErrorKind::AlreadyExists
            {
                return Err(file_error("make the folder", dir)(e));
            }
            let meta = fs::symlink_metadata(dir).map_err(file_error("look at", dir))?;
            let why = if !meta.is_dir() {
                "it is a link or a file, not a folder of its own"
            } else if meta.uid() != self.owner {
                "it belongs to another user"
            } else if meta.mode() & 0o022 != 0 {
                "other users may add or remove files in it"
            } else {
                return Ok(());
            };
            Err(TlsError::UnsafeFolder { path: dir.to_path_buf(), why })
        }
        #[cfg(not(unix))]
        fs::create_dir_all(dir).map_err(file_error("make the folder", dir))
    }

    fn create(&self, id: &InstallId) -> Result<Box<dyn CaKey>, TlsError> {
        self.prepare_folder(&self.dir)?;
        let path = self.path(id);
        let made = self.write_new(&path).and_then(|()| self.open(id));
        match made {
            Ok(KeyLookup::Found(key)) => {
                keep_out_of_backups(&path);
                Ok(key)
            }
            outcome => {
                // Only a file this call made can be here: creating fails on
                // anything that was there before.
                if !matches!(outcome, Err(TlsError::File { action: "create the key file", .. })) {
                    let _ = remove_if_there(&path);
                }
                Err(match outcome {
                    Err(e) => e,
                    Ok(KeyLookup::Unusable(why)) => TlsError::Key(why),
                    Ok(_) => TlsError::Key("its new file could not be read back".into()),
                })
            }
        }
    }

    fn open(&self, id: &InstallId) -> Result<KeyLookup, TlsError> {
        self.prepare_folder(&self.dir)?;
        let path = self.path(id);
        match open_no_link(&path) {
            Ok(file) => self.load(file, &path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(KeyLookup::Missing),
            #[cfg(unix)]
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Ok(KeyLookup::Unusable("the key file is a link".into())),
            Err(e) => Err(file_error("open", &path)(e)),
        }
    }

    fn delete_all(&self) -> Result<(), TlsError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(file_error("look in", &self.dir)(e)),
        };
        for entry in entries {
            let entry = entry.map_err(file_error("look in", &self.dir))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(PREFIX) && name.ends_with(SUFFIX) {
                let path = entry.path();
                // A link is deleted itself, never what it points to.
                remove_if_there(&path).map_err(file_error("delete", &path))?;
            }
        }
        Ok(())
    }
}

/// Keeps the key file out of Time Machine on macOS: a backup disk is often
/// readable on any computer, and a copy there could never be deleted by a
/// reset. Best effort: a failure is only logged. (On Linux the folder must not
/// be under /etc, which tools commit and back up: see
/// [`crate::system_key_store`].)
fn keep_out_of_backups(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let done = std::process::Command::new("/usr/bin/tmutil").arg("addexclusion").arg(path).status();
        if !done.is_ok_and(|status| status.success()) {
            tracing::warn!("could not keep the HTTPS inspection key out of Time Machine backups: {}", path.display());
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
}

/// A new file at `path`, open for writing and readable by its owner only.
/// Fails if anything is there, a link included.
fn new_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// The file at `path` open for reading, never through a link.
fn open_no_link(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod sys {
    /// The user this process acts as.
    pub(super) fn effective_uid() -> u32 {
        // SAFETY: geteuid takes no arguments, cannot fail and touches no
        // memory of this program's.
        unsafe { libc::geteuid() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("captun-tls-file-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn id() -> InstallId {
        InstallId::parse("0123ABCD").unwrap()
    }

    #[test]
    fn a_key_is_kept_between_runs_and_deleted_on_request() {
        let dir = folder("keep");
        let store = FileKeyStore::for_this_user(&dir);
        assert!(matches!(store.open(&id()).unwrap(), KeyLookup::Missing));
        let key = store.create(&id()).unwrap();
        let path = dir.join("ca-key-0123ABCD.pk8");
        assert!(path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }

        // Another run (a new store) finds the same key.
        let KeyLookup::Found(again) = FileKeyStore::for_this_user(&dir).open(&id()).unwrap() else { panic!("kept") };
        assert_eq!(again.public_point(), key.public_point());

        store.delete_all().unwrap();
        assert!(!path.exists());
        assert!(matches!(store.open(&id()).unwrap(), KeyLookup::Missing));
        // Nothing to delete, or no folder at all, is fine.
        store.delete_all().unwrap();
        fs::remove_dir_all(&dir).unwrap();
        store.delete_all().unwrap();
    }

    #[test]
    fn a_file_already_there_is_never_taken_over() {
        let dir = folder("planted");
        let store = FileKeyStore::for_this_user(&dir);
        store.prepare_folder(&dir).unwrap();
        let planted = SoftKey::generate_pkcs8().unwrap();
        fs::write(store.path(&id()), &*planted).unwrap();

        assert!(matches!(store.create(&id()), Err(TlsError::File { .. })));
        assert_eq!(fs::read(store.path(&id())).unwrap(), *planted, "the planted file is left as it was");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_key_file_is_not_used() {
        let dir = folder("damaged");
        let store = FileKeyStore::for_this_user(&dir);
        store.create(&id()).unwrap();
        let path = store.path(&id());
        for damage in [&b""[..], b"not a key", &[0x30; 5000]] {
            fs::remove_file(&path).unwrap();
            new_private_file(&path).unwrap().write_all(damage).unwrap();
            assert!(
                matches!(store.open(&id()).unwrap(), KeyLookup::Unusable(why) if why.contains("damaged")),
                "{} bytes",
                damage.len()
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_others_may_read_or_a_link_is_not_used() {
        use std::os::unix::fs::PermissionsExt;

        let dir = folder("loose");
        let store = FileKeyStore::for_this_user(&dir);
        store.create(&id()).unwrap();
        let path = store.path(&id());

        for mode in [0o640, 0o604, 0o660, 0o666, 0o610] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(store.open(&id()).unwrap(), KeyLookup::Unusable(why) if why.contains("other users")),
                "mode {mode:o}"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(store.open(&id()).unwrap(), KeyLookup::Found(_)), "read-only for its owner is fine");

        // A link to a key, even a good one, is not a key file.
        let real = dir.join("elsewhere");
        fs::rename(&path, &real).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(matches!(store.open(&id()).unwrap(), KeyLookup::Unusable(why) if why.contains("link")));
        // Deleting removes the link, not what it points to.
        store.delete_all().unwrap();
        assert!(real.exists() && fs::symlink_metadata(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_others_may_change_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = folder("folder");
        let store = FileKeyStore::for_this_user(&dir);
        store.prepare_folder(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let err = store.prepare_folder(&dir).unwrap_err();
        assert!(matches!(err, TlsError::UnsafeFolder { why, .. } if why.contains("other users")), "{err}");
        assert!(store.create(&id()).is_err(), "no key is made there");
        assert!(!store.path(&id()).exists());
        // Readable by others is fine; changeable is not.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        store.prepare_folder(&dir).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn only_root_makes_or_opens_keys() {
        if sys::effective_uid() == 0 {
            return; // Run as root: nothing to refuse.
        }
        let dir = folder("not-root");
        let store = FileKeyStore::new(&dir);
        assert!(matches!(store.create(&id()), Err(TlsError::NeedsService(_))));
        assert!(matches!(store.open(&id()), Err(TlsError::NeedsService(_))));
        assert!(!dir.exists(), "nothing is made");
    }
}
