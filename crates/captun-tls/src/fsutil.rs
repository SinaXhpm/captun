//! Reading and writing the CA's public files (the certificate and its
//! record). The key never goes through here.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

use ring::rand::{SecureRandom, SystemRandom};

/// What is in a small file.
pub(crate) enum Contents {
    Missing,
    /// Larger than any file Captun writes there: not one of its own.
    TooLarge,
    Bytes(Vec<u8>),
}

/// The file at `path`, up to `max` bytes.
pub(crate) fn read_small(path: &Path, max: u64) -> io::Result<Contents> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Contents::Missing),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok(if u64::try_from(bytes.len()).is_ok_and(|len| len <= max) { Contents::Bytes(bytes) } else { Contents::TooLarge })
}

/// The suffix of a file being written, before it takes its name.
const UNFINISHED: &str = ".unfinished-";

/// Writes `bytes` to `path` whole or not at all: into a new file beside it,
/// which then replaces it. A file or link planted at that new name is never
/// written through, and one left by a crash is removed by [`remove_unfinished`].
pub(crate) fn write_replacing(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut suffix = [0u8; 8];
    SystemRandom::new().fill(&mut suffix).map_err(|_| io::Error::other("no random numbers"))?;
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let temporary = path.with_file_name(format!("{name}{UNFINISHED}{}", hex(&suffix)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options.open(&temporary)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let done = written.and_then(|()| fs::rename(&temporary, path));
    if done.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    done
}

/// Deletes the file at `path`; one that is not there is fine. A link is
/// deleted itself, never what it points to.
pub(crate) fn remove_if_there(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Deletes what [`write_replacing`] left in `dir` when it was cut short:
/// plain files named `<one of names>.unfinished-<16 hex digits>` and nothing
/// else. A folder, a link or any other name is left alone, so nothing another
/// account puts there can make a reset fail; a file that cannot be deleted is
/// named in the error.
pub(crate) fn remove_unfinished(dir: &Path, names: &[&str]) -> io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else { continue };
        if !names.iter().any(|base| is_unfinished(file_name, base)) {
            continue;
        }
        let path = entry.path();
        // symlink_metadata does not follow a link, so only a real file counts.
        if !fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file()) {
            continue;
        }
        remove_if_there(&path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    }
    Ok(())
}

/// Whether `file_name` is `base` as [`write_replacing`] names it while
/// writing: the suffix and exactly 16 lower-case hex digits.
fn is_unfinished(file_name: &str, base: &str) -> bool {
    file_name
        .strip_prefix(base)
        .and_then(|rest| rest.strip_prefix(UNFINISHED))
        .is_some_and(|digits| digits.len() == 16 && digits.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}


/// `bytes` as lower-case hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_captuns_own_unfinished_files_are_removed() {
        let dir = std::env::temp_dir().join(format!("captun-tls-unfinished-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let ours = dir.join("ca.pem.unfinished-0123456789abcdef");
        fs::write(&ours, b"half").unwrap();
        // Planted by someone else: a folder with the suffix, other names.
        let planted_folder = dir.join("ca.json.unfinished-0123456789abcdef");
        fs::create_dir(&planted_folder).unwrap();
        let other = dir.join("notes.unfinished-0123456789abcdef");
        fs::write(&other, b"x").unwrap();
        let wrong_digits = dir.join("ca.pem.unfinished-XYZ");
        fs::write(&wrong_digits, b"x").unwrap();

        remove_unfinished(&dir, &["ca.pem", "ca.json"]).unwrap();
        assert!(!ours.exists(), "Captun's own half-written file is removed");
        assert!(planted_folder.exists() && other.exists() && wrong_digits.exists(), "everything else is left");
        fs::remove_dir_all(&dir).unwrap();
    }
}
