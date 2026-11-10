//! Takes over what OmniHub, as this program was called before, saved for the
//! service: the online lists it downloaded and its phone key. Run once at
//! start, and only while Captun has none of its own. OmniHub's folders are
//! only read: nothing there is changed, moved or deleted, and no link or
//! junction is followed.

use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use captun_adb::KeyTakeover;
use tracing::{info, warn};

use crate::{lists, paths};

/// The first line of the lists OmniHub saved.
const EARLIER_TITLE: &str = "# OmniHub list";
/// Larger than any saved list: a list is at most 48 MiB unpacked
/// (`lists.rs`), saved one entry per line.
const MAX_LIST_FILE: u64 = 64 * 1024 * 1024;
/// More files than OmniHub's lists folder ever held; any more are not looked at.
const MAX_FILES: usize = 4096;

/// Takes over OmniHub's saved lists and phone key, where Captun has none yet.
/// Blocking.
pub(crate) fn from_omnihub() {
    lists_from(&paths::earlier_lists_dir(), &paths::lists_dir());
    phone_key_from(&paths::earlier_adb_key(), &paths::adb_key());
}

/// Copies the lists OmniHub saved in `from` to `to`, while `to` holds none,
/// and says how many were copied. Each is checked by its header first, as a
/// list file is when it is read.
fn lists_from(from: &Path, to: &Path) -> usize {
    match has_saved_lists(to) {
        Ok(false) => {}
        Ok(true) => return 0,
        Err(why) => {
            warn!("did not take over the online lists OmniHub saved: {why}");
            return 0;
        }
    }
    match folder(from) {
        Ok(true) => {}
        Ok(false) => return 0,
        Err(why) => {
            warn!("did not take over the online lists OmniHub saved: {why}");
            return 0;
        }
    }
    let entries = match fs::read_dir(from) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("did not take over the online lists OmniHub saved: cannot list {}: {e}", from.display());
            return 0;
        }
    };
    let mut copied = 0;
    for entry in entries.take(MAX_FILES).flatten() {
        let name = entry.file_name();
        // Only files named the way saved lists are; nothing else there is one.
        let Some(name) = name.to_str().filter(|name| is_list_name(name)) else { continue };
        let file = from.join(name);
        match copy_list(&file, to, name) {
            Ok(link) => {
                info!("took over the online list OmniHub saved for {link}");
                copied += 1;
            }
            Err(why) => warn!("did not take over the online list OmniHub saved as {}: {why}", file.display()),
        }
    }
    copied
}

/// Copies one saved list: only one OmniHub saved (its first line), whose
/// link names the file, as the list it is for would find it. It is saved
/// with Captun's first line.
fn copy_list(file: &Path, to: &Path, name: &str) -> Result<String, String> {
    let text = read_plain_file(file, MAX_LIST_FILE)?;
    let rest = text
        .strip_prefix(EARLIER_TITLE)
        .and_then(|rest| rest.strip_prefix('\n'))
        .ok_or("it does not start the way the lists OmniHub saved do")?;
    let link = rest.lines().next().and_then(|line| line.strip_prefix("# url: ")).ok_or("it does not say which link it came from")?;
    if lists::file_name(link) != name {
        return Err("its name does not match the link it came from".into());
    }
    lists::save(&to.join(name), &format!("{}\n", lists::TITLE), rest)
        .map_err(|e| format!("cannot save it in {}: {e}", to.display()))?;
    Ok(link.to_owned())
}

/// Whether Captun has saved any list in `dir` yet.
fn has_saved_lists(dir: &Path) -> Result<bool, String> {
    if !folder(dir)? {
        return Ok(false);
    }
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    Ok(entries.flatten().any(|entry| entry.file_name().to_str().is_some_and(is_list_name)))
}

/// A saved list's file name: 16 hexadecimal digits and `.list`.
fn is_list_name(name: &str) -> bool {
    name.strip_suffix(".list")
        .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// Whether `dir` is there as a folder of its own: it and the folder it is in
/// must be folders, not links or junctions to somewhere else.
fn folder(dir: &Path) -> Result<bool, String> {
    for at in [dir.parent(), Some(dir)].into_iter().flatten() {
        match fs::symlink_metadata(at) {
            Ok(meta) if meta.is_dir() && !is_link(&meta) => {}
            Ok(_) => return Err(format!("{} is a link or a file, not a folder of its own", at.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(format!("cannot look at {}: {e}", at.display())),
        }
    }
    Ok(true)
}

/// Reads the plain file at `path`, at most `max` bytes, never through a
/// link: on Windows a link or junction is opened as itself and refused; on
/// Linux and macOS it is refused before opening (the folders read from are
/// root's alone there).
fn read_plain_file(path: &Path, max: u64) -> Result<String, String> {
    const NOT_A_FILE: &str = "it is a link or a folder, not a file";
    let before = fs::symlink_metadata(path).map_err(|e| format!("cannot look at it: {e}"))?;
    if !before.is_file() || is_link(&before) {
        return Err(NOT_A_FILE.into());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        /// `FILE_FLAG_OPEN_REPARSE_POINT`: a link is opened as itself.
        const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|e| format!("cannot open it: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("cannot look at it: {e}"))?;
    // Swapped for something else since the look above.
    if !meta.is_file() || is_link(&meta) {
        return Err(NOT_A_FILE.into());
    }
    if meta.len() > max {
        return Err("it is too large to be a saved list".into());
    }
    let mut text = String::new();
    file.take(max).read_to_string(&mut text).map_err(|e| format!("cannot read it: {e}"))?;
    Ok(text)
}

/// A symbolic link, or on Windows any reparse point (a junction included).
fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        /// `FILE_ATTRIBUTE_REPARSE_POINT`.
        const REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// Takes over OmniHub's phone key through the phone-key module, which uses
/// it only if it passes the checks Captun's own key must pass.
fn phone_key_from(earlier: &Path, path: &Path) {
    match captun_adb::take_over_key(earlier, path) {
        KeyTakeover::Copied => info!(
            "took over the phone key OmniHub made ({}), so phones that allowed OmniHub keep allowing Captun",
            earlier.display()
        ),
        KeyTakeover::NotNeeded => {}
        KeyTakeover::Refused(why) => warn!(
            "did not take over the phone key OmniHub made ({}): {why}. Captun makes a new one when a phone needs it",
            earlier.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use captun_core::Config;

    use super::*;

    const LINK: &str = "https://lists.example/ads.txt";

    /// A fresh folder holding `omnihub/lists` and `captun/lists` (neither made yet).
    fn base(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("captun-migrate-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let (from, to) = (base.join("omnihub").join("lists"), base.join("captun").join("lists"));
        (base, from, to)
    }

    fn omnihub_list(link: &str) -> String {
        format!("{EARLIER_TITLE}\n# url: {link}\n# updated: 5\nads.example\n6.6.6.0/24\n")
    }

    #[test]
    fn omnihubs_saved_lists_are_copied_once_and_left_as_they_were() {
        let (base, from, to) = base("lists");
        fs::create_dir_all(&from).unwrap();
        let name = lists::file_name(LINK);
        fs::write(from.join(&name), omnihub_list(LINK)).unwrap();
        // Not lists: another file, one named for another link, one without
        // OmniHub's first line, and a folder.
        fs::write(from.join("notes.txt"), omnihub_list(LINK)).unwrap();
        fs::write(from.join(lists::file_name("https://elsewhere.example/x")), omnihub_list(LINK)).unwrap();
        let other = "https://lists.example/other.txt";
        fs::write(from.join(lists::file_name(other)), format!("# something else\n# url: {other}\n")).unwrap();
        fs::create_dir_all(from.join(lists::file_name("https://lists.example/folder"))).unwrap();

        assert_eq!(lists_from(&from, &to), 1);
        let copied = fs::read_to_string(to.join(&name)).unwrap();
        assert_eq!(copied, omnihub_list(LINK).replace(EARLIER_TITLE, lists::TITLE));
        assert_eq!(fs::read_dir(&to).unwrap().count(), 1);
        assert_eq!(fs::read_to_string(from.join(&name)).unwrap(), omnihub_list(LINK), "OmniHub's copy stays");

        // The list it is for finds it.
        let config = Config::from_toml(&format!(
            "[network]\ndefault_egress = \"direct\"\n[[egress]]\nid = \"direct\"\ntype = \"direct\"\n[[rule]]\nlists = [\"{LINK}\"]\naction = \"reject\"\n"
        ))
        .unwrap();
        let store = lists::ListStore::new(to.clone());
        assert_eq!(store.compiled(&config).len(), 1);
        let statuses = store.statuses(&config);
        assert_eq!((statuses[0].names, statuses[0].addresses, statuses[0].updated_ms), (1, 1, Some(5)));

        // Captun has lists now: nothing is taken over again.
        fs::write(from.join(lists::file_name(other)), omnihub_list(other)).unwrap();
        assert_eq!(lists_from(&from, &to), 0);
        assert!(!to.join(lists::file_name(other)).exists());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn without_omnihubs_folder_nothing_happens() {
        let (base, from, to) = base("none");
        assert_eq!(lists_from(&from, &to), 0);
        assert!(!to.exists());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn links_are_never_followed() {
        let (base, from, to) = base("links");
        let elsewhere = base.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let name = lists::file_name(LINK);
        fs::write(elsewhere.join(&name), omnihub_list(LINK)).unwrap();
        fs::create_dir_all(from.parent().unwrap()).unwrap();
        // Making links may need rights the tests lack (Windows): then there
        // is nothing to check.
        #[cfg(unix)]
        let folder_link = std::os::unix::fs::symlink(&elsewhere, &from);
        #[cfg(windows)]
        let folder_link = std::os::windows::fs::symlink_dir(&elsewhere, &from);
        if folder_link.is_ok() {
            assert_eq!(lists_from(&from, &to), 0, "a linked folder is not read");
            assert!(!to.exists());
            fs::remove_file(&from).or_else(|_| fs::remove_dir(&from)).unwrap();
        }
        fs::create_dir_all(&from).unwrap();
        #[cfg(unix)]
        let file_link = std::os::unix::fs::symlink(elsewhere.join(&name), from.join(&name));
        #[cfg(windows)]
        let file_link = std::os::windows::fs::symlink_file(elsewhere.join(&name), from.join(&name));
        if file_link.is_ok() {
            assert_eq!(lists_from(&from, &to), 0, "a linked file is not read");
            assert!(!to.join(&name).exists());
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn list_names_are_the_ones_saved_lists_have() {
        assert!(is_list_name(&lists::file_name(LINK)));
        for name in ["0123456789abcdef.lis", "0123456789ABCDEF.list", "0123456789abcde.list", "x.list", ".list", "0123456789abcdeg.list"] {
            assert!(!is_list_name(name), "{name}");
        }
    }
}
