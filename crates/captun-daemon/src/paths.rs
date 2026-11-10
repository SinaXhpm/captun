//! Default file locations. The GUI may override the token location so it
//! lands in a directory private to its own user.

use std::path::PathBuf;

/// This program's name in its folder names: as on Windows and macOS, then as
/// on Linux.
const NAME: (&str, &str) = ("Captun", "captun");
/// What this program was called before (OmniHub), for the folders
/// `migrate.rs` takes saved data over from. They are only read.
const EARLIER_NAME: (&str, &str) = ("OmniHub", "omnihub");

/// `%ProgramData%\<name>`, `/Library/Application Support/<name>` or
/// `/etc/<name>`.
fn data_dir_of((name, linux_name): (&str, &str)) -> PathBuf {
    let name = if cfg!(all(unix, not(target_os = "macos"))) { linux_name } else { name };
    #[cfg(windows)]
    let base = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = PathBuf::from("/Library/Application Support");
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = PathBuf::from("/etc");
    base.join(name)
}

fn data_dir() -> PathBuf {
    data_dir_of(NAME)
}

/// The data folder's owner and permissions on Windows: Administrators own it,
/// SYSTEM and Administrators may do anything, nobody else anything at all,
/// and nothing comes from `%ProgramData%`, which lets every user add files.
/// Passed on to what is made inside (`OICI`). Administrators rather than
/// SYSTEM as owner: an elevated administrator may not hand things to SYSTEM.
#[cfg(windows)]
const DATA_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The same for a file the service saves there. Set on the file itself, so
/// Administrators own it whoever would otherwise (the shell the service was
/// started from, or a policy, can make that the user), and every later run
/// takes it for the service's own.
#[cfg(windows)]
pub(crate) const FILE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Makes the data folder and its lists folder Captun's alone, before anything
/// reads or writes there (Windows; elsewhere they are root's alone already).
/// Gives what is worth putting in the log once it is open, or why the
/// service must not start: then the folder may be someone else's, or hold
/// something of someone else's that the service would read or write.
pub(crate) fn prepare_data_dir() -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        let dir = data_dir();
        let me = secure::Me::find(&dir, DATA_SDDL);
        secure::prepare(&dir, DATA_SDDL, &me)
    }
    #[cfg(not(windows))]
    Ok(Vec::new())
}

/// Locking the data folder down on Windows. Every check and change goes
/// through a handle on the entry itself, opened without following a link, and
/// links are removed or moved as links: nothing here ever acts on where one
/// points.
#[cfg(windows)]
mod secure {
    use std::{
        fs, io,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };

    use captun_ipc::{create_dir_with_sddl, open_for_security, owner_sid_of, protect};

    const SYSTEM: &str = "S-1-5-18";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    /// `FILE_ATTRIBUTE_REPARSE_POINT`: a link, a junction or the like.
    const REPARSE_POINT: u32 = 0x400;
    /// `FILE_ATTRIBUTE_DIRECTORY`.
    const DIRECTORY: u32 = 0x10;
    /// `READ_CONTROL`: enough to read an owner, and never refused because
    /// someone else has the file open.
    const READ_CONTROL: u32 = 0x0002_0000;
    /// `FILE_FLAG_BACKUP_SEMANTICS` (folders open at all) and
    /// `FILE_FLAG_OPEN_REPARSE_POINT` (a link opens as itself).
    const OPEN_AS_ITSELF: u32 = 0x0200_0000 | 0x0020_0000;
    /// The scratch folder [`Me::find`] makes: no owner given, so it gets the
    /// one Windows gives what this service makes; whoever that is may remove
    /// it again (`OW`), nobody else may touch it.
    const PROBE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";
    /// The folder the service keeps the online lists in, inside the data folder.
    const LISTS: &str = "lists";
    /// What marks the name of an entry moved aside: `<name>.untrusted-<time>`.
    /// Nothing reads an entry under such a name.
    const ASIDE: &str = ".untrusted-";

    /// Who this service is, as far as its folders go.
    #[derive(Debug)]
    pub(super) struct Me {
        /// The owner Windows gives what this service makes: Administrators
        /// when elevated, unless a policy ("Object creator") or the shell it
        /// was started from (Git Bash, Cygwin) makes it the user. Its own
        /// folders from before may carry it.
        pub(super) owner: Option<String>,
        /// Whether it may give a folder the data folder's owner and
        /// permissions: false when it runs without administrator rights.
        pub(super) can_lock: bool,
    }

    impl Me {
        /// Found by making a scratch folder beside `dir` and looking at it.
        /// Its name is random, so nobody can make it first; nobody else may
        /// open, rename or remove it. If none can be made, the service is
        /// taken to be elevated: the strict way.
        pub(super) fn find(dir: &Path, sddl: &str) -> Self {
            let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
                return Self { owner: None, can_lock: true };
            };
            for _ in 0..3 {
                let probe = parent.join(format!("{}.check-{:016x}", name.to_string_lossy(), random()));
                match create_dir_with_sddl(&probe, PROBE_SDDL) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(_) => break,
                }
                let found = open_for_security(&probe).and_then(|folder| {
                    let owner = owner_sid_of(&folder)?;
                    Ok((owner, protect(&folder, sddl).is_ok()))
                });
                let _ = fs::remove_dir(&probe);
                if let Ok((owner, can_lock)) = found {
                    return Self { owner: Some(owner), can_lock };
                }
                break;
            }
            Self { owner: None, can_lock: true }
        }

        /// Whether `owner` (a SID) is an account the service's files may
        /// belong to.
        fn trusts(&self, owner: &str) -> bool {
            owner == SYSTEM || owner == ADMINISTRATORS || self.owner.as_deref() == Some(owner)
        }
    }

    /// A number no other program can guess: std's hash keys come from the
    /// system's random source.
    fn random() -> u64 {
        use std::hash::{BuildHasher, Hasher};
        std::collections::hash_map::RandomState::new().build_hasher().finish()
    }

    /// Makes `dir` and its lists folder the service's own with `sddl`, and
    /// takes what another account put in them off the names the service
    /// uses. Fails, so the service does not start, if something is left
    /// under one of them. Without administrator rights (a development run)
    /// nothing is done; only said.
    pub(super) fn prepare(dir: &Path, sddl: &str, me: &Me) -> Result<Vec<String>, String> {
        let mut notes = Vec::new();
        if !me.can_lock {
            notes.push(format!(
                "Not running as administrator, so Captun's data folder {} was not locked down (fine for a development run).",
                dir.display()
            ));
            return Ok(notes);
        }
        own_folder(dir, sddl, me, &mut notes)?;
        // The lists folder first, so one moved aside is looked at below like
        // any other entry.
        let lists = dir.join(LISTS);
        own_folder(&lists, sddl, me, &mut notes)?;
        // Both looked through before giving up, so a start takes out all it
        // can and names all that is left.
        let left: Vec<String> = [clean(dir, me, &[LISTS], &mut notes), clean(&lists, me, &[], &mut notes)]
            .into_iter()
            .filter_map(Result::err)
            .collect();
        if !left.is_empty() {
            return Err(left.join("; "));
        }
        Ok(notes)
    }

    /// Makes `dir` a folder of the service's own. One that is not there is
    /// made with `sddl`. One that is there is kept only if it is a folder,
    /// not a link, that the service may own, and is then given `sddl`
    /// through the same handle it was checked through, so nobody else can
    /// add, change or relink anything in it from then on. Anything else at
    /// that name is moved aside (as itself: a link is moved, not followed)
    /// and the folder made afresh.
    fn own_folder(dir: &Path, sddl: &str, me: &Me, notes: &mut Vec<String>) -> Result<(), String> {
        // Someone who makes it again each time it is moved aside wins only
        // the service not starting.
        for _ in 0..3 {
            match create_dir_with_sddl(dir, sddl) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("{}: it cannot be made ({e})", dir.display())),
            }
            match examine(dir, me) {
                Ok(folder) => {
                    return protect(&folder, sddl)
                        .map_err(|e| format!("{}: it cannot be locked down ({e})", dir.display()));
                }
                Err(why) => {
                    let aside = aside(dir);
                    fs::rename(dir, &aside)
                        .map_err(|e| format!("{}: {why}, and it cannot be moved aside ({e})", dir.display()))?;
                    notes.push(format!(
                        "Moved {} aside to {}, as {why}; a new one was made.",
                        dir.display(),
                        aside.display()
                    ));
                }
            }
        }
        Err(format!("{}: someone else made it again each time it was moved aside", dir.display()))
    }

    /// The folder at `dir`, open to change its security, if it may be kept:
    /// else why not.
    fn examine(dir: &Path, me: &Me) -> Result<fs::File, String> {
        let folder = open_for_security(dir).map_err(|e| match e.kind() {
            io::ErrorKind::InvalidInput => "it is a link to another place".to_owned(),
            _ => format!("it cannot be checked ({e})"),
        })?;
        let meta = folder.metadata().map_err(|e| format!("it cannot be checked ({e})"))?;
        if !meta.is_dir() {
            return Err("it is not a folder".into());
        }
        let owner = owner_sid_of(&folder).map_err(|e| format!("its owner cannot be read ({e})"))?;
        if !me.trusts(&owner) {
            return Err(foreign(&owner));
        }
        Ok(folder)
    }

    /// Takes every entry of `dir` but those named in `keep` off its name if
    /// it is a link or another account owns it ([`discard`]). What the
    /// service made (its logs, list copies, the phone key) stays. An error
    /// names what is still in place, which the service would take for its
    /// own: a link it would write through, settings or a list it would read.
    fn clean(dir: &Path, me: &Me, keep: &[&str], notes: &mut Vec<String>) -> Result<(), String> {
        let entries = fs::read_dir(dir).map_err(|e| format!("{}: it cannot be looked through ({e})", dir.display()))?;
        let mut left = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    left.push(format!("{}: it cannot be looked through to the end ({e})", dir.display()));
                    break;
                }
            };
            if keep.iter().any(|name| entry.file_name() == *name) {
                continue;
            }
            let path = entry.path();
            let Some(why) = untrusted(&path, me) else { continue };
            match discard(&path, &why) {
                Ok(note) => notes.extend(note),
                Err(still) => left.push(still),
            }
        }
        if left.is_empty() { Ok(()) } else { Err(left.join("; ")) }
    }

    /// Why the entry at `path` is not the service's own, if it is not.
    fn untrusted(path: &Path, me: &Me) -> Option<String> {
        let is_link = |meta: &fs::Metadata| meta.file_attributes() & REPARSE_POINT != 0;
        match fs::symlink_metadata(path) {
            Ok(meta) if is_link(&meta) => return Some("it is a link to another place".into()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => return Some(format!("it cannot be looked at ({e})")),
        }
        let opened = fs::OpenOptions::new().access_mode(READ_CONTROL).custom_flags(OPEN_AS_ITSELF).open(path);
        let entry = match opened {
            Ok(entry) => entry,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => return Some(format!("its owner cannot be read ({e})")),
        };
        // Swapped for a link since the look above.
        if entry.metadata().is_ok_and(|meta| is_link(&meta)) {
            return Some("it is a link to another place".into());
        }
        match owner_sid_of(&entry) {
            Ok(owner) if me.trusts(&owner) => None,
            Ok(owner) => Some(foreign(&owner)),
            Err(e) => Some(format!("its owner cannot be read ({e})")),
        }
    }

    /// Why an entry `owner` (a SID) owns is not the service's own.
    fn foreign(owner: &str) -> String {
        format!("{owner} owns it, not SYSTEM or the administrators")
    }

    /// Takes the entry at `path` off its name, so the service never reads or
    /// writes it. A link is removed as a link, never what it points to.
    /// Anything else is moved aside, so nothing is lost: it may be the
    /// service's own from a run whose files got another owner, or settings
    /// someone wrote by hand. Says what was done, for the log, if anything;
    /// an error if it is still under its name.
    fn discard(path: &Path, why: &str) -> Result<Option<String>, String> {
        let gone = || Ok(Some(format!("{} was gone before it could be taken out ({why}).", path.display())));
        let mut not_removed = None;
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_attributes() & REPARSE_POINT != 0 => {
                let removed =
                    if meta.file_attributes() & DIRECTORY != 0 { fs::remove_dir(path) } else { fs::remove_file(path) };
                match removed {
                    Ok(()) => {
                        return Ok(Some(format!("Removed {} from Captun's data folder, as {why}.", path.display())));
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return gone(),
                    Err(e) => not_removed = Some(e),
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return gone(),
            // Moved aside all the same: that needs no look first.
            Err(_) => {}
        }
        if is_aside(path) {
            // Already off the service's names: nothing reads it there.
            return Ok(not_removed.map(|e| {
                format!(
                    "Left {} where it is: it could not be removed ({e}), but nothing reads it ({why}).",
                    path.display()
                )
            }));
        }
        let aside = aside(path);
        match (fs::rename(path, &aside), not_removed) {
            (Ok(()), None) => Ok(Some(format!("Moved {} aside to {}, as {why}.", path.display(), aside.display()))),
            (Ok(()), Some(e)) => Ok(Some(format!(
                "Moved {} aside to {}, as {why} and it could not be removed ({e}).",
                path.display(),
                aside.display()
            ))),
            (Err(e), _) if e.kind() == io::ErrorKind::NotFound => gone(),
            (Err(e), None) => Err(format!("{}: {why}, and it cannot be moved aside ({e})", path.display())),
            (Err(e), Some(first)) => {
                Err(format!("{}: {why}, and it can be neither removed ({first}) nor moved aside ({e})", path.display()))
            }
        }
    }

    /// Whether `path` is the name of something moved aside.
    fn is_aside(path: &Path) -> bool {
        path.file_name().is_some_and(|name| name.to_string_lossy().contains(ASIDE))
    }

    /// The name `path` is moved aside to: `<name>.untrusted-<time>`.
    fn aside(path: &Path) -> PathBuf {
        let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        path.with_file_name(format!("{name}{ASIDE}{}", chrono::Local::now().format("%Y%m%d-%H%M%S%3f")))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A fresh scratch folder under %TEMP%, and who this test is: the
        /// owner it gives what it makes, which it may always assign, so the
        /// tests run without elevation.
        fn scratch(name: &str) -> (PathBuf, Me) {
            let base = std::env::temp_dir().join(format!("captun-data-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).unwrap();
            let found = Me::find(&base.join("Captun"), super::super::DATA_SDDL);
            assert!(found.owner.as_deref().is_some_and(|sid| sid.starts_with("S-1-")), "{found:?}");
            assert_eq!(fs::read_dir(&base).unwrap().count(), 0, "the scratch folder is gone again");
            (base, Me { can_lock: true, ..found })
        }

        /// Someone who sees this test's files as another account's. Not
        /// possible when the tests run elevated: what they make then belongs
        /// to Administrators, whom every view trusts.
        fn stranger(me: &Me) -> Option<Me> {
            let elevated = me.owner.as_deref().is_some_and(|sid| sid == SYSTEM || sid == ADMINISTRATORS);
            if elevated {
                eprintln!("running elevated: files of another account cannot be stood in for");
            }
            (!elevated).then(|| Me { owner: Some("S-1-5-21-1-2-3-1001".into()), can_lock: true })
        }

        /// The data folder's permissions with this test as their owner.
        fn sddl(me: &Me) -> String {
            let owner = me.owner.as_deref().unwrap();
            format!("O:{owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{owner})")
        }

        /// A junction at `link` to `target`, made the way anyone can, with
        /// no elevation; `false` when `mklink` is not there to make one.
        fn junction(link: &Path, target: &Path) -> bool {
            std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        }

        fn names(dir: &Path) -> Vec<String> {
            let mut names: Vec<String> =
                fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            names.sort();
            names
        }

        /// The names in `dir` the service uses: all but what was moved aside.
        fn kept(dir: &Path) -> Vec<String> {
            names(dir).into_iter().filter(|name| !name.contains(ASIDE)).collect()
        }

        /// What was moved aside in `dir`, by the name it had.
        fn moved(dir: &Path) -> Vec<String> {
            names(dir).into_iter().filter_map(|name| Some(name.split_once(ASIDE)?.0.to_owned())).collect()
        }

        /// Holds `path` open the way another account can, letting nobody
        /// remove or rename it meanwhile (no `FILE_SHARE_DELETE`).
        fn hold(path: &Path) -> fs::File {
            const FILE_SHARE_READ: u32 = 0x1;
            fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(OPEN_AS_ITSELF)
                .open(path)
                .unwrap()
        }

        #[test]
        fn a_missing_folder_is_made_locked_with_its_lists_folder() {
            let (base, me) = scratch("new");
            let dir = base.join("Captun");
            let notes = prepare(&dir, &sddl(&me), &me).unwrap();
            assert!(notes.is_empty(), "{notes:?}");
            assert_eq!(names(&dir), ["lists"]);
            for folder in [&dir, &dir.join("lists")] {
                assert_eq!(owner_sid_of(&open_for_security(folder).unwrap()).ok(), me.owner);
            }
            // Again: the same folders, kept as they are.
            fs::write(dir.join("captun-daemon.log"), "kept").unwrap();
            fs::write(dir.join("lists").join("0123456789abcdef.list"), "kept").unwrap();
            assert!(prepare(&dir, &sddl(&me), &me).unwrap().is_empty());
            assert_eq!(fs::read_to_string(dir.join("captun-daemon.log")).unwrap(), "kept");
            assert_eq!(fs::read_to_string(dir.join("lists").join("0123456789abcdef.list")).unwrap(), "kept");
            let _ = fs::remove_dir_all(base);
        }

        #[test]
        fn a_folder_another_account_owns_is_moved_aside_and_made_afresh() {
            let (base, me) = scratch("foreign");
            let Some(stranger) = stranger(&me) else { return };
            let dir = base.join("Captun");
            fs::create_dir_all(dir.join("lists")).unwrap();
            fs::write(dir.join("captun.toml"), "planted").unwrap();
            let notes = prepare(&dir, &sddl(&me), &stranger).unwrap();
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert_eq!(names(&dir), ["lists"], "made afresh");
            let moved: Vec<String> = names(&base).into_iter().filter(|name| name != "Captun").collect();
            assert_eq!(moved.len(), 1);
            assert!(moved[0].starts_with("Captun.untrusted-"), "{moved:?}");
            let moved_file = fs::read_to_string(base.join(&moved[0]).join("captun.toml")).unwrap();
            assert_eq!(moved_file, "planted", "moved as it was");
            let _ = fs::remove_dir_all(base);
        }

        #[test]
        fn what_the_service_made_stays_and_what_another_account_put_inside_is_moved_aside() {
            let (base, me) = scratch("inside");
            let (dir, lists) = (base.join("Captun"), base.join("Captun").join("lists"));
            assert!(prepare(&dir, &sddl(&me), &me).unwrap().is_empty());
            let plant = || {
                fs::write(dir.join("captun-daemon.log"), "a log").unwrap();
                fs::write(dir.join("adbkey"), "a key").unwrap();
                fs::write(lists.join("0123456789abcdef.list"), "a list").unwrap();
            };
            plant();
            assert!(prepare(&dir, &sddl(&me), &me).unwrap().is_empty(), "the service's own stay");
            assert_eq!(names(&dir), ["adbkey", "captun-daemon.log", "lists"]);
            assert_eq!(names(&lists), ["0123456789abcdef.list"]);

            if let Some(stranger) = stranger(&me) {
                // Moved aside, not deleted: they may be the service's own
                // from a run whose files got another owner.
                let mut notes = Vec::new();
                clean(&dir, &stranger, &[LISTS], &mut notes).unwrap();
                clean(&lists, &stranger, &[], &mut notes).unwrap();
                assert_eq!(notes.len(), 3, "{notes:?}");
                assert_eq!(kept(&dir), ["lists"]);
                assert_eq!(moved(&dir), ["adbkey", "captun-daemon.log"]);
                assert!(kept(&lists).is_empty());
                assert_eq!(moved(&lists), ["0123456789abcdef.list"]);
                let list = names(&lists).remove(0);
                assert_eq!(fs::read_to_string(lists.join(list)).unwrap(), "a list", "moved as it was");
                // Once aside they stay where they are, start after start.
                let mut again = Vec::new();
                clean(&dir, &stranger, &[LISTS], &mut again).unwrap();
                clean(&lists, &stranger, &[], &mut again).unwrap();
                assert!(again.is_empty(), "{again:?}");
                assert_eq!(moved(&dir), ["adbkey", "captun-daemon.log"]);
                plant();
            }

            // Links, though this test made them: removed as links, and what
            // they point to stays as it was.
            let elsewhere = base.join("elsewhere");
            fs::create_dir_all(&elsewhere).unwrap();
            fs::write(elsewhere.join("system file"), "untouched").unwrap();
            if junction(&dir.join("captun-daemon.log.1"), &elsewhere)
                && junction(&lists.join("fedcba9876543210.list"), &elsewhere)
            {
                let notes = prepare(&dir, &sddl(&me), &me).unwrap();
                assert_eq!(notes.len(), 2, "{notes:?}");
                assert_eq!(kept(&dir), ["adbkey", "captun-daemon.log", "lists"]);
                assert_eq!(kept(&lists), ["0123456789abcdef.list"]);

                // The lists folder itself a link: moved aside, then removed.
                fs::remove_dir_all(&lists).unwrap();
                assert!(junction(&lists, &elsewhere));
                let notes = prepare(&dir, &sddl(&me), &me).unwrap();
                assert_eq!(notes.len(), 2, "{notes:?}");
                assert_eq!(kept(&dir), ["adbkey", "captun-daemon.log", "lists"]);
                assert!(names(&lists).is_empty(), "a new lists folder");
            } else {
                eprintln!("no junction could be made; that part is not checked");
            }
            assert_eq!(names(&elsewhere), ["system file"]);
            assert_eq!(fs::read_to_string(elsewhere.join("system file")).unwrap(), "untouched");
            let _ = fs::remove_dir_all(base);
        }

        #[test]
        fn another_accounts_file_that_cannot_be_moved_aside_is_named_not_passed_over() {
            let (base, me) = scratch("held");
            let Some(stranger) = stranger(&me) else {
                let _ = fs::remove_dir_all(base);
                return;
            };
            let dir = base.join("Captun");
            assert!(prepare(&dir, &sddl(&me), &me).unwrap().is_empty());
            fs::write(dir.join("captun.toml"), "planted settings").unwrap();
            fs::write(dir.join("adbkey"), "a planted key").unwrap();
            let held = hold(&dir.join("captun.toml"));

            let mut notes = Vec::new();
            let left = clean(&dir, &stranger, &[LISTS], &mut notes).unwrap_err();
            assert!(left.contains("captun.toml") && !left.contains("adbkey"), "{left}");
            assert_eq!(notes.len(), 1, "the other one was moved aside: {notes:?}");
            assert_eq!(kept(&dir), ["captun.toml", "lists"], "still under its name");
            assert_eq!(moved(&dir), ["adbkey"]);

            // Once let go of, it is moved aside too, as it was.
            drop(held);
            let mut notes = Vec::new();
            clean(&dir, &stranger, &[LISTS], &mut notes).unwrap();
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert_eq!(kept(&dir), ["lists"]);
            assert_eq!(moved(&dir), ["adbkey", "captun.toml"]);
            let settings = names(&dir).into_iter().find(|name| name.starts_with("captun.toml")).unwrap();
            assert_eq!(fs::read_to_string(dir.join(settings)).unwrap(), "planted settings");
            let _ = fs::remove_dir_all(base);
        }

        #[test]
        fn a_link_that_cannot_be_taken_out_keeps_the_service_from_starting() {
            let (base, me) = scratch("stuck");
            let (dir, elsewhere) = (base.join("Captun"), base.join("elsewhere"));
            assert!(prepare(&dir, &sddl(&me), &me).unwrap().is_empty());
            fs::create_dir_all(&elsewhere).unwrap();
            // Where the log goes: written through, it would land elsewhere.
            let log = dir.join("captun-daemon.log");
            if !junction(&log, &elsewhere) {
                eprintln!("no junction could be made; nothing to check");
                let _ = fs::remove_dir_all(base);
                return;
            }
            let held = hold(&log);
            let why = prepare(&dir, &sddl(&me), &me).unwrap_err();
            assert!(why.contains("captun-daemon.log") && why.contains("link"), "{why}");
            assert!(fs::symlink_metadata(&log).is_ok(), "still there");

            drop(held);
            let notes = prepare(&dir, &sddl(&me), &me).unwrap();
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert_eq!(names(&dir), ["lists"]);
            assert!(elsewhere.is_dir(), "what it pointed to is untouched");
            let _ = fs::remove_dir_all(base);
        }

        #[test]
        fn a_link_in_the_folders_place_is_moved_aside_not_followed() {
            let (base, me) = scratch("link");
            let (dir, elsewhere) = (base.join("Captun"), base.join("elsewhere"));
            fs::create_dir_all(&elsewhere).unwrap();
            fs::write(elsewhere.join("system file"), "untouched").unwrap();
            if !junction(&dir, &elsewhere) {
                eprintln!("no junction could be made; nothing to check");
                let _ = fs::remove_dir_all(base);
                return;
            }
            let notes = prepare(&dir, &sddl(&me), &me).unwrap();
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert_eq!(names(&dir), ["lists"], "a folder of its own now");
            assert_eq!(names(&elsewhere), ["system file"], "nothing made or locked there");
            assert_eq!(fs::read_to_string(elsewhere.join("system file")).unwrap(), "untouched");
            let _ = fs::remove_dir_all(base);
        }

        #[test]
        fn without_administrator_rights_nothing_is_touched() {
            let (base, _) = scratch("unelevated");
            let dir = base.join("Captun");
            let me = Me { owner: None, can_lock: false };
            let notes = prepare(&dir, super::super::DATA_SDDL, &me).unwrap();
            assert_eq!(notes.len(), 1);
            assert!(!dir.exists());
            let _ = fs::remove_dir_all(base);
        }

        #[test]
        fn only_the_services_own_accounts_are_trusted() {
            let me = Me { owner: Some("S-1-5-21-9-9-9-500".into()), can_lock: true };
            assert!(me.trusts(SYSTEM) && me.trusts(ADMINISTRATORS) && me.trusts("S-1-5-21-9-9-9-500"));
            assert!(!me.trusts("S-1-5-21-9-9-9-1001") && !me.trusts("S-1-5-32-545") && !me.trusts(""));
            assert!(!Me { owner: None, can_lock: true }.trusts("S-1-5-21-9-9-9-500"));
        }
    }
}

pub(crate) fn default_config() -> PathBuf {
    data_dir().join("captun.toml")
}

/// The persistent RSA key for Captun's built-in adb. Created on first use; a
/// stable key means the phone only prompts "Allow USB debugging?" once.
pub(crate) fn adb_key() -> PathBuf {
    data_dir().join("adbkey")
}

/// The phone key OmniHub made, which phones may have allowed.
pub(crate) fn earlier_adb_key() -> PathBuf {
    data_dir_of(EARLIER_NAME).join("adbkey")
}

fn lists_dir_of(names: (&str, &str)) -> PathBuf {
    #[cfg(all(unix, not(target_os = "macos")))]
    return PathBuf::from("/var/lib").join(names.1).join("lists");
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    return data_dir_of(names).join("lists");
}

/// Where downloaded online lists are kept between runs.
pub(crate) fn lists_dir() -> PathBuf {
    lists_dir_of(NAME)
}

/// Where OmniHub kept the online lists it downloaded.
pub(crate) fn earlier_lists_dir() -> PathBuf {
    lists_dir_of(EARLIER_NAME)
}

/// The service's log of its current run (the run before is kept as `.1`).
pub(crate) fn log_file() -> PathBuf {
    #[cfg(target_os = "macos")]
    return PathBuf::from("/Library/Logs/Captun/captun-daemon.log");
    #[cfg(all(unix, not(target_os = "macos")))]
    return PathBuf::from("/var/log/captun/captun-daemon.log");
    #[cfg(not(unix))]
    return data_dir().join("captun-daemon.log");
}

pub(crate) fn default_token() -> PathBuf {
    #[cfg(target_os = "macos")]
    return PathBuf::from("/var/run/captun/ipc.token");
    #[cfg(all(unix, not(target_os = "macos")))]
    return PathBuf::from("/run/captun/ipc.token");
    #[cfg(not(unix))]
    return data_dir().join("ipc.token");
}

/// The unprivileged user who started us, who should own the token file so
/// their GUI can read it: named on the command line (macOS, where the admin
/// prompt leaves no trace of who asked), else as sudo or pkexec record it.
pub(crate) fn invoking_uid(explicit: Option<u32>) -> Option<u32> {
    explicit.or_else(|| ["PKEXEC_UID", "SUDO_UID"].iter().find_map(|var| std::env::var(var).ok()?.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omnihubs_folders_are_captuns_under_the_earlier_name() {
        let lower = |path: PathBuf| path.to_string_lossy().to_lowercase();
        assert_eq!(lower(earlier_lists_dir()), lower(lists_dir()).replace("captun", "omnihub"));
        assert_eq!(lower(earlier_adb_key()), lower(adb_key()).replace("captun", "omnihub"));
        assert_ne!(earlier_lists_dir(), lists_dir());
    }
}
