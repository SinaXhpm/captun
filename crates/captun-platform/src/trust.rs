//! Whether a program file the service loads can be changed by anyone but
//! Windows and the administrators. The service runs with full rights, so a
//! file (or a DLL planted beside it) that an ordinary program can change
//! would run that program's code with them. Captun is installed for all
//! users in Program Files, where only Windows and the administrators can
//! write; anywhere else, this refuses.

use std::path::{Path, PathBuf};

/// Why a program file is not safe to load.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UntrustedFile {
    #[error("{} is missing", .path.display())]
    Missing { path: PathBuf },
    #[error("cannot tell who may change {} ({reason})", .path.display())]
    Unreadable { path: PathBuf, reason: String },
    #[error("{} belongs to {owner}, not to Windows or the administrators", .path.display())]
    Owner { path: PathBuf, owner: String },
    /// `can` says what they can do to it: "change", "add or replace files
    /// in", "rename or replace".
    #[error("{who} can {can} {}", .path.display())]
    Writable { path: PathBuf, who: String, can: &'static str },
    /// It has no access list at all (a NULL DACL, or a drive without
    /// permissions such as FAT), so anyone can change it.
    #[error("{} is not protected: anyone can change it", .path.display())]
    Unprotected { path: PathBuf },
    /// It is a link (a symbolic link or a junction) to another place, so
    /// what the path leads to is not what was checked.
    #[error("{} is a link to another place", .path.display())]
    Link { path: PathBuf },
}

/// Checks that only Windows and the administrators (SYSTEM, Administrators,
/// TrustedInstaller) own and can change `path`, can add or replace files in
/// its folder, and can rename or replace any folder above it up to the drive.
///
/// The path is checked as it is written, from the drive down, and a link
/// anywhere on it fails: a check that followed links would pass the place a
/// link points to now, while loading the same path later may follow it
/// somewhere else. Once each level has passed, nobody but Windows and the
/// administrators can rename, replace or relink it, nor the levels below,
/// which are checked after it. So loading that same path afterwards gets
/// what was checked. Pass a real path, as [`real_path`] gives.
///
/// Other systems have nothing to check here and always pass.
pub fn check_program_file(path: &Path) -> Result<(), UntrustedFile> {
    #[cfg(windows)]
    return windows::check(path);
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
    }
}

/// `path` with every link in it followed and nothing relative left: the
/// path to check with [`check_program_file`] and then load from. On Windows
/// it is written as people write it (`C:\...`, not `\\?\C:\...`, which
/// WinDivert would register its driver under) whenever Windows reads that
/// form back as the same path.
pub fn real_path(path: &Path) -> std::io::Result<PathBuf> {
    let real = std::fs::canonicalize(path)?;
    #[cfg(windows)]
    return Ok(windows::plain(real));
    #[cfg(not(windows))]
    Ok(real)
}

/// Accounts trusted to own and change program files: SYSTEM, Administrators
/// and TrustedInstaller.
#[cfg(any(windows, test))]
const TRUSTED: [&str; 3] =
    ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];
/// Stand-ins that no other program can hold: CREATOR OWNER and CREATOR GROUP
/// only ever name who later creates something, and OWNER RIGHTS is the owner,
/// already checked to be trusted.
#[cfg(any(windows, test))]
const STAND_INS: [&str; 3] = ["S-1-3-0", "S-1-3-1", "S-1-3-4"];

#[cfg(any(windows, test))]
mod rights {
    pub(super) const WRITE_DATA: u32 = 0x0002; // FILE_ADD_FILE on a folder
    pub(super) const APPEND_DATA: u32 = 0x0004; // FILE_ADD_SUBDIRECTORY on a folder
    pub(super) const DELETE_CHILD: u32 = 0x0040;
    pub(super) const DELETE: u32 = 0x0001_0000;
    pub(super) const WRITE_DAC: u32 = 0x0004_0000;
    pub(super) const WRITE_OWNER: u32 = 0x0008_0000;
    pub(super) const GENERIC_ALL: u32 = 0x1000_0000;
    pub(super) const GENERIC_WRITE: u32 = 0x4000_0000;
}

/// Where in the path a checked file or folder is.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// The program file itself.
    File,
    /// The folder holding it: a DLL planted beside the program is loaded
    /// by it.
    Folder,
    /// A folder above that: only renaming or replacing it matters, since
    /// Windows lets ordinary users create folders in a drive's root.
    Above { root: bool },
}

#[cfg(any(windows, test))]
impl Place {
    /// The rights that would let someone else change what is loaded.
    fn risky(self) -> u32 {
        use rights::*;
        let common = WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
        match self {
            Self::File => common | WRITE_DATA | APPEND_DATA | DELETE | GENERIC_WRITE,
            Self::Folder => common | WRITE_DATA | APPEND_DATA | DELETE_CHILD | DELETE | GENERIC_WRITE,
            // A drive's root can be neither deleted nor renamed.
            Self::Above { root: true } => common | DELETE_CHILD,
            Self::Above { root: false } => common | DELETE_CHILD | DELETE,
        }
    }

    #[cfg(windows)]
    fn can(self) -> &'static str {
        match self {
            Self::File => "change",
            Self::Folder => "add or replace files in",
            Self::Above { .. } => "rename or replace",
        }
    }
}

/// What is wrong with one file or folder, before names are put to it.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
enum Problem<'a> {
    Owner(&'a [u8]),
    /// Someone else is allowed a risky right; `None` when the entry does not
    /// say who in a form that can be read.
    Grant(Option<&'a [u8]>),
    Unprotected,
    /// The access list does not parse.
    Damaged,
}

/// Judges one file or folder from its owner and access list (`None`: it has
/// none), both in Windows' binary form. Deny entries are skipped (they could
/// only take rights away), and so are entries only passed on to what is
/// created inside.
#[cfg(any(windows, test))]
fn judge<'a>(owner: &'a [u8], dacl: Option<&'a [u8]>, place: Place) -> Result<(), Problem<'a>> {
    if !sid_text(owner).is_some_and(|sid| TRUSTED.contains(&sid.as_str())) {
        return Err(Problem::Owner(owner));
    }
    let dacl = dacl.ok_or(Problem::Unprotected)?;
    for ace in acl::allowed(dacl).ok_or(Problem::Damaged)? {
        if ace.inherit_only || ace.mask & place.risky() == 0 {
            continue;
        }
        let trusted = ace
            .trustee
            .and_then(sid_text)
            .is_some_and(|sid| TRUSTED.contains(&sid.as_str()) || STAND_INS.contains(&sid.as_str()));
        if !trusted {
            return Err(Problem::Grant(ace.trustee));
        }
    }
    Ok(())
}

/// The length of the SID at the start of `bytes`, when all of it is there.
#[cfg(any(windows, test))]
fn sid_len(bytes: &[u8]) -> Option<usize> {
    let len = 8 + 4 * usize::from(*bytes.get(1)?);
    (bytes.len() >= len).then_some(len)
}

/// A SID in Windows' binary form as text ("S-1-5-18").
#[cfg(any(windows, test))]
fn sid_text(sid: &[u8]) -> Option<String> {
    use std::fmt::Write;
    let len = sid_len(sid)?;
    let authority = sid.get(2..8)?.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let mut text =
        if authority < 1 << 32 { format!("S-{}-{authority}", sid[0]) } else { format!("S-{}-0x{authority:012X}", sid[0]) };
    for sub in sid.get(8..len)?.as_chunks::<4>().0 {
        let _ = write!(text, "-{}", u32::from_le_bytes(*sub));
    }
    Some(text)
}

/// Access control lists in Windows' binary form.
#[cfg(any(windows, test))]
mod acl {
    const ALLOWED: u8 = 0;
    const ALLOWED_COMPOUND: u8 = 4;
    const ALLOWED_OBJECT: u8 = 5;
    const ALLOWED_CALLBACK: u8 = 9;
    const ALLOWED_CALLBACK_OBJECT: u8 = 11;
    const INHERIT_ONLY: u8 = 0x08;
    const OBJECT_TYPE_PRESENT: u32 = 0x1;
    const INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;

    /// An entry that allows rights.
    #[derive(Debug)]
    pub(super) struct Allowed<'a> {
        pub(super) mask: u32,
        pub(super) inherit_only: bool,
        /// Who it allows, as a binary SID.
        pub(super) trustee: Option<&'a [u8]>,
    }

    fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
    }

    fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    }

    fn sid_at(ace: &[u8], at: usize) -> Option<&[u8]> {
        let rest = ace.get(at..)?;
        rest.get(..super::sid_len(rest)?)
    }

    /// The entries of `acl` that allow rights. `None` when the list does not
    /// parse, so the caller refuses rather than guesses.
    pub(super) fn allowed(acl: &[u8]) -> Option<Vec<Allowed<'_>>> {
        let size = usize::from(u16_at(acl, 2)?);
        let count = u16_at(acl, 4)?;
        let acl = acl.get(..size)?;
        let mut entries = Vec::new();
        let mut at = 8;
        for _ in 0..count {
            let kind = *acl.get(at)?;
            let flags = *acl.get(at + 1)?;
            let len = usize::from(u16_at(acl, at + 2)?);
            if len < 4 {
                return None;
            }
            let ace = acl.get(at..at + len)?;
            at += len;
            if !matches!(kind, ALLOWED | ALLOWED_COMPOUND | ALLOWED_OBJECT | ALLOWED_CALLBACK | ALLOWED_CALLBACK_OBJECT) {
                continue;
            }
            let mask = u32_at(ace, 4)?;
            let trustee = match kind {
                // The SID follows the mask; a callback entry's condition comes
                // after it.
                ALLOWED | ALLOWED_CALLBACK => sid_at(ace, 8),
                ALLOWED_OBJECT | ALLOWED_CALLBACK_OBJECT => {
                    let object_flags = u32_at(ace, 8)?;
                    let guids = [OBJECT_TYPE_PRESENT, INHERITED_OBJECT_TYPE_PRESENT]
                        .iter()
                        .filter(|&&flag| object_flags & flag != 0)
                        .count();
                    sid_at(ace, 12 + 16 * guids)
                }
                // A compound entry names a server and a client: whom it
                // allows cannot be told from one SID.
                _ => None,
            };
            entries.push(Allowed { mask, inherit_only: flags & INHERIT_ONLY != 0, trustee });
        }
        Some(entries)
    }
}

#[cfg(windows)]
mod windows {
    use std::{
        io,
        path::{Path, PathBuf},
    };

    use super::{Place, Problem, UntrustedFile, ffi::Security, judge, sid_text};

    pub(super) fn check(path: &Path) -> Result<(), UntrustedFile> {
        // Said first, whatever the folders above are like.
        if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
            return Err(UntrustedFile::Missing { path: shown(path) });
        }
        walk(path, super::ffi::read)
    }

    /// Checks each level of `path` from the drive down, `read` giving a
    /// level's owner and access list without following a link there. Top
    /// down, so each level is read through levels already known to stay put.
    pub(super) fn walk(path: &Path, mut read: impl FnMut(&Path) -> io::Result<Security>) -> Result<(), UntrustedFile> {
        if !written_out(path) {
            return Err(UntrustedFile::Unreadable { path: shown(path), reason: "it is not written out in full".into() });
        }
        let levels: Vec<&Path> = path.ancestors().collect();
        for (depth, at) in levels.into_iter().enumerate().rev() {
            let place = match depth {
                0 => Place::File,
                1 => Place::Folder,
                _ => Place::Above { root: at.parent().is_none() },
            };
            check_one(at, place, &mut read)?;
        }
        Ok(())
    }

    /// Whether every level of `path` is a full path that Windows reads back
    /// as written: nothing relative, and no name that Windows would trim (a
    /// trailing dot or space) so that a level checked alone is another one.
    fn written_out(path: &Path) -> bool {
        path.is_absolute() && path.ancestors().all(|at| std::path::absolute(at).is_ok_and(|back| back == at))
    }

    /// `real` (a canonical, `\\?\` path) without the `\\?\`, when it is on
    /// a drive and Windows reads every level of that form back as the same.
    pub(super) fn plain(real: PathBuf) -> PathBuf {
        let Some(rest) = real.to_str().and_then(|text| text.strip_prefix(r"\\?\")) else { return real };
        let on_drive = matches!(rest.as_bytes(), [letter, b':', b'\\', ..] if letter.is_ascii_alphabetic());
        let plain = PathBuf::from(rest);
        if on_drive && written_out(&plain) { plain } else { real }
    }

    fn check_one(
        at: &Path,
        place: Place,
        read: &mut impl FnMut(&Path) -> io::Result<Security>,
    ) -> Result<(), UntrustedFile> {
        let path = shown(at);
        let security = read(at).map_err(|e| UntrustedFile::Unreadable { path: path.clone(), reason: e.to_string() })?;
        if security.link {
            return Err(UntrustedFile::Link { path });
        }
        judge(&security.owner, security.dacl.as_deref(), place).map_err(|problem| match problem {
            Problem::Owner(sid) => UntrustedFile::Owner { path, owner: name_of(Some(sid)) },
            Problem::Grant(sid) => UntrustedFile::Writable { path, who: name_of(sid), can: place.can() },
            Problem::Unprotected => UntrustedFile::Unprotected { path },
            Problem::Damaged => UntrustedFile::Unreadable { path, reason: "its permissions cannot be read".into() },
        })
    }

    /// An account as Windows shows it ("BUILTIN\Users"), else as its SID.
    fn name_of(sid: Option<&[u8]>) -> String {
        sid.and_then(|sid| super::ffi::account_name(sid).or_else(|| sid_text(sid)))
            .unwrap_or_else(|| "an account Windows cannot name".into())
    }

    /// A path as people write it, without the `\\?\` that following links
    /// puts in front.
    pub(super) fn shown(path: &Path) -> PathBuf {
        let text = path.to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            PathBuf::from(format!(r"\\{rest}"))
        } else if let Some(rest) = text.strip_prefix(r"\\?\") {
            PathBuf::from(rest)
        } else {
            path.to_path_buf()
        }
    }
}

/// Reading who owns a file and its access list.
#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    use std::{io, os::windows::ffi::OsStrExt, path::Path, ptr};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            ACL, Authorization::{GetSecurityInfo, SE_FILE_OBJECT}, DACL_SECURITY_INFORMATION, GetLengthSid, IsValidSid,
            LookupAccountSidW, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FileAttributeTagInfo, GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL,
        },
    };

    /// Who owns a file or folder, and its access list (`None`: it has none),
    /// copied out in Windows' binary form.
    pub(super) struct Security {
        pub(super) owner: Vec<u8>,
        pub(super) dacl: Option<Vec<u8>>,
        /// It is a link to another place (a symbolic link, a junction or a
        /// mount point); `owner` and `dacl` are then the link's own.
        pub(super) link: bool,
    }

    /// Frees what GetSecurityInfo allocated.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by GetSecurityInfo with LocalAlloc, freed
                // once, here; nothing points into it any more.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// An open file or folder, closed when dropped.
    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: a handle CreateFileW opened, closed once, here.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// The reparse tags of links: name surrogates, which stand for another
    /// file or folder. Other reparse points (a compressed system file, a
    /// cloud file) are the file itself.
    const NAME_SURROGATE: u32 = 0x2000_0000;

    /// Reads `path`'s owner and access list through a handle on `path`
    /// itself: a link there is opened, not followed, and said to be one.
    pub(super) fn read(path: &Path) -> io::Result<Security> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call; no security
        // attributes or template are passed. Sharing everything, only to read
        // the attributes and permissions, keeps nobody else from the file.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = Handle(handle);
        let mut tag = FILE_ATTRIBUTE_TAG_INFO { FileAttributes: 0, ReparseTag: 0 };
        let size = u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).map_err(io::Error::other)?;
        // SAFETY: `handle` is open; `tag` is a live local of exactly `size`
        // bytes, the type this information class fills.
        if unsafe { GetFileInformationByHandleEx(handle.0, FileAttributeTagInfo, ptr::addr_of_mut!(tag).cast(), size) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let link = tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag.ReparseTag & NAME_SURROGATE != 0;
        let (mut owner, mut dacl, mut descriptor): (PSID, *mut ACL, PSECURITY_DESCRIPTOR) =
            (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        // SAFETY: `handle` is open with READ_CONTROL; the out pointers are
        // live locals. The group and SACL are not asked for, so their
        // pointers may be null.
        let status = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        let descriptor = Descriptor(descriptor);
        if status != ERROR_SUCCESS {
            return Err(i32::try_from(status).map_or_else(|_| io::Error::other("Windows refused"), io::Error::from_raw_os_error));
        }
        // SAFETY: on success `owner` is null or points at a SID inside
        // `descriptor`, which lives until the end of this function.
        if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
            return Err(io::Error::other("it has no owner"));
        }
        // SAFETY: as above; a valid SID is exactly GetLengthSid bytes long.
        let owner = unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), GetLengthSid(owner) as usize) }.to_vec();
        // SAFETY: a non-null `dacl` points at an ACL inside `descriptor`,
        // whose header gives its whole size in bytes.
        let dacl = (!dacl.is_null())
            .then(|| unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), usize::from((*dacl).AclSize)) }.to_vec());
        drop(descriptor);
        drop(handle);
        Ok(Security { owner, dacl, link })
    }

    /// The account a binary SID names, as "DOMAIN\name", when Windows can say.
    pub(super) fn account_name(sid: &[u8]) -> Option<String> {
        // A copy, aligned for Windows and writable as the API's types ask.
        let mut words = vec![0u32; sid.len().div_ceil(4)];
        // SAFETY: `words` holds at least `sid.len()` bytes; the two do not overlap.
        unsafe { ptr::copy_nonoverlapping(sid.as_ptr(), words.as_mut_ptr().cast::<u8>(), sid.len()) };
        let sid: PSID = words.as_mut_ptr().cast();
        // SAFETY: `sid` points at the copy, which holds every byte its header
        // claims (the caller measured it); IsValidSid only reads it.
        if unsafe { IsValidSid(sid) } == 0 {
            return None;
        }
        let (mut name_len, mut domain_len, mut kind): (u32, u32, SID_NAME_USE) = (0, 0, 0);
        // SAFETY: asks only for the lengths: null buffers with zero lengths,
        // and live locals for the counts.
        unsafe {
            LookupAccountSidW(ptr::null(), sid, ptr::null_mut(), &mut name_len, ptr::null_mut(), &mut domain_len, &mut kind)
        };
        if name_len == 0 {
            return None;
        }
        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len.max(1) as usize];
        domain_len = domain_len.max(1);
        // SAFETY: each buffer is as long as the count passed with it.
        let found = unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid,
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        };
        if found == 0 {
            return None;
        }
        let name = String::from_utf16_lossy(name.get(..name_len as usize)?);
        let domain = String::from_utf16_lossy(domain.get(..domain_len as usize)?);
        Some(if domain.is_empty() { name } else { format!("{domain}\\{name}") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A SID's binary form, from its text.
    fn sid(text: &str) -> Vec<u8> {
        let parts: Vec<u64> = text.trim_start_matches("S-").split('-').map(|p| p.parse().unwrap()).collect();
        let subs = &parts[2..];
        let mut bytes = vec![u8::try_from(parts[0]).unwrap(), u8::try_from(subs.len()).unwrap()];
        bytes.extend_from_slice(&parts[1].to_be_bytes()[2..]);
        for sub in subs {
            bytes.extend_from_slice(&u32::try_from(*sub).unwrap().to_le_bytes());
        }
        bytes
    }

    const SYSTEM: &str = "S-1-5-18";
    const ADMINS: &str = "S-1-5-32-544";
    const INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    const USERS: &str = "S-1-5-32-545";
    const AUTHENTICATED: &str = "S-1-5-11";
    const SOMEONE: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const ALLOW: u8 = 0;
    const DENY: u8 = 1;
    const INHERIT_ONLY: u8 = 0x08;
    const INHERITED: u8 = 0x10;
    const READ_EXECUTE: u32 = 0x0012_00a9;
    const MODIFY: u32 = 0x0013_01bf;
    const FULL: u32 = 0x001f_01ff;
    const ADD_SUBFOLDER: u32 = rights::APPEND_DATA;

    fn ace(kind: u8, flags: u8, mask: u32, who: &str) -> Vec<u8> {
        let sid = sid(who);
        let len = u16::try_from(8 + sid.len()).unwrap();
        let mut bytes = vec![kind, flags];
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(&sid);
        bytes
    }

    fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = aces.concat();
        let size = u16::try_from(8 + body.len()).unwrap();
        let mut bytes = vec![2, 0];
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(aces.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&body);
        bytes
    }

    /// How Windows sets up Program Files and what an installer puts in it.
    fn program_files() -> Vec<u8> {
        acl(&[
            ace(ALLOW, INHERITED, FULL, INSTALLER),
            ace(ALLOW, INHERITED, FULL, SYSTEM),
            ace(ALLOW, INHERITED, FULL, ADMINS),
            ace(ALLOW, INHERITED, READ_EXECUTE, USERS),
            ace(ALLOW, INHERITED | INHERIT_ONLY, FULL, "S-1-3-0"),
            ace(ALLOW, INHERITED, READ_EXECUTE, "S-1-15-2-1"),
        ])
    }

    fn judged(owner: &str, dacl: Option<&[u8]>, place: Place) -> Result<(), String> {
        let owner = sid(owner);
        judge(&owner, dacl, place).map_err(|problem| match problem {
            Problem::Owner(sid) => format!("owner {}", sid_text(sid).unwrap()),
            Problem::Grant(sid) => format!("grant {}", sid.and_then(sid_text).unwrap_or_default()),
            Problem::Unprotected => "unprotected".into(),
            Problem::Damaged => "damaged".into(),
        })
    }

    const FILE: Place = Place::File;
    const FOLDER: Place = Place::Folder;
    const ABOVE: Place = Place::Above { root: false };
    const ROOT: Place = Place::Above { root: true };

    #[test]
    fn sids_read_as_text() {
        for text in [SYSTEM, ADMINS, INSTALLER, SOMEONE, "S-1-0-0", "S-1-15-3-65536-1888954469-739942743"] {
            assert_eq!(sid_text(&sid(text)).as_deref(), Some(text));
        }
        let big = [1, 1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 7, 0, 0, 0];
        assert_eq!(sid_text(&big).as_deref(), Some("S-1-0x010203040506-7"));
        assert_eq!(sid_text(&sid(SYSTEM)[..8]), None, "cut short");
        assert_eq!(sid_text(&[]), None);
    }

    #[test]
    fn an_installed_program_passes_everywhere_in_its_path() {
        let dacl = program_files();
        for owner in [SYSTEM, ADMINS, INSTALLER] {
            for place in [FILE, FOLDER, ABOVE, ROOT] {
                assert_eq!(judged(owner, Some(&dacl), place), Ok(()), "{owner} {place:?}");
            }
        }
    }

    #[test]
    fn someone_elses_file_fails_on_its_owner() {
        assert_eq!(judged(SOMEONE, Some(&program_files()), FILE), Err(format!("owner {SOMEONE}")));
        // The stand-ins never own anything trustworthy.
        assert!(judged("S-1-3-4", Some(&program_files()), FILE).is_err());
    }

    #[test]
    fn no_access_list_fails() {
        assert_eq!(judged(ADMINS, None, FILE), Err("unprotected".into()));
        assert_eq!(judged(ADMINS, None, ROOT), Err("unprotected".into()));
    }

    #[test]
    fn a_damaged_access_list_fails() {
        let mut dacl = program_files();
        dacl.truncate(dacl.len() - 3);
        assert_eq!(judged(ADMINS, Some(&dacl), FILE), Err("damaged".into()));
        // An entry claiming fewer bytes than its own header.
        let mut short = acl(&[ace(ALLOW, 0, FULL, SYSTEM)]);
        short[10] = 2;
        short[11] = 0;
        assert_eq!(judged(ADMINS, Some(&short), FILE), Err("damaged".into()));
    }

    #[test]
    fn each_risky_right_fails_where_it_matters() {
        use rights::*;
        let cases: [(u32, [bool; 4]); 9] = [
            // right: refused at the file, its folder, a folder above, the root
            (WRITE_DATA, [true, true, false, false]),
            (APPEND_DATA, [true, true, false, false]),
            (DELETE_CHILD, [false, true, true, true]),
            (DELETE, [true, true, true, false]),
            (WRITE_DAC, [true, true, true, true]),
            (WRITE_OWNER, [true, true, true, true]),
            (GENERIC_ALL, [true, true, true, true]),
            (GENERIC_WRITE, [true, true, false, false]),
            (READ_EXECUTE, [false, false, false, false]),
        ];
        for (right, refused) in cases {
            let dacl = acl(&[ace(ALLOW, 0, FULL, SYSTEM), ace(ALLOW, 0, right, USERS)]);
            for (place, refused) in [FILE, FOLDER, ABOVE, ROOT].into_iter().zip(refused) {
                let got = judged(INSTALLER, Some(&dacl), place);
                assert_eq!(got.is_err(), refused, "{right:#x} at {place:?}: {got:?}");
                if refused {
                    assert_eq!(got, Err(format!("grant {USERS}")));
                }
            }
        }
    }

    #[test]
    fn a_drive_root_where_users_may_make_folders_passes() {
        // C:\ as Windows sets it up.
        let root = acl(&[
            ace(ALLOW, 0x03, FULL, ADMINS),
            ace(ALLOW, 0x03, FULL, SYSTEM),
            ace(ALLOW, 0x03, READ_EXECUTE, USERS),
            ace(ALLOW, 0x03 | INHERIT_ONLY, MODIFY, AUTHENTICATED),
            ace(ALLOW, 0, ADD_SUBFOLDER, AUTHENTICATED),
        ]);
        assert_eq!(judged(INSTALLER, Some(&root), ROOT), Ok(()));
        assert_eq!(judged(INSTALLER, Some(&root), ABOVE), Ok(()));
        // The same list on the folder holding the program would let anyone
        // plant a folder there.
        assert_eq!(judged(INSTALLER, Some(&root), FOLDER), Err(format!("grant {AUTHENTICATED}")));
    }

    #[test]
    fn inherit_only_and_deny_entries_are_skipped() {
        let dacl = acl(&[
            ace(ALLOW, 0, FULL, SYSTEM),
            ace(ALLOW, INHERIT_ONLY, FULL, SOMEONE),
            ace(DENY, 0, FULL, SOMEONE),
            ace(ALLOW, 0, FULL, "S-1-3-0"),
            ace(ALLOW, 0, FULL, "S-1-3-4"),
        ]);
        assert_eq!(judged(ADMINS, Some(&dacl), FOLDER), Ok(()));
        // A deny entry does not excuse an allow entry: the allow is refused.
        let both = acl(&[ace(DENY, 0, FULL, USERS), ace(ALLOW, 0, MODIFY, USERS)]);
        assert_eq!(judged(ADMINS, Some(&both), FILE), Err(format!("grant {USERS}")));
    }

    #[test]
    fn a_users_own_folder_fails() {
        // %TEMP% and %LOCALAPPDATA%: the user owns it and may do anything.
        let dacl = acl(&[ace(ALLOW, INHERITED, FULL, SYSTEM), ace(ALLOW, INHERITED, FULL, ADMINS), ace(ALLOW, INHERITED, FULL, SOMEONE)]);
        assert_eq!(judged(SOMEONE, Some(&dacl), FILE), Err(format!("owner {SOMEONE}")));
        assert_eq!(judged(ADMINS, Some(&dacl), FOLDER), Err(format!("grant {SOMEONE}")));
    }

    #[test]
    fn callback_and_object_entries_are_read_to_their_sid() {
        const CALLBACK: u8 = 9;
        const OBJECT: u8 = 5;
        // A callback entry: its condition follows the SID.
        let mut callback = ace(CALLBACK, 0, MODIFY, USERS);
        callback.extend_from_slice(b"artx\0\0\0\0");
        let len = u16::try_from(callback.len()).unwrap();
        callback[2..4].copy_from_slice(&len.to_le_bytes());
        assert_eq!(judged(ADMINS, Some(&acl(&[callback])), FILE), Err(format!("grant {USERS}")));
        // An object entry with both GUIDs before the SID.
        let user = sid(SOMEONE);
        let mut object = vec![OBJECT, 0, 0, 0];
        object.extend_from_slice(&FULL.to_le_bytes());
        object.extend_from_slice(&3u32.to_le_bytes());
        object.extend_from_slice(&[0xAA; 32]);
        object.extend_from_slice(&user);
        let len = u16::try_from(object.len()).unwrap();
        object[2..4].copy_from_slice(&len.to_le_bytes());
        assert_eq!(judged(ADMINS, Some(&acl(&[object])), FILE), Err(format!("grant {SOMEONE}")));
        // A compound entry cannot be told apart, so a risky one is refused.
        let compound = ace(4, 0, FULL, SYSTEM);
        assert_eq!(judged(ADMINS, Some(&acl(&[compound])), FILE), Err("grant ".into()));
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_program_passes() {
        let windows = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        let notepad = windows.join(r"System32\notepad.exe");
        assert_eq!(check_program_file(&notepad), Ok(()));
    }

    #[cfg(windows)]
    #[test]
    fn a_file_in_the_users_temp_folder_fails() {
        let path = std::env::temp_dir().join(format!("captun-trust-{}.dll", std::process::id()));
        std::fs::write(&path, b"not a program").unwrap();
        let result = check_program_file(&path);
        std::fs::remove_file(&path).unwrap();
        let err = result.unwrap_err();
        // The level nearest the drive that fails is the one said: the user's
        // own folder, or one below it on the way to the file.
        let (UntrustedFile::Owner { path: at, .. } | UntrustedFile::Writable { path: at, .. }) = &err else {
            panic!("{err:?}")
        };
        assert!(path.starts_with(at), "{err:?}");
        // Said in words, with the path as people write it.
        let said = err.to_string();
        assert!(!said.contains(r"\\?\") && said.contains(&*at.to_string_lossy()), "{said}");
        assert!(!said.contains("S-1-5-"), "names the account: {said}");
    }

    #[cfg(windows)]
    #[test]
    fn a_missing_file_fails_cleanly() {
        let path = std::env::temp_dir().join("captun-no-such-file").join("WinDivert.dll");
        assert_eq!(check_program_file(&path), Err(UntrustedFile::Missing { path: path.clone() }));
        assert!(check_program_file(&path).unwrap_err().to_string().ends_with("is missing"));
    }

    /// A reader that finds every level installed like Program Files, but
    /// `link` a link and `someones` owned by someone else, and notes the
    /// order it was asked in.
    #[cfg(windows)]
    fn reader<'a>(
        link: Option<&'a str>,
        someones: Option<&'a str>,
        asked: &'a mut Vec<String>,
    ) -> impl FnMut(&Path) -> std::io::Result<ffi::Security> + 'a {
        move |at| {
            let at = at.to_string_lossy().into_owned();
            let owner = if someones == Some(at.as_str()) { SOMEONE } else { ADMINS };
            let security = ffi::Security { owner: sid(owner), dacl: Some(program_files()), link: link == Some(at.as_str()) };
            asked.push(at);
            Ok(security)
        }
    }

    #[cfg(windows)]
    #[test]
    fn each_level_is_checked_from_the_drive_down() {
        let path = Path::new(r"C:\Program Files\Captun\WinDivert.dll");
        let mut asked = Vec::new();
        assert_eq!(windows::walk(path, reader(None, None, &mut asked)), Ok(()));
        assert_eq!(asked, [r"C:\", r"C:\Program Files", r"C:\Program Files\Captun", r"C:\Program Files\Captun\WinDivert.dll"]);
    }

    #[cfg(windows)]
    #[test]
    fn a_link_anywhere_on_the_path_fails() {
        for at in [r"C:\Program Files", r"C:\Program Files\Captun", r"C:\Program Files\Captun\WinDivert.dll"] {
            let mut asked = Vec::new();
            let result = windows::walk(Path::new(r"C:\Program Files\Captun\WinDivert.dll"), reader(Some(at), None, &mut asked));
            assert_eq!(result, Err(UntrustedFile::Link { path: PathBuf::from(at) }));
            assert_eq!(asked.last().map(String::as_str), Some(at), "nothing below a link is read");
        }
        // The level nearer the drive is the one said, a link below it or not.
        let mut asked = Vec::new();
        let result = windows::walk(
            Path::new(r"C:\Users\x\Captun\WinDivert.dll"),
            reader(Some(r"C:\Users\x\Captun"), Some(r"C:\Users\x"), &mut asked),
        );
        assert!(matches!(result, Err(UntrustedFile::Owner { ref path, .. }) if path == Path::new(r"C:\Users\x")), "{result:?}");
        let message = UntrustedFile::Link { path: PathBuf::from(r"C:\Captun") }.to_string();
        assert_eq!(message, r"C:\Captun is a link to another place");
    }

    #[cfg(windows)]
    #[test]
    fn a_path_not_written_out_in_full_fails() {
        for path in [r"Captun\WinDivert.dll", r"C:\Program Files\x\..\Captun\WinDivert.dll", r"C:\Captun.\WinDivert.dll"] {
            let mut asked = Vec::new();
            let result = windows::walk(Path::new(path), reader(None, None, &mut asked));
            assert!(matches!(result, Err(UntrustedFile::Unreadable { .. })), "{path}: {result:?}");
            assert!(asked.is_empty(), "{path}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn real_paths_are_written_plainly_when_windows_reads_them_back_the_same() {
        assert_eq!(windows::plain(PathBuf::from(r"\\?\C:\Program Files\Captun")), PathBuf::from(r"C:\Program Files\Captun"));
        for kept in [r"\\?\UNC\server\share\Captun", r"\\?\C:\Captun.\x", r"\\?\C:\Captun \x", r"\\?\Volume{1}\Captun"] {
            assert_eq!(windows::plain(PathBuf::from(kept)), PathBuf::from(kept), "{kept}");
        }
        assert_eq!(windows::plain(PathBuf::from(r"C:\x")), PathBuf::from(r"C:\x"));
    }

    /// A junction in the temporary folder to `target`, removed when dropped
    /// (what it leads to stays).
    #[cfg(windows)]
    struct Junction(PathBuf);

    #[cfg(windows)]
    impl Junction {
        fn to(target: &Path, name: &str) -> Option<Self> {
            let link = std::env::temp_dir().join(format!("captun-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir(&link);
            let made = std::process::Command::new(crate::tools::system_tool(r"System32\cmd.exe"))
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&link)
                .arg(target)
                .output()
                .is_ok_and(|out| out.status.success());
            made.then(|| Self(link))
        }
    }

    #[cfg(windows)]
    impl Drop for Junction {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_program_reached_through_a_link_is_checked_where_it_really_is() {
        let windows = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        let system = windows.join("System32");
        let Some(junction) = Junction::to(&system, "trust-link") else { return };
        let real = real_path(&junction.0).unwrap();
        assert!(!real.to_string_lossy().starts_with(r"\\?\"), "{}", real.display());
        assert!(real.to_string_lossy().eq_ignore_ascii_case(&system.to_string_lossy()), "{}", real.display());
        assert_eq!(check_program_file(&real.join("notepad.exe")), Ok(()));
        // Through the link itself, the user's own folders on the way fail.
        assert!(check_program_file(&junction.0.join("notepad.exe")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_name_windows_would_trim_keeps_its_verbatim_path() {
        // Only a `\\?\` path can make a name that ends in a dot.
        let temp = std::env::temp_dir().join(format!("captun-dot-{}.", std::process::id()));
        let temp = temp.to_string_lossy();
        let dotted = PathBuf::from(if temp.starts_with(r"\\?\") { temp.into_owned() } else { format!(r"\\?\{temp}") });
        if std::fs::create_dir(&dotted).is_err() {
            return;
        }
        let real = real_path(&dotted);
        std::fs::remove_dir(&dotted).unwrap();
        let real = real.unwrap();
        assert!(real.to_string_lossy().starts_with(r"\\?\") && real.to_string_lossy().ends_with('.'), "{}", real.display());
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_paths_are_shown_plainly() {
        assert_eq!(windows::shown(Path::new(r"\\?\C:\Program Files\Captun")), PathBuf::from(r"C:\Program Files\Captun"));
        assert_eq!(windows::shown(Path::new(r"\\?\UNC\server\share\x")), PathBuf::from(r"\\server\share\x"));
        assert_eq!(windows::shown(Path::new(r"C:\x")), PathBuf::from(r"C:\x"));
    }

    #[cfg(not(windows))]
    #[test]
    fn other_systems_always_pass() {
        assert_eq!(check_program_file(Path::new("/no/such/file")), Ok(()));
    }
}
