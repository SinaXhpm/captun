//! Named pipe (Windows) / Unix domain socket transport. The pipe gets an
//! explicit DACL; the Unix socket is world-connectable but useless without the
//! token, which lives in a file only the GUI's user can read.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Duplex for T {}

pub type IpcStream = Box<dyn Duplex>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint(String);

impl Endpoint {
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// Where the service listens unless told otherwise.
    pub fn default_service() -> Self {
        #[cfg(windows)]
        let path = r"\\.\pipe\captun";
        // macOS has no /run; its /var/run is root-owned like Linux's /run.
        #[cfg(target_os = "macos")]
        let path = "/var/run/captun/captun.sock";
        #[cfg(all(unix, not(target_os = "macos")))]
        let path = "/run/captun/captun.sock";
        Self(path.into())
    }

    /// Where the service listened when Captun was called OmniHub. A service
    /// from then may still be running: Captun's own name says nothing about it.
    pub fn earlier_service() -> Self {
        #[cfg(windows)]
        let path = r"\\.\pipe\omnihub";
        #[cfg(target_os = "macos")]
        let path = "/var/run/omnihub/omnihub.sock";
        #[cfg(all(unix, not(target_os = "macos")))]
        let path = "/run/omnihub/omnihub.sock";
        Self(path.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a service listens here now. Nothing is sent: on Windows the
    /// pipe is not even opened (so its permissions do not matter); on Unix a
    /// connection is made and closed at once, and a socket file a stopped
    /// service left behind does not count.
    pub fn is_in_use(&self) -> bool {
        #[cfg(windows)]
        return windows::pipe_exists(self.as_str());
        #[cfg(unix)]
        return std::os::unix::net::UnixStream::connect(self.as_str()).is_ok();
    }
}

/// Who, besides SYSTEM and Administrators, may open the service pipe.
/// Ignored on Unix, where the token alone gates access.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PipeAccess {
    /// Anyone logged on interactively.
    #[default]
    InteractiveUsers,
    /// One account, by SID (`S-1-5-21-…`), normally the user who launched the GUI.
    User(String),
}

#[derive(Debug)]
pub struct IpcListener {
    #[cfg(windows)]
    inner: windows::Listener,
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
}

impl IpcListener {
    pub fn bind(endpoint: &Endpoint, #[allow(unused_variables)] access: &PipeAccess) -> io::Result<Self> {
        #[cfg(windows)]
        let inner = windows::Listener::bind(endpoint.as_str(), access)?;
        #[cfg(unix)]
        let inner = unix::bind(endpoint.as_str())?;
        Ok(Self { inner })
    }

    pub async fn accept(&mut self) -> io::Result<IpcStream> {
        #[cfg(windows)]
        let stream = self.inner.accept().await?;
        #[cfg(unix)]
        let (stream, _) = self.inner.accept().await?;
        Ok(Box::new(stream))
    }
}

pub async fn connect(endpoint: &Endpoint) -> io::Result<IpcStream> {
    #[cfg(windows)]
    let stream = windows::connect(endpoint.as_str()).await?;
    #[cfg(unix)]
    let stream = tokio::net::UnixStream::connect(endpoint.as_str()).await?;
    Ok(Box::new(stream))
}

#[cfg(unix)]
mod unix {
    use std::{fs, io, os::unix::fs::PermissionsExt, path::Path};

    use tokio::net::UnixListener;

    pub(super) fn bind(path: &str) -> io::Result<UnixListener> {
        let path = Path::new(path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        Ok(listener)
    }
}

#[cfg(windows)]
pub use windows::{create_dir_with_sddl, enforce_redirection_trust, open_for_security, owner_sid_of, protect};
#[cfg(windows)]
pub(crate) use windows::{create_file_with_sddl, secret_file_sddl};
#[cfg(all(windows, test))]
pub(crate) use windows::file_dacl;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::{
        fs::File,
        io,
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawHandle, FromRawHandle},
        },
        path::Path,
        ptr,
        time::{Duration, Instant},
    };

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions};
    use windows_sys::{
        Win32::{
            Foundation::{
                BOOL, ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT, ERROR_SUCCESS, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
            },
            Security::{
                ACL,
                Authorization::{
                    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                    SDDL_REVISION_1, SE_FILE_OBJECT,
                },
                DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
                GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
                PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SetKernelObjectSecurity,
            },
            Storage::FileSystem::{
                CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
                FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
            },
            System::{
                Pipes::WaitNamedPipeW,
                Threading::{ProcessRedirectionTrustPolicy, SetProcessMitigationPolicy},
            },
        },
        core::PWSTR,
    };

    use super::PipeAccess;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Copies a string Windows allocated with LocalAlloc, then frees it.
    ///
    /// # Safety
    /// `text` is a NUL-terminated string from LocalAlloc that nothing else
    /// frees.
    unsafe fn take_local_string(text: PWSTR) -> String {
        // SAFETY: `text` is NUL-terminated, so scanning to the terminator
        // stays inside it.
        let copied = unsafe {
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
        };
        // SAFETY: allocated with LocalAlloc (the caller's promise), freed
        // exactly once.
        unsafe { LocalFree(text.cast()) };
        copied
    }

    /// FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_CREATE_PIPE_INSTANCE,
    /// so the GUI's user can talk to the pipe but never host a rogue instance.
    const CLIENT_RIGHTS: &str = "0x12019b";

    /// A SID as text (`S-1-…`): digits and dashes only, so it can never close
    /// its entry in an SDDL string and add another.
    fn checked_sid(sid: &str) -> io::Result<&str> {
        let well_formed = sid.starts_with("S-1-") && sid[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-');
        if well_formed { Ok(sid) } else { Err(io::Error::new(io::ErrorKind::InvalidInput, format!("malformed SID {sid:?}"))) }
    }

    fn sddl(access: &PipeAccess) -> io::Result<String> {
        let trustee = match access {
            PipeAccess::InteractiveUsers => "IU",
            PipeAccess::User(sid) => checked_sid(sid)?,
        };
        // Protected DACL: no inherited entries, nothing for network logons.
        // OW (owner rights) is the account that created the pipe, which needs
        // FILE_CREATE_PIPE_INSTANCE to open further instances even when it is
        // not an elevated administrator (development runs, tests).
        Ok(format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;{CLIENT_RIGHTS};;;{trustee})"))
    }

    /// A protected DACL for a file holding a secret: SYSTEM and Administrators
    /// in full, `reader` (a SID) to read only, and nothing inherited from the
    /// folder, whose entries may let every user read.
    pub(crate) fn secret_file_sddl(reader: Option<&str>) -> io::Result<String> {
        const OWNERS: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
        Ok(match reader {
            Some(sid) => format!("{OWNERS}(A;;FR;;;{})", checked_sid(sid)?),
            None => OWNERS.to_owned(),
        })
    }

    /// Creates `path` as a new file with `sddl` as its security from the first
    /// moment, open for writing and shared with no one until closed. Fails if
    /// anything is there already, a link included (it is not followed), so a
    /// planted file or link is never reused.
    pub(crate) fn create_file_with_sddl(path: &Path, sddl: &str) -> io::Result<File> {
        let descriptor = SecurityDescriptor::from_sddl(sddl)?;
        let attributes = descriptor.attributes();
        let wide = wide(path);
        // SAFETY: `wide` is NUL-terminated and `attributes`, with the
        // descriptor it points to, outlives the call; CreateFileW copies the
        // descriptor into the new file.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
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
        // SAFETY: a valid file handle that nothing else owns; the File closes it.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    /// Creates the folder `path` with `sddl` as its security from the first
    /// moment. Fails if anything is there already (`AlreadyExists`), a folder
    /// or a link alike, so one planted before the service ran is never taken
    /// for its own. An owner in `sddl` must be one the caller may assign.
    pub fn create_dir_with_sddl(path: &Path, sddl: &str) -> io::Result<()> {
        let descriptor = SecurityDescriptor::from_sddl(sddl)?;
        let attributes = descriptor.attributes();
        let wide = wide(path);
        // SAFETY: `wide` is NUL-terminated and `attributes`, with the
        // descriptor it points to, outlives the call, which copies it.
        let ok = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Opens the file or folder at `path` itself to read and change its
    /// security: never through a link, and a link there is refused, so what
    /// [`owner_sid_of`] and [`protect`] see is the object at that name.
    pub fn open_for_security(path: &Path) -> io::Result<File> {
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | WRITE_OWNER)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            // Backup semantics is what lets a folder be opened at all.
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is a link", path.display())));
        }
        Ok(file)
    }

    /// The owner of the open file or folder, as a SID (`S-1-5-18` for
    /// SYSTEM, `S-1-5-32-544` for Administrators). Read through the handle,
    /// so a rename or a link swapped in under its name cannot change the
    /// answer. The handle needs READ_CONTROL.
    pub fn owner_sid_of(file: &File) -> io::Result<String> {
        let mut owner: PSID = ptr::null_mut();
        let mut raw: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: a valid handle, borrowed for the call; on success `owner`
        // points into `raw`, a LocalAlloc'ed descriptor owned (and freed) by
        // the wrapper below, which outlives every use of `owner`.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut raw,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _descriptor = SecurityDescriptor(raw);
        if owner.is_null() {
            return Err(io::Error::other("it has no owner"));
        }
        let mut text: PWSTR = ptr::null_mut();
        // SAFETY: `owner` is a valid SID inside the live descriptor; on
        // success `text` is a LocalAlloc'ed, NUL-terminated string.
        if unsafe { ConvertSidToStringSidW(owner, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as just described, and freed nowhere else.
        Ok(unsafe { take_local_string(text) })
    }

    /// Gives the open file or folder the owner and protected DACL in `sddl`,
    /// which must have both. Only that one object changes: unlike
    /// SetSecurityInfo, SetKernelObjectSecurity never walks into a folder to
    /// rewrite what is in it, so nothing inside is touched or followed. The
    /// handle needs WRITE_OWNER and WRITE_DAC ([`open_for_security`]).
    pub fn protect(file: &File, sddl: &str) -> io::Result<()> {
        let descriptor = SecurityDescriptor::from_sddl(sddl)?;
        if !descriptor.has_owner_and_protected_dacl()? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{sddl:?} needs an owner (O:) and a protected list of who may use it (D:P)"),
            ));
        }
        // SAFETY: a valid handle, borrowed for the call, and a valid
        // descriptor that the call copies.
        let ok = unsafe {
            SetKernelObjectSecurity(
                file.as_raw_handle(),
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Makes this process refuse to follow junctions and other mount points
    /// that a non-administrator created (Redirection Guard), so a planted
    /// junction cannot steer the service's file work into other folders.
    /// Older Windows versions, which lack it, return an error,
    /// which callers ignore: the folder checks do not depend on it.
    pub fn enforce_redirection_trust() -> io::Result<()> {
        // PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY is one DWORD of flag
        // bits; bit 0 is EnforceRedirectionTrust. A plain u32 spares a
        // windows-sys feature for a one-field union.
        let policy: u32 = 1;
        // SAFETY: points at a live DWORD of the length given, which the call
        // only reads.
        let ok = unsafe {
            SetProcessMitigationPolicy(
                ProcessRedirectionTrustPolicy,
                (&policy as *const u32).cast(),
                std::mem::size_of::<u32>(),
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// The DACL of the file or folder at `path`, as SDDL, as it is stored.
    /// GetNamedSecurityInfoW is not used: for a DACL without the
    /// auto-inherited flag it compares the entries marked inherited with the
    /// parent's and, where they differ, reports them as the object's own.
    #[cfg(test)]
    pub(crate) fn file_dacl(path: &Path) -> io::Result<String> {
        use windows_sys::Win32::Security::{
            Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW, GetFileSecurityW,
        };

        let wide = wide(path);
        let mut needed = 0u32;
        // SAFETY: `wide` is NUL-terminated; with no buffer the call only
        // reports the size it needs.
        unsafe { GetFileSecurityW(wide.as_ptr(), DACL_SECURITY_INFORMATION, ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64s keep the descriptor aligned.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buffer` holds at least `needed` bytes and outlives the call.
        let ok = unsafe {
            GetFileSecurityW(wide.as_ptr(), DACL_SECURITY_INFORMATION, buffer.as_mut_ptr().cast(), needed, &mut needed)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut text: PWSTR = ptr::null_mut();
        // SAFETY: `buffer` holds a valid self-relative descriptor; on success
        // `text` is a LocalAlloc'ed, NUL-terminated string, freed below.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                buffer.as_mut_ptr().cast(),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: allocated by the conversion above and freed nowhere else.
        Ok(unsafe { take_local_string(text) })
    }

    #[derive(Debug)]
    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is a self-contained heap block that is never
    // mutated after creation and is freed exactly once in Drop.
    unsafe impl Send for SecurityDescriptor {}
    unsafe impl Sync for SecurityDescriptor {}

    impl SecurityDescriptor {
        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: `wide` is NUL-terminated and outlives the call; the
            // function allocates the descriptor with LocalAlloc on success.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            };
            if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(Self(descriptor)) }
        }

        /// Attributes that hand this descriptor to a create call; valid
        /// while `self` lives.
        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            }
        }

        /// Whether it names an owner and has a protected DACL. A missing
        /// (null) DACL would let everyone in, so it does not count.
        fn has_owner_and_protected_dacl(&self) -> io::Result<bool> {
            let (mut owner, mut defaulted): (PSID, BOOL) = (ptr::null_mut(), 0);
            let (mut present, mut dacl): (BOOL, *mut ACL) = (0, ptr::null_mut());
            let (mut control, mut revision) = (0u16, 0u32);
            // SAFETY: a valid descriptor and out-pointers to live locals; the
            // pointers returned point into the descriptor and are only
            // tested for null here.
            let ok = unsafe {
                GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) != 0
                    && GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) != 0
                    && GetSecurityDescriptorControl(self.0, &mut control, &mut revision) != 0
            };
            if !ok {
                return Err(io::Error::last_os_error());
            }
            Ok(!owner.is_null() && present != 0 && !dacl.is_null() && control & SE_DACL_PROTECTED != 0)
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: allocated with LocalAlloc, by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW or
            // GetSecurityInfo.
            unsafe { LocalFree(self.0) };
        }
    }

    #[derive(Debug)]
    pub(super) struct Listener {
        name: String,
        descriptor: SecurityDescriptor,
        next: NamedPipeServer,
    }

    impl Listener {
        pub(super) fn bind(name: &str, access: &PipeAccess) -> io::Result<Self> {
            let descriptor = SecurityDescriptor::from_sddl(&sddl(access)?)?;
            // `first_pipe_instance` makes startup fail if someone else already
            // owns the name, instead of silently sharing it with a squatter.
            let next = create(name, &descriptor, true)?;
            Ok(Self { name: name.to_owned(), descriptor, next })
        }

        pub(super) async fn accept(&mut self) -> io::Result<NamedPipeServer> {
            self.next.connect().await?;
            let fresh = create(&self.name, &self.descriptor, false)?;
            Ok(std::mem::replace(&mut self.next, fresh))
        }
    }

    fn create(name: &str, descriptor: &SecurityDescriptor, first: bool) -> io::Result<NamedPipeServer> {
        let mut attributes = descriptor.attributes();
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES whose descriptor
        // outlives this call; CreateNamedPipeW copies what it needs.
        unsafe { options.create_with_security_attributes_raw(name, (&mut attributes as *mut SECURITY_ATTRIBUTES).cast()) }
    }

    /// Whether a server holds the pipe `name`. WaitNamedPipeW asks the pipe
    /// system itself, without opening the pipe or taking an instance from its
    /// server, and returns at once when there is no such pipe.
    pub(super) fn pipe_exists(name: &str) -> bool {
        let wide_name = wide(Path::new(name));
        // SAFETY: `wide_name` is NUL-terminated and outlives the call; the
        // timeout is 1 ms (0 would mean the server's default wait).
        if unsafe { WaitNamedPipeW(wide_name.as_ptr(), 1) } != 0 {
            return true;
        }
        // Every instance busy with a client still means a server is there.
        io::Error::last_os_error().raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32)
    }

    pub(super) async fn connect(name: &str) -> io::Result<NamedPipeClient> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match ClientOptions::new().open(name) {
                Ok(client) => return Ok(client),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sddl_restricts_trustee() {
            assert!(sddl(&PipeAccess::InteractiveUsers).unwrap().ends_with(";;;IU)"));
            assert!(sddl(&PipeAccess::User("S-1-5-21-1-2-3-1001".into())).is_ok());
            assert!(sddl(&PipeAccess::User("S-1-5-21)(A;;GA;;;WD".into())).is_err(), "SDDL injection");
            SecurityDescriptor::from_sddl(&sddl(&PipeAccess::InteractiveUsers).unwrap()).unwrap();
        }

        #[test]
        fn a_secret_file_is_for_system_administrators_and_one_reader() {
            assert_eq!(secret_file_sddl(None).unwrap(), "D:P(A;;FA;;;SY)(A;;FA;;;BA)");
            assert_eq!(
                secret_file_sddl(Some("S-1-5-21-1-2-3-1001")).unwrap(),
                "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;S-1-5-21-1-2-3-1001)"
            );
            assert!(secret_file_sddl(Some("S-1-5-21)(A;;FA;;;WD")).is_err(), "SDDL injection");
            assert!(secret_file_sddl(Some("BU")).is_err(), "aliases name whole groups");
            SecurityDescriptor::from_sddl(&secret_file_sddl(Some("S-1-1-0")).unwrap()).unwrap();
        }

        #[test]
        fn a_new_file_gets_its_dacl_and_nothing_existing_is_reused() {
            use std::io::Write;

            let dir = std::env::temp_dir().join(format!("captun-sddl-file-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("secret");
            let sddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)";

            create_file_with_sddl(&path, sddl).unwrap().write_all(b"secret").unwrap();
            assert_eq!(file_dacl(&path).unwrap(), sddl);
            assert_eq!(std::fs::read(&path).unwrap(), b"secret");
            // Already there: refused, and left as it was.
            assert!(create_file_with_sddl(&path, sddl).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"secret");

            // A link planted at the name is not followed (creating one needs
            // Developer Mode or elevation; without, there is nothing to test).
            let (link, target) = (dir.join("link"), dir.join("target"));
            if std::os::windows::fs::symlink_file(&target, &link).is_ok() {
                assert!(create_file_with_sddl(&link, sddl).is_err());
                assert!(!target.exists(), "the link's target was not created");
            }
            let _ = std::fs::remove_dir_all(dir);
        }

        /// A fresh scratch folder under %TEMP%, and the owner this process
        /// gives what it creates (its user, or Administrators when elevated),
        /// which it may always assign.
        fn scratch(name: &str) -> (std::path::PathBuf, String) {
            let dir = std::env::temp_dir().join(format!("captun-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let me = owner_sid_of(&File::create(dir.join("probe")).unwrap()).unwrap();
            assert!(me.starts_with("S-1-"), "{me}");
            (dir, me)
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

        // Owner rights (OW) let whoever owns it delete it afterwards.
        const FOLDER_DACL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)";

        #[test]
        fn a_new_folder_gets_its_security_and_nothing_existing_is_reused() {
            let (dir, me) = scratch("sddl-dir");
            let sddl = format!("O:{me}{FOLDER_DACL}");

            let made = dir.join("made");
            create_dir_with_sddl(&made, &sddl).unwrap();
            assert!(made.is_dir());
            assert_eq!(file_dacl(&made).unwrap(), FOLDER_DACL);
            assert_eq!(owner_sid_of(&open_for_security(&made).unwrap()).unwrap(), me);

            // Already there, made by us or anyone else: refused, left as it was.
            let error = create_dir_with_sddl(&made, &sddl).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            let planted = dir.join("planted");
            std::fs::create_dir(&planted).unwrap();
            let before = file_dacl(&planted).unwrap();
            assert_eq!(create_dir_with_sddl(&planted, &sddl).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(file_dacl(&planted).unwrap(), before);

            // A junction planted at the name is neither reused nor followed.
            let (link, target) = (dir.join("link"), dir.join("target"));
            std::fs::create_dir(&target).unwrap();
            if junction(&link, &target) {
                assert_eq!(create_dir_with_sddl(&link, &sddl).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
                let refused = open_for_security(&link).unwrap_err();
                assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{refused}");
                std::fs::remove_dir(&link).unwrap();
            } else {
                eprintln!("no junction could be made; that part is not checked");
            }

            assert!(create_dir_with_sddl(&dir.join("bad"), "D:P(nonsense)").is_err());
            assert!(!dir.join("bad").exists());
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn protect_changes_that_folder_alone() {
            let (dir, me) = scratch("sddl-protect");
            let folder = dir.join("folder");
            std::fs::create_dir(&folder).unwrap();
            let inside = folder.join("inside");
            std::fs::write(&inside, b"x").unwrap();
            // Not the folder's new entries: had they been passed down (as
            // SetSecurityInfo does), they would show here.
            let inside_before = file_dacl(&inside).unwrap();
            assert!(!inside_before.contains("OW)"), "{inside_before}");

            let handle = open_for_security(&folder).unwrap();
            protect(&handle, &format!("O:{me}{FOLDER_DACL}")).unwrap();
            assert_eq!(file_dacl(&folder).unwrap(), FOLDER_DACL);
            assert_eq!(owner_sid_of(&handle).unwrap(), me);
            // What is inside keeps what it had: nothing was walked or redone.
            assert_eq!(file_dacl(&inside).unwrap(), inside_before);

            // An owner and a protected DACL, or nothing changes.
            for half in [
                FOLDER_DACL.to_owned(),
                format!("O:{me}D:(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)"),
                format!("O:{me}D:NO_ACCESS_CONTROL"),
                format!("O:{me}"),
            ] {
                let refused = protect(&handle, &half).unwrap_err();
                assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{half}: {refused}");
            }
            assert_eq!(file_dacl(&folder).unwrap(), FOLDER_DACL);

            // A handle without the rights to change it is refused by Windows.
            let read_only = std::fs::OpenOptions::new()
                .access_mode(READ_CONTROL)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(&folder)
                .unwrap();
            assert_eq!(owner_sid_of(&read_only).unwrap(), me);
            assert!(protect(&read_only, &format!("O:{me}D:P(A;OICI;FA;;;WD)")).is_err());
            assert_eq!(file_dacl(&folder).unwrap(), FOLDER_DACL);

            drop((handle, read_only));
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn a_plain_file_is_opened_for_security_too() {
            let (dir, me) = scratch("sddl-open");
            let file = dir.join("file");
            std::fs::write(&file, b"x").unwrap();
            assert_eq!(owner_sid_of(&open_for_security(&file).unwrap()).unwrap(), me);
            assert_eq!(open_for_security(&dir.join("missing")).unwrap_err().kind(), io::ErrorKind::NotFound);
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
