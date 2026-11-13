//! Per-OS details of running the Xray child: no console window and low
//! integrity on Windows, no root on Linux and macOS (the user who started
//! Captun, else `nobody`), and dying with the service where the OS can
//! arrange it (a kill-on-close job object on Windows, the parent-death signal
//! on Linux).

use std::{path::Path, process::Stdio, time::Duration};

use tokio::{process::Command, time::timeout};

/// Asks the program for its version ("Xray 26.10.21 (…)" → "26.10.21").
pub(crate) async fn version(binary: &Path, run_as: Option<u32>) -> Option<String> {
    let mut command = Command::new(binary);
    command.arg("version").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    harden(&mut command, run_as);
    crate::allow_run(binary).ok()?;
    let output = timeout(Duration::from_secs(5), command.output()).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next()?;
    let version = first.strip_prefix("Xray ")?.split_whitespace().next()?;
    Some(version.to_owned())
}

/// The account Xray runs as when the service runs as root and nobody in
/// particular started it (a system service): `nobody`.
#[cfg(target_os = "linux")]
const NOBODY: (u32, u32) = (65534, 65534);
#[cfg(target_os = "macos")]
const NOBODY: (u32, u32) = (u32::MAX - 1, u32::MAX - 1);

/// `run_as` is the user who started Captun, if known: Xray runs as them,
/// so it can always reach its own program (which may sit in their home
/// folder in a development build) yet holds no more rights than they do.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(unused_variables))]
pub(crate) fn harden(command: &mut Command, run_as: Option<u32>) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Xray parses data from remote servers; it needs no privileges to
        // listen on loopback and dial out, so it does not get them.
        if nix::unistd::geteuid().is_root() {
            let uid = run_as.filter(|uid| *uid != 0).unwrap_or(NOBODY.0);
            let gid = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
                .ok()
                .flatten()
                .map_or(NOBODY.1, |user| user.gid.as_raw());
            command.uid(uid).gid(gid);
        }
    }
    #[cfg(target_os = "linux")]
    {
        #[allow(unsafe_code)]
        // SAFETY: the closure runs in the forked child before exec and only
        // calls prctl(2), which is async-signal-safe and allocates nothing.
        unsafe {
            command.pre_exec(|| {
                nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL).map_err(std::io::Error::from)
            });
        }
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let _ = command;
}

/// Marks the program file so that Windows starts it at low integrity,
/// whoever starts it: a new process gets the lower of its parent's level and
/// its program file's. The service runs as an administrator; Xray started so
/// keeps the network and can read what the service can, but can write almost
/// nothing (no file in System32, Program Files, ProgramData or the user's
/// folders), whatever its settings say. They are checked as well
/// (`captun_core::link::xray_settings_problem`), as reading still works and a
/// network path would still make Windows sign in to it as the user. The mark
/// is the file's mandatory label: setting one no higher than the service's
/// own level needs only WRITE_OWNER on the file, which administrators hold on
/// Captun's program folder. It is set before every start, so a program file
/// put in place since has it too.
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn lower_integrity(program: &Path) -> std::io::Result<()> {
    use std::{
        io,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        ptr,
    };

    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
            LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetKernelObjectSecurity,
        },
        Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_OWNER},
    };

    // Low integrity; below it, nothing may write the file itself either.
    const LOW: &str = "S:(ML;;NW;;;LW)";
    // The file itself, followed through any link, as that is what runs.
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_OWNER)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(program)?;
    let wide: Vec<u16> = LOW.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and outlives the call, which allocates
    // the descriptor with LocalAlloc on success.
    let made = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), SDDL_REVISION_1, &mut descriptor, ptr::null_mut())
    };
    if made == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle opened with WRITE_OWNER, borrowed for the call, and the
    // valid descriptor made above, which the call copies.
    let set = unsafe { SetKernelObjectSecurity(file.as_raw_handle(), LABEL_SECURITY_INFORMATION, descriptor) };
    let result = if set == 0 { Err(io::Error::last_os_error()) } else { Ok(()) };
    // SAFETY: allocated above by ConvertStringSecurityDescriptorToSecurityDescriptorW,
    // and freed once.
    unsafe { LocalFree(descriptor) };
    result
}

/// Whether this process has an administrator's full rights (UAC-elevated,
/// as the service is) or SYSTEM's. Not knowing counts as yes.
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn elevated() -> bool {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: this process's pseudo-handle, and an out-pointer to a live local.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return true;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut written = 0u32;
    // SAFETY: a token opened for query, and a live TOKEN_ELEVATION whose exact
    // size is passed.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut written,
        )
    };
    // SAFETY: opened above, and closed once.
    unsafe { CloseHandle(token) };
    ok == 0 || elevation.TokenIsElevated != 0
}

/// Checks that only an administrator can have put the program there: a
/// service with full rights must not run a file other users could swap.
#[cfg(unix)]
pub(crate) fn trusted(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match path.metadata() {
        Ok(meta) => {
            let owner_ok = meta.uid() == 0 || meta.uid() == nix::unistd::geteuid().as_raw();
            meta.is_file() && owner_ok && meta.mode() & 0o022 == 0 && crate::check_program(path).is_ok()
        }
        Err(_) => false,
    }
}

/// On Windows the program is only looked for next to the service. Nothing
/// here can tell who may change that folder: the all-users installer makes it
/// administrators-only, and the check the service registers
/// ([`crate::set_program_check`]) refuses a program in a folder other
/// accounts can change, here and again before every start. Without one
/// (tests, development builds) any file there is used.
#[cfg(not(unix))]
pub(crate) fn trusted(path: &Path) -> bool {
    path.is_file() && crate::check_program(path).is_ok()
}

#[cfg(windows)]
pub(crate) use job::Job;

#[cfg(windows)]
#[allow(unsafe_code)]
mod job {
    use std::{ffi::c_void, io, mem, ptr};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
        },
    };

    /// A job object that kills every process in it when its last handle
    /// closes, which happens when the service exits for any reason.
    #[derive(Debug)]
    pub(crate) struct Job(HANDLE);

    // SAFETY: a job handle is a kernel object reference usable from any thread.
    unsafe impl Send for Job {}
    // SAFETY: the job functions used here are thread-safe on a shared handle.
    unsafe impl Sync for Job {}

    impl Job {
        pub(crate) fn kill_on_close() -> io::Result<Self> {
            // SAFETY: null security attributes and name are documented as valid.
            let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Self(handle);
            // SAFETY: the struct is plain data for which all-zero is a valid value.
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `info` is live for the call and its exact size is passed.
            let ok = unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                    mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        pub(crate) fn assign(&self, process: std::os::windows::io::RawHandle) -> io::Result<()> {
            // SAFETY: both handles are valid; `process` belongs to a live child we own.
            let ok = unsafe { AssignProcessToJobObject(self.0, process as HANDLE) };
            if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: the handle came from CreateJobObjectW and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A copy of `whoami.exe`, marked, says it runs at low integrity, whatever
    /// the level of the test that starts it.
    #[test]
    fn a_marked_program_starts_at_low_integrity() {
        let windows = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        let dir = std::env::temp_dir().join(format!("captun-xray-low-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("whoami.exe");
        std::fs::copy(windows.join("System32").join("whoami.exe"), &program).unwrap();

        lower_integrity(&program).unwrap();
        lower_integrity(&program).unwrap();
        let out = std::process::Command::new(&program).arg("/groups").output().unwrap();
        let groups = String::from_utf8_lossy(&out.stdout);
        // The levels' SIDs, which read the same in every language: low,
        // medium, high, system.
        assert!(groups.contains("S-1-16-4096"), "not at low integrity:\n{groups}");
        for higher in ["S-1-16-8192", "S-1-16-12288", "S-1-16-16384"] {
            assert!(!groups.contains(higher), "{higher}:\n{groups}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
