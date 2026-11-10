//! Per-OS details of running the Xray child: no console window on Windows,
//! no root on Linux and macOS (the user who started Captun, else
//! `nobody`), and dying with the service where the OS can
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
