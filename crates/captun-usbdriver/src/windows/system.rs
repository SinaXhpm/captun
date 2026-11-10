//! Small things asked of Windows: whether this process runs elevated, the
//! Windows folder, random bytes, a folder only SYSTEM and Administrators can
//! change, and the lock that lets one install or removal run at a time.

use std::{
    ffi::{OsStr, c_void},
    fs, io,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
};

use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, LocalFree, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Security::{
            Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
            Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
            GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
            TokenElevation,
        },
        Storage::FileSystem::CreateDirectoryW,
        System::{
            SystemInformation::GetSystemWindowsDirectoryW,
            Threading::{CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject},
        },
    },
    core::{PCWSTR, w},
};

/// Owned by Administrators; SYSTEM and Administrators may do anything, no
/// one else anything at all, and nothing comes from the folder above.
const PRIVATE: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The lock's name, in the namespace every session shares.
const LOCK_NAME: PCWSTR = w!(r"Global\CaptunUsbDriver");
/// Only SYSTEM and Administrators may use the lock.
const LOCK: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
/// How long an install or removal waits for another to finish.
const LOCK_WAIT_MS: u32 = 120_000;

/// Whether this process runs with its administrator rights in force.
pub(super) fn is_elevated() -> io::Result<bool> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
    // closing; `token` is a valid place for the handle written.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(token);
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut written = 0u32;
    // SAFETY: `token` is open with query access; `elevation` is a writable
    // TOKEN_ELEVATION of exactly the size passed.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&raw mut elevation).cast::<c_void>(),
            size_u32::<TOKEN_ELEVATION>(),
            &mut written,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(elevation.TokenIsElevated != 0)
}

/// The Windows folder as Windows reports it (not from the environment, which
/// an elevated process takes from the user who started it).
pub(super) fn windows_folder() -> io::Result<PathBuf> {
    let mut buf = vec![0u16; 260];
    // The second try has the room the first asked for.
    for _ in 0..2 {
        let size = u32::try_from(buf.len()).map_err(io::Error::other)?;
        // SAFETY: `buf` is live and writable for `size` UTF-16 units, and the
        // call writes no more than that.
        let len = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), size) } as usize;
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if len < buf.len() {
            buf.truncate(len);
            return Ok(PathBuf::from(String::from_utf16(&buf).map_err(io::Error::other)?));
        }
        // Too small: `len` is the room needed, the closing NUL included.
        buf.resize(len, 0);
    }
    Err(io::Error::other("Windows did not say where its folder is"))
}

/// A new folder with a random name in the Windows folder's `Temp`, whose
/// owner and permissions (see [`PRIVATE`]) are set in the call that makes
/// it, so no one else can put a file in it or change one at any moment. No
/// one but administrators may rename or delete what others made in that
/// `Temp`, so the path keeps naming this folder. Removed when dropped.
#[derive(Debug)]
pub(super) struct PrivateFolder(PathBuf);

impl PrivateFolder {
    pub(super) fn new() -> io::Result<Self> {
        let temp = windows_folder()?.join("Temp");
        for _ in 0..4 {
            let path = temp.join(format!("captun-usb-driver-{}", random_hex(8)?));
            match create_folder(&path, PRIVATE) {
                Ok(()) => return Ok(Self(path)),
                // Someone made one by that name first: never use theirs.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "every folder name tried was taken"))
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateFolder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `bytes` random bytes from Windows' own generator, in hex.
pub(super) fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; bytes];
    let len = u32::try_from(buf.len()).map_err(io::Error::other)?;
    // SAFETY: `buf` is writable for `len` bytes; no algorithm handle is
    // needed with the system's preferred generator.
    let status = unsafe { BCryptGenRandom(ptr::null_mut(), buf.as_mut_ptr(), len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status != 0 {
        return Err(io::Error::other(format!("Windows gave no random bytes (status {status:#x})")));
    }
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Makes a folder with the owner and permissions in `sddl` from the start.
/// Fails if anything is already there, a link included.
fn create_folder(path: &Path, sddl: &str) -> io::Result<()> {
    let path = wide(path.as_os_str())?;
    let descriptor = Descriptor::from_sddl(sddl)?;
    let attributes = descriptor.attributes();
    // SAFETY: `path` is a NUL-terminated UTF-16 string; `attributes` and the
    // descriptor it points to stay alive for the call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The machine-wide lock that keeps two installs or removals (the
/// installer's and the service's) from running at once: each would make a
/// certificate of its own, and one would go unnoted. Only SYSTEM and
/// Administrators may open it, and standard users cannot make global
/// objects, so no one else can hold it. Released on drop, by the thread that
/// took it (a raw handle keeps it on that thread).
#[derive(Debug)]
pub(super) struct Exclusive(Handle);

impl Exclusive {
    pub(super) fn take() -> io::Result<Self> {
        let descriptor = Descriptor::from_sddl(LOCK)?;
        let attributes = descriptor.attributes();
        // SAFETY: `attributes` and its descriptor stay alive for the call;
        // the name is a static NUL-terminated string; not taken at once.
        let mutex = unsafe { CreateMutexW(&attributes, 0, LOCK_NAME) };
        if mutex.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mutex = Handle(mutex);
        // SAFETY: a mutex handle just opened with full access.
        match unsafe { WaitForSingleObject(mutex.0, LOCK_WAIT_MS) } {
            // Abandoned: whoever held it stopped part way, and what it left
            // is found through what it noted.
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(mutex)),
            WAIT_TIMEOUT => {
                Err(io::Error::new(io::ErrorKind::TimedOut, "another install or removal of the driver did not finish"))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl Drop for Exclusive {
    fn drop(&mut self) {
        // SAFETY: this thread took the mutex in `take`.
        unsafe { ReleaseMutex(self.0.0) };
    }
}

/// A security descriptor made from SDDL, freed on drop.
struct Descriptor(Local);

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl = wide(OsStr::new(sddl))?;
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string that outlives the
        // call; `descriptor` is a valid place for the pointer written; the
        // size out-pointer may be null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(Local(descriptor)))
    }

    /// Attributes for a new object with this descriptor; valid while `self` is.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_u32::<SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        }
    }
}

/// `text` as a NUL-terminated UTF-16 string; one with a NUL inside would
/// name something else.
pub(super) fn wide(text: &OsStr) -> io::Result<Vec<u16>> {
    let mut units: Vec<u16> = text.encode_wide().collect();
    if units.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a name with a NUL character in it"));
    }
    units.push(0);
    Ok(units)
}

/// The text in `units` up to the first NUL.
pub(super) fn from_wide(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// The size of `T` for a Windows call that wants it as a 32-bit count; the
/// structures passed here are a few dozen bytes.
pub(super) const fn size_u32<T>() -> u32 {
    size_of::<T>() as u32
}

/// A kernel handle, closed on drop.
#[derive(Debug)]
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this module and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Memory Windows handed out to be freed with `LocalFree`; freed on drop.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Windows call whose result is to
            // be freed with LocalFree, and this is the only place it is freed.
            unsafe { LocalFree(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_windows_folder_and_random_names_come_from_windows() {
        let windows = windows_folder().unwrap();
        assert!(windows.join("System32").is_dir(), "{}", windows.display());
        let (a, b) = (random_hex(8).unwrap(), random_hex(8).unwrap());
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        assert!(is_elevated().is_ok());
    }

    #[test]
    fn names_with_a_nul_are_refused() {
        assert!(wide(OsStr::new("a\0b")).is_err());
        assert_eq!(wide(OsStr::new("ab")).unwrap(), [u16::from(b'a'), u16::from(b'b'), 0]);
        assert_eq!(from_wide(&[u16::from(b'a'), 0, u16::from(b'b')]), "a");
    }
}
