//! Windows' devices and driver store: the phones' USB debugging (ADB)
//! interfaces plugged in now, giving one with no driver the best driver
//! Windows keeps, and adding the package to, or taking it out of, the
//! driver store.

use std::{
    ffi::c_void,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    ptr,
};

use tracing::{debug, warn};
use windows_sys::{
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            CM_Get_DevNode_Status, CMP_WaitNoPendingInstallEvents, CR_SUCCESS, DIGCF_ALLCLASSES, DIGCF_PRESENT,
            DIIDFLAG_NOFINISHINSTALLUI, DN_HAS_PROBLEM, DiInstallDevice, HDEVINFO, SETUP_DI_REGISTRY_PROPERTY,
            SP_DEVINFO_DATA, SPDRP_COMPATIBLEIDS, SPDRP_DRIVER, SPOST_PATH, SUOI_FORCEDELETE, SetupCopyOEMInfW,
            SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
            SetupDiGetDeviceRegistryPropertyW, SetupSetNonInteractiveMode, SetupUninstallOEMInfW,
        },
        Foundation::{
            BOOL, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS,
            ERROR_NOT_AN_INSTALLED_OEM_INF, FreeLibrary, HMODULE, HWND, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        },
        System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
    },
    core::{PCWSTR, s, w},
};

use super::{
    Driver, driver_state, is_published_name,
    system::{from_wide, size_u32, wide, windows_folder},
    waiting,
};
use crate::{
    Phones,
    package::{ADB_COMPATIBLE_ID, INF_MARK},
};

// windows-sys 0.59 declares this only behind a feature that brings in much
// more; it is in setupapi.dll on every Windows version Captun runs on.
#[cfg_attr(target_arch = "x86", link(name = "setupapi", kind = "raw-dylib", import_name_type = "undecorated"))]
#[cfg_attr(not(target_arch = "x86"), link(name = "setupapi", kind = "raw-dylib"))]
unsafe extern "system" {
    /// Where the driver store keeps the package of an INF Windows published.
    fn SetupGetInfDriverStoreLocationW(
        file_name: PCWSTR,
        alternate_platform: *const c_void,
        locale_name: PCWSTR,
        path: *mut u16,
        path_units: u32,
        units_needed: *mut u32,
    ) -> BOOL;
}

/// A USB debugging (ADB) interface plugged in now.
#[derive(Debug)]
pub(super) struct AdbInterface {
    /// Windows' instance ID for it.
    pub(super) id: String,
    /// What it has for a driver.
    pub(super) driver: Driver,
}

/// Every ADB interface plugged in now, known by its compatible ID.
pub(super) fn adb_interfaces() -> io::Result<Vec<AdbInterface>> {
    let list = DeviceList::present_usb()?;
    let mut found = Vec::new();
    let mut index = 0;
    while let Some(device) = list.device(index)? {
        index += 1;
        found.extend(list.adb_interface(&device));
    }
    Ok(found)
}

/// Gives every ADB interface plugged in now that is waiting for a driver
/// the best driver Windows keeps for it: Captun's, unless one that names
/// the phone itself is there too. One with no driver yet waits while
/// Windows is still setting up what was plugged in (`windows_busy`): it may
/// be giving that one a driver right now. An interface with a driver is
/// never touched.
pub(super) fn give_driver(windows_busy: bool) -> io::Result<Phones> {
    let list = DeviceList::present_usb()?;
    let mut phones = Phones::default();
    let mut index = 0;
    while let Some(device) = list.device(index)? {
        index += 1;
        let Some(interface) = list.adb_interface(&device) else { continue };
        if !waiting(interface.driver, windows_busy) {
            continue;
        }
        match list.install_best_driver(&device) {
            Ok(restart) => {
                phones.given += 1;
                phones.restart |= restart;
            }
            Err(e) => {
                warn!(device = %interface.id, "could not give the USB driver to a phone: {e}");
                phones.failed += 1;
            }
        }
    }
    Ok(phones)
}

/// Adds the package whose INF is at `inf` to the driver store, and returns
/// the name Windows gave its copy of the INF (`oemNN.inf`). Windows checks
/// the package's signature here, so the certificate must be trusted first.
pub(super) fn add_to_store(inf: &Path) -> io::Result<String> {
    let path = wide(inf.as_os_str())?;
    let mut copied = vec![0u16; 1024];
    let room = u32::try_from(copied.len()).map_err(io::Error::other)?;
    let mut needed = 0u32;
    // SAFETY: `path` is NUL-terminated; the package's files are next to it
    // (SPOST_PATH); `copied` has room for `room` UTF-16 units; the pointer to
    // the name's last part is not wanted.
    let ok = unsafe {
        SetupCopyOEMInfW(
            path.as_ptr(),
            ptr::null(),
            SPOST_PATH,
            0,
            copied.as_mut_ptr(),
            room,
            &mut needed,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let copied = from_wide(&copied);
    let name = Path::new(&copied).file_name().and_then(|name| name.to_str()).unwrap_or_default().to_owned();
    if !is_published_name(&name) {
        return Err(io::Error::other(format!("Windows kept the INF as {copied}, not under a name of its own")));
    }
    Ok(name)
}

/// Whether Windows is still setting up devices plugged in (some of its
/// device installs are pending), after waiting up to `wait_ms` for it to
/// finish. When Windows cannot tell, it counts as still busy.
pub(super) fn windows_busy(wait_ms: u32) -> bool {
    // SAFETY: takes and returns plain values.
    match unsafe { CMP_WaitNoPendingInstallEvents(wait_ms) } {
        WAIT_OBJECT_0 => false,
        WAIT_TIMEOUT => true,
        _ => {
            debug!("Windows did not say whether it is setting up devices: {}", io::Error::last_os_error());
            true
        }
    }
}

/// Whether Windows' own WinUSB INF binds every ADB interface itself, as the
/// newest builds' does. Its driver then always ranks above Captun's, which
/// would never be used.
pub(super) fn windows_binds_adb() -> bool {
    let Ok(folder) = windows_folder() else { return false };
    fs::read(folder.join("INF").join("winusb.inf")).is_ok_and(|bytes| super::lists_adb(&super::inf_text_of(&bytes)))
}

/// Whether Windows' copy of an INF under `name` is Captun's: a name Windows
/// gives its INFs, and a file that starts with Captun's mark.
pub(super) fn is_ours(name: &str) -> bool {
    is_published_name(name) && windows_folder().is_ok_and(|folder| starts_with_mark(&folder.join("INF").join(name)))
}

/// The names of every copy of Captun's INF Windows keeps (`oemNN.inf`
/// files that start with Captun's mark), noted or not: what an older
/// version, or an install stopped part way, may have left.
pub(super) fn ours_in_store() -> io::Result<Vec<String>> {
    let folder = windows_folder()?.join("INF");
    let mut found = Vec::new();
    for entry in fs::read_dir(&folder)? {
        // One that went away meanwhile, or cannot be read, is not Captun's
        // to remove.
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
        if is_published_name(&name) && starts_with_mark(&folder.join(&name)) {
            found.push(name);
        }
    }
    found.sort();
    Ok(found)
}

/// Whether the file starts with Captun's mark; only that much is read.
fn starts_with_mark(path: &Path) -> bool {
    let mut start = vec![0u8; INF_MARK.len()];
    fs::File::open(path).and_then(|mut file| file.read_exact(&mut start)).is_ok() && start == INF_MARK.as_bytes()
}

/// Where the driver store keeps the package whose INF Windows copied to
/// `inf` (`%WINDIR%\INF\oemNN.inf`).
pub(super) fn driver_store_path(inf: &Path) -> io::Result<PathBuf> {
    let name = wide(inf.as_os_str())?;
    let mut buf = vec![0u16; 1024];
    let room = u32::try_from(buf.len()).map_err(io::Error::other)?;
    let mut needed = 0u32;
    // SAFETY: `name` is NUL-terminated; no other platform and no locale
    // (both may be null); `buf` has room for `room` UTF-16 units.
    let ok = unsafe {
        SetupGetInfDriverStoreLocationW(name.as_ptr(), ptr::null(), ptr::null(), buf.as_mut_ptr(), room, &mut needed)
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(from_wide(&buf)))
}

/// Takes Windows' copy of an INF named `name` out of the driver store: off
/// every device using it first where Windows can do that, then out of the
/// store. Returns whether Windows wants a restart.
pub(super) fn remove_from_store(name: &str) -> io::Result<bool> {
    let path = windows_folder()?.join("INF").join(name);
    match uninstall_everywhere(&path) {
        Some(Ok(restart)) => return Ok(restart),
        Some(Err(e)) => warn!("could not take the USB driver off phones first ({e}); removing it from Windows only"),
        None => {}
    }
    let name = wide(std::ffi::OsStr::new(name))?;
    // SAFETY: `name` is NUL-terminated; no reserved data.
    if unsafe { SetupUninstallOEMInfW(name.as_ptr(), SUOI_FORCEDELETE, ptr::null()) } == 0 {
        let error = io::Error::last_os_error();
        // Already gone is what was wanted.
        if !is(&error, ERROR_FILE_NOT_FOUND) && !is(&error, ERROR_NOT_AN_INSTALLED_OEM_INF) {
            return Err(error);
        }
    }
    Ok(false)
}

/// DiUninstallDriverW, which takes a driver off the devices using it and
/// then out of the store, is in newdev.dll from Windows 10 version 1703 on.
/// It is looked up when needed, so an older Windows still runs the service
/// (and falls back to removing the package only). `None` without it.
fn uninstall_everywhere(inf: &Path) -> Option<io::Result<bool>> {
    type DiUninstallDriverW = unsafe extern "system" fn(HWND, PCWSTR, u32, *mut BOOL) -> BOOL;
    // SAFETY: a static NUL-terminated name, looked for in System32 only.
    let module = unsafe { LoadLibraryExW(w!("newdev.dll"), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return None;
    }
    let module = Library(module);
    // SAFETY: the module is loaded; the name is a static NUL-terminated string.
    let found = unsafe { GetProcAddress(module.0, s!("DiUninstallDriverW")) }?;
    // SAFETY: newdev.dll's DiUninstallDriverW has exactly this signature
    // (newdev.h), and the module stays loaded while it is called.
    let uninstall = unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, DiUninstallDriverW>(found) };
    let call = |inf: &Path| -> io::Result<bool> {
        let path = wide(inf.as_os_str())?;
        let mut restart: BOOL = 0;
        // SAFETY: no window; `path` is NUL-terminated and outlives the call;
        // flags 0 take the driver off every device, then out of the store;
        // `module` keeps the function loaded.
        let ok = unsafe { uninstall(ptr::null_mut(), path.as_ptr(), 0, &mut restart) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(restart != 0) }
    };
    let first = call(inf);
    if first.is_ok() {
        return Some(first);
    }
    // Which copy of the INF it wants is not spelled out: Windows' copy in
    // its INF folder goes first, then the one in the driver store.
    Some(match driver_store_path(inf) {
        Ok(stored) if stored != inf => call(&stored).or(first),
        _ => first,
    })
}

/// Keeps SetupAPI from showing any window while it lives (a service has no
/// one to answer it: a call that would ask fails instead), then puts back
/// what was set before.
#[derive(Debug)]
pub(super) struct Quiet(BOOL);

impl Quiet {
    pub(super) fn new() -> Self {
        // SAFETY: a process-wide setting that takes no pointers.
        Self(unsafe { SetupSetNonInteractiveMode(1) })
    }
}

impl Drop for Quiet {
    fn drop(&mut self) {
        // SAFETY: as above.
        unsafe { SetupSetNonInteractiveMode(self.0) };
    }
}

/// The USB devices present now (composite devices' interfaces included),
/// freed on drop.
struct DeviceList(HDEVINFO);

impl DeviceList {
    fn present_usb() -> io::Result<Self> {
        // SAFETY: every class (so no class GUID), devices Windows' USB
        // enumerator found, by its static NUL-terminated name; no window.
        let list =
            unsafe { SetupDiGetClassDevsW(ptr::null(), w!("USB"), ptr::null_mut(), DIGCF_ALLCLASSES | DIGCF_PRESENT) };
        if list == INVALID_HANDLE_VALUE as HDEVINFO {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(list))
    }

    /// Device `index` of the list, or `None` past its end.
    fn device(&self, index: u32) -> io::Result<Option<SP_DEVINFO_DATA>> {
        let mut device = SP_DEVINFO_DATA {
            cbSize: size_u32::<SP_DEVINFO_DATA>(),
            ClassGuid: windows_sys::core::GUID::from_u128(0),
            DevInst: 0,
            Reserved: 0,
        };
        // SAFETY: the list is open; `device` is a valid SP_DEVINFO_DATA with
        // its size set, for the one written.
        if unsafe { SetupDiEnumDeviceInfo(self.0, index, &mut device) } == 0 {
            let error = io::Error::last_os_error();
            return if is(&error, ERROR_NO_MORE_ITEMS) { Ok(None) } else { Err(error) };
        }
        Ok(Some(device))
    }

    /// The device as an ADB interface, or `None` when it is not one. One
    /// that cannot be read (gone by now, say) is left out: without knowing
    /// whether it has a driver, it must not be given one.
    fn adb_interface(&self, device: &SP_DEVINFO_DATA) -> Option<AdbInterface> {
        let ids = self.property(device, SPDRP_COMPATIBLEIDS).ok()??;
        let adb =
            ids.split(|&unit| unit == 0).any(|id| String::from_utf16_lossy(id).eq_ignore_ascii_case(ADB_COMPATIBLE_ID));
        if !adb {
            return None;
        }
        let (mut status, mut problem) = (0u32, 0u32);
        // SAFETY: both out-pointers are valid; the device instance comes from
        // the list.
        if unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, device.DevInst, 0) } != CR_SUCCESS {
            return None;
        }
        let problem = (status & DN_HAS_PROBLEM != 0).then_some(problem);
        let has_driver = self.property(device, SPDRP_DRIVER).ok()?.is_some();
        let id = self.instance_id(device).ok()?;
        Some(AdbInterface { id, driver: driver_state(problem, has_driver) })
    }

    /// A registry property of the device as UTF-16 units, or `None` when it
    /// has none.
    fn property(&self, device: &SP_DEVINFO_DATA, property: SETUP_DI_REGISTRY_PROPERTY) -> io::Result<Option<Vec<u16>>> {
        let mut kind = 0u32;
        let mut needed = 0u32;
        // SAFETY: the list holds `device`; an empty buffer asks only for the
        // size, written to `needed`.
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(self.0, device, property, &mut kind, ptr::null_mut(), 0, &mut needed)
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if is(&error, ERROR_INVALID_DATA) {
                return Ok(None);
            }
            if !is(&error, ERROR_INSUFFICIENT_BUFFER) {
                return Err(error);
            }
        }
        let mut buf = vec![0u16; (needed as usize).div_ceil(2)];
        let room = u32::try_from(buf.len() * 2).map_err(io::Error::other)?;
        // SAFETY: as above; `buf` has room for `room` bytes.
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                self.0,
                device,
                property,
                &mut kind,
                buf.as_mut_ptr().cast(),
                room,
                &mut needed,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            return if is(&error, ERROR_INVALID_DATA) { Ok(None) } else { Err(error) };
        }
        buf.truncate((needed as usize / 2).min(buf.len()));
        Ok(Some(buf))
    }

    fn instance_id(&self, device: &SP_DEVINFO_DATA) -> io::Result<String> {
        let mut buf = vec![0u16; 512];
        for _ in 0..2 {
            let room = u32::try_from(buf.len()).map_err(io::Error::other)?;
            let mut needed = 0u32;
            // SAFETY: the list holds `device`; `buf` has room for `room` units.
            if unsafe { SetupDiGetDeviceInstanceIdW(self.0, device, buf.as_mut_ptr(), room, &mut needed) } != 0 {
                return Ok(from_wide(&buf));
            }
            let error = io::Error::last_os_error();
            if !is(&error, ERROR_INSUFFICIENT_BUFFER) {
                return Err(error);
            }
            buf.resize(needed as usize + 1, 0);
        }
        Err(io::Error::other("Windows kept asking for more room for a device's ID"))
    }

    /// Installs the best driver Windows keeps for the device. Returns
    /// whether Windows wants a restart.
    fn install_best_driver(&self, device: &SP_DEVINFO_DATA) -> io::Result<bool> {
        let mut restart: BOOL = 0;
        // SAFETY: no window; the list holds `device`; with no driver named,
        // Windows picks the best match in its driver store.
        let ok = unsafe {
            DiInstallDevice(ptr::null_mut(), self.0, device, ptr::null(), DIIDFLAG_NOFINISHINSTALLUI, &mut restart)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(restart != 0)
    }
}

impl Drop for DeviceList {
    fn drop(&mut self) {
        // SAFETY: the list was made by this module and is freed once.
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

/// A loaded library, freed on drop.
struct Library(HMODULE);

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: the module was loaded by this module and is freed once,
        // after the last call into it.
        unsafe { FreeLibrary(self.0) };
    }
}

fn is(error: &io::Error, code: u32) -> bool {
    error.raw_os_error() == Some(code.cast_signed())
}
