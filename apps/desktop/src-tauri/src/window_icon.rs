//! A sharp taskbar and Alt+Tab icon on Windows. Tauri gives the window one
//! image for every size, and Windows stretches it. Instead, this loads the
//! program's own multi-size icon (embedded from `icons/icon.ico`, with drawings
//! hand-tuned for small sizes) at exactly the sizes Windows uses at the
//! window's current display scale. It runs again when that scale changes.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::{
    Foundation::HWND,
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi},
        WindowsAndMessaging::{
            DestroyIcon, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTCOLOR, LoadImageW, SM_CXICON, SM_CXSMICON, SendMessageW,
            WM_SETICON,
        },
    },
};

/// The resource id tauri-build gives the app icon (IDI_APPLICATION).
const APP_ICON: usize = 32512;

/// The icons set last, so the ones they replace can be freed.
static CURRENT: [AtomicIsize; 2] = [AtomicIsize::new(0), AtomicIsize::new(0)];

/// Sets the window's large and small icons from the program's icon resource.
pub(crate) fn apply(hwnd: *mut core::ffi::c_void) {
    let hwnd = hwnd as HWND;
    // SAFETY: GetModuleHandleW(null) returns this program's own module, which
    // lives as long as the process; it needs no release.
    let module = unsafe { GetModuleHandleW(std::ptr::null()) };
    // SAFETY: `hwnd` is the live window Tauri just handed us.
    let dpi = unsafe { GetDpiForWindow(hwnd) };
    for (slot, (kind, metric)) in [(ICON_BIG, SM_CXICON), (ICON_SMALL, SM_CXSMICON)].into_iter().enumerate() {
        // SAFETY: a plain query; 0 for an unknown metric, handled below.
        let size = unsafe { GetSystemMetricsForDpi(metric, dpi) };
        if size <= 0 {
            continue;
        }
        // SAFETY: the name is an integer resource id (MAKEINTRESOURCE), as
        // LoadImageW accepts; the result is an icon we own, or null.
        let icon = unsafe { LoadImageW(module, APP_ICON as *const u16, IMAGE_ICON, size, size, LR_DEFAULTCOLOR) };
        if icon.is_null() {
            continue;
        }
        // SAFETY: WM_SETICON takes the icon kind and handle and returns the
        // previous icon, which we free only if it was one of ours.
        unsafe { SendMessageW(hwnd, WM_SETICON, kind as usize, icon as isize) };
        let previous = CURRENT[slot].swap(icon as isize, Ordering::SeqCst);
        if previous != 0 {
            // SAFETY: `previous` came from LoadImageW above and is no longer
            // set on any window.
            unsafe { DestroyIcon(previous as *mut core::ffi::c_void) };
        }
    }
}
