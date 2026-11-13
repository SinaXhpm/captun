use std::{
    env, io,
    path::{Path, PathBuf},
};

/// Where the GUI expects the service's per-run IPC token. The GUI passes this
/// path to the service when it launches it, so both sides agree. It is in the
/// service's own folder, never in one of the user's: there a program of the
/// user's could swap the folder for a link, and the service, with full
/// rights, would delete or create files wherever it leads, or (macOS, Linux)
/// make a file in a folder whose files root runs or trusts and hand it to
/// the user.
/// - Windows: the service's data folder, `%ProgramData%\Captun`, which only
///   administrators can change. The service gives the file a protected DACL
///   that lets the user read it, and Windows lets them open it by its full
///   path without any right to the folder ("bypass traverse checking").
/// - macOS and Linux: beside the service's socket, in the folder only root
///   can change, where the service hands the file to the user.
pub(crate) fn token_path() -> PathBuf {
    #[cfg(windows)]
    return program_data().join("Captun").join("ipc.token");
    #[cfg(target_os = "macos")]
    return PathBuf::from("/var/run/captun/ipc.token");
    #[cfg(all(unix, not(target_os = "macos")))]
    return PathBuf::from("/run/captun/ipc.token");
}

/// `%ProgramData%` as Windows has it, rather than as the environment says:
/// a user can set that variable for their own account, and the service
/// started from their session would then be told to use a folder of theirs.
#[cfg(windows)]
#[allow(unsafe_code)]
fn program_data() -> PathBuf {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr};

    use windows_sys::{
        Win32::{
            System::Com::CoTaskMemFree,
            UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
        },
        core::PWSTR,
    };

    let mut path: PWSTR = ptr::null_mut();
    // windows-sys types the flag `i32` and the call's flags `u32`; it is 0.
    let flags = KF_FLAG_DEFAULT as u32;
    // SAFETY: a valid folder id, no token (this user), and an out-pointer to
    // a live local, which the call sets to a string it allocates.
    let result = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, flags, ptr::null_mut(), &mut path) };
    let found = (result >= 0 && !path.is_null()).then(|| {
        let mut len = 0;
        // SAFETY: the call returned a NUL-terminated string.
        while unsafe { *path.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: the `len` characters before that NUL.
        PathBuf::from(OsString::from_wide(unsafe { std::slice::from_raw_parts(path, len) }))
    });
    // SAFETY: allocated by SHGetKnownFolderPath (freed whatever it returned,
    // as it asks), and freed once; null is allowed.
    unsafe { CoTaskMemFree(path.cast()) };
    found.unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

/// The user's private Captun folder for the profile copy of the settings.
#[cfg(windows)]
pub(crate) fn settings_dir() -> PathBuf {
    local_app_data().join("Captun")
}

/// `~/Library/Application Support/Captun`, private to the user: the profile
/// copy of the settings and their key.
#[cfg(target_os = "macos")]
pub(crate) fn settings_dir() -> PathBuf {
    application_support().join("Captun")
}

/// `$XDG_CONFIG_HOME/captun`, which unlike the runtime dir survives a reboot.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn settings_dir() -> PathBuf {
    config_home().join("captun")
}

#[cfg(windows)]
fn local_app_data() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(|home| Path::new(&home).join("AppData").join("Local")))
        .unwrap_or_else(env::temp_dir)
}

/// `~/Library/Application Support`.
#[cfg(target_os = "macos")]
fn application_support() -> PathBuf {
    let home = env::var_os("HOME").unwrap_or_else(|| env::temp_dir().into_os_string());
    Path::new(&home).join("Library").join("Application Support")
}

/// `$XDG_CONFIG_HOME`, else `~/.config`.
#[cfg(all(unix, not(target_os = "macos")))]
fn config_home() -> PathBuf {
    if let Some(config) = env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(config);
    }
    let home = env::var_os("HOME").map(PathBuf::from).unwrap_or_else(env::temp_dir);
    home.join(".config")
}

/// The folder Captun runs from, where it keeps its settings, or `None` where
/// that folder belongs to a sealed package: a macOS app bundle (writing inside
/// it would break its signature). An AppImage counts as the folder it is in.
pub(crate) fn app_dir() -> Option<PathBuf> {
    #[cfg(all(unix, not(target_os = "macos")))]
    if let Some(image) = env::var_os("APPIMAGE").filter(|v| !v.is_empty()) {
        return Path::new(&image).parent().map(Path::to_path_buf);
    }
    let exe = env::current_exe().ok()?;
    let dir = exe.parent()?;
    if cfg!(target_os = "macos") && dir.ends_with("Contents/MacOS") {
        return None;
    }
    Some(dir.to_path_buf())
}

/// The service binary ships next to the GUI executable.
pub(crate) fn daemon_path() -> io::Result<PathBuf> {
    let name = if cfg!(windows) { "captun-daemon.exe" } else { "captun-daemon" };
    Ok(env::current_exe()?.with_file_name(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settings_folder_is_captuns_own() {
        assert_eq!(settings_dir().file_name().map(|n| n.to_ascii_lowercase()), Some("captun".into()));
    }

    /// The token sits beside the service's socket, in the folder only root
    /// can change, never in one of the user's.
    #[cfg(unix)]
    #[test]
    fn the_token_is_in_the_services_own_folder() {
        let socket = captun_ipc::Endpoint::default_service();
        assert_eq!(token_path().parent(), Path::new(socket.as_str()).parent());
    }

    /// The token sits in the service's data folder, `%ProgramData%\Captun`,
    /// found as Windows has it: on a computer where nobody has changed it,
    /// where the variable says too.
    #[cfg(windows)]
    #[test]
    fn the_token_is_in_the_services_data_folder() {
        let said = env::var_os("ProgramData").map(PathBuf::from).expect("ProgramData is set");
        let expected = said.join("Captun").join("ipc.token");
        assert!(
            token_path().to_string_lossy().eq_ignore_ascii_case(&expected.to_string_lossy()),
            "{} is not {}",
            token_path().display(),
            expected.display()
        );
    }
}
