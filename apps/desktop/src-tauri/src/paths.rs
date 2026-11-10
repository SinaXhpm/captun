use std::{
    env, io,
    path::{Path, PathBuf},
};

/// The folder names this program used when it was called OmniHub (on Windows
/// and macOS, and on Linux). They are only read, to take its settings over
/// once (see `settings.rs`); nothing is written there.
const EARLIER_NAME: &str = if cfg!(any(windows, target_os = "macos")) { "OmniHub" } else { "omnihub" };

/// Where the GUI expects the service's per-run IPC token. The GUI passes this
/// path to the service when it launches it, so both sides agree; the location
/// is private to the logged-on user.
pub(crate) fn token_path() -> PathBuf {
    token_dir().join("ipc.token")
}

/// The user's private Captun folder for the profile copy of the settings
/// (and, on macOS and Linux, their key), like the token.
#[cfg(windows)]
pub(crate) fn settings_dir() -> PathBuf {
    token_dir()
}

/// The user's private Captun folder, shared with the token.
#[cfg(target_os = "macos")]
pub(crate) fn settings_dir() -> PathBuf {
    token_dir()
}

/// `$XDG_CONFIG_HOME/captun`, which unlike the runtime dir survives a reboot.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn settings_dir() -> PathBuf {
    config_home().join("captun")
}

/// Where OmniHub, as this program was called before, kept the profile copy
/// of its settings: [`settings_dir`] under the earlier name.
#[cfg(windows)]
pub(crate) fn earlier_settings_dir() -> PathBuf {
    local_app_data().join(EARLIER_NAME)
}

/// Where OmniHub, as this program was called before, kept the profile copy
/// of its settings: [`settings_dir`] under the earlier name.
#[cfg(target_os = "macos")]
pub(crate) fn earlier_settings_dir() -> PathBuf {
    application_support().join(EARLIER_NAME)
}

/// Where OmniHub, as this program was called before, kept the profile copy
/// of its settings: [`settings_dir`] under the earlier name.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn earlier_settings_dir() -> PathBuf {
    config_home().join(EARLIER_NAME)
}

#[cfg(windows)]
fn local_app_data() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(|home| Path::new(&home).join("AppData").join("Local")))
        .unwrap_or_else(env::temp_dir)
}

#[cfg(windows)]
fn token_dir() -> PathBuf {
    local_app_data().join("Captun")
}

/// `~/Library/Application Support`.
#[cfg(target_os = "macos")]
fn application_support() -> PathBuf {
    let home = env::var_os("HOME").unwrap_or_else(|| env::temp_dir().into_os_string());
    Path::new(&home).join("Library").join("Application Support")
}

/// `~/Library/Application Support/Captun`, private to the user.
#[cfg(target_os = "macos")]
fn token_dir() -> PathBuf {
    application_support().join("Captun")
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

#[cfg(all(unix, not(target_os = "macos")))]
fn token_dir() -> PathBuf {
    if let Some(runtime) = env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        return Path::new(&runtime).join("captun");
    }
    let home = env::var_os("HOME").map(PathBuf::from).unwrap_or_else(env::temp_dir);
    home.join(".local").join("state").join("captun")
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
    fn the_earlier_folder_is_the_same_place_under_the_earlier_name() {
        let (now, earlier) = (settings_dir(), earlier_settings_dir());
        assert_eq!(now.parent(), earlier.parent());
        assert_eq!(now.file_name().map(|n| n.to_ascii_lowercase()), Some("captun".into()));
        assert_eq!(earlier.file_name().map(|n| n.to_ascii_lowercase()), Some("omnihub".into()));
    }
}
