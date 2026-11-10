//! Windows' own command-line tools, started by their full path and with an
//! environment of Windows' own.
//!
//! The service runs with administrator rights, and a program named without
//! its folder is looked for in the service's own folder before Windows'
//! (Rust's `Command` searches there first, as Windows does). A file placed
//! next to the service would then run in place of PowerShell. So every
//! Windows tool is named by its full path inside the Windows folder, which
//! comes from Windows itself, never from an environment variable the user
//! can set.
//!
//! The environment is the same kind of gap. The service is started as its
//! user, so it carries that user's environment, which any program of theirs
//! can change (HKCU\Environment), and every tool it starts would inherit it:
//! PowerShell loads its network commands from a module folder of theirs put
//! first on `PSModulePath` (`-NoProfile` does not stop that), `COR_PROFILER`
//! and its kin load a DLL of theirs into PowerShell's .NET, and a folder of
//! theirs on `PATH` can hold what PowerShell finds for a command. So a tool
//! starts with an empty environment and gets back only
//! [`windows_environment`], built from the Windows folder.

use std::ffi::OsString;

/// Windows PowerShell 5.1, part of every supported Windows.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const POWERSHELL: &str = r"System32\WindowsPowerShell\v1.0\powershell.exe";
/// Network settings, such as an adapter's DNS servers.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const NETSH: &str = r"System32\netsh.exe";

/// Where Windows lives when it cannot say, and on other systems, where
/// Windows commands are only built by tests.
const DEFAULT_WINDOWS_FOLDER: &str = r"C:\Windows";

/// The full path of `relative`, a file inside the Windows folder, such as
/// [`POWERSHELL`].
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn system_tool(relative: &str) -> String {
    format!("{}\\{relative}", windows_folder().trim_end_matches('\\'))
}

/// The command that starts `program`. On Windows `program` is one of
/// Windows' own tools ([`system_tool`]): it starts with
/// [`windows_environment`] and nothing else, and without a console window.
/// Elsewhere the command is left as it is.
#[cfg_attr(not(any(windows, target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn command(program: &str) -> std::process::Command {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut command = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.env_clear().envs(windows_environment()).creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// All of the environment a Windows tool is given. Every value but the
/// temporary folder comes from the Windows folder: modules only from
/// Windows' own folder (PowerShell adds Program Files' itself, never the
/// user's Documents), programs only from Windows' folders. Nothing else of
/// the service's environment is passed on, so no `COR_*`, `COMPlus_*` or
/// `DOTNET_*` setting, nor anything else the user set, reaches the tool.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn windows_environment() -> Vec<(&'static str, OsString)> {
    let windows = windows_folder().trim_end_matches('\\');
    let system = format!(r"{windows}\System32");
    let drive: String = windows.chars().take_while(|c| *c != '\\').collect();
    let mut environment: Vec<(&'static str, OsString)> = vec![
        ("SystemRoot", windows.into()),
        ("windir", windows.into()),
        ("SystemDrive", drive.into()),
        ("ComSpec", format!(r"{system}\cmd.exe").into()),
        ("PATH", format!(r"{system};{windows};{system}\Wbem;{system}\WindowsPowerShell\v1.0\").into()),
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC".into()),
        ("PSModulePath", format!(r"{system}\WindowsPowerShell\v1.0\Modules").into()),
    ];
    // Only ever written to, never loaded from; the service's own, as any
    // program the user starts with administrator rights has.
    for name in ["TEMP", "TMP"] {
        if let Some(folder) = std::env::var_os(name) {
            environment.push((name, folder));
        }
    }
    environment
}

/// A program's own name, without its folder or `.exe`, for messages.
#[cfg_attr(not(any(windows, target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn tool_name(program: &str) -> &str {
    let name = program.rsplit(['\\', '/']).next().unwrap_or(program);
    name.strip_suffix(".exe").unwrap_or(name)
}

#[cfg(windows)]
fn windows_folder() -> &'static str {
    static FOLDER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FOLDER.get_or_init(|| ffi::windows_folder().unwrap_or_else(|| DEFAULT_WINDOWS_FOLDER.to_owned()))
}

#[cfg(not(windows))]
fn windows_folder() -> &'static str {
    DEFAULT_WINDOWS_FOLDER
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    /// The Windows folder as Windows reports it (shared by every user, even
    /// on a terminal server).
    pub(super) fn windows_folder() -> Option<String> {
        let mut buf = vec![0u16; 260];
        // The second try has the room the first asked for.
        for _ in 0..2 {
            let size = u32::try_from(buf.len()).ok()?;
            // SAFETY: `buf` is live and writable for `size` UTF-16 units, and
            // the call writes no more than that.
            let len = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), size) } as usize;
            if len == 0 {
                return None;
            }
            if len < buf.len() {
                buf.truncate(len);
                return String::from_utf16(&buf).ok();
            }
            // Too small: `len` is the room needed, the closing NUL included.
            buf.resize(len, 0);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_tools_are_named_by_their_full_path() {
        for (tool, ends) in [(POWERSHELL, r"\System32\WindowsPowerShell\v1.0\powershell.exe"), (NETSH, r"\System32\netsh.exe")] {
            let path = system_tool(tool);
            assert!(path.ends_with(ends), "{path}");
            assert!(!path.contains(r"\\"), "{path}");
            #[cfg(windows)]
            {
                let path = std::path::Path::new(&path);
                assert!(path.is_absolute() && path.is_file(), "{}", path.display());
            }
        }
    }

    #[test]
    fn a_tool_is_given_only_windows_own_environment() {
        let environment = windows_environment();
        let value = |name: &str| {
            environment.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.to_string_lossy().into_owned())
        };
        let windows = windows_folder().trim_end_matches('\\').to_owned();
        assert_eq!(value("PSModulePath"), Some(format!(r"{windows}\System32\WindowsPowerShell\v1.0\Modules")));
        assert_eq!(value("SystemRoot"), Some(windows.clone()));
        // Programs only from Windows' own folders.
        let path = value("PATH").unwrap();
        assert!(path.split(';').all(|folder| folder.starts_with(&windows)), "{path}");
        for (name, _) in &environment {
            let upper = name.to_ascii_uppercase();
            assert!(!["COR_", "COMPLUS_", "DOTNET_", "CORECLR_"].iter().any(|p| upper.starts_with(p)), "{name}");
            assert_eq!(environment.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).count(), 1, "{name}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_built_command_carries_only_that_environment() {
        let command = command(&system_tool(POWERSHELL));
        let set: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(n, v)| (n.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned())))
            .collect();
        assert!(set.iter().any(|(n, v)| n.eq_ignore_ascii_case("PSModulePath") && v.as_deref().is_some_and(|v| v.ends_with(r"\System32\WindowsPowerShell\v1.0\Modules"))));
        assert!(!set.iter().any(|(n, _)| n.to_ascii_uppercase().starts_with("COR_")), "{set:?}");
        let allowed = windows_environment();
        assert!(set.iter().all(|(n, _)| allowed.iter().any(|(a, _)| a.eq_ignore_ascii_case(n))), "{set:?}");
    }

    /// What a tool started by [`command`] sees, against what this process has.
    #[cfg(windows)]
    #[test]
    fn a_tool_sees_nothing_of_this_processs_environment() {
        let out = command(&system_tool(r"System32\cmd.exe")).args(["/d", "/c", "set"]).output().unwrap();
        assert!(out.status.success());
        let seen = String::from_utf8_lossy(&out.stdout).to_ascii_uppercase();
        let windows = windows_folder().trim_end_matches('\\').to_ascii_uppercase();
        assert!(seen.contains(&format!(r"PSMODULEPATH={windows}\SYSTEM32\WINDOWSPOWERSHELL\V1.0\MODULES")), "{seen}");
        // Set for every program the user runs, and for tests by cargo.
        let ours: Vec<String> = std::env::vars_os()
            .map(|(name, _)| name.to_string_lossy().to_ascii_uppercase())
            .filter(|name| ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "USERNAME"].contains(&name.as_str()) || name.starts_with("CARGO"))
            .collect();
        assert!(!ours.is_empty());
        for name in ours {
            assert!(!seen.lines().any(|line| line.starts_with(&format!("{name}="))), "{name} reached the tool");
        }
    }

    /// PowerShell finds its network commands in Windows' own module folder,
    /// and never looks in the user's Documents.
    #[cfg(windows)]
    #[test]
    fn powershell_loads_modules_only_from_windows_folders() {
        let script = "$env:PSModulePath; (Get-Command Get-NetIPInterface).Module.ModuleBase";
        let out = command(&system_tool(POWERSHELL)).args(["-NoProfile", "-NonInteractive", "-Command", script]).output().unwrap();
        let said = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        assert!(out.status.success(), "{said} {}", String::from_utf8_lossy(&out.stderr));
        let mut lines = said.lines().map(str::trim).filter(|l| !l.is_empty());
        let module_path = lines.next().unwrap();
        let windows = windows_folder().trim_end_matches('\\').to_ascii_lowercase();
        let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into()).to_ascii_lowercase();
        let own = [format!(r"{windows}\system32\windowspowershell\v1.0\modules"), format!(r"{program_files}\windowspowershell\modules")];
        assert!(!module_path.contains("documents"), "{module_path}");
        assert!(module_path.split(';').all(|folder| own.iter().any(|o| folder.trim_end_matches('\\') == o)), "{module_path}");
        let base = lines.next().unwrap();
        assert!(base.starts_with(&format!(r"{windows}\system32\windowspowershell\v1.0\modules\")), "{base}");
    }

    #[test]
    fn messages_name_a_tool_without_its_folder() {
        assert_eq!(tool_name(&system_tool(POWERSHELL)), "powershell");
        assert_eq!(tool_name(&system_tool(NETSH)), "netsh");
        assert_eq!(tool_name("ip"), "ip");
        assert_eq!(tool_name("/sbin/ifconfig"), "ifconfig");
    }
}
