//! Starts the privileged service on demand: UAC elevation on Windows,
//! polkit (`pkexec`) on Linux, the administrator password prompt on macOS.
//! Arguments are passed as separate arguments; the one place a shell is
//! unavoidable (macOS's prompt runs a shell command) quotes every one.

use std::path::Path;

use crate::paths;

pub(crate) fn start_service(token_path: &Path) -> Result<(), String> {
    let daemon = paths::daemon_path().map_err(|e| format!("Cannot locate the Captun executable: {e}"))?;
    if !daemon.is_file() {
        return Err(format!(
            "The Captun service was not found at {}. Build it with `cargo build -p captun-daemon` or reinstall Captun.",
            daemon.display()
        ));
    }
    let token = token_path.to_string_lossy().into_owned();

    // The GUI keeps the settings and hands them over once connected.
    #[cfg(windows)]
    {
        let sid = win::current_user_sid().map_err(|e| format!("Cannot determine the current user: {e}"))?;
        let params = ["--settings-from-gui", "--token-file", token.as_str(), "--allow-user", sid.as_str()]
            .iter()
            .map(|a| quote_arg(a))
            .collect::<Vec<_>>()
            .join(" ");
        win::run_elevated(&daemon, &params).map_err(|e| format!("Could not start the Captun service: {e}"))
    }

    #[cfg(target_os = "macos")]
    {
        let uid = nix::unistd::getuid().as_raw().to_string();
        let daemon = daemon.to_string_lossy();
        let script = admin_script(&[daemon.as_ref(), "--settings-from-gui", "--token-file", token.as_str(), "--owner-uid", uid.as_str()]);
        let output = std::process::Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(script)
            .output()
            .map_err(|e| format!("Could not ask for administrator approval: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        // osascript reports a cancelled prompt as error -128.
        if stderr.contains("-128") {
            return Err("Administrator approval was declined.".into());
        }
        Err(format!("Could not start the Captun service: {}", stderr.trim()))
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let mut child = std::process::Command::new("pkexec")
            .arg(&daemon)
            .arg("--settings-from-gui")
            .arg("--token-file")
            .arg(&token)
            .spawn()
            .map_err(|e| format!("Could not run pkexec to start the Captun service: {e}"))?;
        // Reap the process when it exits so it never lingers as a zombie.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

/// Quotes one argument for a POSIX shell: inside single quotes nothing is
/// special except the quote itself, written as `'\x27'`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn sh_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// An AppleScript that runs `argv` as root after the administrator prompt,
/// in the background so the prompt returns once the service is launched.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn admin_script(argv: &[&str]) -> String {
    let command = argv.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" ");
    let shell = format!("{command} > /dev/null 2>&1 &");
    // Inside an AppleScript string only backslash and double quote are special.
    let escaped = shell.replace('\\', r"\\").replace('"', r#"\""#);
    format!("do shell script \"{escaped}\" with administrator privileges")
}

/// Quotes one argument following the `CommandLineToArgvW` rules, so paths
/// with spaces or quotes survive the trip through `ShellExecuteExW`.
#[cfg_attr(not(windows), allow(dead_code))]
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod win {
    use std::{ffi::OsStr, io, os::windows::ffi::OsStrExt, path::Path, ptr};

    use windows_sys::{
        Win32::{
            Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE, LocalFree},
            Security::{Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
            System::Threading::{GetCurrentProcess, OpenProcessToken},
            UI::{
                Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW},
                WindowsAndMessaging::SW_HIDE,
            },
        },
        core::PWSTR,
    };

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenProcessToken and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// SID of the account running the GUI, e.g. `S-1-5-21-…-1001`. The service
    /// restricts its pipe to this account.
    pub(super) fn current_user_sid() -> io::Result<String> {
        let mut raw: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; `raw` receives a real token handle owned below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(raw);

        let mut len = 0u32;
        // SAFETY: a size query with a null buffer; it fails by design and
        // reports the required length.
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64 storage keeps the TOKEN_USER header pointer-aligned.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `len` bytes and is suitably aligned.
        if unsafe { GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID
        // points into the same buffer, which outlives this use.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

        let mut text: PWSTR = ptr::null_mut();
        // SAFETY: `sid` is valid while `buf` lives; on success `text` is a
        // LocalAlloc'ed, NUL-terminated UTF-16 string that we free below.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `text` is NUL-terminated, so scanning up to the terminator
        // stays inside the allocation.
        let sid_string = unsafe {
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
        };
        // SAFETY: allocated by ConvertSidToStringSidW, freed exactly once.
        unsafe { LocalFree(text.cast()) };
        Ok(sid_string)
    }

    /// Runs `exe` through the UAC "runas" verb with its console hidden. Blocks
    /// until the user answers the elevation prompt.
    pub(super) fn run_elevated(exe: &Path, params: &str) -> io::Result<()> {
        let verb = wide(OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let params = wide(OsStr::new(params));
        // SAFETY: SHELLEXECUTEINFOW is a plain C struct for which all-zero
        // (null pointers, no flags) is a valid starting state.
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_HIDE;
        // SAFETY: every string pointer is NUL-terminated and outlives the call.
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "administrator approval was declined"));
            }
            return Err(err);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{admin_script, quote_arg, sh_quote};

    #[test]
    fn admin_script_quotes_for_the_shell_and_for_applescript() {
        assert_eq!(sh_quote("/Applications/Captun Beta.app"), "'/Applications/Captun Beta.app'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        let script = admin_script(&["/A B/captun-daemon", "--token-file", r#"/Users/x/say "hi"\"#]);
        assert_eq!(
            script,
            r#"do shell script "'/A B/captun-daemon' '--token-file' '/Users/x/say \"hi\"\\' > /dev/null 2>&1 &" with administrator privileges"#
        );
    }

    #[test]
    fn quoting_follows_argv_rules() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg(r"C:\Users\A B\ipc.token"), r#""C:\Users\A B\ipc.token""#);
        assert_eq!(quote_arg(r"trailing\ dir\"), r#""trailing\ dir\\""#);
        assert_eq!(quote_arg(r#"say "hi""#), r#""say \"hi\"""#);
    }
}
