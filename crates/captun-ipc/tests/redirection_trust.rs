//! Redirection Guard is process-wide and cannot be turned off again, so it
//! is tried in a test binary of its own, away from every other test.
#![cfg(windows)]

use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessMitigationPolicy, ProcessRedirectionTrustPolicy};

/// The process's redirection-trust flags, or `None` where this Windows does
/// not know the policy.
#[allow(unsafe_code)]
fn redirection_trust_flags() -> Option<u32> {
    let mut flags: u32 = 0;
    // SAFETY: the pseudo handle of this process, and a live DWORD of the
    // length given for the policy's one DWORD of flags.
    let ok = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessRedirectionTrustPolicy,
            (&mut flags as *mut u32).cast(),
            std::mem::size_of::<u32>(),
        )
    };
    (ok != 0).then_some(flags)
}

#[test]
fn redirection_trust_is_enforced_where_windows_offers_it() {
    if redirection_trust_flags().is_none() {
        // Too old a Windows: callers carry on without it, whatever it says.
        eprintln!("this Windows has no Redirection Guard; nothing to check");
        let _ = captun_ipc::enforce_redirection_trust();
        return;
    }
    captun_ipc::enforce_redirection_trust().unwrap();
    assert_eq!(redirection_trust_flags().unwrap() & 1, 1, "enforced");
    // Asking again is harmless.
    captun_ipc::enforce_redirection_trust().unwrap();
}
