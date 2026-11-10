//! The safety notice shown after an adb session.
//!
//! Captun reverts the phone-side changes it made (the proxy, the tunnel, any
//! helper). What it deliberately does *not* do is turn USB debugging back off:
//! it needs adb to keep working while Captun is driving the phone, and turning
//! it off would cut Captun's own control mid-session. So, once the user is done,
//! Captun spells out how to turn it off and why they should.

use crate::reverse::ReverseMethod;

/// What happened in the session, so the caution can name exactly what was
/// reverted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionSummary {
    /// Reverse tethering was active, and with which method.
    pub reverse: Option<ReverseMethod>,
}

/// The full, user-facing caution to show after a session ends. English only, to
/// match the app.
pub fn post_session_caution(summary: &SessionSummary) -> String {
    let mut out = String::new();
    out.push_str("Session ended. Captun has undone the changes it made on your phone:\n");

    match summary.reverse {
        Some(ReverseMethod::SystemProxy) => {
            out.push_str("  • The phone's system proxy was cleared and the USB network link reset.\n");
        }
        Some(ReverseMethod::Helper) => {
            out.push_str("  • The helper was stopped and removed, and the USB network link reset.\n");
        }
        None => {}
    }
    if summary.reverse.is_none() {
        out.push_str("  • No phone-side changes were left in place.\n");
    }

    out.push_str(
        "\nOne thing Captun can't turn off for you: USB debugging.\n\
         It is still ON. Captun needs it while it controls the phone, so it never disables it itself.\n\
         Leaving USB debugging on lets any computer you plug into — or software on this one — command your phone.\n\
         When you're finished, turn it off:\n\
         \u{20}  1. Settings → System → Developer options → turn off \"USB debugging\".\n\
         \u{20}  2. Tap \"Revoke USB debugging authorizations\" to forget trusted computers.\n\
         \u{20}  3. Optional: turn Developer options off entirely.\n\
         Then unplug the cable.",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_tells_the_user_to_disable_usb_debugging() {
        let caution = post_session_caution(&SessionSummary::default());
        assert!(caution.contains("USB debugging"));
        assert!(caution.contains("Revoke USB debugging authorizations"));
        assert!(caution.contains("No phone-side changes"));
    }

    #[test]
    fn names_what_was_reverted() {
        let proxy = post_session_caution(&SessionSummary { reverse: Some(ReverseMethod::SystemProxy) });
        assert!(proxy.contains("system proxy was cleared"));

        let helper = post_session_caution(&SessionSummary { reverse: Some(ReverseMethod::Helper) });
        assert!(helper.contains("helper was stopped"));
    }
}
