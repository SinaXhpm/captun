//! Owner and permissions in SDDL, the text Windows itself writes them as (the
//! same in every Windows language). Only read here, so it can be tested on
//! any system.

/// SYSTEM and Administrators, as aliases and as SIDs.
const ADMINS: [&str; 4] = ["SY", "BA", "S-1-5-18", "S-1-5-32-544"];

const UNREADABLE: &str = "Windows reported its permissions in a form Captun does not know";

/// Why [`check_private`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The text is in a form this does not understand. That says nothing
    /// about the object itself, so callers treat it as a failed question to
    /// Windows, never as proof that the object is wrong (a CA is never
    /// replaced over it).
    Unreadable,
    /// The object really is not private, with why in plain words.
    Finding(&'static str),
}

impl Refusal {
    pub(crate) fn why(self) -> &'static str {
        match self {
            Self::Unreadable => UNREADABLE,
            Self::Finding(why) => why,
        }
    }
}

/// Whether `text` (owner and permissions) describes an object only SYSTEM
/// and Administrators can use or change: one of them owns it (an owner may
/// change the permissions), and every entry that lets anyone in names one of
/// them. Entries that keep someone out change nothing. Used for the CA key and
/// for the folder its public files live in.
pub(crate) fn check_private(text: &str) -> Result<(), Refusal> {
    use Refusal::{Finding, Unreadable};
    let parts = split(text).ok_or(Unreadable)?;
    let owner = part(&parts, 'O').ok_or(Unreadable)?;
    if !ADMINS.contains(&owner) {
        return Err(Finding("it belongs to an account other than SYSTEM or Administrators"));
    }
    let dacl = part(&parts, 'D').ok_or(Finding("it has no list of who may use it, so anyone may"))?;
    let (flags, mut entries) = dacl.split_at(dacl.find('(').unwrap_or(dacl.len()));
    if flags.contains("NO_ACCESS_CONTROL") {
        return Err(Finding("it has no list of who may use it, so anyone may"));
    }
    if !known_flags(flags) {
        return Err(Unreadable);
    }
    let mut admitted = 0;
    while !entries.is_empty() {
        let end = entries.find(')').ok_or(Unreadable)?;
        let entry = entries.get(..end).and_then(|e| e.strip_prefix('(')).ok_or(Unreadable)?;
        let fields: Vec<&str> = entry.split(';').collect();
        match fields.as_slice() {
            ["A", _, _, "", "", account] if ADMINS.contains(account) => admitted += 1,
            ["A", ..] => return Err(Finding("accounts other than SYSTEM and Administrators may use it")),
            ["D", _, _, _, _, _] => {}
            _ => return Err(Unreadable),
        }
        entries = &entries[end + 1..];
    }
    if admitted == 0 {
        return Err(Finding("no account may use it"));
    }
    Ok(())
}

/// `P` (protected from inheritance), `AI` and `AR`, in any order.
fn known_flags(mut flags: &str) -> bool {
    while !flags.is_empty() {
        match ["P", "AI", "AR"].iter().find_map(|flag| flags.strip_prefix(flag)) {
            Some(rest) => flags = rest,
            None => return false,
        }
    }
    true
}

fn part<'a>(parts: &[(char, &'a str)], tag: char) -> Option<&'a str> {
    parts.iter().find(|(t, _)| *t == tag).map(|(_, body)| *body)
}

/// Splits `O:…G:…D:…S:…` into its parts, each tag at most once.
fn split(text: &str) -> Option<Vec<(char, &str)>> {
    let bytes = text.as_bytes();
    let mut starts = Vec::new();
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth = depth.checked_sub(1)?,
            b':' if depth == 0 && i > 0 && matches!(bytes[i - 1], b'O' | b'G' | b'D' | b'S') => starts.push(i - 1),
            _ => {}
        }
    }
    if depth != 0 || starts.first() != Some(&0) {
        return None;
    }
    let mut parts: Vec<(char, &str)> = Vec::with_capacity(starts.len());
    for (n, &start) in starts.iter().enumerate() {
        let end = starts.get(n + 1).copied().unwrap_or(bytes.len());
        let tag = char::from(bytes[start]);
        if parts.iter().any(|(t, _)| *t == tag) {
            return None;
        }
        parts.push((tag, text.get(start + 2..end)?));
    }
    Some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captuns_own_keys_pass() {
        for ours in [
            "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",
            "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",
            // As Windows 11 reports a CNG key made with "GA" for both.
            "O:BAD:P(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)",
            // As Windows may write the same thing back.
            "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:S-1-5-32-544D:P(A;;0x1f01ff;;;S-1-5-18)(A;;0x1f01ff;;;S-1-5-32-544)",
            // Inherited entries for SYSTEM and Administrators only are fine,
            // and so is keeping someone out.
            "O:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(D;;FA;;;WD)",
            "O:SYG:SYD:(A;;GA;;;SY)",
        ] {
            assert_eq!(check_private(ours), Ok(()), "{ours}");
        }
    }

    #[test]
    fn anything_else_fails() {
        for (text, why) in [
            ("O:S-1-5-21-1-2-3-1001D:P(A;;GA;;;SY)(A;;GA;;;BA)", "belongs to an account"),
            ("O:BUD:P(A;;GA;;;SY)", "belongs to an account"),
            ("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)", "other than SYSTEM"),
            ("O:SYD:P(A;;GA;;;SY)(A;;GR;;;WD)", "other than SYSTEM"),
            ("O:SYD:AI(A;;GA;;;SY)(A;ID;0x1200a9;;;AU)", "other than SYSTEM"),
            ("O:SYD:P(A;;GA;;;SY)(A;;GA;;;OW)", "other than SYSTEM"),
            ("O:SYD:NO_ACCESS_CONTROL", "anyone may"),
            ("O:SY", "anyone may"),
            ("O:SYD:P", "no account"),
            ("O:SYD:P(D;;GA;;;WD)", "no account"),
        ] {
            let got = check_private(text).unwrap_err();
            assert!(matches!(got, Refusal::Finding(_)), "{text}: {got:?}");
            assert!(got.why().contains(why), "{text}: {}", got.why());
        }
    }

    /// Text this does not understand is a failed question, not a finding:
    /// it must never be mistaken for a key or folder that is really wrong.
    #[test]
    fn unknown_forms_are_unreadable_not_findings() {
        for text in [
            "O:SYD:P(XA;;GA;;;SY;(Member_of {SID(BA)}))",
            "O:SYD:P(AU;SA;GA;;;SY)",
            "O:SYD:P(A;;GA;;;SY",
            "O:SYD:Q(A;;GA;;;SY)",
            "O:SYO:BAD:(A;;GA;;;SY)",
            "D:P(A;;GA;;;SY)",
            "",
        ] {
            assert_eq!(check_private(text), Err(Refusal::Unreadable), "{text}");
        }
    }

    /// The folder for the CA's public files is checked the same way: one
    /// ordinary users may add files to (as ProgramData's own entry allows) is
    /// refused.
    #[test]
    fn folders_others_may_write_to_fail() {
        assert_eq!(check_private("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"), Ok(()));
        assert_eq!(check_private("O:BAD:PAI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)"), Ok(()));
        for text in [
            "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;CIID;DCLCRPCR;;;BU)",
            "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIIOID;GA;;;CO)",
            "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;SY)",
        ] {
            assert!(matches!(check_private(text), Err(Refusal::Finding(_))), "{text}");
        }
    }
}
