//! The iOS and iPadOS configuration profile that installs the CA.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::digest;

use crate::{CertAuthority, Fingerprint, fsutil::hex};

/// The content type iOS and iPadOS offer to install a profile from.
pub const MOBILECONFIG_CONTENT_TYPE: &str = "application/x-apple-aspen-config";

/// What Settings shows as the profile's name.
const DISPLAY_NAME: &str = "Captun HTTPS inspection";
/// The same for every CA Captun makes: installing a newer one replaces the
/// one before (and so takes the old CA off the device).
const IDENTIFIER: &str = "app.captun.https-inspection";

/// What Settings shows about the profile: what it allows, in plain words.
const DESCRIPTION: &str = "With this installed, the Captun computer that shares this network can open this device's secure (HTTPS) connections while the device uses that network, and show the person who runs it what is sent, including pages, messages and passwords. Install it only if you agreed to this. Your device trusts this certificate on every network until you remove this profile: Captun uses it only while you are on its network, but anyone who got its key could use it anywhere. It does nothing until you also turn it on under Settings > General > About > Certificate Trust Settings. To stop it, remove this profile under Settings > General > VPN & Device Management.";

/// What the device asks its user to agree to before it installs the
/// profile.
const CONSENT: &str = "By installing this profile you agree that the Captun computer sharing this network may open this device's secure (HTTPS) connections and show what is sent to the person who runs it, while this device uses that network. Your device trusts this certificate on every network until you remove this profile: Captun uses it only while you are on its network, but anyone who got its key could use it anywhere. You can remove the profile at any time to stop it.";

/// The same in Persian, which most people installing it read.
const CONSENT_FA: &str = "با نصب این پروفایل موافقت می‌کنید که کامپیوتر Captun که این شبکه را به اشتراک می‌گذارد، تا وقتی این دستگاه از آن شبکه استفاده می‌کند، بتواند ارتباط‌های امن (HTTPS) این دستگاه را باز کند و آنچه فرستاده می‌شود را به کسی که آن را اداره می‌کند نشان دهد. این دستگاه تا وقتی این پروفایل را حذف نکنید، در هر شبکه‌ای به این گواهی اعتماد می‌کند: Captun فقط وقتی از آن استفاده می‌کند که روی شبکهٔ خودش باشید، ولی هر کسی که کلید آن را به دست بیاورد می‌تواند هر جایی از آن استفاده کند. هر وقت بخواهید می‌توانید پروفایل را حذف کنید تا این کار متوقف شود.";

impl CertAuthority {
    /// An iOS and iPadOS configuration profile (`.mobileconfig`,
    /// [`MOBILECONFIG_CONTENT_TYPE`]) holding this CA's certificate as a
    /// root certificate (`com.apple.security.root`). It is unsigned, so the
    /// device shows it as not verified; its user installs it and agrees to
    /// what it says, then turns full trust on for the CA, all in Settings.
    /// The same CA always gives the same profile.
    pub fn mobileconfig(&self) -> String {
        let data = STANDARD.encode(self.certificate_der());
        let data: Vec<&str> =
            data.as_bytes().chunks(64).map(|line| std::str::from_utf8(line).unwrap_or_default()).collect();
        let fingerprint = self.fingerprint();
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>ConsentText</key>
	<dict>
		<key>default</key>
		<string>{consent}</string>
		<key>en</key>
		<string>{consent}</string>
		<key>fa</key>
		<string>{consent_fa}</string>
	</dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>{file}.cer</string>
			<key>PayloadContent</key>
			<data>
{data}
			</data>
			<key>PayloadDescription</key>
			<string>{root_description}</string>
			<key>PayloadDisplayName</key>
			<string>{ca_name}</string>
			<key>PayloadIdentifier</key>
			<string>{IDENTIFIER}.root</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{root_uuid}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>{description}</string>
	<key>PayloadDisplayName</key>
	<string>{display_name}</string>
	<key>PayloadIdentifier</key>
	<string>{IDENTIFIER}</string>
	<key>PayloadOrganization</key>
	<string>Captun</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{profile_uuid}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
"#,
            consent = escape(CONSENT),
            consent_fa = escape(CONSENT_FA),
            file = escape(&self.file_stem()),
            data = data.join("\n"),
            root_description = escape(&format!("{}, for Captun's HTTPS inspection. Trusted on every network until this profile is removed.", self.name())),
            ca_name = escape(self.name()),
            root_uuid = uuid(&fingerprint, "root"),
            description = escape(DESCRIPTION),
            display_name = escape(DISPLAY_NAME),
            profile_uuid = uuid(&fingerprint, "profile"),
        )
    }
}

/// `text` safe inside an XML element.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A UUID for the payload `label` of the CA with `fingerprint`: the same for
/// the same CA, different for another. Version 8 (made by a rule of the
/// program's own, RFC 9562), from SHA-256.
fn uuid(fingerprint: &Fingerprint, label: &str) -> String {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"captun https inspection profile\0");
    hash.update(label.as_bytes());
    hash.update(b"\0");
    hash.update(fingerprint.as_bytes());
    let hash = hash.finish();
    let mut bytes: [u8; 16] = hash.as_ref().get(..16).and_then(|b| b.try_into().ok()).unwrap_or_default();
    bytes[6] = (bytes[6] & 0x0F) | 0x80;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let hex = hex(&bytes).to_ascii_uppercase();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_escaped() {
        assert_eq!(escape(r#"a & b < c > "d" 'e'"#), "a &amp; b &lt; c &gt; &quot;d&quot; &apos;e&apos;");
    }

    #[test]
    fn uuids_are_stable_well_formed_and_distinct() {
        let a = Fingerprint::of(b"one certificate");
        let b = Fingerprint::of(b"another certificate");
        let id = uuid(&a, "root");
        assert_eq!(id, uuid(&a, "root"));
        assert_ne!(id, uuid(&a, "profile"));
        assert_ne!(id, uuid(&b, "root"));
        let groups: Vec<&str> = id.split('-').collect();
        assert_eq!(groups.iter().map(|g| g.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12]);
        assert!(groups[2].starts_with('8'), "version 8: {id}");
        assert!(matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'A' | b'B'), "RFC variant: {id}");
    }
}
