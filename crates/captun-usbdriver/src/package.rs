//! The driver package's text: the INF that hands every phone's USB debugging
//! (ADB) interface to Windows' own WinUSB driver, and the catalog definition
//! its catalog is made from. Plain text, so it is checked on every system.

/// The INF's file name. Windows keeps its own copy under a name of its own
/// (`oemNN.inf`).
pub const INF_NAME: &str = "captun_adb.inf";

/// The catalog the INF names, which carries the signature.
pub const CAT_NAME: &str = "captun_adb.cat";

/// The catalog definition the catalog is made from (not installed).
pub const CDF_NAME: &str = "captun_adb.cdf";

/// The compatible ID Windows gives every Android USB debugging (ADB)
/// interface (class FF, subclass 42, protocol 01), whatever the phone. A
/// driver matched by it ranks below any driver that names the phone itself.
pub const ADB_COMPATIBLE_ID: &str = r"USB\Class_FF&SubClass_42&Prot_01";

/// Windows' "Universal Serial Bus devices" class, which WinUSB devices join.
pub const USB_DEVICE_CLASS: &str = "{88BAE032-5A81-49f0-BC3D-A4FF138216D6}";

/// The device interface ADB tools look a phone up by, the same one Google's
/// USB driver and Windows' own (on recent builds) register.
pub const ADB_INTERFACE_GUID: &str = "{F72FE0D4-CBCB-407d-8814-9ED673D0DD6B}";

/// Who the INF says made the driver.
pub const PROVIDER: &str = "Captun";

/// The name of the one-off certificate that signs the catalog: what it is
/// for, and that it was made on, and is trusted by, this computer alone.
pub const CERTIFICATE_NAME: &str = "Captun USB driver (this computer only)";

/// The Windows versions the catalog is good for, as Windows writes them
/// (platform 2 is Windows NT): 8 (6.2), 8.1 (6.3), 10 and 11 (both 10.0).
pub const OS_ATTRIBUTE: &str = "2:6.2,2:6.3,2:10.0";

/// When the package last changed, as INF files write a date (MM/DD/YYYY).
/// Raised together with [`DRIVER_VERSION`].
pub const DRIVER_DATE: &str = "11/06/2026";

/// The package's own version, raised (with [`DRIVER_DATE`]) whenever what
/// it installs changes: the INF or the catalog definition. It is not
/// Captun's version: an install of the same package is kept as it is, so
/// updating Captun leaves the driver of every phone alone.
pub const DRIVER_VERSION: &str = "1.0.0.0";

/// The INF's first line. Before removing the driver Windows keeps under a
/// name it chose, Captun checks that file still starts with this, so a name
/// Windows has since given another maker's driver is never removed.
pub const INF_MARK: &str = "; Captun's USB driver for Android phones (captun_adb.inf)";

/// The INF. The install sections are what Windows' own winusb.inf asks of a
/// driver that uses it (Include/Needs), and the device interface is set so
/// libusb and other ADB tools find the phone.
pub fn inf_text() -> String {
    let mut lines: Vec<String> = vec![
        INF_MARK.into(),
        "; Windows' own WinUSB driver for every phone's USB debugging (ADB)".into(),
        "; interface. Made and signed on this computer, for this computer only.".into(),
        String::new(),
        "[Version]".into(),
        r#"Signature   = "$Windows NT$""#.into(),
        "Class       = USBDevice".into(),
        format!("ClassGuid   = {USB_DEVICE_CLASS}"),
        "Provider    = %Provider%".into(),
        format!("CatalogFile = {CAT_NAME}"),
        format!("DriverVer   = {DRIVER_DATE},{DRIVER_VERSION}"),
        "PnpLockdown = 1".into(),
        String::new(),
        "[Manufacturer]".into(),
        "%Provider% = Captun, NTamd64, NTarm64, NTx86".into(),
    ];
    for platform in ["NTamd64", "NTarm64", "NTx86"] {
        lines.push(String::new());
        lines.push(format!("[Captun.{platform}]"));
        lines.push(format!("%DeviceName% = USB_Install, {ADB_COMPATIBLE_ID}"));
    }
    lines.extend(
        [
            "",
            "[ClassInstall32]",
            "AddReg = ClassInstall_AddReg",
            "",
            "[ClassInstall_AddReg]",
            "HKR,,,,%ClassName%",
            "HKR,,NoInstallClass,,1",
            "HKR,,Icon,,-20",
            "",
            "[USB_Install]",
            "Include = winusb.inf",
            "Needs   = WINUSB.NT",
            "",
            "[USB_Install.HW]",
            "AddReg  = Dev_AddReg",
            "",
            "[USB_Install.Services]",
            "Include = winusb.inf",
            "Needs   = WINUSB.NT.Services",
            "",
            "[Dev_AddReg]",
        ]
        .map(String::from),
    );
    // 0x10000: a list of strings (REG_MULTI_SZ), as the value must be.
    lines.push(format!(r#"HKR,,DeviceInterfaceGUIDs,0x10000,"{ADB_INTERFACE_GUID}""#));
    lines.extend(
        [
            "",
            "[Strings]",
            r#"Provider   = "Captun""#,
            r#"DeviceName = "Android ADB Interface (Captun)""#,
            r#"ClassName  = "Universal Serial Bus devices""#,
        ]
        .map(String::from),
    );
    crlf(&lines)
}

/// The catalog definition for the package in the folder `dir`, as Windows
/// writes the path. Windows reads the definition as 8-bit text, so `dir`
/// must be plain printable ASCII (the service's own folder always is), and
/// without the characters the definition's lines are split by; `None`
/// otherwise.
pub fn cdf_text(dir: &str) -> Option<String> {
    let dir = dir.trim_end_matches('\\');
    let plain = dir.bytes().all(|b| (0x20..0x7f).contains(&b) && !matches!(b, b'=' | b';' | b'[' | b']'));
    if dir.is_empty() || !plain {
        return None;
    }
    // 0x10010001: an attribute that is signed with the catalog, its name
    // and value plain text (CRYPTCAT_ATTR_AUTHENTICATED | _DATAASCII |
    // _NAMEASCII). `<hash>` makes the INF's hash its tag, which is how
    // Windows finds a file in a catalog. Version 2 catalogs use SHA-256.
    let lines = [
        "[CatalogHeader]".to_owned(),
        format!("Name={CAT_NAME}"),
        format!("ResultDir={dir}"),
        "PublicVersion=0x00000001".into(),
        "EncodingType=0x00010001".into(),
        "CatalogVersion=2".into(),
        "HashAlgorithms=SHA256".into(),
        "PageHashes=false".into(),
        format!("CATATTR1=0x10010001:OSAttr:{OS_ATTRIBUTE}"),
        String::new(),
        "[CatalogFiles]".into(),
        format!("<hash>{INF_NAME}={dir}\\{INF_NAME}"),
        format!("<hash>{INF_NAME}ATTR1=0x10010001:OSAttr:{OS_ATTRIBUTE}"),
    ];
    Some(crlf(&lines))
}

/// Lines as Windows' setup files have them: each ended by CR LF.
fn crlf(lines: &[String]) -> String {
    let mut text = String::new();
    for line in lines {
        text.push_str(line);
        text.push_str("\r\n");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The INF's sections, each with its lines (comments and blanks left out).
    fn sections(text: &str) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for line in text.split("\r\n").map(str::trim) {
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                out.push((name.to_owned(), Vec::new()));
            } else {
                out.last_mut().expect("a line before any section").1.push(line.to_owned());
            }
        }
        out
    }

    fn section<'a>(all: &'a [(String, Vec<String>)], name: &str) -> &'a [String] {
        let found: Vec<_> = all.iter().filter(|(n, _)| n == name).collect();
        assert_eq!(found.len(), 1, "exactly one [{name}]");
        &found[0].1
    }

    #[test]
    fn the_inf_binds_winusb_to_every_adb_interface() {
        let text = inf_text();
        assert!(text.is_ascii());
        assert!(text.starts_with(&format!("{INF_MARK}\r\n")));
        assert!(text.ends_with("\r\n") && !text.replace("\r\n", "").contains('\n'), "CR LF line ends only");
        let all = sections(&text);

        let version = section(&all, "Version");
        for expected in [
            r#"Signature   = "$Windows NT$""#,
            "Class       = USBDevice",
            "ClassGuid   = {88BAE032-5A81-49f0-BC3D-A4FF138216D6}",
            "Provider    = %Provider%",
            "CatalogFile = captun_adb.cat",
            "PnpLockdown = 1",
        ] {
            assert!(version.iter().any(|l| l == expected), "[Version] has {expected}");
        }
        assert!(version.iter().any(|l| *l == format!("DriverVer   = {DRIVER_DATE},{DRIVER_VERSION}")));

        // Every platform's models section names the one compatible ID, so
        // no phone's own IDs are needed.
        assert_eq!(section(&all, "Manufacturer"), ["%Provider% = Captun, NTamd64, NTarm64, NTx86"]);
        for platform in ["NTamd64", "NTarm64", "NTx86"] {
            assert_eq!(
                section(&all, &format!("Captun.{platform}")),
                [r"%DeviceName% = USB_Install, USB\Class_FF&SubClass_42&Prot_01"]
            );
        }

        // Windows' own WinUSB, the way its winusb.inf says to use it.
        assert_eq!(section(&all, "USB_Install"), ["Include = winusb.inf", "Needs   = WINUSB.NT"]);
        assert_eq!(section(&all, "USB_Install.Services"), ["Include = winusb.inf", "Needs   = WINUSB.NT.Services"]);
        assert_eq!(section(&all, "USB_Install.HW"), ["AddReg  = Dev_AddReg"]);
        assert_eq!(
            section(&all, "Dev_AddReg"),
            [r#"HKR,,DeviceInterfaceGUIDs,0x10000,"{F72FE0D4-CBCB-407d-8814-9ED673D0DD6B}""#]
        );
        let strings = section(&all, "Strings");
        assert!(strings.iter().any(|l| l == r#"Provider   = "Captun""#));

        // It copies no file of its own: nothing but Windows' WinUSB runs.
        for (name, lines) in &all {
            assert!(!name.starts_with("SourceDisks"), "{name}");
            assert!(lines.iter().all(|l| !l.starts_with("CopyFiles")), "{name}");
        }
    }

    /// The package as it was when [`DRIVER_VERSION`] was last raised: that
    /// version and a fingerprint of the INF and the catalog definition.
    const PACKAGE_AT_THIS_VERSION: (&str, u64) = ("1.0.0.0", 0x4707_712e_4a59_a81c);

    /// FNV-1a, 64 bits: enough to notice that the text changed.
    fn fingerprint(text: &str) -> u64 {
        text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, b| (hash ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
    }

    #[test]
    fn a_changed_package_comes_with_a_new_version() {
        // An install of the same version is kept, so a package that changed
        // without a new version would never reach computers that have one.
        let cdf = cdf_text(r"C:\Windows\Temp\captun-usb-driver-0123456789abcdef").unwrap();
        let now = (DRIVER_VERSION, fingerprint(&(inf_text() + &cdf)));
        assert_eq!(
            now, PACKAGE_AT_THIS_VERSION,
            "the driver package changed: raise DRIVER_VERSION and DRIVER_DATE, then note the new version and fingerprint ({:#018x}) here",
            now.1
        );
    }

    #[test]
    fn the_version_and_date_are_what_inf_files_accept() {
        let parts: Vec<u32> = DRIVER_VERSION.split('.').map(|p| p.parse().unwrap()).collect();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().all(|&p| p <= 65_535));
        let date: Vec<u32> = DRIVER_DATE.split('/').map(|p| p.parse().unwrap()).collect();
        assert!(matches!(date[..], [1..=12, 1..=31, 2000..=2100]), "{DRIVER_DATE}");
        assert_eq!(DRIVER_DATE.len(), 10, "two-digit month and day");
    }

    #[test]
    fn the_catalog_definition_lists_the_inf_by_its_hash_with_the_windows_versions() {
        let dir = r"C:\Windows\Temp\captun-usb-driver-0123456789abcdef";
        let text = cdf_text(&format!("{dir}\\")).unwrap();
        assert!(text.is_ascii());
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(lines[0], "[CatalogHeader]");
        for expected in [
            "Name=captun_adb.cat".to_owned(),
            format!("ResultDir={dir}"),
            "CatalogVersion=2".into(),
            "HashAlgorithms=SHA256".into(),
            "CATATTR1=0x10010001:OSAttr:2:6.2,2:6.3,2:10.0".into(),
            "[CatalogFiles]".into(),
            format!(r"<hash>captun_adb.inf={dir}\captun_adb.inf"),
            "<hash>captun_adb.infATTR1=0x10010001:OSAttr:2:6.2,2:6.3,2:10.0".into(),
        ] {
            assert!(lines.contains(&expected.as_str()), "has {expected}");
        }
        // Only the INF goes in: there is nothing else in the package.
        let members = lines.iter().skip_while(|l| **l != "[CatalogFiles]").skip(1);
        assert_eq!(members.filter(|l| !l.is_empty() && !l.contains("ATTR")).count(), 1);
    }

    #[test]
    fn a_folder_the_catalog_tools_cannot_read_is_refused() {
        assert!(cdf_text(r"C:\Users\Sina (2)\AppData\Local\Temp\x").is_some(), "spaces and parentheses are fine");
        for bad in
            ["", r"\", "C:\\Users\\\u{633}\u{6cc}\u{646}\u{627}\\Temp", "C:\\a\nb", r"C:\a=b", r"C:\a;b", r"C:\[a]"]
        {
            assert!(cdf_text(bad).is_none(), "{bad:?}");
        }
    }
}
