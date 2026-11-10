//! Windows: the package is made and signed in a private folder, its one-off
//! certificate trusted, the package added to the driver store and given to
//! phones waiting for a driver. Each kind of Windows call lives in a small
//! module of its own (`catalog`, `sign`, `store`, `devices`, `record`,
//! `system`); this one orders the steps, and undoes them when one fails.

#[allow(unsafe_code)]
mod catalog;
#[allow(unsafe_code)]
mod devices;
#[allow(unsafe_code)]
mod record;
#[allow(unsafe_code)]
mod sign;
#[allow(unsafe_code)]
mod store;
#[allow(unsafe_code)]
mod system;

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use tracing::{info, warn};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{CM_PROB_DISABLED, CM_PROB_FAILED_INSTALL};

use crate::{
    Detection, DriverError, Install, Phones, Remove,
    package::{ADB_COMPATIBLE_ID, CAT_NAME, CDF_NAME, DRIVER_VERSION, INF_NAME, cdf_text, inf_text},
};
use record::Record;

const WAITING: &str = "waiting for another install or removal of the driver";
const READING: &str = "reading what Captun installed before";
const LOOKING: &str = "looking for what Captun installed before";
const NOTING: &str = "noting what Captun installs";
const FORGETTING: &str = "forgetting what Captun installed";

/// How long giving phones the driver waits for Windows to finish setting up
/// what was plugged in, rather than race it.
const SETTLE_MS: u32 = 10_000;

/// The comment that ends each package's INF, before the copy's own number.
const COPY_LINE: &str = "; This copy: ";

/// A driver package made and signed in a folder, ready to install.
pub struct Package {
    /// The INF.
    pub inf: PathBuf,
    /// The signed catalog.
    pub catalog: PathBuf,
    /// The certificate that signed the catalog (DER). Its private key no
    /// longer exists.
    pub certificate: Vec<u8>,
    /// The certificate's SHA-1 thumbprint, in hex as Windows shows it.
    pub thumbprint: String,
}

impl std::fmt::Debug for Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Package")
            .field("inf", &self.inf)
            .field("catalog", &self.catalog)
            .field("certificate", &format_args!("{} bytes", self.certificate.len()))
            .field("thumbprint", &self.thumbprint)
            .finish()
    }
}

/// Makes the package in `dir`, an existing folder whose path is plain
/// ASCII, and signs its catalog with a certificate made for it alone, whose
/// private key is destroyed before this returns. Installs nothing, so it
/// needs no administrator rights.
pub fn build_package(dir: &Path) -> Result<Package, DriverError> {
    let writing = "writing the driver's files";
    let definition = dir.to_str().and_then(cdf_text).ok_or_else(|| {
        let why = format!("the catalog tools cannot read the folder name {}", dir.display());
        failed(writing, io::Error::new(io::ErrorKind::InvalidInput, why))
    })?;
    let inf = dir.join(INF_NAME);
    let cdf = dir.join(CDF_NAME);
    let catalog = dir.join(CAT_NAME);
    // A last line of its own makes this INF unlike any added before, so
    // Windows keeps this package as a new one, never taking it for an
    // earlier copy whose catalog another certificate signed.
    let copy = system::random_hex(8).map_err(step(writing))?;
    fs::write(&inf, format!("{}{COPY_LINE}{copy}\r\n", inf_text())).map_err(step(writing))?;
    fs::write(&cdf, definition).map_err(step(writing))?;
    // Made afresh, never on top of one left from an earlier attempt.
    remove_if_there(&catalog).map_err(step(writing))?;
    catalog::make(&cdf, &catalog).map_err(step("making the driver's catalog"))?;
    let _ = fs::remove_file(&cdf);
    let certificate = sign::sign_once(&catalog).map_err(step("signing the driver"))?;
    let checking = "checking the signed driver";
    catalog::check(&inf, &catalog, &certificate).map_err(step(checking))?;
    let thumbprint = store::thumbprint(&certificate).map_err(step(checking))?;
    Ok(Package { inf, catalog, certificate, thumbprint: hex(&thumbprint) })
}

pub(crate) fn install() -> Result<Install, DriverError> {
    ensure_elevated()?;
    let _one_at_a_time = system::Exclusive::take().map_err(step(WAITING))?;
    let _quiet = devices::Quiet::new();
    let record = record::read().map_err(step(READING))?;
    if devices::windows_binds_adb() {
        // Windows' own driver would always be used over Captun's, which
        // would only add a certificate to trust: none goes in, and whatever
        // went in before, when this Windows had no driver of its own, comes
        // out. Windows' driver is there either way, so a part that cannot be
        // removed now is tried again next time.
        match remove_everything(&record) {
            Ok(Some(_)) => info!("Windows now brings its own USB driver for phones; removed Captun's"),
            Ok(None) => {}
            Err(e) => warn!("could not remove Captun's USB driver for phones, which Windows' own replaces: {e}"),
        }
        return Ok(Install::WindowsHasOne(give_to_waiting_phones()));
    }
    if intact(&record) {
        tidy(&record);
        return Ok(Install::AlreadyInstalled(give_to_waiting_phones()));
    }
    let folder = system::PrivateFolder::new().map_err(step("making a private folder for the driver"))?;
    let package = build_package(folder.path())?;
    let noted = put_in(&package)?;
    // Windows keeps its own copy of the package.
    drop(folder);
    info!(
        certificate = %package.thumbprint,
        "installed the USB driver for Android phones, signed with a one-off certificate whose key is destroyed"
    );
    // Only now, with the new package in, does one installed before (an
    // older version, or what an install stopped part way left) come out:
    // phones using it move to the new one, not to none.
    tidy(&noted);
    Ok(Install::Installed(give_to_waiting_phones()))
}

pub(crate) fn remove() -> Result<Remove, DriverError> {
    ensure_elevated()?;
    let _one_at_a_time = system::Exclusive::take().map_err(step(WAITING))?;
    let _quiet = devices::Quiet::new();
    let record = record::read().map_err(step(READING))?;
    Ok(match remove_everything(&record)? {
        None => Remove::NothingInstalled,
        Some(restart) => Remove::Removed { restart },
    })
}

pub(crate) fn detect() -> Result<Detection, DriverError> {
    let interfaces = devices::adb_interfaces().map_err(step("looking for phones without a driver"))?;
    // Windows is asked only when it matters: for an interface with no
    // driver yet, which it may be giving one right now.
    let busy = interfaces.iter().any(|i| i.driver == Driver::NoneYet) && devices::windows_busy(0);
    Ok(detection(&interfaces, busy))
}

#[cfg(test)]
pub(crate) fn is_elevated() -> bool {
    system::is_elevated().unwrap_or(false)
}

fn ensure_elevated() -> Result<(), DriverError> {
    match system::is_elevated() {
        Ok(true) => Ok(()),
        Ok(false) => Err(DriverError::NotElevated),
        Err(e) => Err(failed("checking for administrator rights", e)),
    }
}

/// Trusts the package's certificate and adds the package to the driver
/// store, and returns what was noted of it. Each step is noted before it is
/// taken, so whatever an interruption leaves is found and removed later
/// (Captun's mark and name find it too); a step that fails undoes the ones
/// before it.
fn put_in(package: &Package) -> Result<Record, DriverError> {
    let mut noted =
        Record { inf: None, thumbprint: Some(package.thumbprint.clone()), version: Some(DRIVER_VERSION.into()) };
    record::write(&noted).map_err(step(NOTING))?;
    if let Err(e) = store::add(&package.certificate) {
        undo(&noted);
        return Err(failed("trusting the driver's certificate on this computer", e));
    }
    // The certificate is trusted by now, so Windows takes the package
    // without asking anyone.
    let published = match devices::add_to_store(&package.inf) {
        Ok(published) => published,
        Err(e) => {
            undo(&noted);
            return Err(failed("adding the driver to Windows", e));
        }
    };
    noted.inf = Some(published);
    if let Err(e) = record::write(&noted) {
        undo(&noted);
        return Err(failed(NOTING, e));
    }
    Ok(noted)
}

fn undo(noted: &Record) {
    if let Err(e) = remove_recorded(noted) {
        warn!("could not undo a failed install of the USB driver for phones: {e}");
    }
}

/// Whether everything the record names is in place, for this package.
fn intact(record: &Record) -> bool {
    record.version.as_deref() == Some(DRIVER_VERSION)
        && record.inf.as_deref().is_some_and(devices::is_ours)
        && record
            .thumbprint
            .as_deref()
            .and_then(parse_thumbprint)
            .is_some_and(|thumbprint| store::trusts(&thumbprint).unwrap_or(false))
}

/// Removes what the record names, then the record. Returns whether Windows
/// wants a restart. On a failure the record is kept, so a later attempt
/// finds the rest.
fn remove_recorded(record: &Record) -> Result<bool, DriverError> {
    // A name Windows has since given another maker's driver is left alone.
    let infs: Vec<String> = record.inf.iter().filter(|inf| devices::is_ours(inf)).cloned().collect();
    let certificates: Vec<[u8; 20]> = record.thumbprint.as_deref().and_then(parse_thumbprint).into_iter().collect();
    let restart = remove_parts(&infs, &certificates)?;
    record::clear().map_err(step(FORGETTING))?;
    Ok(restart)
}

/// Removes every part of Captun's driver this computer holds, noted in
/// `record` or not, then the record. `None` when there was nothing to
/// remove, else whether Windows wants a restart. On a failure the record is
/// kept, so a later attempt finds the rest.
fn remove_everything(record: &Record) -> Result<Option<bool>, DriverError> {
    let (infs, certificates) = leftovers(&Record::default())?;
    if infs.is_empty() && certificates.is_empty() && record.is_empty() {
        return Ok(None);
    }
    let restart = remove_parts(&infs, &certificates)?;
    record::clear().map_err(step(FORGETTING))?;
    Ok(Some(restart))
}

/// Removes what an older package, or an install stopped part way, left
/// beside the install `kept` names. That install stands whatever happens
/// here: what cannot be removed now is tried again next time.
fn tidy(kept: &Record) {
    let removed = leftovers(kept).and_then(|(infs, certificates)| {
        if infs.is_empty() && certificates.is_empty() {
            return Ok(false);
        }
        info!(
            packages = infs.len(),
            certificates = certificates.len(),
            "removing what an earlier install of the USB driver for phones left"
        );
        remove_parts(&infs, &certificates)
    });
    match removed {
        Ok(true) => info!("Windows wants a restart to finish removing an earlier USB driver for phones"),
        Ok(false) => {}
        Err(e) => warn!("could not remove what an earlier install of the USB driver for phones left: {e}"),
    }
}

/// What of Captun's driver this computer holds besides what `keep` names:
/// Windows' copies of Captun's INF and the certificates made for it, found
/// by Captun's mark and name whether they were noted or not.
fn leftovers(keep: &Record) -> Result<(Vec<String>, Vec<[u8; 20]>), DriverError> {
    let infs = devices::ours_in_store().map_err(step(LOOKING))?;
    let certificates = store::captuns().map_err(step(LOOKING))?;
    Ok(not_kept(infs, certificates, keep))
}

/// The INF names and certificate thumbprints that `keep` does not name.
fn not_kept(infs: Vec<String>, certificates: Vec<[u8; 20]>, keep: &Record) -> (Vec<String>, Vec<[u8; 20]>) {
    let kept_inf = keep.inf.as_deref();
    let kept_thumbprint = keep.thumbprint.as_deref().and_then(parse_thumbprint);
    let infs = infs.into_iter().filter(|inf| !kept_inf.is_some_and(|kept| kept.eq_ignore_ascii_case(inf))).collect();
    let certificates = certificates.into_iter().filter(|thumbprint| Some(*thumbprint) != kept_thumbprint).collect();
    (infs, certificates)
}

/// Takes these copies of Captun's INF out of the driver store and these
/// certificates out of both stores. Each one is tried even when another
/// fails, and the first failure is returned. Returns whether Windows wants
/// a restart.
fn remove_parts(infs: &[String], certificates: &[[u8; 20]]) -> Result<bool, DriverError> {
    let mut restart = false;
    let mut first: Option<DriverError> = None;
    for inf in infs {
        match devices::remove_from_store(inf) {
            Ok(again) => restart |= again,
            Err(e) if first.is_none() => first = Some(failed("removing the driver from Windows", e)),
            Err(e) => warn!("could not remove {inf} from Windows: {e}"),
        }
    }
    for thumbprint in certificates {
        match store::remove(thumbprint) {
            Ok(_) => {}
            Err(e) if first.is_none() => first = Some(failed("removing the driver's certificate", e)),
            Err(e) => warn!("could not remove the driver's certificate {}: {e}", hex(thumbprint)),
        }
    }
    first.map_or(Ok(restart), Err)
}

/// Gives the driver to every ADB interface plugged in now that is waiting
/// for one. Windows may still be setting up a phone plugged in moments ago,
/// picking the best driver in its store (Captun's too, by now) itself, so it
/// is given a little time to finish first. A failure here leaves the install
/// as it is: those phones get the driver when plugged in again.
fn give_to_waiting_phones() -> Phones {
    let busy = devices::windows_busy(SETTLE_MS);
    match devices::give_driver(busy) {
        Ok(phones) => phones,
        Err(e) => {
            warn!("could not look for phones waiting for the USB driver: {e}");
            Phones::default()
        }
    }
}

/// What an ADB interface has for a driver, as far as giving it one goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Driver {
    /// It has one, working or not, or someone turned it off: never touched.
    LeftAlone,
    /// None, and Windows found none for it, or could not install one
    /// (code 28).
    NoneFound,
    /// None yet: Windows may still be setting it up.
    NoneYet,
}

/// What an interface with this problem (if any), with or without a driver
/// installed, has for a driver.
fn driver_state(problem: Option<u32>, has_driver: bool) -> Driver {
    match problem {
        Some(CM_PROB_FAILED_INSTALL) => Driver::NoneFound,
        Some(CM_PROB_DISABLED) => Driver::LeftAlone,
        _ if has_driver => Driver::LeftAlone,
        _ => Driver::NoneYet,
    }
}

/// Whether an interface is waiting for Captun to give it a driver: one
/// Windows found none for, or one with none yet once Windows is not setting
/// up what was plugged in (`windows_busy`) any more.
fn waiting(driver: Driver, windows_busy: bool) -> bool {
    match driver {
        Driver::NoneFound => true,
        Driver::NoneYet => !windows_busy,
        Driver::LeftAlone => false,
    }
}

fn detection(interfaces: &[devices::AdbInterface], windows_busy: bool) -> Detection {
    let missing: Vec<String> =
        interfaces.iter().filter(|i| waiting(i.driver, windows_busy)).map(|i| i.id.clone()).collect();
    if !missing.is_empty() {
        Detection::Missing(missing)
    } else if interfaces.iter().any(|i| i.driver == Driver::NoneYet) {
        Detection::BeingSetUp
    } else if interfaces.is_empty() {
        Detection::None
    } else {
        Detection::Working
    }
}

/// Whether an INF binds devices by the ADB compatible ID: a models line
/// (`name = section, IDs`) naming it, comments aside.
fn lists_adb(inf: &str) -> bool {
    let adb = ADB_COMPATIBLE_ID.to_ascii_lowercase();
    inf.lines().any(|line| {
        let line = line.split(';').next().unwrap_or_default().to_ascii_lowercase();
        line.contains('=') && line.split([',', '=']).skip(1).any(|part| part.trim() == adb)
    })
}

/// An INF file's text: UTF-16 with its byte order mark, as Windows' own are,
/// or 8-bit text.
fn inf_text_of(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => {
            let (pairs, _) = rest.as_chunks::<2>();
            let units: Vec<u16> = pairs.iter().map(|&pair| u16::from_le_bytes(pair)).collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Whether `name` is a name Windows gives the INFs it keeps (`oemNN.inf`):
/// nothing else is ever removed.
fn is_published_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower
        .strip_prefix("oem")
        .and_then(|rest| rest.strip_suffix(".inf"))
        .is_some_and(|number| !number.is_empty() && number.len() <= 5 && number.bytes().all(|b| b.is_ascii_digit()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn parse_thumbprint(text: &str) -> Option<[u8; 20]> {
    if text.len() != 40 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 20];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn remove_if_there(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn failed(step: &'static str, source: io::Error) -> DriverError {
    DriverError::Failed { step, source }
}

fn step(step: &'static str) -> impl FnOnce(io::Error) -> DriverError {
    move |source| failed(step, source)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, env};

    use super::*;
    use crate::package::{CERTIFICATE_NAME, OS_ATTRIBUTE};

    #[test]
    fn only_an_interface_without_a_driver_is_given_one() {
        assert_eq!(driver_state(Some(CM_PROB_FAILED_INSTALL), false), Driver::NoneFound, "code 28: no driver");
        assert_eq!(driver_state(Some(CM_PROB_FAILED_INSTALL), true), Driver::NoneFound);
        assert_eq!(driver_state(None, false), Driver::NoneYet, "none and no problem: Windows may be at it");
        assert_eq!(driver_state(Some(1), false), Driver::NoneYet, "not set up yet");
        assert_eq!(driver_state(None, true), Driver::LeftAlone, "a working driver is never touched");
        assert_eq!(driver_state(Some(10), true), Driver::LeftAlone, "nor one that fails to start");
        assert_eq!(driver_state(Some(CM_PROB_DISABLED), false), Driver::LeftAlone, "nor a device someone turned off");
        // One with none yet waits while Windows is setting devices up.
        assert!(waiting(Driver::NoneFound, true) && waiting(Driver::NoneFound, false));
        assert!(!waiting(Driver::NoneYet, true) && waiting(Driver::NoneYet, false));
        assert!(!waiting(Driver::LeftAlone, true) && !waiting(Driver::LeftAlone, false));
    }

    #[test]
    fn detection_tells_none_working_being_set_up_and_missing_apart() {
        let interface = |id: &str, driver| devices::AdbInterface { id: id.into(), driver };
        for busy in [false, true] {
            assert_eq!(detection(&[], busy), Detection::None);
            assert_eq!(detection(&[interface("A", Driver::LeftAlone)], busy), Detection::Working);
            assert_eq!(
                detection(&[interface("A", Driver::LeftAlone), interface("B", Driver::NoneFound)], busy),
                Detection::Missing(vec!["B".into()])
            );
        }
        // In the first seconds after a phone is plugged in, an interface
        // with no driver yet is Windows' to set up.
        let fresh = [interface("A", Driver::LeftAlone), interface("C", Driver::NoneYet)];
        assert_eq!(detection(&fresh, true), Detection::BeingSetUp);
        assert_eq!(detection(&fresh, false), Detection::Missing(vec!["C".into()]));
        // One Windows found none for still counts while it sets up another.
        assert_eq!(
            detection(&[interface("B", Driver::NoneFound), interface("C", Driver::NoneYet)], true),
            Detection::Missing(vec!["B".into()])
        );
    }

    #[test]
    fn leftovers_are_whatever_the_install_kept_does_not_name() {
        let (kept, older) = ([1u8; 20], [2u8; 20]);
        let keep = Record { inf: Some("oem7.inf".into()), thumbprint: Some(hex(&kept)), version: None };
        let (infs, certificates) = not_kept(vec!["OEM7.INF".into(), "oem12.inf".into()], vec![kept, older], &keep);
        assert_eq!(infs, ["oem12.inf"]);
        assert_eq!(certificates, [older]);
        // Nothing kept: everything goes.
        let (infs, certificates) = not_kept(vec!["oem7.inf".into()], vec![kept], &Record::default());
        assert_eq!(infs, ["oem7.inf"]);
        assert_eq!(certificates, [kept]);
    }

    #[test]
    fn what_captun_left_is_found_without_administrator_rights() {
        // Read only: Windows' INF folder and the machine's two stores.
        for name in devices::ours_in_store().unwrap() {
            assert!(is_published_name(&name) && devices::is_ours(&name), "{name}");
        }
        let certificates = store::captuns().unwrap();
        eprintln!(
            "certificates of Captun's here: {}",
            certificates.iter().map(|t| hex(t)).collect::<Vec<_>>().join(", ")
        );
    }

    #[test]
    fn the_driver_store_keeps_its_own_copy_of_each_inf_windows_published() {
        let folder = system::windows_folder().unwrap().join("INF");
        let published = fs::read_dir(&folder)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .find(|path| path.file_name().and_then(|name| name.to_str()).is_some_and(is_published_name));
        let Some(published) = published else {
            eprintln!("skipped: Windows keeps no INF of another maker here");
            return;
        };
        let stored = devices::driver_store_path(&published).unwrap();
        assert!(stored.to_string_lossy().to_ascii_lowercase().contains(r"\driverstore\"), "{}", stored.display());
        assert_eq!(fs::read(&stored).unwrap(), fs::read(&published).unwrap(), "{}", stored.display());
    }

    #[test]
    fn windows_own_winusb_inf_is_read_for_an_adb_line() {
        // As the newest Windows builds' winusb.inf has it: UTF-16 with a BOM.
        let newest = concat!(
            "[Generic.Section.NTamd64]\r\n",
            r"%USB\MS_COMP_WINUSB.DeviceDesc% = WINUSB,USB\MS_COMP_WINUSB",
            "\r\n",
            r"%USB\MS_COMP_ADB.DeviceDesc% = ADB,USB\Class_ff&SubClass_42&Prot_01",
            "\r\n",
        );
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(newest.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(inf_text_of(&bytes), newest);
        assert!(lists_adb(&inf_text_of(&bytes)));
        // Older ones give WinUSB to devices that ask for it, not to every
        // ADB interface.
        assert!(!lists_adb(concat!(
            "[Generic.Section.NTamd64]\r\n",
            r"%USB\MS_COMP_WINUSB.DeviceDesc% = WINUSB,USB\MS_COMP_WINUSB",
        )));
        // A comment or a section's name binds nothing.
        assert!(!lists_adb(concat!(
            r"; USB\Class_FF&SubClass_42&Prot_01",
            "\r\n",
            r"[USB\Class_FF&SubClass_42&Prot_01]"
        )));
        assert!(lists_adb(&inf_text()));
        assert_eq!(inf_text_of(b"plain"), "plain");
    }

    #[test]
    fn only_names_windows_gives_its_infs_count_as_published() {
        for good in ["oem0.inf", "oem12.inf", "OEM123.INF"] {
            assert!(is_published_name(good), "{good}");
        }
        for bad in ["oem.inf", "oem12.inf.bak", r"..\oem12.inf", "oem1a.inf", "captun_adb.inf", "oem123456.inf", ""] {
            assert!(!is_published_name(bad), "{bad}");
        }
    }

    #[test]
    fn thumbprints_go_to_text_and_back() {
        let bytes: [u8; 20] = std::array::from_fn(|i| u8::try_from(i * 13).unwrap());
        let text = hex(&bytes);
        assert_eq!(text.len(), 40);
        assert_eq!(parse_thumbprint(&text), Some(bytes));
        assert_eq!(parse_thumbprint(&text.to_lowercase()), Some(bytes));
        assert_eq!(parse_thumbprint(&text[..38]), None);
        assert_eq!(parse_thumbprint(&format!("{}zz", &text[..38])), None);
    }

    /// Every key file Windows' key stores hold that this account can see:
    /// CNG and older CryptoAPI keys, the account's own and the machine's.
    fn key_files() -> BTreeSet<PathBuf> {
        fn walk(dir: &Path, out: &mut BTreeSet<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else { return };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.insert(path);
                }
            }
        }
        let mut out = BTreeSet::new();
        for (root, below) in [
            ("APPDATA", r"Microsoft\Crypto\Keys"),
            ("APPDATA", r"Microsoft\Crypto\RSA"),
            ("ProgramData", r"Microsoft\Crypto\Keys"),
            ("ProgramData", r"Microsoft\Crypto\RSA"),
            ("ProgramData", r"Microsoft\Crypto\SystemKeys"),
        ] {
            if let Some(root) = env::var_os(root) {
                walk(&Path::new(&root).join(below), &mut out);
            }
        }
        out
    }

    /// A fresh test folder under the temp folder, if its path is one the
    /// catalog tools can read.
    fn test_folder(name: &str) -> Option<PathBuf> {
        let dir = env::temp_dir().join(format!("captun-usbdriver-{name}-{}", std::process::id()));
        if dir.to_str().and_then(cdf_text).is_none() {
            eprintln!("skipped: the temp folder {} is not a plain ASCII path", dir.display());
            return None;
        }
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Some(dir)
    }

    #[test]
    fn a_package_is_signed_by_a_one_off_certificate_whose_key_is_left_nowhere() {
        let Some(dir) = test_folder("build") else { return };
        let keys_before = key_files();
        let package = build_package(&dir).unwrap();
        let keys_after = key_files();
        let new_keys: Vec<_> = keys_after.difference(&keys_before).collect();
        assert!(new_keys.is_empty(), "no key container or key file is left behind: {new_keys:?}");

        // The INF and its signed catalog, nothing else. The INF ends with a
        // line of its own copy.
        assert!(package.inf.is_file() && package.catalog.is_file());
        let mut names: Vec<String> =
            fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, [CAT_NAME, INF_NAME]);
        let written = fs::read_to_string(&package.inf).unwrap();
        let copy = written.strip_prefix(&inf_text()).and_then(|rest| rest.strip_prefix(COPY_LINE)).unwrap();
        assert!(copy.len() == 18 && copy.ends_with("\r\n") && copy[..16].bytes().all(|b| b.is_ascii_hexdigit()));

        // The catalog lists the INF as Windows hashes it, for the Windows
        // versions, and is signed by the certificate made for it, alone.
        let facts = catalog::read(&package.catalog).unwrap();
        let hash = catalog::windows_hash(&package.inf).unwrap();
        assert!(facts.members.iter().any(|m| m.eq_ignore_ascii_case(&hash)), "{hash} in {:?}", facts.members);
        assert_eq!(facts.os_attribute.as_deref(), Some(OS_ATTRIBUTE));
        assert_eq!(facts.signers, [(package.certificate.clone(), catalog::SHA256.to_owned())]);

        // The certificate: named for what it is, made by itself, good for
        // signing code and nothing else. What leaves here is its encoded
        // bytes alone, which lead to no key (that the key itself is
        // destroyed is checked in `sign`'s tests).
        let certificate = store::describe(&package.certificate).unwrap();
        assert_eq!(certificate.subject, CERTIFICATE_NAME);
        assert_eq!(certificate.issuer, CERTIFICATE_NAME);
        assert_eq!(certificate.usages, ["1.3.6.1.5.5.7.3.3"]);
        assert!(!certificate.has_private_key);
        assert_eq!(package.thumbprint, hex(&store::thumbprint(&package.certificate).unwrap()));

        // A second package gets a certificate, and an INF, of its own.
        let other = test_folder("build-again").unwrap();
        let again = build_package(&other).unwrap();
        assert_ne!(again.thumbprint, package.thumbprint);
        assert_ne!(fs::read(&again.inf).unwrap(), fs::read(&package.inf).unwrap());
        assert!(key_files().difference(&keys_before).next().is_none());

        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(other);
    }

    #[test]
    fn windows_takes_the_certificate_for_signing_code_once_it_is_trusted() {
        // Its usages, and that it may not vouch for other certificates (both
        // marked critical), must not stop Windows from taking it as the
        // root of the driver's signature. Checked in memory, with this
        // certificate the only one trusted, so nothing hides behind the
        // "untrusted root" this computer would report.
        let Some(dir) = test_folder("chain") else { return };
        let package = build_package(&dir).unwrap();
        let (chain, code_signing, base) = store::problems_once_trusted(&package.certificate).unwrap();
        assert_eq!(chain, 0, "problems in the chain: {chain:#x}");
        assert_eq!(code_signing, 0, "the code-signing policy says {code_signing:#x}");
        assert_eq!(base, 0, "the base policy says {base:#x}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_catalog_of_another_inf_or_signer_is_refused() {
        let Some(dir) = test_folder("check") else { return };
        let package = build_package(&dir).unwrap();
        let other = dir.join("other.inf");
        fs::write(&other, "; not the INF the catalog lists\r\n").unwrap();
        assert!(catalog::check(&other, &package.catalog, &package.certificate).is_err());
        let mut certificate = package.certificate.clone();
        let last = certificate.len() - 1;
        certificate[last] ^= 1;
        assert!(catalog::check(&package.inf, &package.catalog, &certificate).is_err());
        assert!(catalog::check(&package.inf, &package.catalog, &package.certificate).is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_computer_with_no_phone_has_none_waiting_for_a_driver() {
        let found = detect().unwrap();
        let plugged_in = devices::adb_interfaces().unwrap();
        eprintln!("Windows binds every ADB interface itself here: {}", devices::windows_binds_adb());
        if plugged_in.is_empty() {
            assert_eq!(found, Detection::None);
        } else {
            // A phone is plugged in: what it reports must match it.
            eprintln!("a phone is plugged in, so this checks it instead: {plugged_in:?}");
            assert_eq!(found, detection(&plugged_in, devices::windows_busy(0)));
            assert_ne!(found, Detection::None);
        }
    }

    /// Changes this computer's certificate and driver stores (and puts back
    /// what it found), so it runs only when asked, from an elevated prompt:
    /// `cargo test -p captun-usbdriver -- --ignored`.
    #[test]
    #[ignore = "needs an elevated prompt; adds to and removes from this computer's certificate and driver stores"]
    fn the_stores_take_the_package_and_give_it_back() {
        /// Takes out again whatever the test put in, even when it fails.
        struct Undo {
            thumbprint: [u8; 20],
            published: Option<String>,
            record: Option<Record>,
            installed: bool,
        }
        impl Drop for Undo {
            fn drop(&mut self) {
                if let Some(published) = self.published.take().filter(|name| devices::is_ours(name)) {
                    let _ = devices::remove_from_store(&published);
                }
                let _ = store::remove(&self.thumbprint);
                if let Some(record) = self.record.take() {
                    let _ = record::write(&record);
                }
                if self.installed {
                    let _ = remove();
                }
            }
        }

        assert!(is_elevated(), "run this from an elevated prompt");
        let _quiet = devices::Quiet::new();

        // A folder only SYSTEM and Administrators can change.
        let folder = system::PrivateFolder::new().unwrap();
        let package = build_package(folder.path()).unwrap();
        let thumbprint = parse_thumbprint(&package.thumbprint).unwrap();
        let mut undo = Undo { thumbprint, published: None, record: None, installed: false };

        store::add(&package.certificate).unwrap();
        assert!(store::trusts(&thumbprint).unwrap());
        assert!(store::captuns().unwrap().contains(&thumbprint));
        let published = devices::add_to_store(&package.inf).unwrap();
        undo.published = Some(published.clone());
        assert!(is_published_name(&published) && devices::is_ours(&published), "{published}");
        assert!(devices::ours_in_store().unwrap().iter().any(|name| name.eq_ignore_ascii_case(&published)));
        devices::remove_from_store(&published).unwrap();
        assert!(!devices::is_ours(&published));
        assert_eq!(store::remove(&thumbprint).unwrap(), 2, "one in Root, one in TrustedPublisher");
        assert!(!store::trusts(&thumbprint).unwrap());
        drop(folder);

        // The record of what was installed reads back, and is put back.
        let found = record::read().unwrap();
        undo.record = Some(found.clone());
        let test = Record {
            inf: Some("oem99999.inf".into()),
            thumbprint: Some(package.thumbprint.clone()),
            version: Some(DRIVER_VERSION.into()),
        };
        record::write(&test).unwrap();
        assert_eq!(record::read().unwrap(), test);
        record::write(&found).unwrap();
        assert_eq!(record::read().unwrap(), found);
        undo.record = None;

        // The whole round, where Captun's driver is not installed for real.
        let only = |record: &Record| {
            let infs = devices::ours_in_store().unwrap();
            assert_eq!(infs.len(), 1, "{infs:?}");
            assert!(record.inf.as_deref().is_some_and(|inf| inf.eq_ignore_ascii_case(&infs[0])), "{record:?}");
            let thumbprint = record.thumbprint.as_deref().and_then(parse_thumbprint).unwrap();
            assert_eq!(store::captuns().unwrap(), [thumbprint]);
        };
        if found.is_empty() && devices::windows_binds_adb() {
            // Windows brings its own: nothing of Captun's goes in.
            assert!(matches!(install().unwrap(), Install::WindowsHasOne(_)));
            assert!(record::read().unwrap().is_empty());
            assert!(devices::ours_in_store().unwrap().is_empty() && store::captuns().unwrap().is_empty());
        } else if found.is_empty() {
            undo.installed = true;
            assert!(matches!(install().unwrap(), Install::Installed(_)));
            let first = record::read().unwrap();
            assert!(intact(&first), "{first:?}");
            only(&first);
            assert!(matches!(install().unwrap(), Install::AlreadyInstalled(_)));
            assert_eq!(record::read().unwrap(), first);
            // A different package installed before is replaced: the new one
            // goes in first, then the old one comes out.
            record::write(&Record { version: Some("0.0.0.1".into()), ..first.clone() }).unwrap();
            assert!(matches!(install().unwrap(), Install::Installed(_)));
            let second = record::read().unwrap();
            assert!(intact(&second) && second.thumbprint != first.thumbprint, "{second:?}");
            only(&second);
            // What nothing notes (an install stopped part way) is found and
            // removed all the same.
            record::clear().unwrap();
            assert!(matches!(remove().unwrap(), Remove::Removed { .. }));
            assert!(record::read().unwrap().is_empty());
            assert!(devices::ours_in_store().unwrap().is_empty() && store::captuns().unwrap().is_empty());
            assert_eq!(remove().unwrap(), Remove::NothingInstalled);
            undo.installed = false;
        }
    }
}
