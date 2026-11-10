//! Pure builders for the individual adb shell commands Captun sends. Each is a
//! plain function returning the command string, so a test can assert on it
//! without a phone attached.

/// The USB gadget function to switch the phone to. Both expose the phone's data
/// connection to the PC as a network interface; NCM is the newer, faster one and
/// is preferred on recent Android, with RNDIS as the broadly-compatible
/// fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbFunction {
    Rndis,
    Ncm,
}

impl UsbFunction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Rndis => "rndis",
            Self::Ncm => "ncm",
        }
    }
}

/// `svc usb setFunctions <func>,adb`: expose the phone's data as a NIC while
/// keeping the ADB interface alive, so Captun does not lose control when the
/// USB gadget reconfigures.
pub(crate) fn set_usb_function_cmd(function: UsbFunction) -> String {
    format!("svc usb setFunctions {},adb", function.as_str())
}

/// `svc usb setFunctions` with no function: restore the default USB mode.
pub(crate) fn reset_usb_function_cmd() -> String {
    "svc usb setFunctions".to_owned()
}

/// Points the phone's system HTTP proxy at `host:port`.
pub(crate) fn set_global_proxy_cmd(host: &str, port: u16) -> String {
    format!("settings put global http_proxy {host}:{port}")
}

/// Clears the phone's system HTTP proxy (`:0` is Android's "no proxy").
pub(crate) fn clear_global_proxy_cmd() -> String {
    "settings put global http_proxy :0".to_owned()
}

/// Force-stops a package (used to stop the helper before its tunnel is removed).
pub(crate) fn force_stop_cmd(package: &str) -> String {
    format!("am force-stop {package}")
}

/// `am start -n COMPONENT` (e.g. `com.example/.MainActivity`).
pub(crate) fn start_component_cmd(component: &str) -> String {
    format!("am start -n {component}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_function_keeps_adb_alive() {
        assert_eq!(set_usb_function_cmd(UsbFunction::Rndis), "svc usb setFunctions rndis,adb");
        assert_eq!(set_usb_function_cmd(UsbFunction::Ncm), "svc usb setFunctions ncm,adb");
        assert_eq!(reset_usb_function_cmd(), "svc usb setFunctions");
    }

    #[test]
    fn proxy_clear_uses_androids_no_proxy_sentinel() {
        assert_eq!(set_global_proxy_cmd("192.168.42.238", 8080), "settings put global http_proxy 192.168.42.238:8080");
        assert!(clear_global_proxy_cmd().ends_with(":0"));
    }
}
