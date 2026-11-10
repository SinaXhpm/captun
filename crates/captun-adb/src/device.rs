//! The structured device record Captun shows and operates on. Built by the
//! native USB enumerator in [`crate::native`] from USB descriptors.

use serde::Serialize;

/// The connection state of a device Captun can see over USB.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// Visible and openable over USB; ready for an ADB session (which may still
    /// prompt "Allow USB debugging?" on the phone the first time).
    Device,
    /// Connected, but the user has not accepted this computer's key on the phone
    /// yet. Surfaced from a failed operation, not from enumeration.
    Unauthorized,
    /// Known but currently offline.
    Offline,
    /// Visible over USB but inaccessible — on Windows usually a missing or wrong
    /// USB driver; on Linux a udev-permission problem.
    NoPermissions,
    /// Any other state.
    Other(String),
}

impl DeviceState {
    /// Whether an ADB session can be opened to a device in this state.
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Device)
    }
}

/// One connected device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdbDevice {
    pub serial: String,
    pub state: DeviceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_id: Option<String>,
}

impl AdbDevice {
    /// A friendly label for the UI: the model if known, else the serial.
    /// Underscores in model names are shown as spaces.
    pub fn label(&self) -> String {
        match &self.model {
            Some(model) if !model.is_empty() => model.replace('_', " "),
            _ => self.serial.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_prefers_the_model() {
        let d = AdbDevice {
            serial: "RF8M9ABCDEF".into(),
            state: DeviceState::Device,
            model: Some("Pixel_7".into()),
            product: None,
            device: None,
            transport_id: None,
        };
        assert!(d.state.is_ready());
        assert_eq!(d.label(), "Pixel 7");
    }

    #[test]
    fn label_falls_back_to_serial() {
        let d = AdbDevice {
            serial: "SER1".into(),
            state: DeviceState::NoPermissions,
            model: None,
            product: None,
            device: None,
            transport_id: None,
        };
        assert!(!d.state.is_ready());
        assert_eq!(d.label(), "SER1");
    }
}
