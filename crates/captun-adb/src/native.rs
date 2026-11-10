//! The built-in adb: a native USB transport so Captun needs no external `adb`
//! binary and no Android platform-tools installed.
//!
//! Devices are enumerated straight from libusb (reading the USB serial string
//! descriptor, which needs no ADB handshake and so never blocks on an
//! "Allow USB debugging?" prompt). Operations open an authenticated ADB session
//! through [`adb_client`], which speaks the ADB wire protocol (CNXN/AUTH with an
//! RSA key) over the device's bulk endpoints.
//!
//! All of this is blocking (libusb is synchronous); the async [`crate::Adb`]
//! runner drives it on a blocking thread with a timeout.

use std::path::Path;

use adb_client::{
    ADBDeviceExt, RustADBError,
    usb::{ADBUSBDevice, USBTransport},
};
use rusb::{Context, Device, DeviceDescriptor, UsbContext, constants::LIBUSB_CLASS_VENDOR_SPEC};

use crate::{
    device::{AdbDevice, DeviceState},
    runner::AdbError,
};

/// Interface class/subclass/protocol that mark a USB interface as ADB. Mirrors
/// what adbd and the platform-tools look for.
const ADB_SUBCLASS: u8 = 0x42;
const ADB_PROTOCOL: u8 = 0x01;
/// Some devices expose ADB under a "bulk" vendor class instead.
const BULK_CLASS: u8 = 0xdc;
const BULK_ADB_SUBCLASS: u8 = 0x02;

/// Lists every connected device that presents an ADB interface. Reads the serial
/// and model from USB string descriptors only — no ADB session, so it is fast
/// and does not raise the phone's authorization prompt. A device we can see but
/// not open (a driver or permission problem) is still listed, marked
/// [`DeviceState::NoPermissions`].
pub(crate) fn enumerate() -> Result<Vec<AdbDevice>, AdbError> {
    let context = Context::new().map_err(usb_err)?;
    let mut devices = Vec::new();
    for device in context.devices().map_err(usb_err)?.iter() {
        let Ok(desc) = device.device_descriptor() else { continue };
        if !is_adb_interface(&device, &desc) {
            continue;
        }
        devices.push(describe(&device, &desc));
    }
    Ok(devices)
}

/// Runs one shell command on the device and returns its stdout. A non-zero exit
/// becomes [`AdbError::Command`] carrying stderr (or stdout, if the command put
/// its message there).
pub(crate) fn run_shell(serial: &str, key: &Path, command: &str) -> Result<String, AdbError> {
    let mut device = open(serial, key)?;
    let command = command.to_owned();
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let code = device
        .shell_command(&command, Some(&mut stdout), Some(&mut stderr))
        .map_err(map_err)?;
    if matches!(code, Some(code) if code != 0) {
        let mut message = String::from_utf8_lossy(&stderr).trim().to_owned();
        if message.is_empty() {
            message = String::from_utf8_lossy(&stdout).trim().to_owned();
        }
        return Err(AdbError::Command { command, stderr: message });
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Installs an APK onto the device.
pub(crate) fn install(serial: &str, key: &Path, apk_path: &str) -> Result<(), AdbError> {
    let mut device = open(serial, key)?;
    device.install(&apk_path, None).map_err(map_err)
}

/// Opens an authenticated ADB session to the device with the given serial. If no
/// serial matches but exactly one ADB device is present, that one is used.
fn open(serial: &str, key: &Path) -> Result<ADBUSBDevice, AdbError> {
    let context = Context::new().map_err(usb_err)?;
    let mut only: Option<Device<Context>> = None;
    let mut count = 0usize;
    let mut chosen: Option<Device<Context>> = None;
    for device in context.devices().map_err(usb_err)?.iter() {
        let Ok(desc) = device.device_descriptor() else { continue };
        if !is_adb_interface(&device, &desc) {
            continue;
        }
        count += 1;
        if serial_of(&device, &desc) == serial {
            chosen = Some(device);
            break;
        }
        only = Some(device);
    }
    let device = match (chosen, count, only) {
        (Some(device), _, _) => device,
        (None, 1, Some(device)) => device,
        _ => return Err(AdbError::DeviceNotFound(serial.to_owned())),
    };
    let transport = USBTransport::new_from_device(device);
    ADBUSBDevice::new_from_transport(transport, Some(key.to_path_buf())).map_err(map_err)
}

/// Reads the USB serial, falling back to a stable `vid:pid` synthetic id when the
/// device exposes no serial string (or we cannot open it to read one).
fn serial_of(device: &Device<Context>, desc: &DeviceDescriptor) -> String {
    device
        .open()
        .ok()
        .and_then(|handle| handle.read_serial_number_string_ascii(desc).ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| synthetic_serial(desc))
}

fn synthetic_serial(desc: &DeviceDescriptor) -> String {
    format!("{:04x}:{:04x}", desc.vendor_id(), desc.product_id())
}

/// Builds the GUI-facing device record from USB descriptors.
fn describe(device: &Device<Context>, desc: &DeviceDescriptor) -> AdbDevice {
    match device.open() {
        Ok(handle) => {
            let serial = handle
                .read_serial_number_string_ascii(desc)
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| synthetic_serial(desc));
            let model = handle.read_product_string_ascii(desc).ok().filter(|s| !s.is_empty());
            AdbDevice { serial, state: DeviceState::Device, model, product: None, device: None, transport_id: None }
        }
        // Visible over USB but not openable: on Windows this is usually a missing
        // or wrong USB driver; on Linux a udev-permission problem.
        Err(_) => AdbDevice {
            serial: synthetic_serial(desc),
            state: DeviceState::NoPermissions,
            model: None,
            product: None,
            device: None,
            transport_id: None,
        },
    }
}

/// Whether any of the device's interfaces is an ADB interface.
fn is_adb_interface(device: &Device<Context>, desc: &DeviceDescriptor) -> bool {
    for n in 0..desc.num_configurations() {
        let Ok(config) = device.config_descriptor(n) else { continue };
        for interface in config.interfaces() {
            for alt in interface.descriptors() {
                let (class, sub, proto) = (alt.class_code(), alt.sub_class_code(), alt.protocol_code());
                if proto == ADB_PROTOCOL
                    && ((class == LIBUSB_CLASS_VENDOR_SPEC && sub == ADB_SUBCLASS)
                        || (class == BULK_CLASS && sub == BULK_ADB_SUBCLASS))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn usb_err(e: rusb::Error) -> AdbError {
    AdbError::Usb(e.to_string())
}

/// Maps an `adb_client` error onto our error, keeping the "another adb owns the
/// device" case distinct so the user gets actionable advice.
fn map_err(e: RustADBError) -> AdbError {
    match e {
        RustADBError::DeviceBusy => AdbError::Busy,
        RustADBError::DeviceNotFound(msg) => AdbError::DeviceNotFound(msg),
        other => AdbError::Adb(other.to_string()),
    }
}
