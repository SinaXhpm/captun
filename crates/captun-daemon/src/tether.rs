//! Phone integration glue: the dispatcher that routes a reverse-tethered phone
//! through the policy engine, plus the small pure helpers the hub's tethering
//! operations need (stable phone identity, error and device mapping).

use std::sync::{Arc, Weak};

use captun_adb::{AdbDevice, AdbError, DeviceState, ReverseMethod};
use captun_core::{EgressId, MacAddr};
use captun_engine::{Dispatcher, FlowAction, FlowRequest};
use captun_ipc::{AdbDeviceInfo, ErrorCode, IpcError, ReverseTetherMethod};

use crate::{engine_glue, hub::Hub};

/// Routes every flow arriving on the reverse-tethering proxy inbound as one
/// station — the phone — so its egress, rules and limits apply. Unlike the
/// hotspot dispatcher it ignores the source IP (the connection arrives over the
/// USB network link) and attributes to a fixed MAC instead.
pub(crate) struct ReverseDispatcher {
    hub: Weak<Hub>,
    phone: MacAddr,
}

impl ReverseDispatcher {
    pub(crate) fn new(hub: &Arc<Hub>, phone: MacAddr) -> Self {
        Self { hub: Arc::downgrade(hub), phone }
    }
}

impl Dispatcher for ReverseDispatcher {
    fn needs_domain(&self) -> bool {
        self.hub.upgrade().is_some_and(|hub| hub.policy().needs_domain())
    }

    fn dispatch(&self, request: &FlowRequest<'_>) -> FlowAction {
        let Some(hub) = self.hub.upgrade() else { return FlowAction::Drop };
        if engine_glue::refused_locally(&hub, request) {
            return FlowAction::Reject;
        }
        engine_glue::forward_for(&hub, self.phone, request)
    }

    // The default `dispatch_device` names the phone from the forward; its
    // refused flows are TCP, which end at once.

    fn still_allowed(&self, request: &FlowRequest<'_>, _device: Option<MacAddr>, outbound: &EgressId) -> bool {
        // Gone with the hub: the inbound is stopping anyway.
        let Some(hub) = self.hub.upgrade() else { return true };
        !engine_glue::refused_locally(&hub, request) && engine_glue::still_forwarded(&hub, self.phone, request, outbound)
    }
}

/// A stable, locally-administered MAC derived from the device serial, so the
/// phone keeps the same identity (and profile) across sessions. FNV-1a keeps it
/// deterministic across runs, which `DefaultHasher` would not.
pub(crate) fn phone_mac_from_serial(serial: &str) -> MacAddr {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in serial.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let h = hash.to_be_bytes();
    // Set the locally-administered bit and clear the multicast bit, so it reads
    // as a private unicast address and never collides with a real vendor MAC.
    let first = (h[2] | 0x02) & 0xfe;
    MacAddr::new([first, h[3], h[4], h[5], h[6], h[7]])
}

/// Maps the wire method to the adb crate's method.
pub(crate) fn to_adb_method(method: ReverseTetherMethod) -> ReverseMethod {
    match method {
        ReverseTetherMethod::SystemProxy => ReverseMethod::SystemProxy,
        ReverseTetherMethod::Helper => ReverseMethod::Helper,
    }
}

/// Turns a built-in-adb failure into an IPC error, keeping the actionable cases
/// (a USB/driver problem, another program holding the device) distinct.
pub(crate) fn adb_error(e: AdbError) -> IpcError {
    match e {
        AdbError::Usb(msg) => IpcError::new(
            ErrorCode::Unsupported,
            format!(
                "Captun's built-in adb could not use USB: {msg}. On Windows, install or repair the phone's USB driver (the \"Android ADB Interface\"/Google USB driver); on Linux, check the udev rules."
            ),
        ),
        AdbError::Busy => IpcError::new(
            ErrorCode::BadRequest,
            "The phone is being held by another program over USB — close any running adb server (e.g. run `adb kill-server`, or quit Android Studio/scrcpy), then try again.",
        ),
        AdbError::Timeout => IpcError::new(
            ErrorCode::BadRequest,
            "Timed out talking to the phone. If it shows \"Allow USB debugging?\", tap \"Always allow\" and try again.",
        ),
        other => IpcError::new(ErrorCode::BadRequest, other.to_string()),
    }
}

/// Flattens an adb device into the GUI-facing shape.
pub(crate) fn device_info(device: &AdbDevice) -> AdbDeviceInfo {
    AdbDeviceInfo {
        serial: device.serial.clone(),
        label: device.label(),
        state: state_str(&device.state),
        model: device.model.clone(),
        ready: device.state.is_ready(),
    }
}

fn state_str(state: &DeviceState) -> String {
    match state {
        DeviceState::Device => "device".into(),
        DeviceState::Unauthorized => "unauthorized".into(),
        DeviceState::Offline => "offline".into(),
        DeviceState::NoPermissions => "no_permissions".into(),
        DeviceState::Other(other) => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_mac_is_stable_private_and_distinct() {
        let a = phone_mac_from_serial("RF8M9ABCDEF");
        assert_eq!(a, phone_mac_from_serial("RF8M9ABCDEF"), "same serial, same MAC");
        assert!(a.is_locally_administered());
        assert!(!a.is_multicast());
        assert_ne!(a, phone_mac_from_serial("OTHER_SERIAL"));
    }

    #[test]
    fn device_info_flattens_state() {
        let device = AdbDevice {
            serial: "S1".into(),
            state: DeviceState::Unauthorized,
            model: None,
            product: None,
            device: None,
            transport_id: None,
        };
        let info = device_info(&device);
        assert_eq!(info.state, "unauthorized");
        assert!(!info.ready);
        assert_eq!(info.label, "S1");
    }
}
