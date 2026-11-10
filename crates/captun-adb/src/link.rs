//! The USB network link to the phone (RNDIS/NCM), over which the phone reaches
//! Captun's proxy on this computer for reverse tethering. Captun only ever
//! gives the phone internet through it; the computer side keeps the link off
//! its own routes (see `captun-platform::tether_net`). Resetting the phone's
//! USB mode, or unplugging the cable, takes the link down.

use crate::command::{UsbFunction, reset_usb_function_cmd, set_usb_function_cmd};

/// The shell command that brings the USB network link up, exposed so the daemon
/// can run it with its own tolerance for the brief disconnect that reconfiguring
/// the USB gadget causes.
pub fn link_up_command(function: UsbFunction) -> String {
    set_usb_function_cmd(function)
}

/// The shell command that tears the USB network link down.
pub fn link_down_command() -> String {
    reset_usb_function_cmd()
}

/// What to tell the user when the link does not appear. Some phones only
/// bring it up from their own "USB tethering" switch; this computer still
/// never uses the phone's internet through it.
pub fn link_hint() -> &'static str {
    "If nothing happens within a few seconds, turn on \"USB tethering\" on the phone once, then press Start again. \
     Captun only uses it to reach the phone; this computer never uses the phone's internet."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_commands_switch_the_usb_mode_and_restore_it() {
        assert_eq!(link_up_command(UsbFunction::Rndis), "svc usb setFunctions rndis,adb");
        assert_eq!(link_down_command(), "svc usb setFunctions");
    }

    #[test]
    fn hint_says_the_phone_internet_is_not_used() {
        assert!(link_hint().contains("USB tethering"));
        assert!(link_hint().contains("never uses the phone's internet"));
    }
}
