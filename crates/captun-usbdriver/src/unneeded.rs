//! macOS and Linux reach a phone's USB debugging interface without any
//! driver of Captun's, so there is nothing to install, remove or look for.

use crate::{Detection, DriverError, Install, Remove};

pub(crate) fn install() -> Result<Install, DriverError> {
    Ok(Install::NotNeeded)
}

pub(crate) fn remove() -> Result<Remove, DriverError> {
    Ok(Remove::NotNeeded)
}

pub(crate) fn detect() -> Result<Detection, DriverError> {
    Ok(Detection::None)
}
