//! The operations Captun performs on a phone, and reversible plans built from
//! them. Operations are transport-agnostic: the native [`crate::Adb`] runner
//! executes each one over the built-in USB ADB session. Keeping them as pure
//! data means a test can assert on exactly what a plan would do without a phone
//! attached.

use std::path::PathBuf;

/// One adb operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdbOp {
    /// Run a shell command on the device.
    Shell(String),
    /// Install an APK from this PC onto the device.
    Install(PathBuf),
    /// Uninstall a package from the device.
    Uninstall(String),
}

impl AdbOp {
    /// A shell operation from anything string-like.
    pub fn shell(command: impl Into<String>) -> Self {
        Self::Shell(command.into())
    }

    /// A human-readable one-liner for logs and the UI.
    pub fn display(&self) -> String {
        match self {
            Self::Shell(command) => format!("shell: {command}"),
            Self::Install(apk) => format!("install {}", apk.display()),
            Self::Uninstall(package) => format!("uninstall {package}"),
        }
    }
}

/// A set of operations and the operations that undo them. `revert` is ordered so
/// it is safe to run even if `apply` only partially succeeded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReversiblePlan {
    pub apply: Vec<AdbOp>,
    pub revert: Vec<AdbOp>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_readable() {
        assert_eq!(AdbOp::shell("svc usb setFunctions").display(), "shell: svc usb setFunctions");
        assert_eq!(AdbOp::Uninstall("org.x".into()).display(), "uninstall org.x");
    }
}
