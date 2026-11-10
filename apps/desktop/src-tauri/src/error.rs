use captun_ipc::{CallError, ErrorCode, PROTOCOL_VERSION, Response};
use serde::Serialize;

/// What answered on the service's pipe could not prove it is the service.
pub(crate) const NOT_THE_SERVICE: &str =
    "Another program answered instead of the Captun service, so Captun did not send it anything.";

/// Error codes the webview sees. The first group mirrors the service's
/// `ErrorCode`; the rest describe problems on the GUI side of the pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorKind {
    Unauthorized,
    BadRequest,
    InvalidConfig,
    NotFound,
    Unsupported,
    HotspotFailed,
    Internal,
    NotConnected,
    Transport,
    Timeout,
    LaunchFailed,
}

impl From<ErrorCode> for ErrorKind {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::Unauthorized => Self::Unauthorized,
            ErrorCode::BadRequest => Self::BadRequest,
            ErrorCode::InvalidConfig => Self::InvalidConfig,
            ErrorCode::NotFound => Self::NotFound,
            ErrorCode::Unsupported => Self::Unsupported,
            ErrorCode::HotspotFailed => Self::HotspotFailed,
            ErrorCode::Internal => Self::Internal,
        }
    }
}

/// Serialized to JS as `{ code, message }`. Service messages (notably config
/// validation errors) are passed through verbatim so the user sees exactly
/// what the service rejected.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct CommandError {
    pub(crate) code: ErrorKind,
    pub(crate) message: String,
}

impl CommandError {
    pub(crate) fn new(code: ErrorKind, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub(crate) fn not_connected() -> Self {
        Self::new(ErrorKind::NotConnected, "Not connected to the Captun service.")
    }

    /// The service answered with a different `Response` variant than the
    /// request calls for, which means the GUI and service disagree on the protocol.
    pub(crate) fn unexpected(response: &Response) -> Self {
        Self::new(ErrorKind::Internal, format!("Unexpected response from the service: {response:?}"))
    }
}

impl From<CallError> for CommandError {
    fn from(e: CallError) -> Self {
        match e {
            CallError::Service(err) => Self::new(err.code.into(), err.message),
            CallError::Disconnected => Self::not_connected(),
            CallError::Timeout => Self::new(ErrorKind::Timeout, e.to_string()),
            CallError::NotTheService => Self::new(ErrorKind::Transport, NOT_THE_SERVICE),
            CallError::OlderService => Self::new(ErrorKind::Transport, "An older Captun service is running."),
            CallError::VersionMismatch { service } if service > PROTOCOL_VERSION => {
                Self::new(ErrorKind::Transport, "A newer Captun service is running. Open the newer Captun app.")
            }
            CallError::VersionMismatch { .. } => Self::new(ErrorKind::Transport, "An older Captun service is running."),
            CallError::Io(_) | CallError::Frame(_) | CallError::Handshake(_) => Self::new(ErrorKind::Transport, e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_posing_as_the_service_is_named_in_plain_words() {
        let error = CommandError::from(CallError::NotTheService);
        assert_eq!(error.code, ErrorKind::Transport);
        assert_eq!(
            error.message,
            "Another program answered instead of the Captun service, so Captun did not send it anything."
        );
        let newer = CommandError::from(CallError::VersionMismatch { service: PROTOCOL_VERSION + 1 });
        assert!(newer.message.starts_with("A newer Captun service"), "{}", newer.message);
        let older = CommandError::from(CallError::OlderService);
        assert!(older.message.starts_with("An older Captun service"), "{}", older.message);
    }
}
