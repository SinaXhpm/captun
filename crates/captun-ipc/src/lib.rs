//! Local IPC between the privileged Captun service and the unprivileged GUI.
//!
//! Wire format: one JSON object per line. Each connection opens with
//! [`handshake`]: both sides prove they hold the per-run token that the
//! service wrote to a file only the GUI's user can read, without sending it,
//! and the client sends nothing before the service has proved itself. Then
//! the service answers with [`ServerFrame::Welcome`] and from then on
//! multiplexes responses (matched by request id) and pushed [`Event`]s over
//! the same connection.

mod client;
mod codec;
pub mod handshake;
mod legacy;
mod protocol;
mod token;
mod transport;

pub use client::{CallError, IpcClient};
pub use codec::{FrameError, FrameReader, FrameWriter, split};
pub use protocol::*;
pub use token::{Token, TokenError, TokenFile};
pub use transport::{Endpoint, IpcListener, IpcStream, PipeAccess, connect};
// For the service's own folders on Windows: created with their security from
// the start, or an existing one checked and locked down through its handle.
#[cfg(windows)]
pub use transport::{create_dir_with_sddl, enforce_redirection_trust, open_for_security, owner_sid_of, protect};
