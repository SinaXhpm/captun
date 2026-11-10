//! Egress connectors. Every way out of the hub, whether a pinned interface, a
//! proxy, or a proxy reached through another proxy, implements [`Outbound`], so
//! the data plane and the DNS forwarder never care which one a client uses.

mod block;
mod direct;
mod fetch;
mod http;
mod prefixed;
mod set;
mod socks5;
mod sys;
mod tls;

use std::{fmt, io, time::Duration};

use async_trait::async_trait;
use captun_core::{EgressId, Secret, TargetAddr};
use tokio::io::{AsyncRead, AsyncWrite};

pub use block::{Block, Unavailable};
pub use direct::{Direct, InterfaceBinding};
pub use fetch::fetch;
pub use http::HttpConnect;
pub use prefixed::PrefixedStream;
pub use set::{OutboundEnv, OutboundSet, XrayEndpoint};
pub use socks5::Socks5;

/// Upper bound for a proxy handshake once the TCP connection is up.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncStream for T {}

pub type BoxStream = Box<dyn AsyncStream>;

#[async_trait]
pub trait Outbound: Send + Sync + fmt::Debug {
    fn id(&self) -> &EgressId;

    /// Opens a TCP stream to `target`. Domain targets are resolved by the
    /// egress itself, so a proxy resolves them remotely.
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream>;

    /// Opens a UDP association. Fails with `Unsupported` on TCP-only egresses.
    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>>;

    /// Opens a UDP association whose datagrams all go to `target`, so an
    /// egress can open only what that needs (one socket rather than one per
    /// address family). Sending elsewhere through it may fail.
    async fn udp_session_to(&self, target: &TargetAddr) -> io::Result<Box<dyn UdpSession>> {
        let _ = target;
        self.udp_session().await
    }

    /// Whether connections start on this computer, names looked up by its own
    /// resolver, rather than on a proxy's side. Only then can a download look
    /// a redirect's name up itself, to check where it really leads.
    fn connects_from_here(&self) -> bool {
        false
    }
}

#[async_trait]
pub trait UdpSession: Send + Sync + fmt::Debug {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()>;

    /// Receives one datagram and reports who sent it.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)>;
}

/// Username/password for SOCKS5 (RFC 1929) and HTTP Basic proxy auth.
#[derive(Clone, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: Secret,
}

pub(crate) fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{what} timed out"))
}
