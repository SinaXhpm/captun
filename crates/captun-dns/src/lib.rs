//! Per-client DNS forwarder for the hotspot.
//!
//! Every query runs through blocklist → overrides → the client's rules →
//! cache → upstream. The upstream is reached through the egress the client's
//! rules pick for the name (an [`Outbound`]), so a client routed through a
//! proxy also resolves through that proxy and its lookups never leak out of
//! the default route.

mod cache;
mod handler;
mod message;
mod reach;
mod server;
mod settings;
mod upstream;

use std::{fmt, net::IpAddr, sync::Arc};

use captun_core::MacAddr;
use captun_outbound::Outbound;

pub use handler::{Admitted, DnsHandler};
pub use server::{DnsServerHandle, serve};
pub use settings::DnsSettings;
pub use upstream::Upstream;

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("dns upstream {id:?}: {reason}")]
    Upstream { id: String, reason: String },
    #[error("cannot set up TLS for DNS upstreams: {0}")]
    Tls(#[from] rustls::Error),
}

/// Where one client's query for one name goes: which configured upstream,
/// and the egress used to reach it.
#[derive(Clone, Debug)]
pub struct DnsRoute {
    pub upstream: String,
    pub outbound: Arc<dyn Outbound>,
    pub client: Option<MacAddr>,
    /// When the upstream cannot be reached, answer address lookups from this
    /// computer's own resolver instead of failing. Meant for devices that go
    /// out directly, as this computer does: a filtered network may block the
    /// upstream itself while the computer's own DNS still works.
    pub system_fallback: bool,
    /// The client's rules block the name: it is answered as blocked.
    pub blocked: bool,
}

/// Maps a query (who asks, for which name) to its route. Implemented by the
/// daemon on top of the client registry and the policy engine.
pub trait DnsRouter: Send + Sync + 'static {
    /// `None` answers the query with REFUSED (unknown or blocked station).
    /// `name` is lowercase, without the trailing dot.
    fn route(&self, client: IpAddr, name: &str) -> Option<DnsRoute>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    NoError,
    NxDomain,
    ServFail,
    Refused,
    Blocked,
    Override,
    Cached,
    /// The upstream could not be reached; this computer's own resolver answered.
    System,
    Failed,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoError => "NOERROR",
            Self::NxDomain => "NXDOMAIN",
            Self::ServFail => "SERVFAIL",
            Self::Refused => "REFUSED",
            Self::Blocked => "BLOCKED",
            Self::Override => "OVERRIDE",
            Self::Cached => "CACHED",
            Self::System => "SYSTEM",
            Self::Failed => "FAILED",
        })
    }
}

/// One answered query, for the live query log in the GUI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryEvent {
    pub at_ms: u64,
    pub client: Option<MacAddr>,
    pub client_ip: IpAddr,
    pub name: String,
    pub qtype: String,
    pub outcome: Outcome,
    pub answers: Vec<String>,
    /// The addresses given in the answer (A and AAAA records), so a later
    /// connection to one of them can be told apart by name.
    pub addrs: Vec<IpAddr>,
    pub upstream: Option<String>,
    pub latency_ms: u32,
}

pub trait QueryObserver: Send + Sync + 'static {
    /// Called once per query on the resolving task, so it must not block.
    fn on_query(&self, event: QueryEvent);
}

/// Transport the query arrived on; only UDP responses are size-limited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}
