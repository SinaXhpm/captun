use std::io;

use async_trait::async_trait;
use captun_core::{EgressId, TargetAddr};

use crate::{BoxStream, Outbound, UdpSession};

/// Refuses everything. Used for `type = "block"` egresses.
#[derive(Debug)]
pub struct Block {
    id: EgressId,
}

impl Block {
    pub fn new(id: EgressId) -> Self {
        Self { id }
    }
}

#[async_trait]
impl Outbound for Block {
    fn id(&self) -> &EgressId {
        &self.id
    }

    async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxStream> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("egress {} blocks all traffic", self.id)))
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("egress {} blocks all traffic", self.id)))
    }
}

/// Stands in for an egress that cannot work right now: its interface is
/// missing, or the Xray sidecar is down. Failing closed here is what makes the
/// per-client kill switch hold, since traffic never falls back to another route.
#[derive(Debug)]
pub struct Unavailable {
    id: EgressId,
    reason: String,
}

impl Unavailable {
    pub fn new(id: EgressId, reason: impl Into<String>) -> Self {
        Self { id, reason: reason.into() }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    fn error(&self) -> io::Error {
        io::Error::new(io::ErrorKind::NotConnected, format!("egress {} is unavailable: {}", self.id, self.reason))
    }
}

#[async_trait]
impl Outbound for Unavailable {
    fn id(&self) -> &EgressId {
        &self.id
    }

    async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxStream> {
        Err(self.error())
    }

    async fn udp_session(&self) -> io::Result<Box<dyn UdpSession>> {
        Err(self.error())
    }
}
