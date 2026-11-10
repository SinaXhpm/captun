//! Domain model shared by every Captun component: addresses, clients,
//! egress definitions, configuration and its validation.

pub mod addr;
pub mod client;
pub mod config;
pub mod domain;
pub mod egress;
pub mod iface;
pub mod link;
pub mod mac;
pub mod secret;
pub mod time;

pub use addr::TargetAddr;
pub use client::{ClientRegistry, ClientState, ObservedClient, Presence, PresenceChange};
pub use config::Config;
pub use domain::{DomainPattern, DomainSet};
pub use egress::{EgressConfig, EgressId, EgressKind, UdpPolicy};
pub use iface::InterfaceKind;
pub use link::{LinkSummary, ShareLink};
pub use mac::MacAddr;
pub use secret::Secret;
