//! The routing engine: it terminates the TCP and UDP flows that hotspot
//! clients open, decides each one through a [`Dispatcher`] (admission, firewall
//! rules and egress selection), and relays it through the chosen egress while
//! applying per-client bandwidth limits and recording traffic.
//!
//! The engine is split so the decision-and-relay path ([`flow`]) is generic
//! over the client stream and fully tested without a packet device, while
//! [`engine::run`] drives it from a real IP-packet source: TCP through
//! userspace TCP stacks (smoltcp, in [`tcp`]) run side by side ([`shard`]),
//! which answer for every address and recover lost packets on their own
//! timers, UDP through a table of flows ([`udp`]). [`serve_inbound`] drives
//! the same path from a local SOCKS5/HTTP proxy port instead of a packet
//! device, for traffic that arrives already proxied — most notably a phone's
//! system proxy during reverse tethering.

mod control;
mod dispatch;
mod engine;
mod flow;
mod inbound;
mod meter;
mod packet;
mod relay;
mod shard;
mod tcp;
mod udp;

#[cfg(test)]
mod engine_tests;

pub use control::FlowControl;
pub use dispatch::{Dispatcher, FlowAction, FlowRequest, Forward, SourceKey};
pub use engine::{EngineHandle, PacketDevice, run};
pub use inbound::{InboundConfig, InboundProtocols, serve_inbound};
pub use meter::{CounterSnapshot, Counters, Direction, FlowMeter, TrafficMeter};
