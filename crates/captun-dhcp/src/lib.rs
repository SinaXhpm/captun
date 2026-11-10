//! A minimal DHCPv4 server for Captun's wired/USB **access networks** — the
//! shared LANs clients connect to over Ethernet or USB instead of Wi-Fi — and
//! for the Wi-Fi networks Captun runs itself (hosted network, hostapd).
//!
//! Captun assigns the access interface a static gateway address and runs this
//! server on it, so devices that plug in get an address, the gateway, and DNS
//! pointing at Captun's own resolver. Confirmed (ACKed) leases are the source
//! of truth for which devices are present, feeding the same client list and
//! policy engine as the Wi-Fi hotspot.
//!
//! The wire codec ([`message`]) is bounds-checked and never panics on hostile
//! input; the [`LeasePool`] and request handling are unit-tested without a socket.
//! The caller binds the UDP socket to the right interface (so one access network
//! never answers DHCP on another) and enables broadcast. Anyone on the segment
//! can send requests under any MAC, so offers hold an address only briefly, new
//! MACs and replies are rate-limited, and RELEASE/DECLINE only touch the
//! sender's own address.

mod lease;
mod message;
mod server;

pub use lease::{Lease, LeasePool, MAX_POOL_ADDRESSES};
pub use message::{CLIENT_PORT, SERVER_PORT};
pub use server::{Admission, DhcpServer, ServerConfig};
