//! The DHCP server loop: answers DISCOVER/REQUEST/RELEASE/DECLINE on a UDP
//! socket the caller has bound to the access-network interface. Replies are
//! broadcast on the local segment (clients have no address yet, and there is
//! no relay).
//!
//! Anyone on the segment can send any number of requests under any MAC, so the
//! server limits how many new MACs get an address (a burst, then one a second)
//! and how many replies it sends a second. On a Wi-Fi network the caller can
//! also pass an admission check, so only devices associated with the access
//! point get an address.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::{
    lease::{Lease, LeasePool},
    message::{self, CLIENT_PORT, DhcpMessage, MessageType, ReplyParams},
};

/// Static answers the server advertises. The gateway doubles as the DHCP server
/// id and the clients' router.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    pub gateway: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    /// DNS server handed to clients (usually the gateway, where Captun's resolver
    /// listens).
    pub dns: Ipv4Addr,
}

/// Decides by MAC whether a device may get an address, consulted for every
/// DISCOVER and REQUEST. It may block for a moment (it can read the access
/// point's station list), so the server calls it off the async threads.
pub type Admission = Arc<dyn Fn([u8; 6]) -> bool + Send + Sync>;

const BROADCAST: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT));

/// New MACs that may get an address at once, then one a second: enough for a
/// room full of devices joining together, too few for a flood of made-up MACs
/// to take the pool.
const NEW_MAC_BURST: u32 = 64;
const NEW_MAC_EVERY_MS: u64 = 1000;
/// Replies sent at once, then one every 10 ms (100 a second).
const REPLY_BURST: u32 = 200;
const REPLY_EVERY_MS: u64 = 10;

/// A token bucket on the server's millisecond clock.
#[derive(Debug)]
struct Bucket {
    capacity: u32,
    every_ms: u64,
    tokens: u32,
    last_ms: u64,
}

impl Bucket {
    fn new(capacity: u32, every_ms: u64, now_ms: u64) -> Self {
        Self { capacity, every_ms, tokens: capacity, last_ms: now_ms }
    }

    fn refill(&mut self, now_ms: u64) {
        // The wall clock can step back; start counting again from there.
        if now_ms < self.last_ms {
            self.last_ms = now_ms;
            return;
        }
        let earned = (now_ms - self.last_ms) / self.every_ms.max(1);
        if earned == 0 {
            return;
        }
        let tokens = u64::from(self.tokens).saturating_add(earned);
        if tokens >= u64::from(self.capacity) {
            self.tokens = self.capacity;
            self.last_ms = now_ms;
        } else {
            self.tokens = tokens as u32;
            self.last_ms += earned * self.every_ms;
        }
    }

    fn ready(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        self.tokens > 0
    }

    fn take(&mut self) {
        self.tokens = self.tokens.saturating_sub(1);
    }
}

/// The server's rate limits; owned by its loop.
#[derive(Debug)]
struct Limits {
    new_macs: Bucket,
    replies: Bucket,
}

impl Limits {
    fn new(now_ms: u64) -> Self {
        Self {
            new_macs: Bucket::new(NEW_MAC_BURST, NEW_MAC_EVERY_MS, now_ms),
            replies: Bucket::new(REPLY_BURST, REPLY_EVERY_MS, now_ms),
        }
    }
}

/// A running server. Dropping it stops the loop; leases can be read meanwhile.
#[derive(Debug)]
pub struct DhcpServer {
    pool: Arc<Mutex<LeasePool>>,
    task: tokio::task::JoinHandle<()>,
}

impl DhcpServer {
    /// Spawns the server on `socket` (already bound and broadcast-enabled),
    /// answering every device on the segment.
    pub fn start(socket: UdpSocket, config: ServerConfig, pool: Arc<Mutex<LeasePool>>) -> Self {
        Self::start_with_admission(socket, config, pool, None)
    }

    /// Like [`start`](Self::start), but with `admission` only the MACs it
    /// accepts get an answer to DISCOVER and REQUEST.
    pub fn start_with_admission(
        socket: UdpSocket,
        config: ServerConfig,
        pool: Arc<Mutex<LeasePool>>,
        admission: Option<Admission>,
    ) -> Self {
        let task = tokio::spawn(run(socket, config, Arc::clone(&pool), admission));
        Self { pool, task }
    }

    /// The ACKed leases currently valid, for the monitor to show as connected
    /// clients.
    pub fn leases(&self) -> Vec<Lease> {
        match self.pool.lock() {
            Ok(pool) => pool.active(now_ms()),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for DhcpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn run(socket: UdpSocket, config: ServerConfig, pool: Arc<Mutex<LeasePool>>, admission: Option<Admission>) {
    let mut buf = [0u8; 1500];
    let mut limits = Limits::new(now_ms());
    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                warn!("dhcp recv failed: {e}");
                continue;
            }
        };
        let Some(msg) = DhcpMessage::parse(&buf[..n]) else { continue };
        if !admitted(admission.as_ref(), &msg).await {
            debug!(?msg.chaddr, "dhcp: not a device on this network, no answer");
            continue;
        }
        let source = match from {
            SocketAddr::V4(from) => Some(*from.ip()),
            SocketAddr::V6(_) => None,
        };
        let Some(reply) = handle_message(&msg, source, &config, &pool, &mut limits, now_ms()) else { continue };
        // During DORA the client has no address, so broadcast; a renewing client
        // (unicast REQUEST with its address set) and a configured one can take a
        // unicast reply. A NAK (yiaddr 0.0.0.0) is always broadcast.
        let your_ip = Ipv4Addr::new(reply[16], reply[17], reply[18], reply[19]);
        let dst = if msg.wants_broadcast() || your_ip.is_unspecified() {
            BROADCAST
        } else {
            SocketAddr::V4(SocketAddrV4::new(your_ip, CLIENT_PORT))
        };
        if let Err(e) = socket.send_to(&reply, dst).await {
            warn!("dhcp send failed: {e}");
        }
    }
}

/// Whether `msg` may be answered: DISCOVER and REQUEST need the admission
/// check's yes when there is one; the rest only ever touch the sender's own
/// lease.
async fn admitted(admission: Option<&Admission>, msg: &DhcpMessage) -> bool {
    let Some(admit) = admission else { return true };
    if !matches!(msg.message_type, Some(MessageType::Discover | MessageType::Request)) {
        return true;
    }
    let (admit, mac) = (Arc::clone(admit), msg.chaddr);
    // A check that crashed admits nobody rather than everybody.
    tokio::task::spawn_blocking(move || admit(mac)).await.unwrap_or(false)
}

/// Decides the reply (if any) to one request and updates the lease pool.
/// `source` is the packet's sender address when known. Pure apart from the pool
/// and the limits, so it is unit-tested without a socket.
fn handle_message(
    msg: &DhcpMessage,
    source: Option<Ipv4Addr>,
    config: &ServerConfig,
    pool: &Mutex<LeasePool>,
    limits: &mut Limits,
    now_ms: u64,
) -> Option<Vec<u8>> {
    let mut pool = pool.lock().ok()?;
    match msg.message_type? {
        MessageType::Discover => {
            if !limits.replies.ready(now_ms) {
                return None;
            }
            let new = !pool.knows(&msg.chaddr, now_ms);
            if new && !limits.new_macs.ready(now_ms) {
                debug!(?msg.chaddr, "dhcp: too many new devices at once, no offer");
                return None;
            }
            let ip = pool.offer(msg.chaddr, msg.requested_ip, msg.hostname.clone(), now_ms)?;
            if new {
                limits.new_macs.take();
            }
            limits.replies.take();
            debug!(?msg.chaddr, %ip, "dhcp offer");
            Some(reply(msg, config, MessageType::Offer, ip, pool.ttl_ms()))
        }
        MessageType::Request => {
            // If the client is confirming a different server's offer, stay quiet.
            if msg.server_id.is_some_and(|sid| sid != config.gateway) {
                return None;
            }
            let wanted = msg.requested_ip.or_else(|| (!msg.ciaddr.is_unspecified()).then_some(msg.ciaddr))?;
            if !limits.replies.ready(now_ms) {
                return None;
            }
            // A MAC this server does not know claiming an address back counts as
            // a new device; the device asks again if there is no answer.
            let new = !pool.knows(&msg.chaddr, now_ms);
            if new && !limits.new_macs.ready(now_ms) {
                debug!(?msg.chaddr, "dhcp: too many new devices at once, no answer");
                return None;
            }
            limits.replies.take();
            match pool.request(msg.chaddr, wanted, msg.hostname.clone(), now_ms) {
                Some(ip) => {
                    if new {
                        limits.new_macs.take();
                    }
                    debug!(?msg.chaddr, %ip, "dhcp ack");
                    Some(reply(msg, config, MessageType::Ack, ip, pool.ttl_ms()))
                }
                None => {
                    debug!(?msg.chaddr, %wanted, "dhcp nak");
                    Some(reply(msg, config, MessageType::Nak, Ipv4Addr::UNSPECIFIED, 0))
                }
            }
        }
        MessageType::Release => {
            if !pool.release(&msg.chaddr, msg.ciaddr, source) {
                debug!(?msg.chaddr, ciaddr = %msg.ciaddr, "dhcp: release does not match the lease, ignored");
            }
            None
        }
        MessageType::Decline => {
            if pool.decline(&msg.chaddr, msg.requested_ip, now_ms) {
                warn!(address = ?msg.requested_ip, "a device found its address already in use; it is set aside for a while");
            }
            None
        }
        _ => None,
    }
}

fn reply(msg: &DhcpMessage, config: &ServerConfig, kind: MessageType, your_ip: Ipv4Addr, ttl_ms: u64) -> Vec<u8> {
    message::build_reply(
        msg,
        &ReplyParams {
            message_type: kind,
            your_ip,
            server_id: config.gateway,
            subnet_mask: config.subnet_mask,
            router: config.gateway,
            dns: config.dns,
            lease_secs: u32::try_from(ttl_ms / 1000).unwrap_or(u32::MAX),
        },
    )
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::OFFER_HOLD_MS;

    const GW: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
    const SECOND: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 2);

    fn config() -> ServerConfig {
        ServerConfig { gateway: GW, subnet_mask: Ipv4Addr::new(255, 255, 255, 0), dns: GW }
    }

    /// Nine addresses, .2 to .10.
    fn pool() -> Mutex<LeasePool> {
        pool_to(Ipv4Addr::new(10, 7, 0, 10))
    }

    fn pool_to(end: Ipv4Addr) -> Mutex<LeasePool> {
        Mutex::new(LeasePool::new(GW, SECOND, end, 3_600_000))
    }

    struct Packet {
        kind: u8,
        chaddr: [u8; 6],
        ciaddr: Ipv4Addr,
        requested: Option<Ipv4Addr>,
        server_id: Option<Ipv4Addr>,
    }

    impl Packet {
        fn new(kind: u8, chaddr: [u8; 6]) -> Self {
            Self { kind, chaddr, ciaddr: Ipv4Addr::UNSPECIFIED, requested: None, server_id: None }
        }

        /// Crafts the request bytes and parses them as the server would.
        fn parse(&self) -> DhcpMessage {
            let mut buf = vec![0u8; 236];
            buf[0] = 1; // BOOTREQUEST
            buf[1] = 1;
            buf[2] = 6;
            buf[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // broadcast
            buf[12..16].copy_from_slice(&self.ciaddr.octets());
            buf[28..34].copy_from_slice(&self.chaddr);
            buf.extend_from_slice(&[99, 130, 83, 99]);
            buf.extend_from_slice(&[53, 1, self.kind]);
            if let Some(ip) = self.requested {
                buf.extend_from_slice(&[50, 4]);
                buf.extend_from_slice(&ip.octets());
            }
            if let Some(sid) = self.server_id {
                buf.extend_from_slice(&[54, 4]);
                buf.extend_from_slice(&sid.octets());
            }
            buf.push(255);
            DhcpMessage::parse(&buf).unwrap()
        }
    }

    const DISCOVER: u8 = 1;
    const REQUEST: u8 = 3;
    const DECLINE: u8 = 4;
    const RELEASE: u8 = 7;

    fn mac(n: u32) -> [u8; 6] {
        let b = n.to_be_bytes();
        [2, 0, b[0], b[1], b[2], b[3]]
    }

    fn discover(chaddr: [u8; 6]) -> DhcpMessage {
        Packet::new(DISCOVER, chaddr).parse()
    }

    fn request(chaddr: [u8; 6], ip: Ipv4Addr) -> DhcpMessage {
        Packet { requested: Some(ip), server_id: Some(GW), ..Packet::new(REQUEST, chaddr) }.parse()
    }

    /// Handles one message with fresh limits.
    fn handle(msg: &DhcpMessage, pool: &Mutex<LeasePool>, now: u64) -> Option<Vec<u8>> {
        handle_message(msg, None, &config(), pool, &mut Limits::new(now), now)
    }

    fn reply_type(bytes: &[u8]) -> u8 {
        // option 53 is the first option we emit.
        bytes[236 + 4 + 2]
    }

    fn your_ip(bytes: &[u8]) -> Ipv4Addr {
        Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])
    }

    #[test]
    fn discover_yields_an_offer() {
        let p = pool();
        let reply = handle(&discover(mac(1)), &p, 0).expect("should offer");
        assert_eq!(reply_type(&reply), 2, "OFFER");
        assert_eq!(your_ip(&reply), SECOND, "lowest free address");
        assert!(p.lock().unwrap().active(0).is_empty(), "an offer is not a lease");
    }

    #[test]
    fn request_for_offered_address_is_acked() {
        let p = pool();
        handle(&discover(mac(1)), &p, 0);
        let reply = handle(&request(mac(1), SECOND), &p, 0).expect("should ack");
        assert_eq!(reply_type(&reply), 5, "ACK");
        assert_eq!(p.lock().unwrap().active(0).len(), 1);
    }

    #[test]
    fn request_for_a_taken_address_is_naked() {
        let p = pool();
        handle(&discover(mac(1)), &p, 0);
        let reply = handle(&request(mac(2), SECOND), &p, 0).expect("should nak");
        assert_eq!(reply_type(&reply), 6, "NAK");
    }

    #[test]
    fn request_to_another_server_is_ignored() {
        let p = pool();
        let other = Packet {
            requested: Some(SECOND),
            server_id: Some(Ipv4Addr::new(192, 168, 0, 1)),
            ..Packet::new(REQUEST, mac(1))
        };
        assert!(handle(&other.parse(), &p, 0).is_none(), "not our offer");
    }

    #[test]
    fn requests_from_unknown_macs_are_still_acked() {
        let p = pool();
        let reply = handle(&request(mac(1), Ipv4Addr::new(10, 7, 0, 5)), &p, 0).expect("should ack");
        assert_eq!(reply_type(&reply), 5, "a device claiming its address back after a restart");
    }

    #[test]
    fn release_frees_the_address_only_for_its_holder() {
        let p = pool();
        handle(&discover(mac(1)), &p, 0);
        handle(&request(mac(1), SECOND), &p, 0);
        let mut limits = Limits::new(0);
        // A forged RELEASE: right MAC, but no address of its own in the packet.
        let forged = Packet::new(RELEASE, mac(1)).parse();
        assert!(handle_message(&forged, None, &config(), &p, &mut limits, 1).is_none());
        // Right ciaddr, sent from another device.
        let spoofed = Packet { ciaddr: SECOND, ..Packet::new(RELEASE, mac(1)) }.parse();
        assert!(handle_message(&spoofed, Some(Ipv4Addr::new(10, 7, 0, 9)), &config(), &p, &mut limits, 1).is_none());
        assert_eq!(p.lock().unwrap().active(1).len(), 1, "lease kept");
        // The device itself.
        assert!(handle_message(&spoofed, Some(SECOND), &config(), &p, &mut limits, 1).is_none());
        assert_eq!(p.lock().unwrap().active(1).len(), 0, "lease released");
    }

    #[test]
    fn decline_sets_only_the_senders_address_aside() {
        let p = pool();
        handle(&discover(mac(1)), &p, 0);
        handle(&request(mac(1), SECOND), &p, 0);
        let other = Ipv4Addr::new(10, 7, 0, 3);
        handle(&discover(mac(2)), &p, 0);
        // mac(2) declining mac(1)'s address changes nothing.
        let hostile = Packet { requested: Some(SECOND), ..Packet::new(DECLINE, mac(2)) }.parse();
        assert!(handle(&hostile, &p, 1).is_none());
        assert_eq!(p.lock().unwrap().active(1).len(), 1);
        // Declining its own offer sets that address aside.
        let own = Packet { requested: Some(other), ..Packet::new(DECLINE, mac(2)) }.parse();
        assert!(handle(&own, &p, 2).is_none());
        let next = handle(&discover(mac(2)), &p, 3).unwrap();
        assert_ne!(your_ip(&next), other);
    }

    #[test]
    fn a_flood_of_new_macs_gets_a_burst_then_one_a_second() {
        let p = pool_to(Ipv4Addr::new(10, 7, 3, 255));
        let mut limits = Limits::new(0);
        let offers = (0..1000)
            .filter(|n| handle_message(&discover(mac(*n)), None, &config(), &p, &mut limits, 0).is_some())
            .count();
        assert_eq!(offers, NEW_MAC_BURST as usize);
        // A device already offered an address is not held back.
        assert!(handle_message(&discover(mac(0)), None, &config(), &p, &mut limits, 0).is_some());
        assert!(handle_message(&request(mac(0), SECOND), None, &config(), &p, &mut limits, 0).is_some());
        // Nor is a device that is still unknown, once a second has passed.
        assert!(handle_message(&discover(mac(5000)), None, &config(), &p, &mut limits, 999).is_none());
        assert!(handle_message(&discover(mac(5000)), None, &config(), &p, &mut limits, 1000).is_some());
        assert!(handle_message(&discover(mac(5001)), None, &config(), &p, &mut limits, 1000).is_none());
    }

    #[test]
    fn offers_from_a_flood_free_up_after_a_minute() {
        let p = pool(); // .2 to .10
        let mut limits = Limits::new(0);
        for n in 0..9 {
            assert!(handle_message(&discover(mac(n)), None, &config(), &p, &mut limits, 0).is_some());
        }
        assert!(handle_message(&discover(mac(100)), None, &config(), &p, &mut limits, 0).is_none(), "pool held");
        let later = OFFER_HOLD_MS + 1;
        let reply = handle_message(&discover(mac(100)), None, &config(), &p, &mut limits, later).expect("free again");
        assert_eq!(reply_type(&reply), 2);
    }

    #[test]
    fn replies_are_limited_per_second() {
        let p = pool();
        handle(&discover(mac(1)), &p, 0);
        handle(&request(mac(1), SECOND), &p, 0);
        let mut limits = Limits::new(0);
        // Renewals from a known device: only the reply limit applies.
        let sent = (0..1000)
            .filter(|_| handle_message(&request(mac(1), SECOND), None, &config(), &p, &mut limits, 0).is_some())
            .count();
        assert_eq!(sent, REPLY_BURST as usize);
        assert!(handle_message(&request(mac(1), SECOND), None, &config(), &p, &mut limits, REPLY_EVERY_MS).is_some());
        assert!(handle_message(&request(mac(1), SECOND), None, &config(), &p, &mut limits, REPLY_EVERY_MS).is_none());
    }

    #[tokio::test]
    async fn the_admission_check_gates_discover_and_request_only() {
        let only_one: Admission = Arc::new(|chaddr| chaddr == mac(1));
        let check = Some(&only_one);
        assert!(admitted(check, &discover(mac(1))).await);
        assert!(!admitted(check, &discover(mac(2))).await, "not associated with the access point");
        assert!(!admitted(check, &request(mac(2), SECOND)).await);
        // RELEASE and DECLINE already only touch the sender's own lease.
        assert!(admitted(check, &Packet::new(RELEASE, mac(2)).parse()).await);
        assert!(admitted(check, &Packet::new(DECLINE, mac(2)).parse()).await);
        // Without a check (cable sharing) everyone is answered.
        assert!(admitted(None, &discover(mac(2))).await);
        // A check that panics admits nobody.
        let broken: Admission = Arc::new(|_| panic!("station list exploded"));
        assert!(!admitted(Some(&broken), &discover(mac(1))).await);
    }

    #[test]
    fn buckets_refill_and_survive_a_clock_step_back() {
        let mut b = Bucket::new(2, 1000, 5000);
        assert!(b.ready(5000));
        b.take();
        b.take();
        assert!(!b.ready(5999));
        assert!(b.ready(6000));
        b.take();
        assert!(!b.ready(100), "clock stepped back: nothing earned");
        assert!(!b.ready(1099));
        assert!(b.ready(1100));
        assert!(b.ready(1_000_000));
        b.take();
        b.take();
        assert!(!b.ready(1_000_000), "never more than its capacity");
    }
}
