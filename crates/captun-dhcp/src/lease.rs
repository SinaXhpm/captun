//! The address pool: hands out and tracks IPv4 leases over a configured range,
//! sticky per client MAC and with expiry so addresses free up again.
//!
//! An OFFER only holds its address for a short while; the lease itself starts
//! with the ACK. So a device that sends DISCOVERs under made-up MACs ties up
//! each address for a minute, not for a whole lease, and only ACKed leases count
//! as devices on the network.

use std::{collections::HashMap, net::Ipv4Addr};

use tracing::warn;

/// How long an OFFER keeps its address for the device it was offered to.
pub(crate) const OFFER_HOLD_MS: u64 = 60 * 1000;
/// How long a declined address (another device already uses it) is not
/// offered again, unless no other address is free.
pub(crate) const DECLINED_MS: u64 = 10 * 60 * 1000;
/// The most addresses one pool hands out. Larger ranges are cut to this, so
/// finding a free address stays cheap whatever the settings say.
pub const MAX_POOL_ADDRESSES: u32 = 4096;

/// One active lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    /// Absolute expiry in the caller's millisecond clock.
    pub expires_at_ms: u64,
}

/// The one address a MAC has: offered, leased, or both while a leased device
/// asks again.
#[derive(Clone, Debug)]
struct Binding {
    ip: Ipv4Addr,
    hostname: Option<String>,
    /// End of the ACKed lease; `None` while the address is only offered.
    leased_until: Option<u64>,
    /// End of the hold an OFFER put on the address.
    offered_until: Option<u64>,
}

impl Binding {
    fn leased(&self, now_ms: u64) -> bool {
        self.leased_until.is_some_and(|t| t > now_ms)
    }

    fn offered(&self, now_ms: u64) -> bool {
        self.offered_until.is_some_and(|t| t > now_ms)
    }

    fn live(&self, now_ms: u64) -> bool {
        self.leased(now_ms) || self.offered(now_ms)
    }
}

/// A pool of addresses between `start` and `end` (inclusive), excluding the
/// gateway. Allocation is sticky: a MAC keeps its address across requests.
#[derive(Debug)]
pub struct LeasePool {
    gateway: Ipv4Addr,
    start: u32,
    end: u32,
    ttl_ms: u64,
    by_mac: HashMap<[u8; 6], Binding>,
    /// Owner of every address that is leased or offered.
    by_ip: HashMap<u32, [u8; 6]>,
    /// Declined addresses, and until when they are not offered.
    declined: HashMap<u32, u64>,
}

impl LeasePool {
    /// `start..=end` is the assignable host range, cut to its first
    /// [`MAX_POOL_ADDRESSES`]. The gateway (if it falls in the range) is
    /// reserved. Panics only on a caller bug: `start > end`.
    pub fn new(gateway: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr, ttl_ms: u64) -> Self {
        let (start, mut end) = (u32::from(start), u32::from(end));
        assert!(start <= end, "lease range start must not exceed end");
        let last = start.saturating_add(MAX_POOL_ADDRESSES - 1);
        if end > last {
            warn!(
                "the range of addresses to hand out has {} addresses; only the first {MAX_POOL_ADDRESSES} ({} to {}) are used",
                u64::from(end - start) + 1,
                Ipv4Addr::from(start),
                Ipv4Addr::from(last)
            );
            end = last;
        }
        Self {
            gateway,
            start,
            end,
            ttl_ms,
            by_mac: HashMap::new(),
            by_ip: HashMap::new(),
            declined: HashMap::new(),
        }
    }

    pub fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }

    /// Whether `mac` has an address here (offered or leased) at `now_ms`.
    pub fn knows(&self, mac: &[u8; 6], now_ms: u64) -> bool {
        self.by_mac.get(mac).is_some_and(|b| b.live(now_ms))
    }

    /// Chooses an address for `mac` (for an OFFER): its current one if any, else
    /// the requested address when it is in range and free, else the lowest free
    /// address. The address is held for [`OFFER_HOLD_MS`]; a longer lease the
    /// MAC already has is kept as it is. Returns `None` only when the pool is
    /// full.
    pub fn offer(
        &mut self,
        mac: [u8; 6],
        requested: Option<Ipv4Addr>,
        hostname: Option<String>,
        now_ms: u64,
    ) -> Option<Ipv4Addr> {
        self.reap(now_ms);
        let hold = now_ms.saturating_add(OFFER_HOLD_MS);
        if let Some(binding) = self.by_mac.get_mut(&mac) {
            binding.offered_until = Some(binding.offered_until.map_or(hold, |t| t.max(hold)));
            if hostname.is_some() {
                binding.hostname = hostname;
            }
            return Some(binding.ip);
        }
        let ip = requested
            .filter(|ip| self.is_free_for(*ip, &mac) && !self.declined.contains_key(&u32::from(*ip)))
            .or_else(|| self.lowest_free())?;
        self.declined.remove(&u32::from(ip));
        self.by_ip.insert(u32::from(ip), mac);
        self.by_mac.insert(mac, Binding { ip, hostname, leased_until: None, offered_until: Some(hold) });
        Some(ip)
    }

    /// Confirms a REQUEST: ACK (returns the address) when `mac` may hold
    /// `requested`, otherwise `None` (the server should NAK). Starts or renews
    /// the lease.
    ///
    /// A MAC this pool does not know may claim any free address (devices ask
    /// for their old one back after this computer restarts; leases are not
    /// saved). A MAC with a live lease may not move to another address: it
    /// asks with DISCOVER and is offered its own.
    pub fn request(&mut self, mac: [u8; 6], requested: Ipv4Addr, hostname: Option<String>, now_ms: u64) -> Option<Ipv4Addr> {
        self.reap(now_ms);
        if !self.is_free_for(requested, &mac) {
            return None;
        }
        let own = self.by_mac.get(&mac);
        if let Some(binding) = own
            && binding.ip != requested
            && binding.leased(now_ms)
        {
            return None;
        }
        if own.is_none_or(|b| b.ip != requested) && self.declined.contains_key(&u32::from(requested)) {
            return None;
        }
        // Any offer of another address is given up for the one asked for.
        let previous = self.by_mac.remove(&mac);
        if let Some(prev) = &previous
            && prev.ip != requested
        {
            self.by_ip.remove(&u32::from(prev.ip));
        }
        let renewed = now_ms.saturating_add(self.ttl_ms);
        let (hostname, leased_until) = match previous {
            Some(prev) if prev.ip == requested => {
                (hostname.or(prev.hostname), prev.leased_until.filter(|t| *t > renewed).unwrap_or(renewed))
            }
            Some(prev) => (hostname.or(prev.hostname), renewed),
            None => (hostname, renewed),
        };
        self.by_ip.insert(u32::from(requested), mac);
        self.by_mac.insert(mac, Binding { ip: requested, hostname, leased_until: Some(leased_until), offered_until: None });
        Some(requested)
    }

    /// A RELEASE: frees `mac`'s lease, but only when the device names that
    /// address in `ciaddr` and, when the packet's source address is known
    /// (not 0.0.0.0), sends from it. Anyone can put any MAC in a packet; only
    /// the device using the address can do both. Returns whether it freed one.
    pub fn release(&mut self, mac: &[u8; 6], ciaddr: Ipv4Addr, source: Option<Ipv4Addr>) -> bool {
        let Some(binding) = self.by_mac.get(mac) else { return false };
        let from_holder = source.is_none_or(|s| s.is_unspecified() || s == binding.ip);
        if ciaddr != binding.ip || !from_holder {
            return false;
        }
        self.remove(mac);
        true
    }

    /// A DECLINE: the device found `address` already in use. Only the address
    /// this MAC holds or was offered is affected (when the packet names none,
    /// that one); it is not offered again for [`DECLINED_MS`]. Returns whether
    /// anything changed.
    pub fn decline(&mut self, mac: &[u8; 6], address: Option<Ipv4Addr>, now_ms: u64) -> bool {
        let Some(binding) = self.by_mac.get(mac).filter(|b| b.live(now_ms)) else { return false };
        let ip = binding.ip;
        if address.is_some_and(|a| a != ip) {
            return false;
        }
        self.remove(mac);
        self.declined.insert(u32::from(ip), now_ms.saturating_add(DECLINED_MS));
        true
    }

    /// The ACKed leases still valid at `now_ms`. Addresses that were only
    /// offered are not listed: no device has confirmed them.
    pub fn active(&self, now_ms: u64) -> Vec<Lease> {
        self.by_mac
            .iter()
            .filter_map(|(mac, b)| {
                let expires_at_ms = b.leased_until.filter(|t| *t > now_ms)?;
                Some(Lease { mac: *mac, ip: b.ip, hostname: b.hostname.clone(), expires_at_ms })
            })
            .collect()
    }

    fn remove(&mut self, mac: &[u8; 6]) {
        if let Some(binding) = self.by_mac.remove(mac) {
            self.by_ip.remove(&u32::from(binding.ip));
        }
    }

    fn in_range(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        v >= self.start && v <= self.end && ip != self.gateway
    }

    /// Free for `mac`: in range, not the gateway, and either unowned or already
    /// this MAC's.
    fn is_free_for(&self, ip: Ipv4Addr, mac: &[u8; 6]) -> bool {
        self.in_range(ip) && self.by_ip.get(&u32::from(ip)).is_none_or(|owner| owner == mac)
    }

    /// The lowest free address that nobody declined; failing that, the one
    /// declined longest ago, so declines can never use the whole pool up.
    fn lowest_free(&self) -> Option<Ipv4Addr> {
        let free = |v: &u32| Ipv4Addr::from(*v) != self.gateway && !self.by_ip.contains_key(v);
        (self.start..=self.end)
            .find(|v| free(v) && !self.declined.contains_key(v))
            .or_else(|| self.declined.iter().filter(|&(v, _)| free(v)).min_by_key(|&(v, until)| (*until, *v)).map(|(v, _)| *v))
            .map(Ipv4Addr::from)
    }

    fn reap(&mut self, now_ms: u64) {
        let expired: Vec<[u8; 6]> = self.by_mac.iter().filter(|(_, b)| !b.live(now_ms)).map(|(mac, _)| *mac).collect();
        for mac in expired {
            self.remove(&mac);
        }
        // A lease that ran out while a new offer holds the address is only an offer again.
        for binding in self.by_mac.values_mut() {
            if !binding.leased(now_ms) {
                binding.leased_until = None;
            }
        }
        self.declined.retain(|_, until| *until > now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GW: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
    const START: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 2);
    const END: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 4);
    const A: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const B: [u8; 6] = [2, 0, 0, 0, 0, 2];
    const HOUR: u64 = 3_600_000;

    fn pool() -> LeasePool {
        LeasePool::new(GW, START, END, HOUR)
    }

    /// DISCOVER then REQUEST, as a device joining does.
    fn join(p: &mut LeasePool, mac: [u8; 6], now: u64) -> Ipv4Addr {
        let ip = p.offer(mac, None, None, now).unwrap();
        assert_eq!(p.request(mac, ip, None, now), Some(ip));
        ip
    }

    #[test]
    fn offer_is_sticky_per_mac() {
        let mut p = pool();
        let first = p.offer(A, None, None, 0).unwrap();
        let again = p.offer(A, None, None, 10).unwrap();
        assert_eq!(first, again, "same MAC keeps its address");
        assert_eq!(first, START, "allocates the lowest free address");
    }

    #[test]
    fn distinct_macs_get_distinct_addresses() {
        let mut p = pool();
        let a = p.offer(A, None, None, 0).unwrap();
        let b = p.offer(B, None, None, 0).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn honours_a_free_requested_address_and_skips_the_gateway() {
        let mut p = pool();
        let ip = p.offer(A, Some(Ipv4Addr::new(10, 7, 0, 3)), None, 0).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 7, 0, 3));
        // Requesting the gateway is refused; falls back to a free address.
        let ip2 = p.offer(B, Some(GW), None, 0).unwrap();
        assert_ne!(ip2, GW);
    }

    #[test]
    fn request_acks_own_and_naks_taken_or_out_of_range() {
        let mut p = pool();
        let a = p.offer(A, None, None, 0).unwrap();
        assert_eq!(p.request(A, a, None, 0), Some(a), "own address is ACKed");
        // B cannot take A's address.
        assert_eq!(p.request(B, a, None, 0), None, "taken address is NAKed");
        // Out of range is NAKed.
        assert_eq!(p.request(B, Ipv4Addr::new(10, 7, 0, 99), None, 0), None);
        assert_eq!(p.request(B, GW, None, 0), None, "the gateway is never a lease");
    }

    #[test]
    fn pool_exhaustion_returns_none() {
        let mut p = pool(); // three addresses: .2 .3 .4
        assert!(p.offer([2, 0, 0, 0, 0, 1], None, None, 0).is_some());
        assert!(p.offer([2, 0, 0, 0, 0, 2], None, None, 0).is_some());
        assert!(p.offer([2, 0, 0, 0, 0, 3], None, None, 0).is_some());
        assert!(p.offer([2, 0, 0, 0, 0, 4], None, None, 0).is_none(), "pool full");
    }

    #[test]
    fn an_offer_is_held_briefly_and_is_not_a_lease() {
        let mut p = pool();
        let a = p.offer(A, None, None, 0).unwrap();
        assert!(p.active(0).is_empty(), "nobody confirmed the offer");
        assert!(p.knows(&A, 0));
        // Still held just before the hold ends, so B gets another address.
        assert_ne!(p.offer(B, Some(a), None, OFFER_HOLD_MS - 1), Some(a));
        // A DISCOVER flood under made-up MACs frees up a minute later.
        assert!(!p.knows(&A, OFFER_HOLD_MS));
        assert_eq!(p.offer([2, 0, 0, 0, 0, 9], Some(a), None, OFFER_HOLD_MS + 1), Some(a), "freed address is reused");
    }

    #[test]
    fn the_ack_starts_the_full_lease() {
        let mut p = pool();
        let a = join(&mut p, A, 0);
        let leases = p.active(1);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, a);
        assert_eq!(leases[0].expires_at_ms, HOUR);
        assert_eq!(p.active(HOUR - 1).len(), 1);
        assert!(p.active(HOUR).is_empty(), "the lease runs out");
    }

    #[test]
    fn an_offer_never_shortens_a_lease() {
        let mut p = pool();
        let a = join(&mut p, A, 0);
        // The leased device sends a DISCOVER again (e.g. its cable was replugged).
        assert_eq!(p.offer(A, None, None, 1000), Some(a));
        let lease = p.active(OFFER_HOLD_MS + 2000).pop().expect("lease still there after the offer's hold");
        assert_eq!(lease.expires_at_ms, HOUR);
        // And it stays the device's own after the hold.
        assert_eq!(p.request(B, a, None, OFFER_HOLD_MS + 2000), None);
    }

    #[test]
    fn expired_leases_free_up_and_drop_from_active() {
        let mut p = pool();
        let a = join(&mut p, A, 0);
        assert_eq!(p.active(500).len(), 1);
        // After the TTL, the lease is gone and its address is reusable by B.
        assert!(p.active(HOUR + 1).is_empty());
        let b = p.offer(B, None, None, HOUR + 1).unwrap();
        assert_eq!(b, a, "freed address is reused");
    }

    #[test]
    fn unknown_macs_may_claim_a_free_address_back() {
        let mut p = pool();
        let wanted = Ipv4Addr::new(10, 7, 0, 3);
        assert_eq!(p.request(A, wanted, None, 0), Some(wanted), "INIT-REBOOT after this computer restarted");
        assert_eq!(p.active(1).len(), 1);
    }

    #[test]
    fn a_leased_device_cannot_move_to_another_address() {
        let mut p = pool();
        let a = join(&mut p, A, 0);
        let other = Ipv4Addr::new(10, 7, 0, 4);
        assert_ne!(a, other);
        assert_eq!(p.request(A, other, None, 10), None, "would let one device walk the pool");
        assert_eq!(p.active(11)[0].ip, a, "its own lease is untouched");
        assert_eq!(p.request(A, a, None, 20), Some(a));
    }

    #[test]
    fn a_device_with_only_an_offer_may_ask_for_another_address() {
        let mut p = pool();
        let offered = p.offer(A, None, None, 0).unwrap();
        let other = Ipv4Addr::new(10, 7, 0, 4);
        assert_eq!(p.request(A, other, None, 1), Some(other));
        // The offer it passed on is free again.
        assert_eq!(p.offer(B, Some(offered), None, 2), Some(offered));
    }

    #[test]
    fn a_renewal_keeps_the_lease_and_never_shortens_it() {
        let mut p = LeasePool::new(GW, START, END, HOUR);
        let a = join(&mut p, A, 0);
        assert_eq!(p.request(A, a, None, 1000), Some(a));
        assert_eq!(p.active(1001)[0].expires_at_ms, HOUR + 1000);
    }

    #[test]
    fn release_needs_the_devices_own_address() {
        let mut p = pool();
        let a = join(&mut p, A, 0);
        let elsewhere = Ipv4Addr::new(10, 7, 0, 4);
        // Another device forging A's MAC: wrong ciaddr, or sent from elsewhere.
        assert!(!p.release(&A, Ipv4Addr::UNSPECIFIED, None));
        assert!(!p.release(&A, elsewhere, None));
        assert!(!p.release(&A, a, Some(elsewhere)));
        assert_eq!(p.active(1).len(), 1, "the lease survives");
        assert!(!p.release(&B, a, Some(a)), "not B's lease");
        // A itself releasing.
        assert!(p.release(&A, a, Some(a)));
        assert!(p.active(1).is_empty());
    }

    #[test]
    fn release_with_an_unknown_source_checks_ciaddr() {
        let mut p = pool();
        let a = join(&mut p, A, 0);
        assert!(p.release(&A, a, Some(Ipv4Addr::UNSPECIFIED)));
        assert!(!p.knows(&A, 1));
    }

    #[test]
    fn decline_sets_the_address_aside_for_a_while() {
        let mut p = pool();
        let a = p.offer(A, None, None, 0).unwrap();
        assert!(p.decline(&A, Some(a), 10));
        assert!(!p.knows(&A, 10));
        // Not offered again, to A or anyone, while there are others.
        assert_ne!(p.offer(A, None, None, 20), Some(a));
        assert_ne!(p.offer(B, Some(a), None, 20), Some(a));
        assert_eq!(p.request([2, 0, 0, 0, 0, 3], a, None, 30), None, "nor ACKed");
        // Offered again once the time is up.
        assert_eq!(p.offer([2, 0, 0, 0, 0, 4], Some(a), None, 10 + DECLINED_MS), Some(a));
    }

    #[test]
    fn decline_only_touches_the_senders_own_address() {
        let mut p = pool();
        let a = join(&mut p, A, 0);
        let b = p.offer(B, None, None, 0).unwrap();
        assert!(!p.decline(&B, Some(a), 1), "B cannot push A off its address");
        assert!(!p.decline(&[2, 0, 0, 0, 0, 9], Some(a), 1), "nor can a MAC with nothing here");
        assert_eq!(p.active(2).len(), 1);
        assert!(p.decline(&B, None, 3), "no address named means its own");
        assert_ne!(p.offer(B, None, None, 4), Some(b));
        // An offer that ran out is nothing to decline.
        assert!(!p.decline(&B, None, 4 + OFFER_HOLD_MS));
    }

    #[test]
    fn declined_addresses_are_still_used_when_nothing_else_is_free() {
        let mut p = pool(); // .2 .3 .4
        for (i, mac) in [[2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 3]].iter().enumerate() {
            p.offer(*mac, None, None, i as u64);
            assert!(p.decline(mac, None, i as u64));
        }
        // Everything declined: the one declined longest ago comes back first.
        assert_eq!(p.offer(B, None, None, 100), Some(START));
    }

    #[test]
    fn hostname_is_remembered_across_requests() {
        let mut p = pool();
        p.offer(A, None, Some("laptop".into()), 0);
        p.request(A, START, None, 10); // no hostname this time
        let lease = p.active(20).into_iter().next().unwrap();
        assert_eq!(lease.hostname.as_deref(), Some("laptop"));
    }

    #[test]
    fn huge_ranges_are_cut_to_the_limit() {
        let mut p = LeasePool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 255, 255, 254), HOUR);
        let last = Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 0, 0, 2)) + MAX_POOL_ADDRESSES - 1);
        assert_eq!(p.request(A, last, None, 0), Some(last));
        let past = Ipv4Addr::from(u32::from(last) + 1);
        assert_eq!(p.request(B, past, None, 0), None, "outside the cut range");
        // Near the top of the address space the cut cannot overflow.
        let top = LeasePool::new(GW, Ipv4Addr::new(255, 255, 255, 250), Ipv4Addr::BROADCAST, HOUR);
        assert_eq!(top.end, u32::MAX);
    }
}
