//! Bounded response cache. Entries are keyed per upstream, because two
//! clients on different upstreams (say a filtering resolver and a plain one)
//! must never see each other's answers.
//!
//! Answers are kept as the bytes the upstream sent: their length is what they
//! really take, so the byte budget holds, and a hit copies only a reference
//! while the lock is held. Parsing and aging the TTLs happen after.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};

use crate::message::for_each_record_mut;

/// Negative answers without an SOA (RFC 2308 says they should carry one).
const DEFAULT_NEGATIVE_TTL: u32 = 60;
/// Answers bigger than this are rare (most take a few hundred bytes) and are
/// still answered, just not kept: each would take the room of many others.
const MAX_ENTRY_BYTES: usize = 4096;
/// All entries together, whatever `cache_size` allows. Counting entries alone
/// let one device fill the cache with the largest answers it could get and
/// hold gigabytes for a day.
const MAX_CACHE_BYTES: usize = 32 << 20;
/// What an entry takes besides its answer: its key twice (in the map and in
/// `order`), its map slot and the room the map and the queue keep spare.
const ENTRY_OVERHEAD: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    pub(crate) upstream: String,
    /// The outbound the answer came through: one fetched directly (where it
    /// can be tampered with or differ by country) is not served to devices
    /// that go out through a proxy.
    pub(crate) outbound: String,
    pub(crate) name: Name,
    pub(crate) qtype: RecordType,
    pub(crate) qclass: DNSClass,
}

#[derive(Debug)]
struct Entry {
    /// The answer as the upstream sent it.
    wire: Arc<[u8]>,
    stored: Instant,
    expires: Instant,
    /// Ties the entry to its marker in [`DnsCache::order`].
    seq: u64,
}

/// Holds at most `capacity` answers and [`MAX_CACHE_BYTES`]. When either is
/// reached the oldest answers go first, however long they still had to live:
/// dropping the soonest to expire let a device that stores day-long answers
/// keep them while every other device's answers were thrown out.
#[derive(Debug)]
pub(crate) struct DnsCache {
    entries: HashMap<CacheKey, Entry>,
    /// Every key in the order it was stored, oldest first, with the `seq` it
    /// was stored under. A marker whose entry has since been replaced or has
    /// expired no longer matches it and is skipped.
    order: VecDeque<(CacheKey, u64)>,
    next_seq: u64,
    /// The [`cost`] of all entries together.
    bytes: usize,
    capacity: usize,
}

impl DnsCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self { entries: HashMap::new(), order: VecDeque::new(), next_seq: 0, bytes: 0, capacity }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Empties the cache and gives it a new limit on entries.
    pub(crate) fn clear(&mut self, capacity: usize) {
        *self = Self::new(capacity);
    }

    /// The stored answer and the whole seconds it has spent in the cache;
    /// [`aged_answer`] makes a reply of them once the lock is let go.
    pub(crate) fn get(&mut self, key: &CacheKey, now: Instant) -> Option<(Arc<[u8]>, u32)> {
        let entry = self.entries.get(key)?;
        if now >= entry.expires {
            self.remove(key);
            return None;
        }
        let elapsed = u32::try_from(now.duration_since(entry.stored).as_secs()).unwrap_or(u32::MAX);
        Some((entry.wire.clone(), elapsed))
    }

    /// Keeps `wire`, the upstream's answer, for `ttl` seconds, making room by
    /// dropping the oldest entries first.
    pub(crate) fn insert(&mut self, key: CacheKey, wire: Arc<[u8]>, ttl: u32, now: Instant) {
        if self.capacity == 0 || ttl == 0 || wire.len() > MAX_ENTRY_BYTES {
            return;
        }
        self.remove(&key);
        let size = cost(&wire);
        while self.entries.len() >= self.capacity || self.bytes + size > MAX_CACHE_BYTES {
            if !self.evict_oldest() {
                break;
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.order.push_back((key.clone(), seq));
        self.bytes += size;
        let expires = now + Duration::from_secs(u64::from(ttl));
        self.entries.insert(key, Entry { wire, stored: now, expires, seq });
        // Replaced and expired entries leave their markers behind.
        if self.order.len() > 2 * self.entries.len() + 64 {
            let entries = &self.entries;
            self.order.retain(|(key, seq)| entries.get(key).is_some_and(|e| e.seq == *seq));
        }
    }

    fn remove(&mut self, key: &CacheKey) {
        if let Some(old) = self.entries.remove(key) {
            self.bytes -= cost(&old.wire);
        }
    }

    /// Drops the oldest entry; `false` if there is none.
    fn evict_oldest(&mut self) -> bool {
        while let Some((key, seq)) = self.order.pop_front() {
            if self.entries.get(&key).is_some_and(|e| e.seq == seq) {
                self.remove(&key);
                return true;
            }
        }
        false
    }
}

/// What an entry counts against [`MAX_CACHE_BYTES`].
fn cost(wire: &[u8]) -> usize {
    wire.len() + ENTRY_OVERHEAD
}

/// A stored answer as a reply, with every TTL reduced by the `elapsed`
/// seconds it spent in the cache, so downstream caches never hold a record
/// past its real expiry. `None` if it does not parse.
pub(crate) fn aged_answer(wire: &[u8], elapsed: u32) -> Option<Message> {
    let mut message = Message::from_vec(wire).ok()?;
    for_each_record_mut(&mut message, |r| {
        r.set_ttl(r.ttl().saturating_sub(elapsed));
    });
    Some(message)
}

/// How long a response may be cached, or `None` if it must not be.
pub(crate) fn cacheable_ttl(message: &Message, min_ttl: u32, max_ttl: u32) -> Option<u32> {
    if message.truncated() {
        return None;
    }
    let ttl = match message.response_code() {
        ResponseCode::NoError if !message.answers().is_empty() => message.answers().iter().map(|r| r.ttl()).min()?,
        // NODATA and NXDOMAIN: the SOA in the authority section bounds the
        // negative TTL (RFC 2308 §5).
        ResponseCode::NoError | ResponseCode::NXDomain => message
            .name_servers()
            .iter()
            .find_map(|r| match r.data() {
                RData::SOA(soa) => Some(r.ttl().min(soa.minimum())),
                _ => None,
            })
            .unwrap_or(DEFAULT_NEGATIVE_TTL),
        _ => return None,
    };
    let ttl = ttl.clamp(min_ttl, max_ttl.max(min_ttl));
    (ttl > 0).then_some(ttl)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use hickory_proto::rr::{Record, rdata::A};

    use super::*;

    fn key(name: &str) -> CacheKey {
        CacheKey {
            upstream: "u".into(),
            outbound: "direct".into(),
            name: Name::from_str(name).unwrap(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
        }
    }

    fn answer(ttl: u32) -> Message {
        let mut m = Message::new();
        m.add_answer(Record::from_rdata(Name::from_str("a.test.").unwrap(), ttl, RData::A(A(Ipv4Addr::LOCALHOST))));
        m
    }

    fn wire(message: &Message) -> Arc<[u8]> {
        message.to_vec().unwrap().into()
    }

    /// Stands in for an answer of `len` bytes; the cache never parses it.
    fn filler(len: usize) -> Arc<[u8]> {
        vec![0u8; len].into()
    }

    #[test]
    fn expires_and_ages_ttls() {
        let mut cache = DnsCache::new(8);
        let t0 = Instant::now();
        cache.insert(key("a.test."), wire(&answer(10)), 10, t0);
        let (stored, elapsed) = cache.get(&key("a.test."), t0 + Duration::from_secs(4)).unwrap();
        assert_eq!(elapsed, 4);
        assert_eq!(aged_answer(&stored, elapsed).unwrap().answers()[0].ttl(), 6);
        assert!(cache.get(&key("a.test."), t0 + Duration::from_secs(10)).is_none());
        assert_eq!((cache.len(), cache.bytes), (0, 0), "the expired entry gave its bytes back");
        assert!(aged_answer(&[0x12, 0x34], 0).is_none());
    }

    #[test]
    fn stays_bounded() {
        let mut cache = DnsCache::new(16);
        let t0 = Instant::now();
        for i in 0..100u32 {
            cache.insert(key(&format!("n{i}.test.")), wire(&answer(60)), 60 + i, t0);
            assert!(cache.len() <= 16);
        }
        // The newest entries are kept.
        assert!(cache.get(&key("n99.test."), t0).is_some());
        assert!(cache.get(&key("n84.test."), t0).is_some());
        assert!(cache.get(&key("n83.test."), t0).is_none());
    }

    #[test]
    fn many_large_answers_stay_within_the_byte_budget() {
        let mut cache = DnsCache::new(1_000_000);
        let t0 = Instant::now();
        let big = filler(MAX_ENTRY_BYTES);
        let fits = MAX_CACHE_BYTES / cost(&big);
        for i in 0..2 * fits {
            cache.insert(key(&format!("n{i}.test.")), big.clone(), 86_400, t0);
            assert!(cache.bytes <= MAX_CACHE_BYTES);
        }
        assert_eq!((cache.len(), cache.bytes), (fits, fits * cost(&big)));
        assert_eq!(cache.order.len(), fits);
        assert!(cache.get(&key(&format!("n{}.test.", 2 * fits - 1)), t0).is_some());
        assert!(cache.get(&key(&format!("n{}.test.", fits - 1)), t0).is_none());
    }

    #[test]
    fn large_answers_are_not_kept() {
        let mut cache = DnsCache::new(8);
        let t0 = Instant::now();
        cache.insert(key("big.test."), filler(5 * 1024), 60, t0);
        assert!(cache.get(&key("big.test."), t0).is_none());
        assert_eq!((cache.len(), cache.bytes), (0, 0));
        cache.insert(key("edge.test."), filler(MAX_ENTRY_BYTES), 60, t0);
        assert!(cache.get(&key("edge.test."), t0).is_some(), "4 KiB itself is kept");
    }

    #[test]
    fn a_long_ttl_protects_nothing() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new(2);
        cache.insert(key("day.test."), filler(100), 86_400, t0);
        cache.insert(key("minute.test."), filler(100), 60, t0);
        cache.insert(key("new.test."), filler(100), 60, t0);
        assert!(cache.get(&key("day.test."), t0).is_none(), "the oldest went first");
        assert!(cache.get(&key("minute.test."), t0).is_some());
        assert!(cache.get(&key("new.test."), t0).is_some());

        // The same when the bytes run out first.
        let mut cache = DnsCache::new(1_000_000);
        let big = filler(MAX_ENTRY_BYTES);
        for i in 0..MAX_CACHE_BYTES / cost(&big) {
            cache.insert(key(&format!("day{i}.test.")), big.clone(), 86_400, t0);
        }
        cache.insert(key("minute.test."), big.clone(), 60, t0);
        assert!(cache.get(&key("day0.test."), t0).is_none());
        assert!(cache.get(&key("day1.test."), t0).is_some());
        assert!(cache.get(&key("minute.test."), t0).is_some());
    }

    #[test]
    fn replaced_and_expired_entries_give_their_bytes_back() {
        let mut cache = DnsCache::new(2);
        let t0 = Instant::now();
        cache.insert(key("a.test."), filler(100), 60, t0);
        cache.insert(key("b.test."), filler(200), 60, t0);
        // Storing `a` again makes it the newest; its first marker is skipped.
        cache.insert(key("a.test."), filler(300), 30, t0);
        assert_eq!(cache.bytes, cost(&filler(200)) + cost(&filler(300)));
        cache.insert(key("c.test."), filler(400), 60, t0);
        assert!(cache.get(&key("b.test."), t0).is_none(), "b was the oldest");
        assert!(cache.get(&key("a.test."), t0).is_some());
        assert!(cache.get(&key("a.test."), t0 + Duration::from_secs(30)).is_none());
        assert_eq!((cache.len(), cache.bytes), (1, cost(&filler(400))));
    }

    #[test]
    fn markers_left_behind_are_dropped() {
        let mut cache = DnsCache::new(4);
        let t0 = Instant::now();
        for _ in 0..1000 {
            cache.insert(key("same.test."), filler(10), 60, t0);
            assert!(cache.order.len() <= 2 * cache.len() + 64);
        }
        assert_eq!((cache.len(), cache.bytes), (1, cost(&filler(10))));
    }

    #[test]
    fn clear_starts_over_with_the_new_limit() {
        let mut cache = DnsCache::new(4);
        let t0 = Instant::now();
        cache.insert(key("a.test."), filler(10), 60, t0);
        cache.clear(1);
        assert_eq!((cache.len(), cache.bytes, cache.order.len()), (0, 0, 0));
        cache.insert(key("a.test."), filler(10), 60, t0);
        cache.insert(key("b.test."), filler(10), 60, t0);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&key("b.test."), t0).is_some());

        cache.clear(0);
        cache.insert(key("a.test."), filler(10), 60, t0);
        assert_eq!((cache.len(), cache.bytes), (0, 0), "a limit of 0 turns the cache off");
    }

    #[test]
    fn ttl_rules() {
        assert_eq!(cacheable_ttl(&answer(300), 0, 100), Some(100));
        assert_eq!(cacheable_ttl(&answer(5), 30, 100), Some(30));
        assert_eq!(cacheable_ttl(&answer(0), 0, 100), None);

        let mut servfail = Message::new();
        servfail.set_response_code(ResponseCode::ServFail);
        assert_eq!(cacheable_ttl(&servfail, 0, 100), None);

        let mut nx = Message::new();
        nx.set_response_code(ResponseCode::NXDomain);
        assert_eq!(cacheable_ttl(&nx, 0, 100), Some(DEFAULT_NEGATIVE_TTL));
    }
}
