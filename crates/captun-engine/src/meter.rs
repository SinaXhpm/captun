use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use captun_core::MacAddr;
use captun_policy::TokenBucket;

/// One speed limit's bucket, shared by everything it paces.
type Bucket = Arc<Mutex<TokenBucket>>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The speed limit on all devices together in one direction: its rate and
/// bucket while one is set.
#[derive(Debug, Default)]
struct TotalLimit {
    kbps: Option<u64>,
    bucket: Option<TokenBucket>,
}

/// How one flow is paced in one direction: by its device's limit, if it has
/// one, and by the limit on all devices together, if one is set, whichever
/// holds it back more. The device's bucket is shared by all its flows and the
/// total one by every flow, so neither limit can be beaten by opening more
/// connections; a change to the total limit reaches flows already open.
#[derive(Clone, Debug)]
pub(crate) struct SharedBucket {
    device: Option<Bucket>,
    total: Arc<Mutex<TotalLimit>>,
}

impl SharedBucket {
    /// Charges `bytes` to both limits and says how long to wait before
    /// sending them (see [`TokenBucket::take`]).
    pub(crate) fn take(&self, bytes: usize, now: Instant) -> Duration {
        // The device's bucket first, then the total one, as in `try_take`.
        let device = self.device.as_ref().map_or(Duration::ZERO, |b| lock(b).take(bytes, now));
        let total = lock(&self.total).bucket.as_mut().map_or(Duration::ZERO, |b| b.take(bytes, now));
        device.max(total)
    }

    /// Charges `bytes` only if both limits can pay for them now, and says
    /// whether they did (see [`TokenBucket::try_take`]): a datagram either
    /// limit refuses is charged to neither.
    pub(crate) fn try_take(&self, bytes: usize, now: Instant) -> bool {
        // Always the device's lock before the total one, so two flows never
        // wait on each other.
        let mut device = self.device.as_ref().map(|b| lock(b));
        let mut total = lock(&self.total);
        let fits = device.as_mut().is_none_or(|b| b.can_take(bytes, now))
            && total.bucket.as_mut().is_none_or(|b| b.can_take(bytes, now));
        if fits {
            if let Some(b) = device.as_mut() {
                b.try_take(bytes, now);
            }
            if let Some(b) = total.bucket.as_mut() {
                b.try_take(bytes, now);
            }
        }
        fits
    }
}

/// Which way bytes are flowing, from the hotspot client's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Internet → client.
    Down,
    /// Client → internet.
    Up,
}

/// Byte totals for one client (or for traffic that could not be attributed to
/// a known station). Updated lock-free from the two directions of each flow.
#[derive(Debug, Default)]
pub struct Counters {
    down: AtomicU64,
    up: AtomicU64,
    flows: AtomicU64,
}

impl Counters {
    pub(crate) fn add(&self, direction: Direction, bytes: u64) {
        match direction {
            Direction::Down => &self.down,
            Direction::Up => &self.up,
        }
        .fetch_add(bytes, Ordering::Relaxed);
    }

    fn flow_started(&self) {
        self.flows.fetch_add(1, Ordering::Relaxed);
    }

    fn flow_ended(&self) {
        self.flows.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            down_bytes: self.down.load(Ordering::Relaxed),
            up_bytes: self.up.load(Ordering::Relaxed),
            active_flows: self.flows.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub down_bytes: u64,
    pub up_bytes: u64,
    pub active_flows: u64,
}

/// Cumulative traffic per station. Rates are derived by the caller from the
/// difference between two snapshots, so the meter itself stays simple.
#[derive(Debug, Default)]
pub struct TrafficMeter {
    clients: Mutex<HashMap<MacAddr, Arc<Counters>>>,
    /// Flows whose source IP did not map to a known station.
    unattributed: Arc<Counters>,
    /// Speed limits per device, direction and rate: one bucket for all of a
    /// device's flows, so its limit holds however many it opens.
    buckets: Mutex<HashMap<(MacAddr, Direction, u64), Bucket>>,
    /// The speed limit on all devices together, down and up.
    total: [Arc<Mutex<TotalLimit>>; 2],
}

impl TrafficMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// What paces a flow of `client` in `direction`: the device's limit at
    /// `kbps`, shared by all its flows (a flow of no known device gets one of
    /// its own), and the limit on all devices together. Always given, so a
    /// total limit set later reaches the flow too.
    pub(crate) fn bucket(&self, client: Option<MacAddr>, direction: Direction, kbps: Option<u64>) -> Option<SharedBucket> {
        let device = kbps.filter(|k| *k > 0).map(|kbps| {
            let fresh = || Arc::new(Mutex::new(TokenBucket::from_kbps(kbps, Instant::now())));
            match client {
                None => fresh(),
                Some(mac) => lock(&self.buckets).entry((mac, direction, kbps)).or_insert_with(fresh).clone(),
            }
        });
        Some(SharedBucket { device, total: self.total[way(direction)].clone() })
    }

    /// Sets the speed limit on all devices together, in kbit/s; `None` (or 0)
    /// either way is unlimited. Flows already open keep to it at once; an
    /// unchanged limit keeps its bucket, and what is owed on it.
    pub fn set_total_limit(&self, down_kbps: Option<u64>, up_kbps: Option<u64>) {
        for (direction, kbps) in [(Direction::Down, down_kbps), (Direction::Up, up_kbps)] {
            let kbps = kbps.filter(|k| *k > 0);
            let mut total = lock(&self.total[way(direction)]);
            if total.kbps != kbps {
                *total = TotalLimit { kbps, bucket: kbps.map(|k| TokenBucket::from_kbps(k, Instant::now())) };
            }
        }
    }

    /// Counters for a flow belonging to `client` (or the unattributed bucket).
    /// Held by the flow for its lifetime, so per-chunk accounting is a plain
    /// atomic add with no map lookup.
    pub fn counters(&self, client: Option<MacAddr>) -> Arc<Counters> {
        match client {
            None => self.unattributed.clone(),
            Some(mac) => self
                .clients
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(mac)
                .or_default()
                .clone(),
        }
    }

    pub fn snapshot(&self, client: &MacAddr) -> Option<CounterSnapshot> {
        self.clients.lock().unwrap_or_else(|e| e.into_inner()).get(client).map(|c| c.snapshot())
    }

    /// Every station's counters now, in no order.
    pub fn snapshot_all(&self) -> Vec<(MacAddr, CounterSnapshot)> {
        self.clients.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(mac, c)| (*mac, c.snapshot())).collect()
    }

    pub fn unattributed(&self) -> CounterSnapshot {
        self.unattributed.snapshot()
    }

    /// Forgets a station's counters, e.g. when it is removed from the config.
    pub fn forget(&self, client: &MacAddr) {
        self.clients.lock().unwrap_or_else(|e| e.into_inner()).remove(client);
        self.buckets.lock().unwrap_or_else(|e| e.into_inner()).retain(|(mac, _, _), _| mac != client);
    }
}

/// Where a direction's total limit sits in `TrafficMeter::total`.
fn way(direction: Direction) -> usize {
    match direction {
        Direction::Down => 0,
        Direction::Up => 1,
    }
}

/// RAII counter for one flow: bumps the active-flow gauge while it lives and
/// records bytes as they move.
#[derive(Debug)]
pub struct FlowMeter {
    counters: Arc<Counters>,
}

impl FlowMeter {
    pub(crate) fn new(counters: Arc<Counters>) -> Self {
        counters.flow_started();
        Self { counters }
    }

    pub(crate) fn add(&self, direction: Direction, bytes: u64) {
        self.counters.add(direction, bytes);
    }
}

impl Drop for FlowMeter {
    fn drop(&mut self) {
        self.counters.flow_ended();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([2, 0, 0, 0, 0, n])
    }

    #[test]
    fn counts_per_client_and_direction() {
        let meter = TrafficMeter::new();
        {
            let flow = FlowMeter::new(meter.counters(Some(mac(1))));
            flow.add(Direction::Down, 500);
            flow.add(Direction::Up, 120);
            let snap = meter.snapshot(&mac(1)).unwrap();
            assert_eq!((snap.down_bytes, snap.up_bytes, snap.active_flows), (500, 120, 1));
        }
        // Dropping the flow leaves totals but clears the active-flow gauge.
        assert_eq!(meter.snapshot(&mac(1)).unwrap().active_flows, 0);
        assert!(meter.snapshot(&mac(9)).is_none());
    }

    #[test]
    fn unattributed_bucket_and_forget() {
        let meter = TrafficMeter::new();
        FlowMeter::new(meter.counters(None)).add(Direction::Down, 42);
        assert_eq!(meter.unattributed().down_bytes, 42);

        FlowMeter::new(meter.counters(Some(mac(1)))).add(Direction::Up, 10);
        meter.forget(&mac(1));
        assert!(meter.snapshot(&mac(1)).is_none());
    }

    // 800 kbit/s is 100 000 B/s, with a burst of a quarter second: 25 000 B.
    const TOTAL_KBPS: u64 = 800;

    #[test]
    fn the_total_limit_is_shared_by_every_device_and_reaches_open_flows() {
        let meter = TrafficMeter::new();
        let t0 = Instant::now();
        // Taken before any total limit is set, as a flow already open would.
        let a = meter.bucket(Some(mac(1)), Direction::Down, None).unwrap();
        let b = meter.bucket(Some(mac(2)), Direction::Down, None).unwrap();
        assert_eq!(a.take(1_000_000, t0), Duration::ZERO, "unlimited until a total is set");

        meter.set_total_limit(Some(TOTAL_KBPS), None);
        // The burst goes free; what comes after is paid for by every device.
        assert_eq!(a.take(25_000, t0), Duration::ZERO);
        let wait = b.take(100_000, t0);
        assert!((wait.as_secs_f64() - 1.0).abs() < 0.01, "the second device waits for the first: {wait:?}");
        // Upload has no total limit.
        let up = meter.bucket(Some(mac(2)), Direction::Up, None).unwrap();
        assert_eq!(up.take(1_000_000, t0), Duration::ZERO);

        // Setting the same limit again keeps what is owed; lifting it frees everyone.
        meter.set_total_limit(Some(TOTAL_KBPS), None);
        assert!(a.take(1, t0) > Duration::ZERO, "the debt stays");
        meter.set_total_limit(None, None);
        assert_eq!(a.take(1_000_000, t0), Duration::ZERO);
    }

    #[test]
    fn a_device_waits_for_whichever_limit_is_tighter() {
        let meter = TrafficMeter::new();
        let t0 = Instant::now();
        meter.set_total_limit(Some(TOTAL_KBPS), Some(TOTAL_KBPS));
        // The device's own limit is a quarter of the total: 25 000 B/s.
        let device = meter.bucket(Some(mac(1)), Direction::Down, Some(200)).unwrap();
        assert_eq!(device.take(16_384, t0), Duration::ZERO, "its burst (16 KiB at the least)");
        let wait = device.take(25_000, t0);
        assert!((wait.as_secs_f64() - 1.0).abs() < 0.01, "paced by its own, tighter limit: {wait:?}");
    }

    #[test]
    fn a_datagram_either_limit_refuses_is_charged_to_neither() {
        let meter = TrafficMeter::new();
        let t0 = Instant::now();
        meter.set_total_limit(None, Some(TOTAL_KBPS));
        let tight = meter.bucket(Some(mac(1)), Direction::Up, Some(200)).unwrap();
        let other = meter.bucket(Some(mac(2)), Direction::Up, None).unwrap();
        // The total limit's whole burst and one more of its bursts in debt:
        // datagrams may go no further.
        assert!(other.try_take(25_000, t0));
        assert!(other.try_take(25_000, t0));
        assert!(!other.try_take(1_000, t0), "over the total limit");
        // Refused by the total limit, so the device's own bucket keeps its burst.
        assert!(!tight.try_take(1_000, t0));
        meter.set_total_limit(None, None);
        assert!(tight.try_take(16_384, t0), "the device's burst is still whole");
        assert!(tight.try_take(16_384, t0), "one burst of debt");
        assert!(!tight.try_take(1_000, t0), "and then its own limit refuses");
    }
}
