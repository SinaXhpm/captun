use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use captun_core::MacAddr;
use captun_policy::TokenBucket;

/// A device's speed limit in one direction, shared by all its flows.
pub(crate) type SharedBucket = Arc<Mutex<TokenBucket>>;

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
    buckets: Mutex<HashMap<(MacAddr, Direction, u64), SharedBucket>>,
}

impl TrafficMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The bucket pacing `client`'s traffic in `direction` at `kbps`, shared
    /// by all its flows; a flow of no known device gets one of its own.
    pub(crate) fn bucket(&self, client: Option<MacAddr>, direction: Direction, kbps: Option<u64>) -> Option<SharedBucket> {
        let kbps = kbps.filter(|k| *k > 0)?;
        let fresh = || Arc::new(Mutex::new(TokenBucket::from_kbps(kbps, Instant::now())));
        let Some(mac) = client else { return Some(fresh()) };
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        Some(buckets.entry((mac, direction, kbps)).or_insert_with(fresh).clone())
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

    pub fn unattributed(&self) -> CounterSnapshot {
        self.unattributed.snapshot()
    }

    /// Forgets a station's counters, e.g. when it is removed from the config.
    pub fn forget(&self, client: &MacAddr) {
        self.clients.lock().unwrap_or_else(|e| e.into_inner()).remove(client);
        self.buckets.lock().unwrap_or_else(|e| e.into_inner()).retain(|(mac, _, _), _| mac != client);
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
}
