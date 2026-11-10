//! How often each rule decided. The caller counts the decisions of real
//! traffic (a test of the rules is never counted); the counters travel with
//! the compiled rules, so an index always counts against the rules it came
//! from.

use std::sync::atomic::{AtomicU64, Ordering};

/// One rule's counts, as last read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hits {
    /// New connections the rule decided.
    pub connections: u64,
    /// Name lookups the rule decided.
    pub lookups: u64,
    /// When it last decided either (ms since the epoch); `None` until it does.
    pub last_ms: Option<u64>,
}

/// One rule's counters.
#[derive(Debug, Default)]
struct Counter {
    connections: AtomicU64,
    lookups: AtomicU64,
    /// 0 until the rule first decides.
    last_ms: AtomicU64,
}

impl Counter {
    fn read(&self) -> Hits {
        Hits {
            connections: self.connections.load(Ordering::Relaxed),
            lookups: self.lookups.load(Ordering::Relaxed),
            last_ms: Some(self.last_ms.load(Ordering::Relaxed)).filter(|&ms| ms != 0),
        }
    }
}

/// Counters for every rule, by index into `config.rules`. Atomics only, so
/// a flow or lookup that counts never allocates, takes a lock or waits on
/// another.
#[derive(Debug)]
pub struct HitCounters {
    rules: Box<[Counter]>,
}

impl HitCounters {
    /// Counters at zero for `rules` rules.
    pub fn new(rules: usize) -> Self {
        Self { rules: (0..rules).map(|_| Counter::default()).collect() }
    }

    /// How many rules are counted.
    pub(crate) fn len(&self) -> usize {
        self.rules.len()
    }

    /// Counts a connection rule `index` decided at `now_ms`.
    pub fn connection(&self, index: usize, now_ms: u64) {
        if let Some(counter) = self.rules.get(index) {
            counter.connections.fetch_add(1, Ordering::Relaxed);
            counter.last_ms.store(now_ms, Ordering::Relaxed);
        }
    }

    /// Counts a name lookup rule `index` decided at `now_ms`.
    pub fn lookup(&self, index: usize, now_ms: u64) {
        if let Some(counter) = self.rules.get(index) {
            counter.lookups.fetch_add(1, Ordering::Relaxed);
            counter.last_ms.store(now_ms, Ordering::Relaxed);
        }
    }

    /// Every rule's counts, in order.
    pub fn snapshot(&self) -> Vec<Hits> {
        self.rules.iter().map(Counter::read).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_each_rule_on_its_own() {
        let hits = HitCounters::new(3);
        hits.connection(0, 1_000);
        hits.connection(0, 2_000);
        hits.lookup(2, 1_500);
        // An index the rules do not have is not counted anywhere.
        hits.connection(3, 9_000);
        hits.lookup(usize::MAX, 9_000);
        assert_eq!(
            hits.snapshot(),
            [
                Hits { connections: 2, lookups: 0, last_ms: Some(2_000) },
                Hits::default(),
                Hits { connections: 0, lookups: 1, last_ms: Some(1_500) },
            ]
        );
    }
}
