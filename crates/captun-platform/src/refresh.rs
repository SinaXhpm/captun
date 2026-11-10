//! A value read from the system now and then and shared by every caller: one
//! read at a time, served while it is fresh.

use std::{
    fmt,
    ops::Deref,
    sync::{Condvar, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) struct Refreshed<T> {
    state: Mutex<State<T>>,
    /// Woken when a read ends.
    read_ended: Condvar,
    /// How long a value serves, from when its read began: the value is as old
    /// as that moment, however long the read took.
    fresh_for: Duration,
    /// How long a value also serves after its read ended, so reads slower than
    /// `fresh_for` do not run back to back.
    rest: Duration,
    /// How long a caller waits for a read already running before it takes the
    /// value in hand: a read that never ends must not hold up everyone.
    wait_at_most: Duration,
}

struct State<T> {
    value: T,
    /// When the last read began and ended. A failed read counts too, so a
    /// system that fails to answer is not asked again at once.
    began: Option<Instant>,
    ended: Option<Instant>,
    reading: bool,
}

impl<T> fmt::Debug for Refreshed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refreshed").field("fresh_for", &self.fresh_for).finish_non_exhaustive()
    }
}

impl<T: Clone> Refreshed<T> {
    pub(crate) const fn new(value: T, fresh_for: Duration, rest: Duration, wait_at_most: Duration) -> Self {
        Self {
            state: Mutex::new(State { value, began: None, ended: None, reading: false }),
            read_ended: Condvar::new(),
            fresh_for,
            rest,
            wait_at_most,
        }
    }

    /// The value in hand, never waiting for a read.
    pub(crate) fn value(&self) -> T {
        lock(&self.state).value.clone()
    }

    /// The value in hand, when it is still fresh.
    pub(crate) fn fresh(&self) -> Option<T> {
        let state = lock(&self.state);
        self.is_fresh(&state, Instant::now()).then(|| state.value.clone())
    }

    fn is_fresh(&self, state: &State<T>, now: Instant) -> bool {
        self.is_fresh_within(state, now, self.fresh_for)
    }

    fn is_fresh_within(&self, state: &State<T>, now: Instant, fresh_for: Duration) -> bool {
        let within = |at: Option<Instant>, span: Duration| at.is_some_and(|at| now.saturating_duration_since(at) < span);
        within(state.began, fresh_for) || within(state.ended, self.rest)
    }

    /// The value, read again first when it is no longer fresh. A caller that
    /// finds a read running waits for its result instead of starting another.
    /// `read` gives `None` when it fails, and the value in hand stands.
    pub(crate) fn get(&self, read: impl FnOnce() -> Option<T>) -> T {
        self.get_when(|cache, state, now| cache.is_fresh(state, now), read)
    }

    /// [`Self::get`] for a caller that takes a value only while it is
    /// `fresh_for` old, from when its read began, rather than the cache's own
    /// span; a slow read still rests the same.
    pub(crate) fn get_within(&self, fresh_for: Duration, read: impl FnOnce() -> Option<T>) -> T {
        self.get_when(move |cache, state, now| cache.is_fresh_within(state, now, fresh_for), read)
    }

    /// The value from a read that began at `since` or later, for a caller that
    /// has just changed what is read, or waits for it to change.
    pub(crate) fn get_since(&self, since: Instant, read: impl FnOnce() -> Option<T>) -> T {
        self.get_when(|_, state, _| state.began.is_some_and(|began| began >= since), read)
    }

    fn get_when(&self, fresh: impl Fn(&Self, &State<T>, Instant) -> bool, read: impl FnOnce() -> Option<T>) -> T {
        let start = Instant::now();
        let deadline = start.checked_add(self.wait_at_most).unwrap_or(start);
        let mut state = lock(&self.state);
        loop {
            let now = Instant::now();
            if fresh(self, &state, now) {
                return state.value.clone();
            }
            if !state.reading {
                break;
            }
            let left = deadline.saturating_duration_since(now);
            if left.is_zero() {
                return state.value.clone();
            }
            state = self.read_ended.wait_timeout(state, left).unwrap_or_else(PoisonError::into_inner).0;
        }
        state.reading = true;
        drop(state);
        Reading { cache: self, began: None, fresh: None }.run(read)
    }

    /// Claims the next read when one is due and none is running, for the
    /// caller to run elsewhere (on a blocking thread, say).
    pub(crate) fn claim<H: Deref<Target = Self>>(cache: H) -> Option<Reading<T, H>> {
        {
            let mut state = lock(&cache.state);
            if state.reading || cache.is_fresh(&state, Instant::now()) {
                return None;
            }
            state.reading = true;
        }
        Some(Reading { cache, began: None, fresh: None })
    }
}

/// A read one caller has claimed. Dropped, whether it ran, failed or
/// panicked, it lets the next read start and wakes those waiting.
pub(crate) struct Reading<T, H: Deref<Target = Refreshed<T>>> {
    cache: H,
    began: Option<Instant>,
    fresh: Option<T>,
}

impl<T, H: Deref<Target = Refreshed<T>>> fmt::Debug for Reading<T, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reading").field("began", &self.began).finish_non_exhaustive()
    }
}

impl<T: Clone, H: Deref<Target = Refreshed<T>>> Reading<T, H> {
    /// Runs the read and keeps what it gives; returns the value in hand after.
    pub(crate) fn run(mut self, read: impl FnOnce() -> Option<T>) -> T {
        // Stamped before the read, so the value's age counts from what it saw.
        self.began = Some(Instant::now());
        self.fresh = read();
        match &self.fresh {
            Some(value) => value.clone(),
            None => self.cache.value(),
        }
    }
}

impl<T, H: Deref<Target = Refreshed<T>>> Drop for Reading<T, H> {
    fn drop(&mut self) {
        let cache = &*self.cache;
        let mut state = lock(&cache.state);
        if let Some(value) = self.fresh.take() {
            state.value = value;
        }
        if let Some(began) = self.began {
            state.began = Some(began);
            state.ended = Some(Instant::now());
        }
        state.reading = false;
        drop(state);
        cache.read_ended.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread::sleep,
    };

    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// A cache of a number, its times in milliseconds.
    fn cache(fresh_for: u64, rest: u64, wait: u64) -> Refreshed<u32> {
        Refreshed::new(0, Duration::from_millis(fresh_for), Duration::from_millis(rest), Duration::from_millis(wait))
    }

    #[test]
    fn a_fresh_value_is_served_without_reading() {
        let cache = cache(10_000, 0, 1000);
        let reads = AtomicUsize::new(0);
        let read = || {
            reads.fetch_add(1, Ordering::Relaxed);
            Some(7)
        };
        assert_eq!(cache.fresh(), None, "nothing read yet");
        assert_eq!(cache.get(read), 7);
        assert_eq!(cache.get(read), 7);
        assert_eq!(cache.fresh(), Some(7));
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_stale_value_is_read_again() {
        let cache = cache(20, 0, 1000);
        assert_eq!(cache.get(|| Some(1)), 1);
        sleep(MS * 40);
        assert_eq!(cache.fresh(), None);
        assert_eq!(cache.get(|| Some(2)), 2);
    }

    #[test]
    fn a_caller_may_take_a_shorter_span() {
        let cache = cache(10_000, 0, 1000);
        assert_eq!(cache.get(|| Some(1)), 1);
        sleep(MS * 40);
        // Still fresh for the cache's own span, too old for 20 ms.
        assert_eq!(cache.get(|| Some(2)), 1);
        assert_eq!(cache.get_within(MS * 20, || Some(3)), 3);
        // That read serves both, from when it began.
        assert_eq!(cache.get_within(MS * 20, || Some(4)), 3);
        assert_eq!(cache.get(|| Some(5)), 3);
    }

    #[test]
    fn a_shorter_span_still_rests_after_a_slow_read() {
        let cache = cache(10, 100, 1000);
        // Slower than either span: its value serves on for the rest.
        assert_eq!(
            cache.get_within(MS * 10, || {
                sleep(MS * 30);
                Some(1)
            }),
            1
        );
        assert_eq!(cache.get_within(MS * 10, || Some(2)), 1);
    }

    #[test]
    fn the_age_counts_from_when_the_read_began() {
        // A read slower than the value stays fresh is stale once it ends.
        let plain = cache(30, 0, 1000);
        plain.get(|| {
            sleep(MS * 60);
            Some(1)
        });
        assert_eq!(plain.fresh(), None);
        // With a rest, its value still serves for a moment after it ended.
        let rested = cache(30, 5_000, 1000);
        rested.get(|| {
            sleep(MS * 60);
            Some(1)
        });
        assert_eq!(rested.fresh(), Some(1));
    }

    #[test]
    fn callers_share_one_read() {
        let cache = Arc::new(cache(10_000, 0, 5_000));
        let reads = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (cache, reads) = (cache.clone(), reads.clone());
                std::thread::spawn(move || {
                    cache.get(|| {
                        reads.fetch_add(1, Ordering::Relaxed);
                        sleep(MS * 150);
                        Some(5)
                    })
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), 5, "every caller gets the one read's result");
        }
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_failed_read_keeps_the_value_and_is_not_retried_at_once() {
        let cache = cache(10_000, 0, 1000);
        assert_eq!(cache.get(|| Some(3)), 3);
        let fresh_since = Instant::now();
        let reads = AtomicUsize::new(0);
        let failing = || {
            reads.fetch_add(1, Ordering::Relaxed);
            None
        };
        assert_eq!(cache.get_since(fresh_since, failing), 3, "the last good value stands in");
        assert_eq!(cache.get(failing), 3);
        assert_eq!(reads.load(Ordering::Relaxed), 1, "the failed read counts as a read");
    }

    #[test]
    fn get_since_reads_again_even_while_fresh() {
        let cache = cache(10_000, 10_000, 1000);
        assert_eq!(cache.get(|| Some(1)), 1);
        let since = Instant::now();
        assert_eq!(cache.get_since(since, || Some(2)), 2);
        assert_eq!(cache.get_since(since, || Some(3)), 2, "a read since then is in hand");
    }

    /// Starts a read of `value` on another thread that takes `ms`, and
    /// returns once it is running.
    fn reading_elsewhere(cache: &Arc<Refreshed<u32>>, ms: u64, value: u32) -> std::thread::JoinHandle<u32> {
        let (started, running) = std::sync::mpsc::channel();
        let cache = cache.clone();
        let thread = std::thread::spawn(move || {
            cache.get(|| {
                started.send(()).unwrap();
                sleep(Duration::from_millis(ms));
                Some(value)
            })
        });
        running.recv().unwrap();
        thread
    }

    #[test]
    fn get_since_does_not_settle_for_a_read_that_began_before() {
        let cache = Arc::new(cache(10_000, 10_000, 5_000));
        let slow = reading_elsewhere(&cache, 150, 1);
        let since = Instant::now();
        assert_eq!(cache.get_since(since, || Some(2)), 2, "waits for the running read, then reads again");
        assert_eq!(slow.join().unwrap(), 1);
    }

    #[test]
    fn a_read_that_hangs_holds_others_up_only_so_long() {
        let cache = Arc::new(cache(0, 0, 50));
        assert_eq!(cache.get(|| Some(1)), 1);
        let hung = reading_elsewhere(&cache, 600, 2);
        let asked = Instant::now();
        assert_eq!(cache.get(|| Some(9)), 1, "the value in hand, not a second read");
        assert!(asked.elapsed() < MS * 400, "gave up waiting after {:?}", asked.elapsed());
        assert_eq!(hung.join().unwrap(), 2);
    }

    #[test]
    fn a_panicking_read_lets_the_next_one_run() {
        let cache = Arc::new(cache(0, 0, 1000));
        let panicked = {
            let cache = cache.clone();
            std::thread::spawn(move || cache.get(|| panic!("the system's answer confused us")))
        };
        assert!(panicked.join().is_err());
        assert_eq!(cache.get(|| Some(4)), 4, "not stuck waiting for the read that panicked");
    }

    #[test]
    fn a_claimed_read_runs_elsewhere_and_only_once() {
        let cache = Arc::new(cache(10_000, 0, 1000));
        let claim = Refreshed::claim(cache.clone()).unwrap();
        assert!(Refreshed::claim(cache.clone()).is_none(), "one read at a time");
        let thread = std::thread::spawn(move || claim.run(|| Some(6)));
        assert_eq!(thread.join().unwrap(), 6);
        assert_eq!(cache.fresh(), Some(6));
        assert!(Refreshed::claim(cache.clone()).is_none(), "fresh: nothing due");
    }

    #[test]
    fn a_claim_dropped_unrun_gives_the_read_back() {
        let cache = Arc::new(cache(10_000, 0, 1000));
        drop(Refreshed::claim(cache.clone()).unwrap());
        assert_eq!(cache.fresh(), None, "nothing was read");
        assert!(Refreshed::claim(cache.clone()).is_some(), "the next read may start");
    }
}
