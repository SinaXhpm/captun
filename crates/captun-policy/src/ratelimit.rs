use std::time::{Duration, Instant};

/// Shortest burst we allow, so a capped TCP flow can still open its window.
const MIN_BURST_BYTES: f64 = 16.0 * 1024.0;

/// Token bucket that may go into debt: a write is admitted whole and the
/// debt is paid off by waiting, which keeps the average rate exact without
/// having to split buffers into token-sized pieces.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: u64, burst_bytes: u64, now: Instant) -> Self {
        let burst = (burst_bytes as f64).max(MIN_BURST_BYTES);
        Self { rate: (rate_bytes_per_sec as f64).max(1.0), burst, tokens: burst, last: now }
    }

    /// Kilobits per second as written in the config, with a burst worth a
    /// quarter of a second of traffic.
    pub fn from_kbps(kbps: u64, now: Instant) -> Self {
        let rate = kbps.saturating_mul(1000) / 8;
        Self::new(rate, rate / 4, now)
    }

    pub fn rate_bytes_per_sec(&self) -> u64 {
        self.rate as u64
    }

    /// Charges `bytes` and returns how long the caller must wait before
    /// sending them.
    pub fn take(&mut self, bytes: usize, now: Instant) -> Duration {
        self.refill(now);
        self.tokens -= bytes as f64;
        if self.tokens >= 0.0 { Duration::ZERO } else { Duration::from_secs_f64(-self.tokens / self.rate) }
    }

    /// Charges `bytes` only if the bucket can pay for them now, and says
    /// whether it did; nothing ever waits. For datagrams, which are dropped
    /// over the limit rather than held back in a queue.
    ///
    /// A datagram may leave the bucket in debt by up to one burst. Streams
    /// sharing the bucket ([`take`](Self::take)) keep it just below empty
    /// while they fill the limit, so datagrams that waited for it to fill
    /// would never get through beside them. One larger than two bursts needs
    /// a full bucket instead. Streams pay the debt by waiting, and the debt
    /// stays bounded, so the average rate stays exact.
    pub fn try_take(&mut self, bytes: usize, now: Instant) -> bool {
        self.refill(now);
        let bytes = bytes as f64;
        if self.tokens < (bytes - self.burst).min(self.burst) {
            return false;
        }
        self.tokens -= bytes;
        true
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
            self.last = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_paced() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100_000, 20_000, t0);
        assert_eq!(bucket.take(20_000, t0), Duration::ZERO, "burst is free");
        let wait = bucket.take(50_000, t0);
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6, "50 kB at 100 kB/s: {wait:?}");

        // After paying the debt the bucket is empty, not negative.
        let t1 = t0 + wait;
        assert!((bucket.take(10_000, t1).as_secs_f64() - 0.1).abs() < 1e-6);
    }

    #[test]
    fn idle_time_refills_up_to_burst_only() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100_000, 20_000, t0);
        bucket.take(20_000, t0);
        let later = t0 + Duration::from_secs(60);
        assert_eq!(bucket.take(20_000, later), Duration::ZERO);
        assert!(bucket.take(1, later) > Duration::ZERO);
    }

    #[test]
    fn try_take_admits_what_the_bucket_can_pay_and_drops_the_rest() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100_000, 20_000, t0);
        // A full bucket, then one burst of credit: 40 datagrams of 1 000 B.
        let admitted = (0..100).filter(|_| bucket.try_take(1_000, t0)).count();
        assert_eq!(admitted, 40);
        // What was refused cost nothing: 10 ms later 1 000 B more may go.
        let t1 = t0 + Duration::from_millis(10);
        assert!(bucket.try_take(1_000, t1));
        assert!(!bucket.try_take(1_000, t1));
    }

    #[test]
    fn try_take_never_goes_deeper_than_one_burst_in_debt() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100_000, 20_000, t0);
        while bucket.try_take(1_500, t0) {}
        assert!(bucket.tokens >= -bucket.burst, "{} in debt", -bucket.tokens);
        // Streams sharing the bucket pay the datagrams' debt (19 000 B): a
        // stream's next 10 000 B wait for it as well as for themselves.
        let wait = bucket.take(10_000, t0);
        assert!(wait > Duration::from_millis(250), "{wait:?}");
    }

    #[test]
    fn try_take_over_a_second_keeps_to_the_rate() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100_000, 20_000, t0);
        let mut admitted = 0;
        for ms in 0..=1_000 {
            // A flood: ten 1 000 B datagrams every millisecond, 10 MB/s.
            let now = t0 + Duration::from_millis(ms);
            admitted += (0..10).filter(|_| bucket.try_take(1_000, now)).count();
        }
        // One second at 100 kB/s, the full bucket and one burst of credit.
        assert!((139..=141).contains(&admitted), "{admitted} kB in a second");
    }

    #[test]
    fn datagrams_get_through_beside_a_stream_that_fills_the_limit() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100_000, 20_000, t0);
        let (mut now, mut stream_sent, mut datagrams_sent) = (t0, 0u64, 0u64);
        while now < t0 + Duration::from_secs(2) {
            // The stream sends 16 KiB at a time and waits as it is told.
            let wait = bucket.take(16 * 1024, now);
            stream_sent += 16 * 1024;
            // A call's datagrams keep coming meanwhile, one per 20 ms.
            let resume = now + wait;
            while now < resume {
                datagrams_sent += u64::from(bucket.try_take(200, now));
                now += Duration::from_millis(20);
            }
            now = now.max(resume);
        }
        assert!(datagrams_sent >= 50, "only {datagrams_sent} datagrams of 100 got through");
        // Together they still keep to the limit.
        let rate = (stream_sent + datagrams_sent * 200) as f64 / (now - t0).as_secs_f64();
        assert!(rate <= 100_000.0 * 1.25, "{rate} B/s");
    }

    #[test]
    fn a_datagram_larger_than_two_bursts_needs_a_full_bucket() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100_000, 20_000, t0);
        assert!(bucket.try_take(60_000, t0), "a full bucket pays for it");
        assert!(!bucket.try_take(60_000, t0 + Duration::from_millis(500)));
        assert!(bucket.try_take(60_000, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn kbps_conversion() {
        let bucket = TokenBucket::from_kbps(8_000, Instant::now());
        assert_eq!(bucket.rate_bytes_per_sec(), 1_000_000);
    }
}
