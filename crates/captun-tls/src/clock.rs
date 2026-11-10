use std::fmt;

use time::OffsetDateTime;

/// Where certificates get the time from; tests move it.
pub(crate) trait Clock: Send + Sync + fmt::Debug {
    /// Now, in whole seconds (certificates hold no fractions).
    fn now(&self) -> OffsetDateTime;
}

/// The computer's own clock.
#[derive(Debug)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        whole_seconds(OffsetDateTime::now_utc())
    }
}

pub(crate) fn whole_seconds(at: OffsetDateTime) -> OffsetDateTime {
    at.replace_nanosecond(0).unwrap_or(at)
}

/// A clock that stands still until moved.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct TestClock(std::sync::Mutex<OffsetDateTime>);

#[cfg(test)]
impl TestClock {
    pub(crate) fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(std::sync::Mutex::new(SystemClock.now())))
    }

    pub(crate) fn advance(&self, by: time::Duration) {
        let mut now = self.0.lock().unwrap();
        *now += by;
    }
}

#[cfg(test)]
impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}
