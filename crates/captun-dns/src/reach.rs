//! Whether a DNS server can be reached on one way out, for devices that may
//! be answered by this computer's own resolver instead (those that go out
//! directly).
//!
//! A server counts as unreachable only after a few errors close together that
//! say it could not be reached. A bad answer never counts: a device can cause
//! one with a name of its choosing, and it would send every device on that
//! way out to this computer's resolver. While a server counts as unreachable,
//! one query now and then still tries it, so one that works again is used
//! again within seconds.

use std::{
    collections::VecDeque,
    io,
    time::{Duration, Instant},
};

/// This many errors that say the server could not be reached ...
pub(crate) const MARK_AFTER: usize = 3;
/// ... within this long make it count as unreachable.
const MARK_WITHIN: Duration = Duration::from_secs(10);
/// While it counts as unreachable, one query tries it again this often.
pub(crate) const TRY_EVERY: Duration = Duration::from_secs(5);

/// What is known about one DNS server on one way out. The handler drops it
/// whenever the server answers, so the errors before no longer count.
#[derive(Debug, Default)]
pub(crate) struct Reach {
    /// When the latest errors happened, at most [`MARK_AFTER`] of them.
    failures: VecDeque<Instant>,
    /// Set while the server counts as unreachable: when a query last tried it.
    tried: Option<Instant>,
}

impl Reach {
    /// Whether a query asks the server now, rather than only this computer's
    /// resolver. While the server counts as unreachable only one query about
    /// every [`TRY_EVERY`] does.
    pub(crate) fn should_ask(&mut self, now: Instant) -> bool {
        match self.tried {
            Some(at) if now.saturating_duration_since(at) < TRY_EVERY => false,
            Some(_) => {
                self.tried = Some(now);
                true
            }
            None => true,
        }
    }

    /// Notes an error that says the server could not be reached; true when it
    /// made the server count as unreachable.
    pub(crate) fn failed(&mut self, now: Instant) -> bool {
        if self.failures.len() == MARK_AFTER {
            self.failures.pop_front();
        }
        self.failures.push_back(now);
        let close_together = self.failures.len() == MARK_AFTER
            && self.failures.front().is_some_and(|first| now.saturating_duration_since(*first) <= MARK_WITHIN);
        if self.tried.is_none() && close_together {
            self.tried = Some(now);
            return true;
        }
        false
    }

    pub(crate) fn unreachable(&self) -> bool {
        self.tried.is_some()
    }
}

/// Whether `e` says the server could not be reached, rather than that it
/// answered badly. A connection that closed before the answer came counts.
pub(crate) fn cannot_reach(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn after(t0: Instant, secs: u64) -> Instant {
        t0 + Duration::from_secs(secs)
    }

    #[test]
    fn three_errors_close_together_make_a_server_unreachable() {
        let t0 = Instant::now();
        let mut reach = Reach::default();
        assert!(!reach.failed(t0));
        assert!(!reach.failed(after(t0, 4)));
        assert!(reach.should_ask(after(t0, 5)), "two errors are not enough");
        assert!(reach.failed(after(t0, 10)), "the third within 10 s is");
        assert!(reach.unreachable());
        assert!(!reach.should_ask(after(t0, 11)));
    }

    #[test]
    fn errors_far_apart_do_not() {
        let t0 = Instant::now();
        let mut reach = Reach::default();
        for secs in [0, 6, 12, 18, 24, 30] {
            assert!(!reach.failed(after(t0, secs)));
        }
        assert!(!reach.unreachable());
        assert!(reach.should_ask(after(t0, 31)));
    }

    #[test]
    fn while_unreachable_one_query_tries_now_and_then() {
        let t0 = Instant::now();
        let mut reach = Reach::default();
        for _ in 0..MARK_AFTER {
            reach.failed(t0);
        }
        assert!(!reach.should_ask(after(t0, 1)));
        assert!(!reach.should_ask(after(t0, 4)));
        assert!(reach.should_ask(after(t0, 5)), "the first query 5 s on tries it");
        assert!(!reach.should_ask(after(t0, 5)), "and only that one");
        assert!(!reach.should_ask(after(t0, 9)));
        assert!(reach.should_ask(after(t0, 10)));
        // More errors while it counts as unreachable change nothing.
        assert!(!reach.failed(after(t0, 10)));
        assert!(!reach.should_ask(after(t0, 11)));
        assert!(reach.unreachable());
    }

    #[test]
    fn only_errors_that_say_the_server_cannot_be_reached_count() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(cannot_reach(&kind.into()), "{kind:?}");
        }
        // ResourceBusy: the query waited for a turn and was never sent.
        for kind in [io::ErrorKind::InvalidData, io::ErrorKind::InvalidInput, io::ErrorKind::Other, io::ErrorKind::ResourceBusy] {
            assert!(!cannot_reach(&kind.into()), "{kind:?}");
        }
    }
}
