//! Firewall and routing decisions. Given who sent a flow and where it is
//! going, decide whether it may pass and which egress carries it. The engine
//! is pure (the caller supplies the clock) and immutable: a config change
//! builds a new engine that is swapped in atomically. The one exception is
//! the rules' hit counters, which the caller bumps for real traffic and which
//! carry over to the next engine while the rules stay the same.

mod engine;
mod hits;
pub mod lists;
mod ranges;
mod ratelimit;

pub use engine::{Admission, Decision, FlowContext, Lists, LocalTime, Lookup, PolicyEngine, Verdict};
pub use hits::{HitCounters, Hits};
pub use lists::RuleList;
pub use ratelimit::TokenBucket;
