//! Polls the hotspot backend: access point state and associated stations.

use std::{sync::Arc, time::Duration};

use captun_core::PresenceChange;
use captun_ipc::HotspotState;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, info, warn};

use crate::hub::{Hub, lock};

const POLL: Duration = Duration::from_secs(2);

pub(crate) async fn run(hub: Arc<Hub>) {
    let mut ticker = interval(POLL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_error: Option<String> = None;

    let mut clients_error: Option<String> = None;

    loop {
        ticker.tick().await;
        // First, before anything below can cut the tick short: a rule's time
        // window that opened or closed applies to open connections at once.
        hub.check_schedules();
        // Keeps the table that tells devices apart fresh, off this thread.
        hub.refresh_neighbors();
        hub.check_engine().await;
        // What devices may reach follows the shared networks and this
        // computer's addresses; rules that could not be put in are retried.
        hub.reconcile_reach().await;

        // Start and stop own the status while they run: observe_hotspot leaves
        // it alone while they hold the control lock. A transition Windows
        // makes by itself (its power-saving turn-off, say) is looked at again
        // every tick until it settles, never taken as final.
        let current = hub.hotspot_status();

        let state = match hub.backend().state().await {
            Ok(state) => {
                last_error = None;
                state
            }
            Err(e) => {
                let message = e.to_string();
                // Report a persistent failure once, not every two seconds.
                if last_error.as_deref() != Some(&message) {
                    warn!("hotspot state unavailable: {message}");
                    last_error = Some(message);
                }
                continue;
            }
        };

        // Keep a start error visible until the user acts on it.
        let error = if !state.running && current.state == HotspotState::Failed { current.error.clone() } else { None };
        if current.state == HotspotState::Running && !state.running {
            info!("the access point went down outside Captun");
        }
        hub.observe_hotspot(Hub::status_from_backend(&state, error)).await;

        let mut observed = if state.running {
            match hub.backend().clients().await {
                Ok(list) => {
                    clients_error = None;
                    list
                }
                Err(e) => {
                    // Once per problem, not every two seconds.
                    let message = e.to_string();
                    if clients_error.as_deref() != Some(&message) {
                        warn!("cannot list hotspot clients: {message}");
                        clients_error = Some(message);
                    }
                    continue;
                }
            }
        } else {
            Vec::new()
        };
        // The device limit covers Wi-Fi stations only; the access network's DHCP
        // pool bounds its own.
        let stations: Vec<_> = observed.iter().map(|c| c.mac).collect();
        let capacity_changed = hub.update_capacity(&stations);
        // Devices on the wired/USB access network are tracked by their DHCP leases.
        observed.extend(hub.access_leases());
        let changes = lock(&hub.registry).apply_snapshot(&observed, hub.now_ms());
        log_changes(&changes);
        // Right after the snapshot, so whoever just left is weighed too.
        let forgotten = hub.prune_devices();
        if !changes.is_empty() || capacity_changed || forgotten {
            hub.broadcast_clients();
        }
    }
}

/// Each device's coming and going at debug, and one line at info for a tick
/// in which several came or went: a device sending under made-up MACs makes
/// hundreds a tick, which must not fill the log.
fn log_changes(changes: &[PresenceChange]) {
    let (mut joined, mut left) = (0, 0);
    for change in changes {
        match change {
            PresenceChange::Joined(_) => joined += 1,
            PresenceChange::Left(_) => left += 1,
            PresenceChange::Updated(_) => {}
        }
        debug!(?change, "device presence changed");
    }
    if joined + left > 1 {
        info!("{}", summary(joined, left));
    }
}

/// "12 devices joined, 10 left", "1 device left".
fn summary(joined: usize, left: usize) -> String {
    let count = |n: usize| if n == 1 { "1 device".to_owned() } else { format!("{n} devices") };
    match (joined, left) {
        (0, left) => format!("{} left", count(left)),
        (joined, 0) => format!("{} joined", count(joined)),
        (joined, left) => format!("{} joined, {left} left", count(joined)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_busy_tick_reads_as_one_line() {
        assert_eq!(summary(12, 10), "12 devices joined, 10 left");
        assert_eq!(summary(2, 0), "2 devices joined");
        assert_eq!(summary(0, 3), "3 devices left");
        assert_eq!(summary(1, 1), "1 device joined, 1 left");
    }
}
