use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

use crate::MacAddr;

/// Admin decision about a station. `Pending` stations are held in quarantine
/// when `network.quarantine_new_clients` is on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientState {
    #[default]
    Pending,
    Approved,
    Blocked,
}

/// What a hotspot backend reports about one associated station.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedClient {
    pub mac: MacAddr,
    #[serde(default)]
    pub addrs: Vec<IpAddr>,
    #[serde(default)]
    pub hostname: Option<String>,
}

/// Live presence of a station, reconciled from backend snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    pub mac: MacAddr,
    pub addrs: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub online: bool,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "mac", rename_all = "snake_case")]
pub enum PresenceChange {
    Joined(MacAddr),
    Left(MacAddr),
    Updated(MacAddr),
}

/// How long [`ClientRegistry::prune`] remembers an offline station that has
/// nothing saved: a day.
pub const OFFLINE_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
/// The most offline stations [`ClientRegistry::prune`] remembers.
pub const MAX_OFFLINE: usize = 1000;

/// Who is on the hotspot right now, with an IP → MAC index for the data plane,
/// which only sees IP headers on some platforms.
#[derive(Debug, Default)]
pub struct ClientRegistry {
    clients: HashMap<MacAddr, Presence>,
    by_ip: HashMap<IpAddr, MacAddr>,
}

impl ClientRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconciles a full snapshot from the hotspot backend. Stations missing
    /// from the snapshot are marked offline but remembered.
    pub fn apply_snapshot(&mut self, observed: &[ObservedClient], now_ms: u64) -> Vec<PresenceChange> {
        let mut changes = Vec::new();
        let mut seen = HashSet::with_capacity(observed.len());

        for obs in observed {
            if !seen.insert(obs.mac) {
                continue;
            }
            match self.clients.entry(obs.mac) {
                Entry::Vacant(slot) => {
                    slot.insert(Presence {
                        mac: obs.mac,
                        addrs: obs.addrs.clone(),
                        hostname: obs.hostname.clone(),
                        online: true,
                        first_seen_ms: now_ms,
                        last_seen_ms: now_ms,
                    });
                    changes.push(PresenceChange::Joined(obs.mac));
                }
                Entry::Occupied(mut slot) => {
                    let p = slot.get_mut();
                    let was_online = p.online;
                    let mut changed = false;
                    // Backends often learn addresses and names a beat after
                    // association; keep what we knew rather than blanking it.
                    if !obs.addrs.is_empty() && p.addrs != obs.addrs {
                        p.addrs = obs.addrs.clone();
                        changed = true;
                    }
                    if obs.hostname.is_some() && p.hostname != obs.hostname {
                        p.hostname = obs.hostname.clone();
                        changed = true;
                    }
                    p.online = true;
                    p.last_seen_ms = now_ms;
                    if !was_online {
                        changes.push(PresenceChange::Joined(obs.mac));
                    } else if changed {
                        changes.push(PresenceChange::Updated(obs.mac));
                    }
                }
            }
        }

        for p in self.clients.values_mut() {
            if p.online && !seen.contains(&p.mac) {
                p.online = false;
                changes.push(PresenceChange::Left(p.mac));
            }
        }

        self.reindex();
        changes
    }

    pub fn get(&self, mac: &MacAddr) -> Option<&Presence> {
        self.clients.get(mac)
    }

    /// Resolves the online station currently holding `ip`.
    pub fn by_ip(&self, ip: &IpAddr) -> Option<&Presence> {
        self.by_ip.get(ip).and_then(|mac| self.clients.get(mac))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Presence> {
        self.clients.values()
    }

    pub fn online_count(&self) -> usize {
        self.clients.values().filter(|p| p.online).count()
    }

    /// Drops an offline station from memory. Online stations are kept, since
    /// the next snapshot would re-add them anyway.
    pub fn forget(&mut self, mac: &MacAddr) -> bool {
        match self.clients.get(mac) {
            Some(p) if !p.online => {
                self.clients.remove(mac);
                true
            }
            _ => false,
        }
    }

    /// Forgets offline stations nobody needs remembered, so made-up MACs (a
    /// device can send under any number of them) cannot grow the list without
    /// end. Stations `keep` accepts (saved settings: a name, a rule) and online
    /// stations always stay. Of the rest, those last seen more than
    /// [`OFFLINE_RETENTION_MS`] ago go, and past [`MAX_OFFLINE`] of them the
    /// ones seen longest ago go too, so a flood cannot push out kept devices.
    /// Returns the MACs it dropped.
    pub fn prune(&mut self, now_ms: u64, keep: impl Fn(&MacAddr) -> bool) -> Vec<MacAddr> {
        let cutoff = now_ms.saturating_sub(OFFLINE_RETENTION_MS);
        let mut candidates: Vec<(u64, MacAddr)> =
            self.clients.values().filter(|p| !p.online && !keep(&p.mac)).map(|p| (p.last_seen_ms, p.mac)).collect();
        let mut removed: Vec<MacAddr> = Vec::new();
        candidates.retain(|&(seen, mac)| {
            let old = seen < cutoff;
            if old {
                removed.push(mac);
            }
            !old
        });
        if candidates.len() > MAX_OFFLINE {
            let excess = candidates.len() - MAX_OFFLINE;
            // The `excess` seen longest ago end up first, in no particular order.
            candidates.select_nth_unstable(excess - 1);
            removed.extend(candidates[..excess].iter().map(|&(_, mac)| mac));
        }
        for mac in &removed {
            self.clients.remove(mac);
        }
        // Only offline stations went and the address index holds online ones
        // alone, so it is still right.
        debug_assert!(self.by_ip.values().all(|mac| self.clients.contains_key(mac)));
        removed
    }

    fn reindex(&mut self) {
        self.by_ip.clear();
        for p in self.clients.values().filter(|p| p.online) {
            for ip in &p.addrs {
                self.by_ip.insert(*ip, p.mac);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(mac: &str, ip: Option<&str>) -> ObservedClient {
        ObservedClient {
            mac: mac.parse().unwrap(),
            addrs: ip.map(|ip| vec![ip.parse().unwrap()]).unwrap_or_default(),
            hostname: None,
        }
    }

    #[test]
    fn join_update_leave_rejoin() {
        let mut reg = ClientRegistry::new();
        let a: MacAddr = "02:00:00:00:00:01".parse().unwrap();

        assert_eq!(reg.apply_snapshot(&[obs("02:00:00:00:00:01", None)], 1), vec![PresenceChange::Joined(a)]);
        assert_eq!(
            reg.apply_snapshot(&[obs("02:00:00:00:00:01", Some("192.168.137.5"))], 2),
            vec![PresenceChange::Updated(a)]
        );
        assert_eq!(reg.by_ip(&"192.168.137.5".parse().unwrap()).unwrap().mac, a);

        assert_eq!(reg.apply_snapshot(&[], 3), vec![PresenceChange::Left(a)]);
        assert!(reg.by_ip(&"192.168.137.5".parse().unwrap()).is_none());
        assert_eq!(reg.get(&a).unwrap().addrs.len(), 1, "address is remembered while offline");

        assert_eq!(reg.apply_snapshot(&[obs("02:00:00:00:00:01", None)], 4), vec![PresenceChange::Joined(a)]);
        assert_eq!(reg.get(&a).unwrap().first_seen_ms, 1);
    }

    #[test]
    fn steady_state_is_quiet() {
        let mut reg = ClientRegistry::new();
        let snap = [obs("02:00:00:00:00:01", Some("10.0.0.2"))];
        reg.apply_snapshot(&snap, 1);
        assert!(reg.apply_snapshot(&snap, 2).is_empty());
    }

    fn nth(n: u32) -> String {
        let b = n.to_be_bytes();
        format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3])
    }

    const DAY: u64 = OFFLINE_RETENTION_MS;

    #[test]
    fn prune_drops_old_offline_stations_only() {
        let mut reg = ClientRegistry::new();
        reg.apply_snapshot(&[obs(&nth(1), Some("10.0.0.2")), obs(&nth(2), None), obs(&nth(3), None)], 1);
        // 2 and 3 leave; 1 stays online for days.
        reg.apply_snapshot(&[obs(&nth(1), Some("10.0.0.2"))], 2);
        reg.apply_snapshot(&[obs(&nth(1), Some("10.0.0.2"))], 3 * DAY);
        let named: MacAddr = nth(3).parse().unwrap();
        let removed = reg.prune(3 * DAY, |mac| *mac == named);
        assert_eq!(removed, vec![nth(2).parse::<MacAddr>().unwrap()]);
        assert!(reg.get(&nth(1).parse().unwrap()).is_some(), "online stations stay");
        assert!(reg.get(&named).is_some(), "stations with saved settings stay");
        assert_eq!(reg.by_ip(&"10.0.0.2".parse().unwrap()).unwrap().mac.to_string(), nth(1), "index still right");
    }

    #[test]
    fn prune_keeps_recently_seen_stations() {
        let mut reg = ClientRegistry::new();
        reg.apply_snapshot(&[obs(&nth(1), None)], 10);
        reg.apply_snapshot(&[], 20);
        assert!(reg.prune(10 + DAY, |_| false).is_empty(), "last seen exactly a day ago");
        assert_eq!(reg.prune(11 + DAY, |_| false).len(), 1);
        assert!(reg.prune(0, |_| false).is_empty(), "nothing left; an early clock is harmless");
    }

    #[test]
    fn prune_caps_offline_stations_oldest_first() {
        let mut reg = ClientRegistry::new();
        let total = MAX_OFFLINE as u32 + 50;
        // One station joins and leaves per millisecond, as a MAC flood does.
        for n in 0..total {
            reg.apply_snapshot(&[obs(&nth(n), None)], u64::from(n) * 2);
        }
        reg.apply_snapshot(&[obs(&nth(9999), Some("10.0.0.9"))], u64::from(total) * 2);
        let kept: MacAddr = nth(0).parse().unwrap();
        let removed = reg.prune(u64::from(total) * 2, |mac| *mac == kept);
        assert_eq!(removed.len(), 49, "{total} offline, one of them kept");
        let removed: HashSet<MacAddr> = removed.into_iter().collect();
        for n in 1..50 {
            assert!(removed.contains(&nth(n).parse().unwrap()), "station {n} was among the oldest");
        }
        assert!(reg.get(&kept).is_some(), "the oldest of all is kept by the caller");
        assert!(reg.get(&nth(50).parse().unwrap()).is_some());
        assert_eq!(reg.iter().filter(|p| !p.online).count(), MAX_OFFLINE + 1);
        assert_eq!(reg.online_count(), 1);
        assert!(reg.by_ip(&"10.0.0.9".parse().unwrap()).is_some());
        assert!(reg.prune(u64::from(total) * 2, |mac| *mac == kept).is_empty(), "nothing more to drop");
    }

    #[test]
    fn ip_moves_to_new_owner() {
        let mut reg = ClientRegistry::new();
        reg.apply_snapshot(&[obs("02:00:00:00:00:01", Some("10.0.0.2"))], 1);
        reg.apply_snapshot(&[obs("02:00:00:00:00:02", Some("10.0.0.2"))], 2);
        assert_eq!(reg.by_ip(&"10.0.0.2".parse().unwrap()).unwrap().mac.to_string(), "02:00:00:00:00:02");
        assert!(!reg.forget(&"02:00:00:00:00:02".parse().unwrap()));
        assert!(reg.forget(&"02:00:00:00:00:01".parse().unwrap()));
    }
}
