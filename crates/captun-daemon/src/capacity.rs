//! The hotspot's device limit: stations get a slot in arrival order and keep
//! it while they stay connected; anyone beyond the limit waits for a free slot.

use std::collections::HashSet;

use captun_core::MacAddr;

#[derive(Debug, Default)]
pub(crate) struct Capacity {
    /// Stations holding a slot, oldest first.
    admitted: Vec<MacAddr>,
}

impl Capacity {
    /// Reconciles the slots with the stations `present` now and returns the ones
    /// held back. Lowering the limit evicts the most recent arrivals first.
    pub(crate) fn update(&mut self, present: &[MacAddr], limit: Option<u32>) -> HashSet<MacAddr> {
        let cap = limit.map_or(usize::MAX, |l| l as usize);
        self.admitted.retain(|mac| present.contains(mac));
        self.admitted.truncate(cap);
        for &mac in present {
            if self.admitted.len() >= cap {
                break;
            }
            if !self.admitted.contains(&mac) {
                self.admitted.push(mac);
            }
        }
        present.iter().filter(|mac| !self.admitted.contains(mac)).copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, n])
    }

    fn held(set: HashSet<MacAddr>) -> Vec<MacAddr> {
        let mut v: Vec<_> = set.into_iter().collect();
        v.sort();
        v
    }

    #[test]
    fn no_limit_admits_everyone() {
        let mut c = Capacity::default();
        assert!(c.update(&[mac(1), mac(2), mac(3)], None).is_empty());
    }

    #[test]
    fn arrivals_beyond_the_limit_wait_for_a_slot() {
        let mut c = Capacity::default();
        assert!(c.update(&[mac(1), mac(2)], Some(2)).is_empty());
        assert_eq!(held(c.update(&[mac(1), mac(2), mac(3)], Some(2))), [mac(3)]);
        // A slot frees up: the waiting station takes it.
        assert!(c.update(&[mac(2), mac(3)], Some(2)).is_empty());
        // The one that left comes back to a full hotspot and now waits itself.
        assert_eq!(held(c.update(&[mac(1), mac(2), mac(3)], Some(2))), [mac(1)]);
    }

    #[test]
    fn slots_are_kept_regardless_of_report_order() {
        let mut c = Capacity::default();
        c.update(&[mac(1)], Some(1));
        assert_eq!(held(c.update(&[mac(2), mac(1)], Some(1))), [mac(2)]);
    }

    #[test]
    fn lowering_the_limit_evicts_the_latest_arrivals() {
        let mut c = Capacity::default();
        c.update(&[mac(1), mac(2), mac(3)], None);
        assert_eq!(held(c.update(&[mac(1), mac(2), mac(3)], Some(1))), [mac(2), mac(3)]);
    }
}
