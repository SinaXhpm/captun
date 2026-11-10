//! Names each device looked up, by the addresses it was given, so that a rule
//! about a name also catches that device's connections that never say which
//! name they are for: QUIC, calls, and apps' own protocols. Each device has
//! names of its own: what one device's lookups return never changes how
//! another's connections are decided, so a guest cannot steer other devices'
//! traffic with lookups of its choosing, nor push out what they learned.

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use captun_core::MacAddr;

/// Addresses remembered per device and generation. Two generations are kept,
/// so an address stays known for at least this many newer ones of the same
/// device.
const PER_DEVICE: usize = 2048;
/// Devices whose names are kept. A new one past this pushes out the one that
/// learned least recently.
const MAX_DEVICES: usize = 512;
/// Addresses taken from one answer. One answer can carry thousands; more
/// would only push out the device's own other names.
const PER_ANSWER: usize = 32;
/// The longest name kept: the longest a website's name can be written. A
/// longer one (written with escapes) is no name a rule is about.
const MAX_NAME: usize = 253;
/// What one remembered address is counted as besides its name: its place in
/// a map, with the room maps keep spare, and the name's own header.
const ENTRY_BYTES: usize = 96;
/// What all devices' names may take together. One device's own share is far
/// below it (2 × 2048 addresses at most 349 bytes each, about 1.4 MiB), so it
/// bounds what many devices together can make the service hold. Past it, the
/// device that learned least recently is forgotten first.
const MAX_BYTES: usize = 32 * 1024 * 1024;

/// What one address was looked up by, and when.
#[derive(Debug)]
struct Learned {
    name: Arc<str>,
    /// [`LearnedNames::clock`] when it was learned.
    at: u64,
}

/// One device's names, in two generations.
#[derive(Debug, Default)]
struct DeviceNames {
    current: HashMap<IpAddr, Learned>,
    previous: HashMap<IpAddr, Learned>,
    /// What each generation is counted as (see [`ENTRY_BYTES`]).
    current_bytes: usize,
    previous_bytes: usize,
    /// [`LearnedNames::clock`] when it last learned a name.
    last: u64,
}

impl DeviceNames {
    fn get(&self, ip: &IpAddr) -> Option<&Learned> {
        self.current.get(ip).or_else(|| self.previous.get(ip))
    }

    fn bytes(&self) -> usize {
        self.current_bytes + self.previous_bytes
    }
}

#[derive(Debug, Default)]
pub(crate) struct LearnedNames {
    devices: HashMap<MacAddr, DeviceNames>,
    /// Counts the answers learned from, to tell which came last.
    clock: u64,
    /// What all devices' names are counted as.
    bytes: usize,
}

/// What one address learned by `name` is counted as.
fn cost(name: &str) -> usize {
    ENTRY_BYTES + name.len()
}

impl LearnedNames {
    /// Remembers that `device` was given `addrs` when it looked up `name`.
    pub(crate) fn learn(&mut self, device: MacAddr, name: &Arc<str>, addrs: &[IpAddr]) {
        if name.len() > MAX_NAME {
            return;
        }
        // 0.0.0.0 answers a blocked name; loopback answers local ones.
        let mut addrs = addrs
            .iter()
            .map(IpAddr::to_canonical)
            .filter(|a| !a.is_unspecified() && !a.is_loopback())
            .take(PER_ANSWER)
            .peekable();
        if addrs.peek().is_none() {
            return;
        }
        if !self.devices.contains_key(&device) && self.devices.len() >= MAX_DEVICES {
            self.forget_least_recent(device);
        }
        self.clock += 1;
        let (at, added) = (self.clock, cost(name));
        let names = self.devices.entry(device).or_default();
        names.last = at;
        for addr in addrs {
            // The same name again only says it is still in use.
            if let Some(known) = names.current.get_mut(&addr)
                && known.name == *name
            {
                known.at = at;
                continue;
            }
            if names.current.len() >= PER_DEVICE {
                self.bytes = self.bytes.saturating_sub(names.previous_bytes);
                names.previous = std::mem::take(&mut names.current);
                names.previous_bytes = std::mem::take(&mut names.current_bytes);
            }
            if let Some(replaced) = names.current.insert(addr, Learned { name: name.clone(), at }) {
                let freed = cost(&replaced.name);
                names.current_bytes = names.current_bytes.saturating_sub(freed);
                self.bytes = self.bytes.saturating_sub(freed);
            }
            names.current_bytes += added;
            self.bytes += added;
        }
        while self.bytes > MAX_BYTES && self.forget_least_recent(device) {}
    }

    /// The name `device` last looked `ip` up by, if it did lately.
    pub(crate) fn name_for(&self, device: MacAddr, ip: IpAddr) -> Option<Arc<str>> {
        self.devices.get(&device)?.get(&ip.to_canonical()).map(|learned| learned.name.clone())
    }

    /// The name a device last looked `ip` up by, whichever device that was.
    /// Only for the rules tester's "any device": a connection goes by its own
    /// device's names alone.
    pub(crate) fn any_name_for(&self, ip: IpAddr) -> Option<Arc<str>> {
        let ip = ip.to_canonical();
        self.devices
            .values()
            .filter_map(|names| names.get(&ip))
            .max_by_key(|learned| learned.at)
            .map(|learned| learned.name.clone())
    }

    /// Forgets every name `device` looked up.
    pub(crate) fn forget(&mut self, device: MacAddr) {
        if let Some(names) = self.devices.remove(&device) {
            self.bytes = self.bytes.saturating_sub(names.bytes());
        }
    }

    /// Forgets the device that learned least recently, other than `keep`.
    /// Says whether there was one.
    fn forget_least_recent(&mut self, keep: MacAddr) -> bool {
        let oldest = self
            .devices
            .iter()
            .filter(|(mac, _)| **mac != keep)
            .min_by_key(|(_, names)| names.last)
            .map(|(mac, _)| *mac);
        match oldest {
            Some(mac) => {
                self.forget(mac);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    const fn device(n: u16) -> MacAddr {
        let [high, low] = n.to_be_bytes();
        MacAddr::new([0x02, 0, 0, 0, high, low])
    }

    fn name(text: &str) -> Arc<str> {
        Arc::from(text)
    }

    /// `count` addresses from `base` on, one answer each, all by `text`.
    fn fill(names: &mut LearnedNames, mac: MacAddr, text: &str, base: u32, count: usize) {
        let text = name(text);
        for n in 0..count as u32 {
            names.learn(mac, &text, &[IpAddr::from(Ipv4Addr::from(base + n))]);
        }
    }

    /// What every device's names are counted as, added up afresh.
    fn counted(names: &LearnedNames) -> usize {
        names
            .devices
            .values()
            .flat_map(|device| device.current.values().chain(device.previous.values()))
            .map(|learned| cost(&learned.name))
            .sum()
    }

    #[test]
    fn the_latest_name_for_an_address_is_kept_for_a_while() {
        let mut names = LearnedNames::default();
        let me = device(1);
        names.learn(me, &name("g.whatsapp.net"), &[ip("157.240.1.53"), ip("2a03:2880::1"), ip("0.0.0.0"), ip("::1")]);
        assert_eq!(names.name_for(me, ip("157.240.1.53")).as_deref(), Some("g.whatsapp.net"));
        assert_eq!(names.name_for(me, ip("::ffff:157.240.1.53")).as_deref(), Some("g.whatsapp.net"));
        assert_eq!(names.name_for(me, ip("0.0.0.0")), None);
        assert_eq!(names.name_for(me, ip("::1")), None);

        names.learn(me, &name("other.example"), &[ip("157.240.1.53")]);
        assert_eq!(names.name_for(me, ip("157.240.1.53")).as_deref(), Some("other.example"));

        // Older addresses outlive one generation, then go.
        fill(&mut names, me, "filler.example", 0x0B00_0000, PER_DEVICE);
        assert_eq!(names.name_for(me, ip("2a03:2880::1")).as_deref(), Some("g.whatsapp.net"));
        fill(&mut names, me, "filler.example", 0x0C00_0000, PER_DEVICE);
        assert_eq!(names.name_for(me, ip("2a03:2880::1")), None);
        assert_eq!(names.bytes, counted(&names));
    }

    #[test]
    fn one_devices_lookups_never_change_anothers() {
        let mut names = LearnedNames::default();
        let (victim, guest) = (device(1), device(2));
        names.learn(victim, &name("g.whatsapp.net"), &[ip("157.240.1.53")]);

        // The guest's answer names the same address otherwise: only its own
        // connections go by that.
        names.learn(guest, &name("sites.ir"), &[ip("157.240.1.53")]);
        assert_eq!(names.name_for(victim, ip("157.240.1.53")).as_deref(), Some("g.whatsapp.net"));
        assert_eq!(names.name_for(guest, ip("157.240.1.53")).as_deref(), Some("sites.ir"));
        assert_eq!(names.name_for(device(3), ip("157.240.1.53")), None, "a device that looked nothing up");

        // However many addresses the guest is given, it pushes out only its own.
        fill(&mut names, guest, "flood.example", 0x0B00_0000, 3 * PER_DEVICE);
        assert_eq!(names.name_for(victim, ip("157.240.1.53")).as_deref(), Some("g.whatsapp.net"));
        assert_eq!(names.name_for(guest, ip("157.240.1.53")), None);
        let held = &names.devices[&guest];
        assert!(held.current.len() + held.previous.len() <= 2 * PER_DEVICE);
        assert_eq!(names.bytes, counted(&names));
    }

    #[test]
    fn one_answer_gives_at_most_32_addresses() {
        let mut names = LearnedNames::default();
        let many: Vec<IpAddr> = (1..=100u8).map(|n| IpAddr::from(Ipv4Addr::new(10, 0, 0, n))).collect();
        names.learn(device(1), &name("many.example"), &many);
        let known = many.iter().filter(|addr| names.name_for(device(1), **addr).is_some()).count();
        assert_eq!(known, PER_ANSWER);
        assert!(names.name_for(device(1), many[0]).is_some(), "the first ones");
    }

    #[test]
    fn a_name_too_long_to_be_a_websites_is_not_kept() {
        let mut names = LearnedNames::default();
        let long = format!("{}.example", "a".repeat(MAX_NAME));
        names.learn(device(1), &name(&long), &[ip("192.0.2.1")]);
        assert_eq!(names.name_for(device(1), ip("192.0.2.1")), None);
        assert!(names.devices.is_empty(), "nothing kept for it");
        // Nor does an answer with no address worth keeping make room for one.
        names.learn(device(1), &name("blocked.example"), &[ip("0.0.0.0")]);
        assert!(names.devices.is_empty());
    }

    #[test]
    fn the_device_that_learned_least_recently_is_forgotten_first() {
        let mut names = LearnedNames::default();
        let addr = ip("192.0.2.1");
        for n in 0..MAX_DEVICES as u16 {
            names.learn(device(n), &name("seen.example"), &[addr]);
        }
        // The first device learns again; the second is now the one that
        // learned least recently.
        names.learn(device(0), &name("again.example"), &[ip("192.0.2.2")]);
        names.learn(device(9999), &name("new.example"), &[addr]);
        assert_eq!(names.devices.len(), MAX_DEVICES);
        assert_eq!(names.name_for(device(1), addr), None, "forgotten");
        assert_eq!(names.name_for(device(0), addr).as_deref(), Some("seen.example"));
        assert_eq!(names.name_for(device(9999), addr).as_deref(), Some("new.example"));
        assert_eq!(names.bytes, counted(&names));
    }

    #[test]
    fn many_devices_together_stay_within_the_bytes_allowed() {
        let mut names = LearnedNames::default();
        let longest = "a".repeat(MAX_NAME);
        let per_device = 2 * PER_DEVICE * cost(&longest);
        let devices = MAX_BYTES / per_device + 2;
        for n in 0..devices {
            let base = 0x0B00_0000 + u32::try_from(n * 2 * PER_DEVICE).unwrap();
            fill(&mut names, device(u16::try_from(n).unwrap()), &longest, base, 2 * PER_DEVICE);
            assert!(names.bytes <= MAX_BYTES, "{} bytes after device {n}", names.bytes);
        }
        assert_eq!(names.bytes, counted(&names));
        assert!(!names.devices.contains_key(&device(0)), "the device that learned least recently went first");
        assert!(names.devices.contains_key(&device(u16::try_from(devices - 1).unwrap())), "the one learning now stays");
    }

    #[test]
    fn any_device_gives_the_name_looked_up_last() {
        let mut names = LearnedNames::default();
        let addr = ip("2001:db8::7");
        assert_eq!(names.any_name_for(addr), None);
        names.learn(device(1), &name("first.example"), &[addr]);
        names.learn(device(2), &name("second.example"), &[addr]);
        // Another address since, which says nothing about this one.
        names.learn(device(1), &name("elsewhere.example"), &[IpAddr::V6(Ipv6Addr::LOCALHOST), ip("2001:db8::8")]);
        assert_eq!(names.any_name_for(addr).as_deref(), Some("second.example"));
        // The first device looks the same name up again.
        names.learn(device(1), &name("first.example"), &[addr]);
        assert_eq!(names.any_name_for(addr).as_deref(), Some("first.example"));
    }

    #[test]
    fn a_forgotten_device_keeps_nothing() {
        let mut names = LearnedNames::default();
        names.learn(device(1), &name("one.example"), &[ip("192.0.2.1")]);
        names.learn(device(2), &name("two.example"), &[ip("192.0.2.2")]);
        names.forget(device(1));
        names.forget(device(7));
        assert_eq!(names.name_for(device(1), ip("192.0.2.1")), None);
        assert_eq!(names.any_name_for(ip("192.0.2.1")), None);
        assert_eq!(names.name_for(device(2), ip("192.0.2.2")).as_deref(), Some("two.example"));
        assert_eq!(names.bytes, cost("two.example"));
    }
}
