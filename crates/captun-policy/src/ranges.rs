use std::net::IpAddr;

use ipnet::IpNet;

/// Address ranges compiled for lookup by binary search, so a rule listing
/// tens of thousands of ranges (a whole country, a cloud provider) costs a
/// few comparisons per flow.
#[derive(Debug, Default)]
pub(crate) struct RangeSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl RangeSet {
    pub(crate) fn new(nets: &[IpNet]) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for net in nets {
            match net {
                IpNet::V4(n) => v4.push((u32::from(n.network()), u32::from(n.broadcast()))),
                IpNet::V6(n) => v6.push((u128::from(n.network()), u128::from(n.broadcast()))),
            }
        }
        Self { v4: merged(v4), v6: merged(v6) }
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        // An IPv4 address written as IPv6 (::ffff:a.b.c.d) is the IPv4 one.
        match ip.to_canonical() {
            IpAddr::V4(a) => covers(&self.v4, u32::from(a)),
            IpAddr::V6(a) => covers(&self.v6, u128::from(a)),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Sorted, with overlapping ranges joined, so each address falls in at most
/// one.
fn merged<T: Ord + Copy>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out.shrink_to_fit();
    out
}

fn covers<T: Ord + Copy>(ranges: &[(T, T)], address: T) -> bool {
    // The last range starting at or before the address is the only candidate.
    let after = ranges.partition_point(|&(start, _)| start <= address);
    after > 0 && ranges[after - 1].1 >= address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_ranges_are_matched_exactly() {
        let nets: Vec<IpNet> = ["10.0.0.0/8", "10.1.0.0/16", "192.168.1.0/24", "192.168.2.0/24", "8.8.8.8/32", "2001:db8::/32"]
            .iter()
            .map(|n| n.parse().unwrap())
            .collect();
        let set = RangeSet::new(&nets);
        // 10.1/16 sits inside 10/8 and is merged into it.
        assert_eq!(set.v4.len(), 4);
        for inside in ["10.0.0.0", "10.255.255.255", "10.1.2.3", "192.168.1.200", "192.168.2.0", "8.8.8.8", "::ffff:8.8.8.8", "2001:db8:ffff::1"] {
            assert!(set.contains(inside.parse().unwrap()), "{inside} should match");
        }
        for outside in ["9.255.255.255", "11.0.0.0", "192.168.3.0", "8.8.8.9", "8.8.8.7", "2001:db9::1", "0.0.0.0"] {
            assert!(!set.contains(outside.parse().unwrap()), "{outside} should not match");
        }
        assert!(!RangeSet::default().contains("1.1.1.1".parse().unwrap()));
        assert!(RangeSet::default().is_empty());
    }
}
