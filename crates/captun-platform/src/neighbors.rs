//! Which hardware address holds an IP on a local network, from the system's
//! neighbor (ARP) table. A device's first packets come before the hotspot's
//! own device list mentions it; the neighbor table already does, since the
//! device had to find the gateway before sending anything.

use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};

use captun_core::MacAddr;

use crate::refresh::Refreshed;

/// Every IPv4 address in the neighbor table, with the hardware address the
/// system last saw at it.
pub type Table = HashMap<IpAddr, MacAddr>;

/// The hardware address the system last saw at `ip`, if any. Reads the whole
/// table each time: lookups that come often share one read through a
/// [`Snapshot`].
pub fn mac_of(ip: IpAddr) -> Option<MacAddr> {
    table()?.get(&ip.to_canonical()).copied()
}

/// The system's IPv4 neighbor table, read once (one `GetIpNetTable2` on
/// Windows, `/proc/net/arp` on Linux). `None` when the system cannot give it.
/// Only complete entries for a single device's address are in it: never a
/// broadcast or multicast address, which no device holds.
pub fn table() -> Option<Table> {
    sys::table()
}

/// A device's own hardware address: not all zeros (an entry still being
/// resolved), and not a group address (broadcast, multicast).
#[cfg_attr(not(any(windows, target_os = "linux", test)), allow(dead_code))]
fn is_device_mac(octets: [u8; 6]) -> bool {
    octets != [0; 6] && octets[0] & 1 == 0
}

/// Adds an entry. The same address can be listed on two adapters; one the
/// system has just confirmed (`live`) wins over one it has not.
#[cfg_attr(not(any(windows, target_os = "linux", test)), allow(dead_code))]
fn keep_best(found: &mut HashMap<IpAddr, (MacAddr, bool)>, ip: IpAddr, mac: MacAddr, live: bool) {
    found
        .entry(ip)
        .and_modify(|entry| {
            if live && !entry.1 {
                *entry = (mac, live);
            }
        })
        .or_insert((mac, live));
}

#[cfg_attr(not(any(windows, target_os = "linux", test)), allow(dead_code))]
fn settle(found: HashMap<IpAddr, (MacAddr, bool)>) -> Table {
    found.into_iter().map(|(ip, (mac, _))| (ip, mac)).collect()
}

/// How often a [`Snapshot`] reads the table again, at most.
const REFRESH_EVERY: Duration = Duration::from_millis(500);
/// How long [`Snapshot::fresh_table`] waits for a read already running.
const WAIT_AT_MOST: Duration = Duration::from_secs(2);

/// The neighbor table as last read, for lookups on every new flow or DNS
/// query. It is read again at most every half second, and only when someone
/// asks, and never on the caller's thread when that is an async one. Clones
/// share one table.
#[derive(Clone)]
pub struct Snapshot {
    cache: Arc<Refreshed<Arc<Table>>>,
    read: fn() -> Option<Table>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot").field("entries", &self.cache.value().len()).finish_non_exhaustive()
    }
}

impl Default for Snapshot {
    fn default() -> Self {
        Self::new()
    }
}

impl Snapshot {
    /// An empty snapshot; the first lookup starts the first read.
    pub fn new() -> Self {
        Self::reading(table, REFRESH_EVERY)
    }

    fn reading(read: fn() -> Option<Table>, every: Duration) -> Self {
        Self { cache: Arc::new(Refreshed::new(Arc::default(), every, Duration::ZERO, WAIT_AT_MOST)), read }
    }

    /// The hardware address at `ip` in the table in hand. Never waits for the
    /// system: see [`Snapshot::table`]. A device new since the last read is
    /// found once the read this lookup started has finished, moments later.
    pub fn mac_of(&self, ip: IpAddr) -> Option<MacAddr> {
        self.table().get(&ip.to_canonical()).copied()
    }

    /// The table in hand. Never waits for the system: when the table is older
    /// than half a second, a read starts beside the caller, on the runtime's
    /// blocking threads from inside Tokio. Outside it the read runs here,
    /// since no async thread is held up.
    pub fn table(&self) -> Arc<Table> {
        if let Some(reading) = Refreshed::claim(Arc::clone(&self.cache)) {
            let read = self.read;
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => drop(runtime.spawn_blocking(move || reading.run(|| read().map(Arc::new)))),
                Err(_) => return reading.run(|| read().map(Arc::new)),
            }
        }
        self.cache.value()
    }

    /// The hardware address at `ip`, waiting for a fresh read first when the
    /// table is older than half a second. The read runs on a blocking thread.
    pub async fn mac_of_fresh(&self, ip: IpAddr) -> Option<MacAddr> {
        self.fresh_table().await.get(&ip.to_canonical()).copied()
    }

    /// The table, read again first (on a blocking thread) when it is older
    /// than half a second.
    pub async fn fresh_table(&self) -> Arc<Table> {
        if let Some(table) = self.cache.fresh() {
            return table;
        }
        let (cache, read) = (Arc::clone(&self.cache), self.read);
        tokio::task::spawn_blocking(move || cache.get(|| read().map(Arc::new)))
            .await
            .unwrap_or_else(|_| self.cache.value())
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod sys {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
    };

    use captun_core::MacAddr;
    use windows_sys::Win32::{
        Foundation::NO_ERROR,
        NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_ROW2, MIB_IPNET_TABLE2},
        Networking::WinSock::{AF_INET, NlnsIncomplete, NlnsReachable, NlnsUnreachable},
    };

    use super::{Table, is_device_mac, keep_best, settle};

    pub(super) fn table() -> Option<Table> {
        let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        // SAFETY: GetIpNetTable2 allocates the table and stores its address in
        // `table`, a live local; it is freed below with FreeMibTable, once.
        if unsafe { GetIpNetTable2(AF_INET, &mut table) } != NO_ERROR || table.is_null() {
            return None;
        }
        // SAFETY: on success `table` points at a MIB_IPNET_TABLE2 whose
        // `Table` holds `NumEntries` rows one after another, valid until
        // freed; the rows are reached through the whole allocation.
        let rows = unsafe {
            std::slice::from_raw_parts((&raw const (*table).Table).cast::<MIB_IPNET_ROW2>(), (*table).NumEntries as usize)
        };
        let mut found = HashMap::with_capacity(rows.len());
        for row in rows {
            if row.PhysicalAddressLength != 6 || row.State == NlnsUnreachable || row.State == NlnsIncomplete {
                continue;
            }
            let Ok(octets) = <[u8; 6]>::try_from(&row.PhysicalAddress[..6]) else { continue };
            if !is_device_mac(octets) {
                continue;
            }
            // SAFETY: an AF_INET table holds IPv4 addresses in the union.
            let address = Ipv4Addr::from(unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes());
            keep_best(&mut found, IpAddr::V4(address), MacAddr::new(octets), row.State == NlnsReachable);
        }
        // SAFETY: allocated by GetIpNetTable2 above; `rows` is not used after this.
        unsafe { FreeMibTable(table.cast()) };
        Some(settle(found))
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use super::Table;

    pub(super) fn table() -> Option<Table> {
        std::fs::read_to_string("/proc/net/arp").ok().map(|text| super::parse_proc_arp(&text))
    }
}

/// `/proc/net/arp`: "IP address  HW type  Flags  HW address  Mask  Device",
/// a header line, then one line per entry.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_arp(text: &str) -> Table {
    /// The entry is complete (`ATF_COM`).
    const COMPLETE: u32 = 0x2;
    let mut found = HashMap::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(ip) = fields.first().and_then(|f| f.parse::<IpAddr>().ok()) else { continue };
        let flags = fields.get(2).and_then(|f| u32::from_str_radix(f.trim_start_matches("0x"), 16).ok()).unwrap_or(0);
        let Some(mac) = fields.get(3).and_then(|f| f.parse::<MacAddr>().ok()) else { continue };
        if flags & COMPLETE != 0 && is_device_mac(mac.octets()) {
            // The file says nothing fresher about one entry than another.
            keep_best(&mut found, ip, mac, false);
        }
    }
    settle(found)
}

#[cfg(not(any(windows, target_os = "linux")))]
mod sys {
    use super::Table;

    pub(super) fn table() -> Option<Table> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };

    use super::*;

    #[test]
    fn an_address_nobody_holds_has_no_hardware_address() {
        // A documentation address: never in the table, and asking must not fail.
        assert!(super::mac_of("192.0.2.123".parse().unwrap()).is_none());
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn the_whole_table_reads_and_holds_only_devices() {
        let table = table().expect("the neighbor table can be read");
        assert!(table.values().all(|mac| is_device_mac(mac.octets())), "{table:?}");
        assert!(table.keys().all(IpAddr::is_ipv4));
        // Each entry is what a single lookup finds too (the table may change
        // in between, so only when it is still there).
        if let Some((ip, mac)) = table.iter().next()
            && let Some(again) = super::mac_of(*ip)
        {
            assert_eq!(again, *mac);
        }
    }

    #[test]
    fn only_a_single_devices_address_counts() {
        assert!(is_device_mac([0x3c, 0x22, 0xfb, 1, 2, 3]));
        assert!(!is_device_mac([0; 6]), "not resolved yet");
        assert!(!is_device_mac([0xff; 6]), "broadcast");
        assert!(!is_device_mac([0x01, 0x00, 0x5e, 0, 0, 0x16]), "IPv4 multicast");
        assert!(!is_device_mac([0x33, 0x33, 0, 0, 0, 1]), "IPv6 multicast");
    }

    #[test]
    fn a_confirmed_entry_wins_over_one_on_another_adapter() {
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let (old, new) = (MacAddr::new([2, 0, 0, 0, 0, 1]), MacAddr::new([2, 0, 0, 0, 0, 2]));
        let mut found = HashMap::new();
        keep_best(&mut found, ip, old, false);
        keep_best(&mut found, ip, new, true);
        keep_best(&mut found, ip, old, false);
        assert_eq!(settle(found)[&ip], new);
    }

    #[test]
    fn proc_arp_gives_complete_device_entries() {
        let text = "\
IP address       HW type     Flags       HW address            Mask     Device
10.74.0.23       0x1         0x2         3c:22:fb:01:02:03     *        wlan0
10.74.0.24       0x1         0x0         00:00:00:00:00:00     *        wlan0
10.74.0.255      0x1         0x6         ff:ff:ff:ff:ff:ff     *        wlan0
10.74.0.30       0x1         0x6         3c:22:fb:0a:0b:0c     *        wlan0
garbage line
";
        let table = parse_proc_arp(text);
        assert_eq!(table.len(), 2, "{table:?}");
        assert_eq!(table[&"10.74.0.23".parse::<IpAddr>().unwrap()], MacAddr::new([0x3c, 0x22, 0xfb, 1, 2, 3]));
        assert!(table.contains_key(&"10.74.0.30".parse::<IpAddr>().unwrap()), "a permanent entry is complete too");
    }

    static READS: AtomicUsize = AtomicUsize::new(0);
    const DEVICE: Ipv4Addr = Ipv4Addr::new(10, 74, 0, 23);
    const DEVICE_MAC: MacAddr = MacAddr::new([0x3c, 0x22, 0xfb, 1, 2, 3]);

    fn counted_read() -> Option<Table> {
        READS.fetch_add(1, Ordering::SeqCst);
        Some(HashMap::from([(IpAddr::V4(DEVICE), DEVICE_MAC)]))
    }

    #[test]
    fn a_snapshot_reads_at_most_every_so_often_however_often_asked() {
        // Outside a runtime the read runs on the caller's thread.
        READS.store(0, Ordering::SeqCst);
        let snapshot = Snapshot::reading(counted_read, Duration::from_millis(400));
        let until = Instant::now() + Duration::from_millis(100);
        let mut lookups = 0;
        while Instant::now() < until {
            assert_eq!(snapshot.mac_of(IpAddr::V4(DEVICE)), Some(DEVICE_MAC));
            // An IPv4-mapped IPv6 source is the same device.
            assert_eq!(snapshot.mac_of(IpAddr::V6(DEVICE.to_ipv6_mapped())), Some(DEVICE_MAC));
            lookups += 2;
        }
        assert!(lookups > 100);
        assert_eq!(READS.load(Ordering::SeqCst), 1, "one read served {lookups} lookups");
        std::thread::sleep(Duration::from_millis(450));
        snapshot.mac_of(IpAddr::V4(DEVICE));
        assert_eq!(READS.load(Ordering::SeqCst), 2, "read again once it was old");
        assert!(snapshot.clone().mac_of(Ipv4Addr::new(10, 74, 0, 99).into()).is_none());
    }

    fn slow_read() -> Option<Table> {
        std::thread::sleep(Duration::from_millis(300));
        Some(HashMap::from([(IpAddr::V4(DEVICE), DEVICE_MAC)]))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_lookup_on_an_async_thread_never_waits_for_the_system() {
        // One async thread: had the read run on it, the lookup would take the
        // read's 300 ms.
        let snapshot = Snapshot::reading(slow_read, Duration::from_millis(500));
        let asked = Instant::now();
        assert_eq!(snapshot.mac_of(IpAddr::V4(DEVICE)), None, "nothing read yet");
        assert!(asked.elapsed() < Duration::from_millis(100), "waited {:?}", asked.elapsed());
        // The read it started finishes beside it; an async caller can wait.
        assert_eq!(snapshot.mac_of_fresh(IpAddr::V4(DEVICE)).await, Some(DEVICE_MAC));
        assert_eq!(snapshot.mac_of(IpAddr::V4(DEVICE)), Some(DEVICE_MAC));
        assert_eq!(snapshot.fresh_table().await.len(), 1);
    }
}
