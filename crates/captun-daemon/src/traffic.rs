//! Each device's speed, for the GUI: read from the routing engine's counters
//! once a second while a GUI is connected, and sent as `Event::Traffic`.
//! The device list (`Event::Clients`) is sent only when it changes, so the
//! speeds travel on their own.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use captun_core::MacAddr;
use captun_engine::CounterSnapshot;
use captun_ipc::{DeviceTraffic, Event};
use tokio::time::{MissedTickBehavior, interval};

use crate::hub::Hub;

/// How often speeds are read, and so the time each one covers.
const EVERY: Duration = Duration::from_secs(1);

/// Reads every online device's traffic once a second and sends it to the
/// connected GUIs. Does nothing while none is connected.
pub(crate) async fn run(hub: Arc<Hub>) {
    let mut ticker = interval(EVERY);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Some(report) = hub.read_traffic(Instant::now()) {
            hub.emit(Event::Traffic(report));
        }
    }
}

/// The last reading: each device's counters and speeds then. The next
/// reading measures from it, and the device list shows its speeds; nothing
/// else moves it.
#[derive(Debug, Default)]
pub(crate) struct Speeds {
    /// When it was taken.
    at: Option<Instant>,
    devices: HashMap<MacAddr, Reading>,
    /// The last report sent: the same report is not sent again.
    sent: Vec<DeviceTraffic>,
}

/// One device in a reading.
#[derive(Clone, Copy, Debug)]
struct Reading {
    counters: CounterSnapshot,
    /// Bits per second down and up since the reading before.
    rx_bps: u64,
    tx_bps: u64,
}

impl Speeds {
    /// Takes a reading of `devices`' counters at `now`: each one's speeds
    /// since the last reading, in bits per second (none for a device that
    /// was not in it). Only these devices are kept for the next reading.
    /// Gives the report, unless it is the same as the last one sent.
    pub(crate) fn read(&mut self, devices: Vec<(MacAddr, CounterSnapshot)>, now: Instant) -> Option<Vec<DeviceTraffic>> {
        let secs = self.at.map(|at| now.saturating_duration_since(at).as_secs_f64()).filter(|secs| *secs > 0.0);
        let mut readings = HashMap::with_capacity(devices.len());
        let mut report = Vec::with_capacity(devices.len());
        for (mac, counters) in devices {
            let (rx_bps, tx_bps) = match (self.devices.get(&mac), secs) {
                (Some(before), Some(secs)) => (
                    bits_per_second(counters.down_bytes, before.counters.down_bytes, secs),
                    bits_per_second(counters.up_bytes, before.counters.up_bytes, secs),
                ),
                _ => (0, 0),
            };
            readings.insert(mac, Reading { counters, rx_bps, tx_bps });
            report.push(DeviceTraffic {
                mac,
                rx_bytes: counters.down_bytes,
                tx_bytes: counters.up_bytes,
                rx_bps,
                tx_bps,
                active_flows: u32::try_from(counters.active_flows).unwrap_or(u32::MAX),
            });
        }
        self.at = Some(now);
        self.devices = readings;
        report.sort_unstable_by_key(|device| device.mac);
        if report == self.sent {
            return None;
        }
        self.sent.clone_from(&report);
        Some(report)
    }

    /// The speeds of the last reading, bits per second down and up, for each
    /// device in it.
    pub(crate) fn rates(&self) -> HashMap<MacAddr, (u64, u64)> {
        self.devices.iter().map(|(mac, reading)| (*mac, (reading.rx_bps, reading.tx_bps))).collect()
    }

    /// Starts afresh: nobody watched for a while, and the next speeds must
    /// not be the average over that time.
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
}

/// The speed of a counter that went from `before` to `now` bytes in `secs`
/// seconds. A counter that went back (its device was forgotten, then came
/// again) counts as no traffic.
fn bits_per_second(now: u64, before: u64, secs: f64) -> u64 {
    let bits = now.saturating_sub(before).saturating_mul(8);
    // Rounded; a float too large for u64 saturates.
    (bits as f64 / secs).round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([2, 0, 0, 0, 0, n])
    }

    fn counters(down_bytes: u64, up_bytes: u64, active_flows: u64) -> CounterSnapshot {
        CounterSnapshot { down_bytes, up_bytes, active_flows }
    }

    #[test]
    fn speeds_are_bits_per_second_since_the_last_reading() {
        let mut speeds = Speeds::default();
        let start = Instant::now();
        let first = speeds.read(vec![(mac(1), counters(1_000, 500, 2))], start).unwrap();
        // Nothing to measure from yet: the totals, and no speed.
        assert_eq!((first[0].rx_bytes, first[0].tx_bytes, first[0].rx_bps, first[0].tx_bps), (1_000, 500, 0, 0));
        assert_eq!(first[0].active_flows, 2);

        // 125 000 bytes down and 12 500 up in one second.
        let second = speeds.read(vec![(mac(1), counters(126_000, 13_000, 3))], start + EVERY).unwrap();
        assert_eq!((second[0].rx_bps, second[0].tx_bps), (1_000_000, 100_000));
        assert_eq!(speeds.rates()[&mac(1)], (1_000_000, 100_000));

        // A late tick: the average over the time it covers.
        let third = speeds.read(vec![(mac(1), counters(376_000, 13_000, 3))], start + EVERY * 3).unwrap();
        assert_eq!((third[0].rx_bps, third[0].tx_bps), (1_000_000, 0));
    }

    #[test]
    fn only_the_devices_reported_are_kept() {
        let mut speeds = Speeds::default();
        let start = Instant::now();
        speeds.read(vec![(mac(1), counters(10, 10, 1)), (mac(2), counters(10, 10, 1))], start);
        speeds.read(vec![(mac(2), counters(20, 10, 1))], start + EVERY);
        assert_eq!(speeds.rates().keys().copied().collect::<Vec<_>>(), [mac(2)], "device 1 left");
        // Back a second later: measured afresh, not from two seconds before.
        let back = speeds.read(vec![(mac(1), counters(5_000, 10, 1)), (mac(2), counters(20, 10, 1))], start + EVERY * 2).unwrap();
        assert_eq!((back[0].mac, back[0].rx_bps), (mac(1), 0));
    }

    #[test]
    fn a_report_the_same_as_the_last_is_not_sent_again() {
        let mut speeds = Speeds::default();
        let start = Instant::now();
        assert!(speeds.read(vec![(mac(1), counters(10, 10, 0))], start).is_some());
        // Idle: the same totals, no speed.
        assert!(speeds.read(vec![(mac(1), counters(10, 10, 0))], start + EVERY).is_none());
        assert!(speeds.read(vec![(mac(1), counters(10, 10, 1))], start + EVERY * 2).is_some(), "a connection opened");
        // The device left: an empty report says so.
        assert_eq!(speeds.read(Vec::new(), start + EVERY * 3), Some(Vec::new()));
        assert!(speeds.read(Vec::new(), start + EVERY * 4).is_none());
    }

    #[test]
    fn counters_that_went_back_are_no_traffic() {
        let mut speeds = Speeds::default();
        let start = Instant::now();
        speeds.read(vec![(mac(1), counters(9_000, 9_000, 0))], start);
        let report = speeds.read(vec![(mac(1), counters(100, 100, 0))], start + EVERY).unwrap();
        assert_eq!((report[0].rx_bps, report[0].tx_bps), (0, 0));
    }

    #[test]
    fn a_fresh_start_measures_nothing_from_before() {
        let mut speeds = Speeds::default();
        let start = Instant::now();
        speeds.read(vec![(mac(1), counters(0, 0, 0))], start);
        speeds.clear();
        // An hour later, with a GUI again: no average over the hour.
        let later = speeds.read(vec![(mac(1), counters(1 << 30, 0, 0))], start + Duration::from_secs(3600)).unwrap();
        assert_eq!(later[0].rx_bps, 0);
        assert_eq!(speeds.rates()[&mac(1)], (0, 0));
    }
}
