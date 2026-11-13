//! Each device's data use: counted from the routing engine's counters every
//! few seconds, kept per hour on disk for the Usage page, and per period for
//! the data allowances (`Quota`).
//!
//! Hours and periods are local time: a day starts at local midnight, and an
//! hour where the local clock's hour starts (half past, in some time zones).
//! Each local day's hours are kept in a file of their own, named by the date;
//! the use counted toward allowances is kept in one more file beside them.

use std::{
    collections::{BTreeMap, HashMap},
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use captun_core::{
    Config, MacAddr,
    config::{QuotaPeriod, Weekday},
};
use captun_engine::CounterSnapshot;
use captun_ipc::{DeviceUsage, ErrorCode, IpcError, QuotaUse, UsageBytes, UsageReport};
use chrono::{DateTime, Datelike, Days, Local, Months, NaiveDate, TimeZone, Timelike};
use serde::{Deserialize, Serialize};
use tokio::time::{MissedTickBehavior, interval};
use tracing::{info, warn};

use crate::hub::{Hub, lock};

/// How often the counters are read: how late an allowance can be noticed
/// as used up, at most.
const EVERY: Duration = Duration::from_secs(5);
/// How many readings go by between two saves to disk: what a crash can lose.
const SAVE_EVERY: u32 = 12;
/// How many readings go by between two device lists sent to the app while
/// devices with an allowance use data, so it shows how much is left.
const SHOW_EVERY: u32 = 6;
/// How long a device that used nothing is remembered toward allowances that
/// start over (those that never do are kept): past any month.
const FORGET_AFTER_MS: i64 = 62 * 86_400_000;
/// How long the hours are kept: a little over a year, so a year ago can be
/// compared with now.
pub(crate) const KEEP_DAYS: u64 = 400;
/// Most bounds one question about use may have.
pub(crate) const MAX_BOUNDS: usize = 2_000;

/// Reads the counters every few seconds for as long as the service runs,
/// and saves what it counted now and then.
pub(crate) async fn run(hub: Arc<Hub>) {
    let mut ticker = interval(EVERY);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut readings = 0u32;
    loop {
        ticker.tick().await;
        if let Some(day) = hub.record_usage() {
            let _ = tokio::task::spawn_blocking(move || day.save()).await;
        }
        readings = readings.wrapping_add(1);
        if readings.is_multiple_of(SAVE_EVERY) {
            hub.save_usage().await;
        }
        if readings.is_multiple_of(SHOW_EVERY) {
            hub.show_allowances();
        }
    }
}

/// Now, in ms since the epoch.
pub(crate) fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Download and upload, in bytes, as kept on disk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Bytes(u64, u64);

impl Bytes {
    fn add(&mut self, other: Bytes) {
        self.0 = self.0.saturating_add(other.0);
        self.1 = self.1.saturating_add(other.1);
    }

    fn total(self) -> u64 {
        self.0.saturating_add(self.1)
    }
}

/// One local day's hours: each hour's start (ms since the epoch) to what
/// each device used in it.
type Hours = BTreeMap<i64, BTreeMap<MacAddr, Bytes>>;

/// A day's file.
#[derive(Debug, Default, Serialize, Deserialize)]
struct DayFile {
    hours: Hours,
}

/// What a device used in one period of each kind, toward its allowance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Counted {
    /// Where the period started (ms since the epoch); the period it counts.
    since: i64,
    /// Bytes used in it, download and upload together.
    used: u64,
    /// Bytes given on top of the allowance for it.
    extra: u64,
}

/// What a device used in the current day, week and month, and since its
/// allowance was last reset by hand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Periods {
    day: Counted,
    week: Counted,
    month: Counted,
    total: Counted,
    /// When the device last used anything (ms since the epoch).
    #[serde(default)]
    last_ms: i64,
}

impl Periods {
    fn get_mut(&mut self, every: QuotaPeriod) -> &mut Counted {
        match every {
            QuotaPeriod::Day => &mut self.day,
            QuotaPeriod::Week => &mut self.week,
            QuotaPeriod::Month => &mut self.month,
            QuotaPeriod::Total => &mut self.total,
        }
    }
}

/// When each kind of period that holds `now_ms` started, and the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Starts {
    day: i64,
    week: i64,
    month: i64,
    next_day: i64,
    next_week: i64,
    next_month: i64,
}

impl Starts {
    fn of(every: QuotaPeriod, starts: &Starts) -> (i64, Option<i64>) {
        match every {
            QuotaPeriod::Day => (starts.day, Some(starts.next_day)),
            QuotaPeriod::Week => (starts.week, Some(starts.next_week)),
            QuotaPeriod::Month => (starts.month, Some(starts.next_month)),
            QuotaPeriod::Total => (0, None),
        }
    }
}

/// Where the local hour holding `now_ms` started: the minutes and seconds
/// the local clock shows taken off, so a half-hour time zone and a change
/// of clocks both come out right.
fn hour_start<Tz: TimeZone>(tz: &Tz, now_ms: i64) -> i64 {
    match tz.timestamp_millis_opt(now_ms).single() {
        Some(local) => now_ms - i64::from(local.minute() * 60 + local.second()) * 1000 - i64::from(local.timestamp_subsec_millis()),
        None => now_ms - now_ms.rem_euclid(3_600_000),
    }
}

fn local<Tz: TimeZone>(tz: &Tz, ms: i64) -> Option<DateTime<Tz>> {
    tz.timestamp_millis_opt(ms).single()
}

/// Where local `date` started: at midnight, or, where the clocks jump over
/// midnight that day, at the first hour that exists.
fn day_start<Tz: TimeZone>(tz: &Tz, date: NaiveDate) -> i64 {
    for hour in 0..4 {
        if let Some(start) = date.and_hms_opt(hour, 0, 0).and_then(|t| tz.from_local_datetime(&t).earliest()) {
            return start.timestamp_millis();
        }
    }
    // No such time zone; UTC midnight rather than nothing.
    date.and_hms_opt(0, 0, 0).map_or(0, |t| t.and_utc().timestamp_millis())
}

fn starts<Tz: TimeZone>(tz: &Tz, now_ms: i64, week_starts: Weekday) -> Starts {
    let today = local(tz, now_ms).map_or_else(|| DateTime::from_timestamp_millis(now_ms).unwrap_or_default().date_naive(), |t| t.date_naive());
    let back = (today.weekday().num_days_from_monday() + 7 - week_index(week_starts)) % 7;
    let week = today - Days::new(u64::from(back));
    let month = today.with_day(1).unwrap_or(today);
    Starts {
        day: day_start(tz, today),
        week: day_start(tz, week),
        month: day_start(tz, month),
        next_day: day_start(tz, today + Days::new(1)),
        next_week: day_start(tz, week + Days::new(7)),
        next_month: day_start(tz, month + Months::new(1)),
    }
}

fn week_index(day: Weekday) -> u32 {
    match day {
        Weekday::Mon => 0,
        Weekday::Tue => 1,
        Weekday::Wed => 2,
        Weekday::Thu => 3,
        Weekday::Fri => 4,
        Weekday::Sat => 5,
        Weekday::Sun => 6,
    }
}

/// The book of everyone's data use: today's hours and the periods in
/// memory, the days before on disk.
#[derive(Debug)]
pub(crate) struct Usage {
    /// Where the files are; none keeps everything in memory (tests).
    dir: Option<PathBuf>,
    /// The counters at the last reading: what moved since is new use.
    last: HashMap<MacAddr, (u64, u64)>,
    /// The local day being counted, and its hours.
    day: NaiveDate,
    hours: Hours,
    periods: HashMap<MacAddr, Periods>,
    /// Counted since the last save.
    unsaved: bool,
    /// Counted since the app was last shown the allowances.
    unshown: bool,
}

impl Usage {
    /// Picks up today's hours and the periods where the last run left them.
    /// A file that cannot be read is set aside, never in the way.
    pub(crate) fn open<Tz: TimeZone>(dir: Option<PathBuf>, tz: &Tz, now_ms: i64) -> Self {
        let day = local(tz, now_ms).map_or_else(NaiveDate::default, |t| t.date_naive());
        let hours = dir.as_deref().map(|dir| read_day(dir, day)).unwrap_or_default();
        let periods = dir.as_deref().map(read_periods).unwrap_or_default();
        Self { dir, last: HashMap::new(), day, hours, periods, unsaved: false, unshown: false }
    }

    /// Counts what each device used since the last reading of `readings`,
    /// in the local hour holding `now_ms` and toward its allowances. A
    /// counter that went back (its device was forgotten and came again)
    /// counts from zero. Devices not in `readings` are let go of.
    /// Returns the day just finished, to be saved, when this reading starts
    /// a new one.
    pub(crate) fn record<Tz: TimeZone>(
        &mut self,
        readings: &[(MacAddr, CounterSnapshot)],
        tz: &Tz,
        now_ms: i64,
        week_starts: Weekday,
    ) -> Option<FinishedDay> {
        let hour = hour_start(tz, now_ms);
        let today = local(tz, hour).map_or(self.day, |t| t.date_naive());
        let finished = if today == self.day {
            None
        } else {
            let hours = std::mem::take(&mut self.hours);
            let finished = self.dir.clone().map(|dir| FinishedDay { dir, day: self.day, hours });
            self.day = today;
            // The clock may have gone back to a day already kept.
            self.hours = self.dir.as_deref().map(|dir| read_day(dir, today)).unwrap_or_default();
            finished
        };
        let starts = starts(tz, now_ms, week_starts);
        let mut last = HashMap::with_capacity(readings.len());
        for &(mac, counters) in readings {
            let now = (counters.down_bytes, counters.up_bytes);
            let before = self.last.get(&mac).copied().unwrap_or((0, 0));
            let moved = |now: u64, before: u64| now.checked_sub(before).unwrap_or(now);
            let used = Bytes(moved(now.0, before.0), moved(now.1, before.1));
            last.insert(mac, now);
            if used == Bytes::default() {
                continue;
            }
            self.hours.entry(hour).or_default().entry(mac).or_default().add(used);
            let periods = self.periods.entry(mac).or_default();
            for (every, since) in [
                (QuotaPeriod::Day, starts.day),
                (QuotaPeriod::Week, starts.week),
                (QuotaPeriod::Month, starts.month),
                (QuotaPeriod::Total, 0),
            ] {
                let counted = periods.get_mut(every);
                if counted.since != since && every != QuotaPeriod::Total {
                    *counted = Counted { since, used: 0, extra: 0 };
                }
                counted.used = counted.used.saturating_add(used.total());
            }
            periods.last_ms = now_ms;
            self.unsaved = true;
            self.unshown = true;
        }
        self.last = last;
        finished
    }

    /// The counted use of `mac` in the period `every` holding `now_ms`:
    /// nothing for a period that has not been counted in yet.
    fn counted<Tz: TimeZone>(&self, mac: &MacAddr, every: QuotaPeriod, tz: &Tz, now_ms: i64, week_starts: Weekday) -> (Counted, Option<i64>) {
        let (since, next) = Starts::of(every, &starts(tz, now_ms, week_starts));
        let counted = self.periods.get(mac).map(|p| match every {
            QuotaPeriod::Day => p.day,
            QuotaPeriod::Week => p.week,
            QuotaPeriod::Month => p.month,
            QuotaPeriod::Total => p.total,
        });
        match counted {
            Some(counted) if counted.since == since => (counted, next),
            _ => (Counted { since, used: 0, extra: 0 }, next),
        }
    }

    /// How `mac`'s allowance stands, if `config` gives it one.
    pub(crate) fn quota_use<Tz: TimeZone>(&self, config: &Config, mac: &MacAddr, tz: &Tz, now_ms: i64) -> Option<QuotaUse> {
        let quota = config.quota_for(mac)?;
        let (counted, next) = self.counted(mac, quota.every, tz, now_ms, config.network.week_starts);
        let allowed = quota.bytes().saturating_add(counted.extra);
        Some(QuotaUse {
            quota,
            used: counted.used,
            allowed,
            over: counted.used >= allowed,
            resets_at_ms: next.and_then(|ms| u64::try_from(ms).ok()),
        })
    }

    /// Every device that used up its allowance, with the speed it is slowed
    /// to (none: cut off). Only devices that used anything can be in it.
    pub(crate) fn over_quota<Tz: TimeZone>(&self, config: &Config, tz: &Tz, now_ms: i64) -> HashMap<MacAddr, Option<u64>> {
        self.periods
            .keys()
            .filter_map(|mac| {
                let used = self.quota_use(config, mac, tz, now_ms)?;
                used.over.then_some((*mac, used.quota.then_kbps))
            })
            .collect()
    }

    /// Starts `mac`'s allowance over: nothing used, nothing extra, in the
    /// period of the allowance it has now (for one that never starts over,
    /// from now on).
    pub(crate) fn reset<Tz: TimeZone>(&mut self, config: &Config, mac: MacAddr, tz: &Tz, now_ms: i64) {
        let Some(quota) = config.quota_for(&mac) else { return };
        let (since, _) = Starts::of(quota.every, &starts(tz, now_ms, config.network.week_starts));
        *self.periods.entry(mac).or_default().get_mut(quota.every) = Counted { since, used: 0, extra: 0 };
        self.unsaved = true;
    }

    /// Gives `mac` `bytes` more in the current period of its allowance.
    pub(crate) fn add<Tz: TimeZone>(&mut self, config: &Config, mac: MacAddr, bytes: u64, tz: &Tz, now_ms: i64) {
        let Some(quota) = config.quota_for(&mac) else { return };
        let (counted, _) = self.counted(&mac, quota.every, tz, now_ms, config.network.week_starts);
        let extra = counted.extra.saturating_add(bytes);
        *self.periods.entry(mac).or_default().get_mut(quota.every) = Counted { extra, ..counted };
        self.unsaved = true;
    }

    /// Forgets the devices that used nothing for [`FORGET_AFTER_MS`],
    /// unless `config` gives them an allowance that never starts over: so
    /// phones that make up a new address on every visit do not pile up.
    pub(crate) fn forget_idle(&mut self, config: &Config, now_ms: i64) {
        let before = self.periods.len();
        self.periods.retain(|mac, periods| {
            periods.last_ms > now_ms - FORGET_AFTER_MS || config.quota_for(mac).is_some_and(|q| q.every == QuotaPeriod::Total)
        });
        if self.periods.len() != before {
            self.unsaved = true;
        }
    }

    /// Whether anything was counted since the last time this was asked.
    pub(crate) fn take_unshown(&mut self) -> bool {
        std::mem::take(&mut self.unshown)
    }

    /// What there is to save, if anything was counted since the last save.
    pub(crate) fn take_saving(&mut self) -> Option<Saving> {
        let dir = self.dir.clone()?;
        if !std::mem::take(&mut self.unsaved) {
            return None;
        }
        Some(Saving { dir, day: self.day, hours: self.hours.clone(), periods: self.periods.clone() })
    }

    /// The hours this book has in memory (today's), and where the rest are,
    /// for a question about use.
    pub(crate) fn sources(&self) -> Sources {
        Sources { dir: self.dir.clone(), today: Some((self.day, self.hours.clone())) }
    }
}

/// A day the book just finished counting, to be saved.
#[derive(Debug)]
pub(crate) struct FinishedDay {
    dir: PathBuf,
    day: NaiveDate,
    hours: Hours,
}

impl FinishedDay {
    /// Writes the day's file, and deletes files past [`KEEP_DAYS`].
    pub(crate) fn save(self) {
        if let Err(e) = write_json(&day_file(&self.dir, self.day), &DayFile { hours: self.hours }) {
            warn!("cannot save the data use of {}: {e}", self.day);
        }
        prune(&self.dir, self.day);
    }
}

/// A copy of what the book counted, written out off the book's lock.
#[derive(Debug)]
pub(crate) struct Saving {
    dir: PathBuf,
    day: NaiveDate,
    hours: Hours,
    periods: HashMap<MacAddr, Periods>,
}

impl Saving {
    pub(crate) fn write(self) {
        if let Err(e) = write_json(&day_file(&self.dir, self.day), &DayFile { hours: self.hours }) {
            warn!("cannot save today's data use: {e}");
        }
        if let Err(e) = write_json(&periods_file(&self.dir), &self.periods) {
            warn!("cannot save the data use counted toward allowances: {e}");
        }
    }
}

/// Where the hours of a question about use come from.
#[derive(Debug)]
pub(crate) struct Sources {
    dir: Option<PathBuf>,
    today: Option<(NaiveDate, Hours)>,
}

impl Sources {
    /// What was used between each two neighbouring `bounds` (ms since the
    /// epoch, rising), by `device` or by all, and by each device over the
    /// whole span: an hour counts where it starts. Reads the days' files.
    pub(crate) fn report<Tz: TimeZone>(self, tz: &Tz, bounds: &[i64], device: Option<MacAddr>) -> UsageReport {
        let (Some(&first), Some(&end)) = (bounds.first(), bounds.last()) else { return UsageReport::default() };
        if bounds.len() < 2 || bounds.windows(2).any(|w| w[0] >= w[1]) {
            return UsageReport::default();
        }
        let mut buckets = vec![Bytes::default(); bounds.len() - 1];
        let mut devices: HashMap<MacAddr, Bytes> = HashMap::new();
        let (Some(first_day), Some(last_day)) = (local(tz, first).map(|t| t.date_naive()), local(tz, end - 1).map(|t| t.date_naive())) else {
            return UsageReport::default();
        };
        // An hour that starts before the first day can still end in it.
        let mut day = first_day.pred_opt().unwrap_or(first_day);
        while day <= last_day {
            let hours = match &self.today {
                Some((today, hours)) if *today == day => hours.clone(),
                _ => self.dir.as_deref().map(|dir| read_day(dir, day)).unwrap_or_default(),
            };
            for (&hour, used) in hours.range(first..end) {
                let index = bounds.partition_point(|&b| b <= hour) - 1;
                for (mac, &bytes) in used {
                    if device.is_some_and(|d| d != *mac) {
                        continue;
                    }
                    buckets[index].add(bytes);
                    devices.entry(*mac).or_default().add(bytes);
                }
            }
            let Some(next) = day.succ_opt() else { break };
            day = next;
        }
        let mut devices: Vec<DeviceUsage> = devices.into_iter().map(|(mac, b)| DeviceUsage { mac, down: b.0, up: b.1 }).collect();
        devices.sort_unstable_by(|a, b| (b.down + b.up).cmp(&(a.down + a.up)).then(a.mac.cmp(&b.mac)));
        let kept_since_ms = self
            .dir
            .as_deref()
            .and_then(oldest_day)
            .or(self.today.as_ref().map(|(day, _)| *day))
            .map(|day| day_start(tz, day))
            .and_then(|ms| u64::try_from(ms).ok());
        UsageReport { buckets: buckets.into_iter().map(|b| UsageBytes { down: b.0, up: b.1 }).collect(), devices, kept_since_ms }
    }
}

impl Hub {
    /// Counts what every device used since the last reading, and puts the
    /// allowances in force: a device that just used its up is cut off or
    /// slowed, one whose allowance started over gets back to normal. Returns
    /// the day just finished, to be saved.
    pub(crate) fn record_usage(&self) -> Option<FinishedDay> {
        let readings = self.meter.snapshot_all();
        let config = self.config();
        let now = now_ms();
        let (finished, over) = {
            let mut usage = lock(&self.usage);
            let finished = usage.record(&readings, &Local, now, config.network.week_starts);
            if finished.is_some() {
                usage.forget_idle(&config, now);
            }
            (finished, usage.over_quota(&config, &Local, now))
        };
        self.set_over_quota(over);
        finished
    }

    /// Puts in force which devices are over their allowance. Their open
    /// connections end, so they reconnect cut off, slowed or back to normal.
    fn set_over_quota(&self, over: HashMap<MacAddr, Option<u64>>) {
        let changed: Vec<MacAddr> = {
            let mut current = lock(&self.over_quota);
            if *current == over {
                return;
            }
            let mut changed: Vec<MacAddr> =
                current.keys().chain(over.keys()).filter(|mac| current.get(mac) != over.get(mac)).copied().collect();
            changed.sort_unstable();
            changed.dedup();
            *current = over;
            changed
        };
        info!(devices = changed.len(), "data allowances used up or started over");
        // Under the capacity lock, then this one (see `install_policy`).
        self.refresh_policy();
        self.flows.reset_devices(&changed);
        self.broadcast_clients();
    }

    /// Saves what was counted since the last save, off the async threads.
    pub(crate) async fn save_usage(&self) {
        let saving = lock(&self.usage).take_saving();
        if let Some(saving) = saving {
            let _ = tokio::task::spawn_blocking(move || saving.write()).await;
        }
    }

    /// Sends the app the device list again when devices with an allowance
    /// used data since it last got one, so it shows how much is left.
    pub(crate) fn show_allowances(&self) {
        if !self.has_listeners() {
            return;
        }
        let config = self.config();
        let any = config.network.device_quota.is_some()
            || config.groups.iter().any(|g| g.quota.is_some())
            || config.clients.iter().any(|c| c.quota.is_some());
        if lock(&self.usage).take_unshown() && any {
            self.broadcast_clients();
        }
    }

    /// How `mac`'s allowance stands now, for the device list.
    pub(crate) fn quota_use(&self, config: &Config, mac: &MacAddr) -> Option<QuotaUse> {
        lock(&self.usage).quota_use(config, mac, &Local, now_ms())
    }

    /// What was used between each two neighbouring `bounds`, by `device` or
    /// by all, and by each device over the whole span.
    pub(crate) async fn usage_report(&self, bounds: Vec<u64>, device: Option<MacAddr>) -> Result<UsageReport, IpcError> {
        let bad = |why: &str| IpcError::new(ErrorCode::BadRequest, why.to_string());
        if bounds.len() < 2 || bounds.len() > MAX_BOUNDS {
            return Err(bad("ask about between 1 and 1,999 stretches of time"));
        }
        let bounds: Vec<i64> =
            bounds.into_iter().map(i64::try_from).collect::<Result<_, _>>().map_err(|_| bad("a time is out of range"))?;
        if bounds.windows(2).any(|w| w[0] >= w[1]) {
            return Err(bad("the times must rise"));
        }
        let span_days = (bounds[bounds.len() - 1] - bounds[0]) / 86_400_000;
        if span_days > i64::try_from(KEEP_DAYS).unwrap_or(i64::MAX) + 2 {
            return Err(bad("ask about at most 400 days at a time"));
        }
        let sources = lock(&self.usage).sources();
        tokio::task::spawn_blocking(move || sources.report(&Local, &bounds, device))
            .await
            .map_err(|e| IpcError::new(ErrorCode::Internal, format!("reading the data use failed: {e}")))
    }

    /// Starts `mac`'s allowance over now.
    pub(crate) fn reset_quota(&self, mac: MacAddr) -> Result<(), IpcError> {
        self.change_quota(mac, |usage, config, now| usage.reset(config, mac, &Local, now))
    }

    /// Gives `mac` `mb` more megabytes in this period of its allowance.
    pub(crate) fn add_quota(&self, mac: MacAddr, mb: u64) -> Result<(), IpcError> {
        if mb == 0 || mb > captun_core::config::MAX_QUOTA_MB {
            return Err(IpcError::new(ErrorCode::BadRequest, "give between 1 MB and a petabyte".to_string()));
        }
        self.change_quota(mac, |usage, config, now| usage.add(config, mac, mb.saturating_mul(captun_core::config::MB), &Local, now))
    }

    fn change_quota(&self, mac: MacAddr, change: impl FnOnce(&mut Usage, &Config, i64)) -> Result<(), IpcError> {
        let config = self.config();
        if config.quota_for(&mac).is_none() {
            return Err(IpcError::new(ErrorCode::BadRequest, format!("device {mac} has no data allowance")));
        }
        let now = now_ms();
        let over = {
            let mut usage = lock(&self.usage);
            change(&mut usage, &config, now);
            usage.over_quota(&config, &Local, now)
        };
        self.set_over_quota(over);
        // Its allowance changed even if it was not over: show it.
        self.broadcast_clients();
        Ok(())
    }
}

fn day_file(dir: &Path, day: NaiveDate) -> PathBuf {
    dir.join(format!("{}.json", day.format("%Y-%m-%d")))
}

fn periods_file(dir: &Path) -> PathBuf {
    dir.join("allowances.json")
}

fn read_day(dir: &Path, day: NaiveDate) -> Hours {
    read_json::<DayFile>(&day_file(dir, day)).map(|file| file.hours).unwrap_or_default()
}

fn read_periods(dir: &Path) -> HashMap<MacAddr, Periods> {
    read_json(&periods_file(dir)).unwrap_or_default()
}

/// A file's contents, or nothing when it is not there. One that cannot be
/// read is renamed aside (`.bad`), so the next save does not lose it too.
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let text = match fs::read(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!("cannot read {}: {e}", path.display());
            return None;
        }
    };
    match serde_json::from_slice(&text) {
        Ok(value) => Some(value),
        Err(e) => {
            warn!("{} is damaged ({e}); it is set aside and counting starts afresh", path.display());
            let _ = fs::rename(path, path.with_extension("json.bad"));
            None
        }
    }
}

/// Writes atomically: a crash never leaves half a file.
fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec(value).map_err(io::Error::other)?)?;
    fs::rename(&tmp, path)
}

/// The days kept, by their files' names.
fn days(dir: &Path) -> Vec<NaiveDate> {
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new() };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?.strip_suffix(".json")?;
            NaiveDate::parse_from_str(name, "%Y-%m-%d").ok()
        })
        .collect()
}

fn oldest_day(dir: &Path) -> Option<NaiveDate> {
    days(dir).into_iter().min()
}

/// Deletes the days more than [`KEEP_DAYS`] before `today`.
fn prune(dir: &Path, today: NaiveDate) {
    let Some(oldest) = today.checked_sub_days(Days::new(KEEP_DAYS)) else { return };
    for day in days(dir).into_iter().filter(|day| *day < oldest) {
        let _ = fs::remove_file(day_file(dir, day));
    }
}

#[cfg(test)]
mod tests {
    use captun_core::config::{MB, Quota, QuotaPeriod};
    use chrono::{FixedOffset, Utc};

    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([2, 0, 0, 0, 0, n])
    }

    fn reading(n: u8, down: u64, up: u64) -> (MacAddr, CounterSnapshot) {
        (mac(n), CounterSnapshot { down_bytes: down, up_bytes: up, active_flows: 0 })
    }

    /// Tehran: half an hour off whole hours, as some time zones are.
    fn tehran() -> FixedOffset {
        FixedOffset::east_opt(3 * 3600 + 1800).unwrap()
    }

    /// `hh:mm` local on 2026-11-13 (a Friday) in `tz`, in ms.
    fn at<Tz: TimeZone>(tz: &Tz, day: u32, hh: u32, mm: u32) -> i64 {
        tz.from_local_datetime(&NaiveDate::from_ymd_opt(2026, 11, day).unwrap().and_hms_opt(hh, mm, 0).unwrap())
            .unwrap()
            .timestamp_millis()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("captun-usage-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn with_quota(mb: u64, every: QuotaPeriod, then_kbps: Option<u64>) -> Config {
        let mut config = Config::default();
        config.network.device_quota = Some(Quota { mb, every, then_kbps });
        config
    }

    #[test]
    fn hours_start_on_the_local_hour_even_half_an_hour_off() {
        let tz = tehran();
        assert_eq!(hour_start(&tz, at(&tz, 13, 10, 42)), at(&tz, 13, 10, 0));
        assert_eq!(hour_start(&Utc, 7_200_000 + 59_999), 7_200_000);
    }

    #[test]
    fn periods_start_at_local_midnight_on_the_chosen_weekday_and_the_first() {
        let tz = tehran();
        // 2026-11-13 is a Friday.
        let s = starts(&tz, at(&tz, 13, 10, 0), Weekday::Sat);
        assert_eq!(s.day, at(&tz, 13, 0, 0));
        assert_eq!(s.next_day, at(&tz, 14, 0, 0));
        assert_eq!(s.week, at(&tz, 7, 0, 0), "the Saturday before");
        assert_eq!(s.next_week, at(&tz, 14, 0, 0));
        assert_eq!(s.month, at(&tz, 1, 0, 0));
        assert_eq!(starts(&tz, at(&tz, 13, 10, 0), Weekday::Fri).week, at(&tz, 13, 0, 0), "a Friday week starts today");
        assert_eq!(starts(&tz, at(&tz, 13, 10, 0), Weekday::Mon).week, at(&tz, 9, 0, 0));
    }

    #[test]
    fn what_moved_since_the_last_reading_is_counted_once() {
        let tz = tehran();
        let mut usage = Usage::open(None, &tz, at(&tz, 13, 10, 0));
        usage.record(&[reading(1, 1000, 100)], &tz, at(&tz, 13, 10, 0), Weekday::Mon);
        usage.record(&[reading(1, 1500, 100), reading(2, 10, 0)], &tz, at(&tz, 13, 10, 30), Weekday::Mon);
        // Device 1 was forgotten and came again: its counter starts over.
        usage.record(&[reading(1, 200, 0)], &tz, at(&tz, 13, 11, 5), Weekday::Mon);
        let hours = &usage.hours;
        assert_eq!(hours[&at(&tz, 13, 10, 0)][&mac(1)], Bytes(1500, 100));
        assert_eq!(hours[&at(&tz, 13, 10, 0)][&mac(2)], Bytes(10, 0));
        assert_eq!(hours[&at(&tz, 13, 11, 0)][&mac(1)], Bytes(200, 0));
        assert_eq!(usage.periods[&mac(1)].day.used, 1800);
        assert_eq!(usage.periods[&mac(1)].total.used, 1800);
    }

    #[test]
    fn an_allowance_used_up_cuts_off_or_slows_and_starts_over_with_its_period() {
        let tz = tehran();
        let config = with_quota(1, QuotaPeriod::Day, Some(128));
        let mut usage = Usage::open(None, &tz, at(&tz, 13, 22, 0));
        usage.record(&[reading(1, 600_000, 0), reading(2, 100, 0)], &tz, at(&tz, 13, 22, 0), Weekday::Mon);
        assert!(usage.over_quota(&config, &tz, at(&tz, 13, 22, 0)).is_empty());
        usage.record(&[reading(1, MB, 0), reading(2, 100, 0)], &tz, at(&tz, 13, 22, 1), Weekday::Mon);
        let over = usage.over_quota(&config, &tz, at(&tz, 13, 22, 1));
        assert_eq!(over, [(mac(1), Some(128))].into_iter().collect());
        let state = usage.quota_use(&config, &mac(1), &tz, at(&tz, 13, 22, 1)).unwrap();
        assert_eq!((state.used, state.allowed, state.over), (MB, MB, true));
        assert_eq!(state.resets_at_ms, Some(at(&tz, 14, 0, 0) as u64));
        // Midnight: a new day, nothing used in it yet.
        assert!(usage.over_quota(&config, &tz, at(&tz, 14, 0, 0)).is_empty());
        // Cut off when no speed is given.
        let config = with_quota(1, QuotaPeriod::Day, None);
        assert_eq!(usage.over_quota(&config, &tz, at(&tz, 13, 23, 0)), [(mac(1), None)].into_iter().collect());
    }

    #[test]
    fn extra_and_a_reset_count_for_the_current_period_only() {
        let tz = tehran();
        let config = with_quota(1, QuotaPeriod::Week, None);
        let now = at(&tz, 13, 12, 0);
        let mut usage = Usage::open(None, &tz, now);
        usage.record(&[reading(1, 3 * MB / 2, 0)], &tz, now, Weekday::Mon);
        assert!(usage.quota_use(&config, &mac(1), &tz, now).unwrap().over);
        usage.add(&config, mac(1), MB, &tz, now);
        let state = usage.quota_use(&config, &mac(1), &tz, now).unwrap();
        assert_eq!((state.used, state.allowed, state.over), (3 * MB / 2, 2 * MB, false));
        usage.reset(&config, mac(1), &tz, now);
        let state = usage.quota_use(&config, &mac(1), &tz, now).unwrap();
        assert_eq!((state.used, state.allowed), (0, MB), "the extra goes with a reset");
        // The day and month still count what was used: only the week started over.
        assert_eq!(usage.periods[&mac(1)].day.used, 3 * MB / 2);
        // A device with no allowance is neither reset nor topped up.
        let mut none = Usage::open(None, &tz, now);
        none.add(&Config::default(), mac(1), 5, &tz, now);
        assert!(none.periods.is_empty());
    }

    #[test]
    fn a_question_about_use_adds_up_hours_where_they_start() {
        let tz = tehran();
        let dir = temp_dir("report");
        let mut usage = Usage::open(Some(dir.clone()), &tz, at(&tz, 12, 23, 0));
        usage.record(&[reading(1, 100, 10), reading(2, 1, 1)], &tz, at(&tz, 12, 23, 10), Weekday::Mon);
        // The next day: yesterday is saved to its own file.
        let finished = usage.record(&[reading(1, 300, 10), reading(2, 1, 1)], &tz, at(&tz, 13, 0, 20), Weekday::Mon).unwrap();
        finished.save();
        usage.record(&[reading(1, 300, 10), reading(2, 51, 1)], &tz, at(&tz, 13, 9, 0), Weekday::Mon);
        assert!(day_file(&dir, NaiveDate::from_ymd_opt(2026, 11, 12).unwrap()).exists());

        let bounds = [at(&tz, 12, 0, 0), at(&tz, 13, 0, 0), at(&tz, 14, 0, 0)];
        let report = usage.sources().report(&tz, &bounds, None);
        assert_eq!(report.buckets, [UsageBytes { down: 101, up: 11 }, UsageBytes { down: 250, up: 0 }]);
        assert_eq!(report.devices[0], DeviceUsage { mac: mac(1), down: 300, up: 10 });
        assert_eq!(report.devices[1], DeviceUsage { mac: mac(2), down: 51, up: 1 });
        assert_eq!(report.kept_since_ms, Some(bounds[0] as u64));

        let one = usage.sources().report(&tz, &bounds[..2], Some(mac(2)));
        assert_eq!(one.buckets, [UsageBytes { down: 1, up: 1 }]);
        assert_eq!(one.devices.len(), 1);
        // Bounds that do not rise ask nothing.
        assert_eq!(usage.sources().report(&tz, &[bounds[1], bounds[0]], None), UsageReport::default());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn what_was_counted_comes_back_after_a_restart_and_a_damaged_file_is_set_aside() {
        let tz = tehran();
        let dir = temp_dir("restart");
        let now = at(&tz, 13, 9, 0);
        let config = with_quota(1, QuotaPeriod::Month, None);
        let mut usage = Usage::open(Some(dir.clone()), &tz, now);
        usage.record(&[reading(1, 700_000, 0)], &tz, now, Weekday::Mon);
        usage.take_saving().unwrap().write();
        assert!(usage.take_saving().is_none(), "nothing new to save");

        let again = Usage::open(Some(dir.clone()), &tz, now);
        assert_eq!(again.hours, usage.hours);
        assert_eq!(again.quota_use(&config, &mac(1), &tz, now).unwrap().used, 700_000);

        fs::write(periods_file(&dir), b"{ not json").unwrap();
        let fresh = Usage::open(Some(dir.clone()), &tz, now);
        assert!(fresh.periods.is_empty());
        assert!(periods_file(&dir).with_extension("json.bad").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_device_over_its_allowance_is_held_by_the_rules_until_given_more() {
        use captun_policy::Admission;
        let mut config = Config::default();
        config.client_mut(mac(1)).quota = Some(Quota { mb: 1, every: QuotaPeriod::Day, then_kbps: None });
        let (events, _rx) = tokio::sync::broadcast::channel(16);
        let hub = Hub::new(None, config, captun_platform::default_backend(), events, None);
        lock(&hub.usage).record(&[reading(1, 3 * MB / 2, MB / 2)], &Local, now_ms(), Weekday::Mon);
        hub.record_usage();
        assert_eq!(hub.policy().admission(&mac(1)), Admission::OverQuota);
        let shown = hub.client_views().into_iter().find(|c| c.mac == mac(1)).unwrap().quota.unwrap();
        assert_eq!((shown.used, shown.allowed, shown.over), (2 * MB, MB, true));

        hub.add_quota(mac(1), 5).unwrap();
        assert_ne!(hub.policy().admission(&mac(1)), Admission::OverQuota, "6 MB allowed now");
        hub.reset_quota(mac(1)).unwrap();
        let shown = hub.client_views().into_iter().find(|c| c.mac == mac(1)).unwrap().quota.unwrap();
        assert_eq!((shown.used, shown.allowed, shown.over), (0, MB, false));
        // A device with no allowance has none to give more of.
        assert!(hub.add_quota(mac(2), 5).is_err());
        assert!(hub.add_quota(mac(1), 0).is_err());
    }

    #[test]
    fn days_past_keeping_are_deleted() {
        let dir = temp_dir("prune");
        fs::create_dir_all(&dir).unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 11, 13).unwrap();
        let old = today - Days::new(KEEP_DAYS + 1);
        let kept = today - Days::new(KEEP_DAYS);
        for day in [old, kept] {
            write_json(&day_file(&dir, day), &DayFile::default()).unwrap();
        }
        fs::write(dir.join("allowances.json"), b"{}").unwrap();
        prune(&dir, today);
        assert!(!day_file(&dir, old).exists());
        assert!(day_file(&dir, kept).exists());
        assert!(dir.join("allowances.json").exists());
        let _ = fs::remove_dir_all(dir);
    }
}
