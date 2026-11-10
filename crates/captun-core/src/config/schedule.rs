use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Weekday {
    pub const ALL: [Weekday; 7] = [Self::Mon, Self::Tue, Self::Wed, Self::Thu, Self::Fri, Self::Sat, Self::Sun];

    /// Monday = 0 … Sunday = 6.
    pub fn from_index(index: u8) -> Option<Self> {
        Self::ALL.get(usize::from(index)).copied()
    }

    pub fn previous(self) -> Self {
        Self::ALL[(self as usize + 6) % 7]
    }
}

/// Minutes since local midnight, written as `HH:MM`. The default is midnight.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockTime(u16);

impl ClockTime {
    pub fn from_minutes(minutes: u16) -> Option<Self> {
        (minutes < 24 * 60).then_some(Self(minutes))
    }

    pub fn minutes(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid time {0:?}: expected HH:MM")]
pub struct ParseClockTimeError(String);

impl FromStr for ClockTime {
    type Err = ParseClockTimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseClockTimeError(s.to_owned());
        let (h, m) = s.split_once(':').ok_or_else(err)?;
        if h.is_empty() || h.len() > 2 || m.len() != 2 {
            return Err(err());
        }
        let h: u16 = h.parse().map_err(|_| err())?;
        let m: u16 = m.parse().map_err(|_| err())?;
        if h > 23 || m > 59 {
            return Err(err());
        }
        Ok(Self(h * 60 + m))
    }
}

impl fmt::Display for ClockTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}", self.0 / 60, self.0 % 60)
    }
}

impl fmt::Debug for ClockTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for ClockTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ClockTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

/// A recurring local-time window. `end` before `start` wraps past midnight,
/// so `22:00`–`06:00` on `fri` covers Friday night into Saturday morning.
/// `start == end` means the whole day.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// Empty means every day.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<Weekday>,
    pub start: ClockTime,
    pub end: ClockTime,
}

impl Schedule {
    pub fn contains(&self, day: Weekday, time: ClockTime) -> bool {
        let on = |d: Weekday| self.days.is_empty() || self.days.contains(&d);
        let (start, end, t) = (self.start, self.end, time);
        if start == end {
            on(day)
        } else if start < end {
            on(day) && start <= t && t < end
        } else {
            (on(day) && t >= start) || (on(day.previous()) && t < end)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> ClockTime {
        s.parse().unwrap()
    }

    #[test]
    fn same_day_window() {
        let s = Schedule { days: vec![Weekday::Mon], start: t("08:00"), end: t("17:30") };
        assert!(s.contains(Weekday::Mon, t("08:00")));
        assert!(s.contains(Weekday::Mon, t("17:29")));
        assert!(!s.contains(Weekday::Mon, t("17:30")));
        assert!(!s.contains(Weekday::Tue, t("09:00")));
    }

    #[test]
    fn overnight_window_belongs_to_start_day() {
        let s = Schedule { days: vec![Weekday::Fri], start: t("22:00"), end: t("06:00") };
        assert!(s.contains(Weekday::Fri, t("23:00")));
        assert!(s.contains(Weekday::Sat, t("05:59")));
        assert!(!s.contains(Weekday::Fri, t("05:00")));
        assert!(!s.contains(Weekday::Sat, t("23:00")));
    }

    #[test]
    fn parse_time() {
        assert_eq!(t("7:05").minutes(), 425);
        assert!("24:00".parse::<ClockTime>().is_err());
        assert!("12:5".parse::<ClockTime>().is_err());
        assert_eq!(Weekday::Mon.previous(), Weekday::Sun);
    }
}
