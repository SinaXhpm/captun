use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// IEEE 802 MAC-48 address. Clients on the hotspot are identified by it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Locally administered addresses are what phones use for per-network
    /// "private" MACs, so the UI can flag them as possibly rotating.
    pub const fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid MAC address {0:?}")]
pub struct ParseMacError(String);

impl FromStr for MacAddr {
    type Err = ParseMacError;

    /// Accepts `aa:bb:cc:dd:ee:ff` and `AA-BB-CC-DD-EE-FF` (the Windows form).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseMacError(s.to_owned());
        let mut octets = [0u8; 6];
        let mut parts = s.trim().split([':', '-']);
        for octet in &mut octets {
            let part = parts.next().ok_or_else(err)?;
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(err());
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| err())?;
        }
        if parts.next().is_some() {
            return Err(err());
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_separators() {
        let a: MacAddr = "aa:bb:cc:00:11:22".parse().unwrap();
        let b: MacAddr = "AA-BB-CC-00-11-22".parse().unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_string(), "aa:bb:cc:00:11:22");
    }

    #[test]
    fn rejects_malformed() {
        for bad in ["", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "+a:bb:cc:dd:ee:ff", "aaa:b:cc:dd:ee:ff"] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn flags() {
        let private: MacAddr = "da:a1:19:00:00:01".parse().unwrap();
        assert!(private.is_locally_administered());
        assert!(!private.is_multicast());
    }
}
