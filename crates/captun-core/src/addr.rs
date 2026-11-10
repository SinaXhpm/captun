use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::domain::is_valid_hostname;

/// Destination of a connection: either a resolved socket address or a
/// hostname that the egress (e.g. a SOCKS5 proxy) resolves remotely.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(addr) => Some(addr.ip()),
            Self::Domain(..) => None,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::Ip(_) => None,
            Self::Domain(host, _) => Some(host),
        }
    }

    /// Host part without the port, as it appears in a `Host` header or SNI.
    pub fn host(&self) -> String {
        match self {
            Self::Ip(addr) => addr.ip().to_string(),
            Self::Domain(host, _) => host.clone(),
        }
    }

    /// Parses `host[:port]`, filling in `default_port` when the port is absent.
    pub fn parse_with_default_port(s: &str, default_port: u16) -> Result<Self, ParseTargetError> {
        if let Ok(target) = s.parse() {
            return Ok(target);
        }
        let host = s.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Self::Ip(SocketAddr::new(ip, default_port)));
        }
        if is_valid_hostname(host) {
            return Ok(Self::Domain(host.to_ascii_lowercase(), default_port));
        }
        Err(ParseTargetError(s.to_owned()))
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid address {0:?}: expected host:port")]
pub struct ParseTargetError(String);

impl FromStr for TargetAddr {
    type Err = ParseTargetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseTargetError(s.to_owned());
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(Self::Ip(addr));
        }
        let (host, port) = s.rsplit_once(':').ok_or_else(err)?;
        let port: u16 = port.parse().map_err(|_| err())?;
        // A bare IPv6 address without brackets is ambiguous; SocketAddr
        // already handled the bracketed form above.
        if host.contains(':') {
            return Err(err());
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Self::Ip(SocketAddr::new(ip, port)));
        }
        if !is_valid_hostname(host) {
            return Err(err());
        }
        Ok(Self::Domain(host.to_ascii_lowercase(), port))
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => addr.fmt(f),
            Self::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

impl fmt::Debug for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for TargetAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TargetAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_forms() {
        assert_eq!("1.2.3.4:80".parse::<TargetAddr>().unwrap(), TargetAddr::Ip("1.2.3.4:80".parse().unwrap()));
        assert_eq!("[::1]:443".parse::<TargetAddr>().unwrap().port(), 443);
        assert_eq!(
            "Example.COM:8080".parse::<TargetAddr>().unwrap(),
            TargetAddr::Domain("example.com".into(), 8080)
        );
        assert!("::1:80".parse::<TargetAddr>().is_err());
        assert!("example.com".parse::<TargetAddr>().is_err());
        assert!("bad host:80".parse::<TargetAddr>().is_err());
    }

    #[test]
    fn default_port() {
        assert_eq!(TargetAddr::parse_with_default_port("1.1.1.1", 853).unwrap().port(), 853);
        assert_eq!(TargetAddr::parse_with_default_port("[2606:4700::1111]", 53).unwrap().port(), 53);
        assert_eq!(TargetAddr::parse_with_default_port("dns.google:5353", 53).unwrap().port(), 5353);
    }

    #[test]
    fn display_round_trips() {
        for s in ["1.2.3.4:80", "[::1]:443", "example.com:8080"] {
            assert_eq!(s.parse::<TargetAddr>().unwrap().to_string(), s);
        }
    }
}
