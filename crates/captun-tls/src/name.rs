use std::{fmt, net::IpAddr};

use rcgen::{SanType, string::Ia5String};
use rustls::pki_types::DnsName;

use crate::TlsError;

/// How much of a refused name is repeated in the error, which may be logged.
const SHOWN: usize = 80;

/// What a site certificate is made for: a website name (lower case, without
/// a trailing dot) or an IP address. It is the certificate's only subject
/// alternative name, and nothing relies on a common name. Made only by
/// [`SiteName::parse`], so one site is always spelled one way.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SiteName(Name);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Name {
    Dns(String),
    Ip(IpAddr),
}

impl SiteName {
    /// The website name, if it is one.
    pub fn dns_name(&self) -> Option<&str> {
        match &self.0 {
            Name::Dns(name) => Some(name),
            Name::Ip(_) => None,
        }
    }

    /// The IP address, if it is one.
    pub fn ip(&self) -> Option<IpAddr> {
        match self.0 {
            Name::Ip(ip) => Some(ip),
            Name::Dns(_) => None,
        }
    }

    /// The name as a certificate's subject alternative name: a DNS name or
    /// an IP address.
    pub(crate) fn subject_alt_name(&self) -> Result<SanType, TlsError> {
        Ok(match &self.0 {
            Name::Dns(name) => {
                SanType::DnsName(Ia5String::try_from(name.as_str()).map_err(|_| TlsError::BadSiteName(name.clone()))?)
            }
            Name::Ip(ip) => SanType::IpAddress(*ip),
        })
    }

    /// Reads `host` as a TLS client names a server (SNI) or a proxy request
    /// names its target (CONNECT): a name like `example.com` (a trailing dot
    /// and capitals are fine), or an IP address, an IPv6 one possibly in
    /// brackets. Wildcards, ports and anything that is not a valid name are
    /// refused.
    pub fn parse(host: &str) -> Result<Self, TlsError> {
        let bare = host.strip_prefix('[').and_then(|inner| inner.strip_suffix(']'));
        if let Some(ip) = bare.unwrap_or(host).parse::<IpAddr>().ok().filter(|ip| bare.is_none() || ip.is_ipv6()) {
            return Ok(Self(Name::Ip(ip)));
        }
        let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        // A second trailing dot would leave an empty label.
        if name.ends_with('.') || DnsName::try_from(name.as_str()).is_err() {
            return Err(TlsError::BadSiteName(host.chars().take(SHOWN).collect()));
        }
        Ok(Self(Name::Dns(name)))
    }
}

impl fmt::Display for SiteName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Name::Dns(name) => f.write_str(name),
            Name::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_read_the_way_clients_send_them() {
        let dns = |host: &str| SiteName::parse(host).unwrap().dns_name().map(str::to_owned);
        let ip = |host: &str| SiteName::parse(host).unwrap().ip();
        assert_eq!(dns("Example.COM").as_deref(), Some("example.com"));
        assert_eq!(dns("www.example.com.").as_deref(), Some("www.example.com"));
        assert_eq!(dns("_dmarc.example.com").as_deref(), Some("_dmarc.example.com"));
        assert_eq!(dns("localhost").as_deref(), Some("localhost"));
        assert_eq!(ip("192.0.2.7"), Some("192.0.2.7".parse().unwrap()));
        assert_eq!(ip("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(ip("[2001:db8::1]"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(dns("192.0.2.7"), None);
        assert_eq!(ip("example.com"), None);
        assert_eq!(SiteName::parse("Example.COM.").unwrap(), SiteName::parse("example.com").unwrap());
        assert_eq!(SiteName::parse("Example.COM").unwrap().to_string(), "example.com");
    }

    #[test]
    fn anything_else_is_refused() {
        let long_label = format!("{}.com", "a".repeat(64));
        // 263 characters; 253 is the most a name may have.
        let long_name = format!("{}com", "abcdefghi.".repeat(26));
        for bad in [
            "",
            ".",
            "*.example.com",
            "example.com..",
            "exa mple.com",
            "example.com:443",
            "a..b",
            "-a.com",
            "a-.com",
            "[192.0.2.7]",
            "[example.com]",
            "fe80::1%eth0",
            "1.2.3",
            "bücher.de",
            "example.com/x",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(SiteName::parse(bad).is_err(), "{bad:?} must be refused");
        }
        let err = SiteName::parse(&"x/".repeat(500)).unwrap_err().to_string();
        assert!(err.len() < 200, "a refused name is cut short in the error: {err}");
    }
}
