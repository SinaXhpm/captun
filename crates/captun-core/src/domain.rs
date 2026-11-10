use std::{borrow::Cow, collections::HashSet, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Lowercases a DNS name and strips the trailing root dot, borrowing when the
/// input is already canonical (the common case on the hot path).
pub fn normalize_domain(name: &str) -> Cow<'_, str> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
}

/// Hostname check used for config input, SNI and `Host` headers. Underscores
/// are tolerated because real-world names (`_dmarc`, some CDNs) use them.
pub fn is_valid_hostname(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// One domain matcher, in the same notation Xray routing uses so imported
/// rule lists keep their meaning:
/// - `example.com` / `domain:example.com` — the domain and all subdomains
/// - `full:example.com` — exactly this name
/// - `keyword:ads` — any name containing the substring
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum DomainPattern {
    Suffix(String),
    Full(String),
    Keyword(String),
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid domain pattern {0:?}")]
pub struct ParseDomainPatternError(String);

impl FromStr for DomainPattern {
    type Err = ParseDomainPatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseDomainPatternError(s.to_owned());
        let s = s.trim();
        if let Some(keyword) = s.strip_prefix("keyword:") {
            let keyword = keyword.to_ascii_lowercase();
            if keyword.is_empty() || keyword.contains(char::is_whitespace) {
                return Err(err());
            }
            return Ok(Self::Keyword(keyword));
        }
        let (full, name) = match s.strip_prefix("full:") {
            Some(name) => (true, name),
            None => (false, s.strip_prefix("domain:").or_else(|| s.strip_prefix("*.")).unwrap_or(s)),
        };
        if !is_valid_hostname(name) {
            return Err(err());
        }
        let name = normalize_domain(name).into_owned();
        Ok(if full { Self::Full(name) } else { Self::Suffix(name) })
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suffix(name) => f.write_str(name),
            Self::Full(name) => write!(f, "full:{name}"),
            Self::Keyword(keyword) => write!(f, "keyword:{keyword}"),
        }
    }
}

impl fmt::Debug for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for DomainPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DomainPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

/// A compiled set of [`DomainPattern`]s. Lookups cost one hash probe per label
/// of the queried name plus a scan of the (usually tiny) keyword list.
#[derive(Clone, Debug, Default)]
pub struct DomainSet {
    full: HashSet<String>,
    suffix: HashSet<String>,
    /// A set, so that adding each one stays quick however many there are;
    /// a match still looks for them one by one.
    keywords: HashSet<String>,
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, pattern: DomainPattern) {
        match pattern {
            DomainPattern::Full(name) => {
                self.full.insert(name);
            }
            DomainPattern::Suffix(name) => {
                self.suffix.insert(name);
            }
            DomainPattern::Keyword(keyword) => {
                self.keywords.insert(keyword);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.full.len() + self.suffix.len() + self.keywords.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn matches(&self, name: &str) -> bool {
        let name = normalize_domain(name);
        let name = name.as_ref();
        if self.full.contains(name) || self.suffix.contains(name) {
            return true;
        }
        if name.match_indices('.').any(|(i, _)| self.suffix.contains(&name[i + 1..])) {
            return true;
        }
        self.keywords.iter().any(|k| name.contains(k.as_str()))
    }
}

impl FromIterator<DomainPattern> for DomainSet {
    fn from_iter<I: IntoIterator<Item = DomainPattern>>(iter: I) -> Self {
        let mut set = Self::new();
        set.extend(iter);
        set
    }
}

impl Extend<DomainPattern> for DomainSet {
    fn extend<I: IntoIterator<Item = DomainPattern>>(&mut self, iter: I) {
        for pattern in iter {
            self.insert(pattern);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(patterns: &[&str]) -> DomainSet {
        patterns.iter().map(|p| p.parse::<DomainPattern>().unwrap()).collect()
    }

    #[test]
    fn suffix_matches_domain_and_subdomains_only() {
        let s = set(&["example.com"]);
        assert!(s.matches("example.com"));
        assert!(s.matches("a.b.Example.COM."));
        assert!(!s.matches("notexample.com"));
        assert!(!s.matches("com"));
    }

    #[test]
    fn full_and_keyword() {
        let s = set(&["full:api.example.com", "keyword:tracker"]);
        assert!(s.matches("api.example.com"));
        assert!(!s.matches("x.api.example.com"));
        assert!(s.matches("cdn.tracker-net.io"));
    }

    #[test]
    fn keywords_count_once_and_build_quickly() {
        let mut s = set(&["keyword:ads", "keyword:ADS", "keyword:ads", "example.com"]);
        assert_eq!(s.len(), 2);
        // Adding one is a hash probe, not a walk through the ones already there.
        s.extend((0..50_000).map(|i| DomainPattern::Keyword(format!("kw{i:05}"))));
        s.extend((0..50_000).map(|i| DomainPattern::Keyword(format!("kw{i:05}"))));
        assert_eq!(s.len(), 50_002);
        assert!(s.matches("cdn.kw49999.io") && s.matches("x.ads.io") && !s.matches("kw5.io"));
    }

    #[test]
    fn pattern_syntax() {
        assert_eq!("*.Example.com".parse::<DomainPattern>().unwrap(), DomainPattern::Suffix("example.com".into()));
        assert_eq!("domain:x.io".parse::<DomainPattern>().unwrap().to_string(), "x.io");
        assert!("keyword:".parse::<DomainPattern>().is_err());
        assert!("bad domain".parse::<DomainPattern>().is_err());
        assert!("-bad.com".parse::<DomainPattern>().is_err());
    }
}
