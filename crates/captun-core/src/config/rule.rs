use std::fmt;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use super::Schedule;
use crate::{DomainPattern, EgressId, MacAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Inclusive port range, written as `443` or `"8000-8999"`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

impl fmt::Debug for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end { write!(f, "{}", self.start) } else { write!(f, "{}-{}", self.start, self.end) }
    }
}

impl Serialize for PortRange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.start == self.end {
            serializer.serialize_u16(self.start)
        } else {
            serializer.collect_str(&format_args!("{}-{}", self.start, self.end))
        }
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Port(u16),
            Text(String),
        }
        let range = match Raw::deserialize(deserializer)? {
            Raw::Port(p) => PortRange { start: p, end: p },
            Raw::Text(s) => {
                let parse = |v: &str| v.trim().parse::<u16>().map_err(|_| de::Error::custom(format!("invalid port range {s:?}")));
                match s.split_once('-') {
                    Some((a, b)) => PortRange { start: parse(a)?, end: parse(b)? },
                    None => {
                        let p = parse(&s)?;
                        PortRange { start: p, end: p }
                    }
                }
            }
        };
        if range.start > range.end {
            return Err(de::Error::custom(format!("port range {range:?} is reversed")));
        }
        Ok(range)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Let the flow through on the client's own egress.
    Allow,
    /// Silently drop.
    Deny,
    /// Refuse actively (TCP RST / ICMP unreachable) so apps fail fast.
    Reject,
    /// Let the flow through on a specific egress.
    Route(EgressId),
}

/// One firewall/routing rule. Rules are evaluated top to bottom and the first
/// match wins. Every non-empty condition must hold; within one condition any
/// listed value may match. Where the traffic goes is one condition: names
/// (`domains`), addresses (`cidrs`) and online `lists` together, any of
/// which may match.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default = "super::yes")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<MacAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<DomainPattern>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidrs: Vec<IpNet>,
    /// Links to online lists of names and addresses (blocklists, a service's
    /// addresses), downloaded only when asked. Their entries count as if
    /// written in `domains` and `cidrs`; until a list is downloaded it adds
    /// nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
    pub action: RuleAction,
}
