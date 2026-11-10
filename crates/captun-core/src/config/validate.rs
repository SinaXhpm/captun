use std::{collections::HashSet, net::IpAddr, path::Path};

use super::{CONFIG_VERSION, Config, ConfigError, DnsProtocol, MAX_CLIENT_LIMIT, RateLimit, RuleAction};
use crate::{
    EgressId, EgressKind, UdpPolicy,
    domain::is_valid_hostname,
    link::{Security, ShareLink, VpnProtocol},
};

/// Online lists one rule may use.
const MAX_RULE_LISTS: usize = 32;

/// An online list's link: http(s) with a host (no user name in it), nothing a
/// download could not ask for.
pub fn is_list_link(link: &str) -> bool {
    let Some(rest) = link.strip_prefix("https://").or_else(|| link.strip_prefix("http://")) else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    link.len() <= 2048 && !host.is_empty() && !host.contains('@') && !link.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn is_private_host(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => host == "localhost" || host.ends_with(".local") || host.ends_with(".lan"),
    }
}

/// A VPN-link outbound needs a link the sidecar can run.
fn check_vpn_link(link: &str) -> Result<(), String> {
    match ShareLink::parse(link).map_err(|e| e.to_string())? {
        ShareLink::Vpn(vpn) => match (&vpn.protocol, &vpn.security) {
            (_, Security::Tls(tls)) if tls.insecure && tls.pinned_cert_sha256.is_none() => Err(
                "the link turns off certificate checks, which Xray no longer allows; ask the provider for the certificate's SHA-256 (pcs) or a properly signed server"
                    .into(),
            ),
            // Xray refuses unencrypted VLESS to anything but a private address.
            (VpnProtocol::Vless { encryption, .. }, Security::None)
                if encryption == "none" && !is_private_host(&vpn.host) =>
            {
                Err("this VLESS link has no encryption (no TLS or REALITY), which Xray refuses for public servers".into())
            }
            _ => Ok(()),
        },
        ShareLink::Socks5 { .. } | ShareLink::Http { .. } => {
            Err("this is a plain proxy link; add it as a SOCKS5 or HTTP proxy instead".into())
        }
    }
}

/// Whether an Xray config file is on one of this computer's own drives. The
/// elevated service opens it, and on Windows a network path (`\\server\share`)
/// would make Windows sign in to that server as the service; device paths
/// (`\\?\`, `\\.\`) are refused with them. Elsewhere any full path will do.
fn on_local_drive(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        true
    }
}

pub fn validate_ssid(ssid: &str) -> Result<(), String> {
    if ssid.is_empty() || ssid.len() > 32 {
        return Err("hotspot network name must be 1-32 bytes".into());
    }
    if ssid.chars().any(char::is_control) {
        return Err("hotspot network name must not contain control characters".into());
    }
    Ok(())
}

/// WPA2/WPA3-Personal accepts 8-63 printable ASCII characters, or the raw
/// 256-bit PSK as 64 hex digits.
pub fn validate_passphrase(passphrase: &str) -> Result<(), String> {
    let raw_psk = passphrase.len() == 64 && passphrase.bytes().all(|b| b.is_ascii_hexdigit());
    let ascii = (8..=63).contains(&passphrase.len()) && passphrase.bytes().all(|b| (0x20..=0x7e).contains(&b));
    if raw_psk || ascii {
        Ok(())
    } else {
        Err("hotspot password must be 8-63 printable ASCII characters or a 64-digit hex key".into())
    }
}

fn check_limit(errors: &mut Vec<String>, who: &str, limit: &RateLimit) {
    if limit.down_kbps == Some(0) || limit.up_kbps == Some(0) {
        errors.push(format!("{who}: speed limits must be greater than 0 (omit them for unlimited)"));
    }
}

impl Config {
    /// Why traffic cannot be routed through this egress, if it cannot.
    fn unusable_egress(&self, id: &EgressId) -> Option<&'static str> {
        match self.egress(id) {
            None => Some("does not exist"),
            Some(egress) if !egress.enabled => Some("is turned off"),
            Some(_) => None,
        }
    }

    /// Checks everything that serde cannot: lengths, uniqueness, and that
    /// every cross-reference (egress, group, DNS upstream) resolves. All
    /// problems are reported at once so the GUI can show them together.
    /// Messages use the GUI's words: an egress is an "outbound", a client a
    /// "device", the access network "cable sharing".
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        if self.version != CONFIG_VERSION {
            errors.push(format!("unsupported config version {} (expected {CONFIG_VERSION})", self.version));
        }

        if let Err(msg) = validate_ssid(&self.hotspot.ssid) {
            errors.push(msg);
        }
        if !self.hotspot.passphrase.is_empty()
            && let Err(msg) = validate_passphrase(self.hotspot.passphrase.expose())
        {
            errors.push(msg);
        }
        if let Some(max) = self.hotspot.max_clients
            && !(1..=MAX_CLIENT_LIMIT).contains(&max)
        {
            errors.push(format!(
                "hotspot device limit must be 1-{MAX_CLIENT_LIMIT} (omit it to use the system limit)"
            ));
        }

        let mut egress_ids = HashSet::new();
        for egress in &self.egresses {
            if !egress.id.is_well_formed() {
                errors.push(format!(
                    "outbound ID {:?} must be 1-32 characters of letters, digits, '-' or '_'",
                    egress.id.as_str()
                ));
            }
            if !egress_ids.insert(&egress.id) {
                errors.push(format!("two outbounds share the ID {}", egress.id));
            }
        }

        for egress in &self.egresses {
            let who = format!("outbound {:?}", egress.display_name());
            match &egress.kind {
                EgressKind::Socks5 { username, password, .. } | EgressKind::Http { username, password, .. } => {
                    if password.is_some() && username.is_none() {
                        errors.push(format!("{who}: password is set without a username"));
                    }
                    if username.as_ref().is_some_and(|u| u.is_empty() || u.len() > 255) {
                        errors.push(format!("{who}: username must be 1-255 bytes"));
                    }
                    if password.as_ref().is_some_and(|p| p.expose().len() > 255) {
                        errors.push(format!("{who}: password must be at most 255 bytes"));
                    }
                }
                EgressKind::Xray { link, config_file } => match (link, config_file) {
                    (Some(_), Some(_)) | (None, None) => {
                        errors.push(format!("{who}: set either a share link or a config file (exactly one)"));
                    }
                    (Some(link), None) => {
                        if let Err(why) = check_vpn_link(link.expose()) {
                            errors.push(format!("{who}: {why}"));
                        }
                    }
                    (None, Some(path)) if !path.is_absolute() => {
                        errors.push(format!("{who}: the config file must be a full path"));
                    }
                    (None, Some(path)) if !on_local_drive(path) => {
                        errors.push(format!(
                            "{who}: the Xray config file must be on this computer's own drive, not a network folder"
                        ));
                    }
                    _ => {}
                },
                EgressKind::Direct { interface } => {
                    if interface.as_ref().is_some_and(|i| i.trim().is_empty()) {
                        errors.push(format!(
                            "{who}: network adapter must not be empty (omit it to use the system default)"
                        ));
                    }
                }
                EgressKind::Block => {}
            }

            if let Some(via) = egress.kind.via()
                && let Some(why) = self.unusable_egress(via)
            {
                errors.push(format!("{who} reaches its proxy through outbound {:?}, which {why}", via.as_str()));
            }

            match &egress.udp {
                UdpPolicy::Native if !egress.kind.supports_native_udp() => errors.push(format!(
                    "{who}: {} proxies cannot carry UDP; block UDP or send it through another outbound",
                    egress.kind.type_name().to_uppercase()
                )),
                UdpPolicy::Via(target) if target == &egress.id => {
                    errors.push(format!("{who} cannot send UDP through itself"));
                }
                UdpPolicy::Via(target) => match (self.unusable_egress(target), self.egress(target)) {
                    (Some(why), _) => {
                        errors.push(format!("{who} sends UDP through outbound {:?}, which {why}", target.as_str()));
                    }
                    (None, Some(t)) if !t.kind.supports_native_udp() => errors.push(format!(
                        "{who} sends UDP through outbound {:?}, which cannot carry UDP either",
                        target.as_str()
                    )),
                    _ => {}
                },
                _ => {}
            }
        }

        for egress in &self.egresses {
            let mut chain = HashSet::from([&egress.id]);
            let mut next = egress.kind.via();
            while let Some(hop) = next {
                if !chain.insert(hop) {
                    errors.push(format!("outbound {:?}: proxy chain loops back through {hop}", egress.display_name()));
                    break;
                }
                next = self.egress(hop).and_then(|e| e.kind.via());
            }
        }

        if let Some(why) = self.unusable_egress(&self.network.default_egress) {
            errors.push(format!("the default outbound {:?} {why}", self.network.default_egress.as_str()));
        }

        let access = &self.access_network;
        if !(8..=30).contains(&access.prefix_len) {
            errors.push("cable sharing: the subnet prefix must be between 8 and 30".into());
        } else {
            let (net, bcast) = (u32::from(access.network()), u32::from(access.broadcast()));
            let (gw, start, end) =
                (u32::from(access.gateway), u32::from(access.dhcp_start), u32::from(access.dhcp_end));
            // Usable host addresses exclude the network and broadcast addresses.
            let host = |ip: u32| ip > net && ip < bcast;
            if !host(gw) {
                errors.push("cable sharing: the gateway must be a host address inside its own subnet".into());
            }
            if !host(start) || !host(end) {
                errors.push(
                    "cable sharing: the DHCP range must lie inside the subnet (excluding the network and broadcast addresses)"
                        .into(),
                );
            } else if start > end {
                errors.push("cable sharing: the first DHCP address must not come after the last".into());
            } else if (start..=end).contains(&gw) {
                errors.push("cable sharing: the gateway must not fall inside the DHCP range".into());
            }
        }
        if access.enabled && access.interface.as_ref().is_none_or(|i| i.trim().is_empty()) {
            errors.push("cable sharing: choose a network adapter to share on before turning it on".into());
        }
        if access.lease_secs < 60 {
            errors.push("cable sharing: the lease time must be at least 60 seconds".into());
        }

        let dns = &self.dns;
        let mut upstream_ids = HashSet::new();
        for upstream in &dns.upstreams {
            let who = format!("DNS server {:?}", upstream.id);
            if upstream.id.is_empty() {
                errors.push("DNS server ID must not be empty".into());
            }
            if !upstream_ids.insert(upstream.id.as_str()) {
                errors.push(format!("duplicate {who}"));
            }
            if let Err(e) = upstream.target() {
                errors.push(format!("{who}: {e}"));
            }
            if matches!(upstream.protocol, DnsProtocol::Tls | DnsProtocol::Https)
                && let Ok(name) = upstream.tls_server_name()
                && !is_valid_hostname(&name)
                && name.parse::<IpAddr>().is_err()
            {
                errors.push(format!("{who}: invalid TLS server name {name:?}"));
            }
            if upstream.protocol == DnsProtocol::Https && !upstream.doh_path().starts_with('/') {
                errors.push(format!("{who}: path must start with '/'"));
            }
            if upstream.protocol != DnsProtocol::Https && upstream.path.is_some() {
                errors.push(format!("{who}: a path only applies to DNS over HTTPS"));
            }
        }
        let known_upstream = |id: &str| upstream_ids.contains(id);
        if !known_upstream(&dns.default_upstream) {
            errors.push(format!("the default DNS server {:?} does not exist", dns.default_upstream));
        }
        if dns.port == 0 {
            errors.push("the DNS port must not be 0".into());
        }
        if dns.min_ttl > dns.max_ttl {
            errors.push("the shortest DNS cache time must not exceed the longest".into());
        }
        if dns.cache_size > 1_000_000 {
            errors.push("the DNS cache size must be at most 1000000".into());
        }
        for o in &dns.overrides {
            if o.addrs.is_empty() {
                errors.push(format!("custom DNS answer {}: needs at least one address", o.domain));
            }
        }

        let mut group_ids = HashSet::new();
        for group in &self.groups {
            let who = format!("group {:?}", group.name.as_deref().unwrap_or(&group.id));
            if group.id.is_empty() {
                errors.push("group ID must not be empty".into());
            }
            if !group_ids.insert(group.id.as_str()) {
                errors.push(format!("duplicate {who}"));
            }
            if let Some(egress) = &group.egress
                && let Some(why) = self.unusable_egress(egress)
            {
                errors.push(format!("{who} uses outbound {:?}, which {why}", egress.as_str()));
            }
            if let Some(upstream) = &group.dns_upstream
                && !known_upstream(upstream)
            {
                errors.push(format!("{who} uses DNS server {upstream:?}, which does not exist"));
            }
            if let Some(limit) = &group.limit {
                check_limit(&mut errors, &who, limit);
            }
        }

        let mut macs = HashSet::new();
        for client in &self.clients {
            let who = match &client.alias {
                Some(alias) => format!("device {alias:?}"),
                None => format!("device {}", client.mac),
            };
            if !macs.insert(client.mac) {
                errors.push(format!("duplicate {who}"));
            }
            if client.alias.as_ref().is_some_and(|a| a.chars().count() > 64) {
                errors.push(format!("{who}: name must be at most 64 characters"));
            }
            if let Some(group) = &client.group
                && !group_ids.contains(group.as_str())
            {
                errors.push(format!("{who} is in group {group:?}, which does not exist"));
            }
            if let Some(egress) = &client.egress
                && let Some(why) = self.unusable_egress(egress)
            {
                errors.push(format!("{who} uses outbound {:?}, which {why}", egress.as_str()));
            }
            if let Some(upstream) = &client.dns_upstream
                && !known_upstream(upstream)
            {
                errors.push(format!("{who} uses DNS server {upstream:?}, which does not exist"));
            }
            if let Some(limit) = &client.limit {
                check_limit(&mut errors, &who, limit);
            }
        }

        for (i, rule) in self.rules.iter().enumerate() {
            let who = match &rule.name {
                Some(name) => format!("rule {} ({name})", i + 1),
                None => format!("rule {}", i + 1),
            };
            for group in &rule.groups {
                if !group_ids.contains(group.as_str()) {
                    errors.push(format!("{who} applies to group {group:?}, which does not exist"));
                }
            }
            if let RuleAction::Route(egress) = &rule.action
                && let Some(why) = self.unusable_egress(egress)
            {
                errors.push(format!("{who} sends traffic through outbound {:?}, which {why}", egress.as_str()));
            }
            if rule.lists.len() > MAX_RULE_LISTS {
                errors.push(format!("{who} has {} online lists; at most {MAX_RULE_LISTS} are allowed", rule.lists.len()));
            }
            for link in &rule.lists {
                if !is_list_link(link) {
                    errors.push(format!("{who}: {link:?} is not a web link (http:// or https://)"));
                }
            }
        }

        if self.tls_inspection.terms_version == 0 {
            errors.push("HTTPS inspection: the terms version must be at least 1".into());
        }
        if self.portal.password.as_ref().is_some_and(|p| p.is_empty()) {
            errors.push("sign-in page: the password must not be empty (omit it to turn it off)".into());
        }
        if self.portal.session_hours == 0 {
            errors.push("sign-in page: sessions must last at least 1 hour".into());
        }

        if errors.is_empty() { Ok(()) } else { Err(ConfigError::Invalid(errors)) }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{EgressConfig, UdpPolicy};

    fn with_config_file(path: &str) -> Config {
        let mut config = Config::default();
        config.egresses.push(EgressConfig {
            id: "vpn".into(),
            name: None,
            kind: EgressKind::Xray { link: None, config_file: Some(PathBuf::from(path)) },
            udp: UdpPolicy::Native,
            enabled: true,
        });
        config
    }

    fn errors(config: &Config) -> Vec<String> {
        match config.validate() {
            Ok(()) => Vec::new(),
            Err(ConfigError::Invalid(errors)) => errors,
            Err(other) => panic!("unexpected {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn xray_config_files_must_be_on_a_local_drive() {
        assert!(errors(&with_config_file(r"C:\VPN\outbound.json")).is_empty());
        assert!(errors(&with_config_file(r"D:/vpn/outbound.json")).is_empty());
        for path in [
            r"\\server\share\outbound.json",
            r"//server/share/outbound.json",
            r"\\?\C:\VPN\outbound.json",
            r"\\?\UNC\server\share\outbound.json",
            r"\\.\pipe\outbound",
        ] {
            let errors = errors(&with_config_file(path));
            assert_eq!(
                errors,
                ["outbound \"vpn\": the Xray config file must be on this computer's own drive, not a network folder"],
                "{path}"
            );
        }
        // Not a full path at all: the older message, not both.
        assert_eq!(errors(&with_config_file(r"C:outbound.json")), ["outbound \"vpn\": the config file must be a full path"]);
    }

    #[cfg(unix)]
    #[test]
    fn xray_config_files_need_a_full_path() {
        assert!(errors(&with_config_file("/etc/captun/outbound.json")).is_empty());
        assert_eq!(errors(&with_config_file("outbound.json")), ["outbound \"vpn\": the config file must be a full path"]);
    }
}
