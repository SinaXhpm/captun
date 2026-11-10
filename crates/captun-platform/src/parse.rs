//! Pure parsers and generators for the Linux backend's tool output and
//! NetworkManager keyfiles. Kept platform-independent so they are tested on
//! every build host.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{collections::BTreeMap, fmt::Write, net::IpAddr};

use captun_core::{MacAddr, ObservedClient, config::WifiBand};
use serde::Deserialize;

/// `iw dev <if> station dump`: the authoritative list of associated stations.
pub(crate) fn iw_stations(text: &str) -> Vec<MacAddr> {
    text.lines()
        .filter_map(|line| line.strip_prefix("Station "))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|mac| mac.parse().ok())
        .collect()
}

#[derive(Deserialize)]
struct NeighEntry {
    dst: IpAddr,
    lladdr: Option<String>,
    #[serde(default)]
    state: Vec<String>,
}

/// `ip -j neigh show dev <if>`: IP ↔ MAC pairs the kernel currently believes in.
pub(crate) fn ip_neigh(json: &str) -> Vec<(IpAddr, MacAddr)> {
    let entries: Vec<NeighEntry> = serde_json::from_str(json).unwrap_or_default();
    entries
        .into_iter()
        .filter(|e| !e.state.iter().any(|s| s == "FAILED" || s == "INCOMPLETE"))
        .filter_map(|e| Some((e.dst, e.lladdr?.parse().ok()?)))
        .collect()
}

/// dnsmasq lease file: `<expiry> <mac> <ip> <hostname|*> <client-id|*>`.
pub(crate) fn dnsmasq_leases(text: &str) -> Vec<(MacAddr, IpAddr, Option<String>)> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let _expiry = f.next()?;
            let mac = f.next()?.parse().ok()?;
            let ip = f.next()?.parse().ok()?;
            let host = f.next().filter(|h| *h != "*").map(str::to_owned);
            Some((mac, ip, host))
        })
        .collect()
}

/// macOS bootpd lease file (`/var/db/dhcpd_leases`), written by Internet
/// Sharing: one `{ key=value … }` block per lease. Hardware addresses carry
/// a type prefix (`1,`) and drop leading zeros (`1,a:b:c:d:e:f`).
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn bootpd_leases(text: &str) -> Vec<(MacAddr, IpAddr, Option<String>)> {
    let mut leases = Vec::new();
    let (mut name, mut ip, mut mac) = (None, None, None);
    for line in text.lines().map(str::trim) {
        match line {
            "{" => (name, ip, mac) = (None, None, None),
            "}" => {
                if let (Some(m), Some(i)) = (mac.take(), ip.take()) {
                    leases.push((m, i, name.take()));
                }
            }
            _ => match line.split_once('=') {
                Some(("name", v)) => name = Some(v.to_owned()).filter(|v| !v.is_empty()),
                Some(("ip_address", v)) => ip = v.parse().ok(),
                Some(("hw_address", v)) => mac = bootpd_mac(v),
                _ => {}
            },
        }
    }
    leases
}

fn bootpd_mac(value: &str) -> Option<MacAddr> {
    let hex = value.split_once(',').map_or(value, |(_, mac)| mac);
    let parts: Vec<u8> = hex.split(':').map(|p| u8::from_str_radix(p, 16)).collect::<Result<_, _>>().ok()?;
    Some(MacAddr(parts.try_into().ok()?))
}

/// Joins the three sources. With a station list, presence comes from it alone
/// (neighbour entries linger for minutes after a station leaves); without one
/// (no `iw`), any live neighbour entry counts as present.
pub(crate) fn merge(
    stations: Option<Vec<MacAddr>>,
    neigh: &[(IpAddr, MacAddr)],
    leases: &[(MacAddr, IpAddr, Option<String>)],
) -> Vec<ObservedClient> {
    let present: Vec<MacAddr> = match stations {
        Some(list) => list,
        None => neigh.iter().map(|(_, mac)| *mac).collect(),
    };
    let mut out: BTreeMap<MacAddr, ObservedClient> = BTreeMap::new();
    for mac in present {
        out.entry(mac).or_insert_with(|| ObservedClient { mac, addrs: Vec::new(), hostname: None });
    }
    for (ip, mac) in neigh {
        if let Some(client) = out.get_mut(mac)
            && !client.addrs.contains(ip)
        {
            client.addrs.push(*ip);
        }
    }
    for (mac, ip, host) in leases {
        if let Some(client) = out.get_mut(mac) {
            if !client.addrs.contains(ip) {
                client.addrs.push(*ip);
            }
            if client.hostname.is_none() {
                client.hostname = host.clone();
            }
        }
    }
    out.into_values().collect()
}

/// Escapes a GLib key-file string value.
fn keyfile_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (i, c) in value.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' if i == 0 => out.push_str("\\s"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

pub(crate) struct KeyfileSpec<'a> {
    pub(crate) id: &'a str,
    pub(crate) uuid: &'a str,
    pub(crate) interface: Option<&'a str>,
    pub(crate) ssid: &'a str,
    pub(crate) passphrase: &'a str,
    pub(crate) band: WifiBand,
    pub(crate) isolate_clients: bool,
}

/// NetworkManager keyfile for a WPA2 access point in "shared" (NAT + DHCP)
/// mode. Writing the file (0600, root) keeps the passphrase off command lines,
/// where any local user could read it from /proc.
pub(crate) fn nm_keyfile(spec: &KeyfileSpec<'_>) -> String {
    let mut f = String::new();
    // The SSID is written as a byte list so any byte sequence survives.
    let ssid_bytes: String = spec.ssid.bytes().map(|b| format!("{b};")).collect();
    let _ = writeln!(f, "[connection]\nid={}\nuuid={}\ntype=wifi\nautoconnect=false", spec.id, spec.uuid);
    if let Some(iface) = spec.interface {
        let _ = writeln!(f, "interface-name={}", keyfile_escape(iface));
    }
    let _ = writeln!(f, "\n[wifi]\nmode=ap\nssid={ssid_bytes}");
    match spec.band {
        WifiBand::Ghz2_4 => f.push_str("band=bg\n"),
        WifiBand::Ghz5 => f.push_str("band=a\n"),
        // NetworkManager has no 6 GHz AP band selector; leave it to the driver.
        WifiBand::Auto | WifiBand::Ghz6 => {}
    }
    let _ = writeln!(f, "ap-isolation={}", if spec.isolate_clients { 1 } else { 0 });
    let _ = writeln!(
        f,
        "\n[wifi-security]\nkey-mgmt=wpa-psk\nproto=rsn\npairwise=ccmp\ngroup=ccmp\npsk={}",
        keyfile_escape(spec.passphrase)
    );
    f.push_str("\n[ipv4]\nmethod=shared\n\n[ipv6]\nmethod=ignore\n");
    f
}

/// Random RFC 4122 version-4 UUID.
pub(crate) fn uuid_v4() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// `nmcli -t -f A,B connection show id X` prints `A:value` lines, with `:`
/// inside values escaped as `\:`.
pub(crate) fn nmcli_fields(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.to_owned(), v.replace("\\:", ":")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootpd_leases_parse_and_pad_hardware_addresses() {
        let text = "{
	name=iPhone
	ip_address=192.168.2.2
	hw_address=1,a:b:c:1:2:3
	identifier=1,a:b:c:1:2:3
	lease=0x6543
}
{
	ip_address=192.168.2.3
	hw_address=1,de:ad:be:ef:0:1
}
{
	name=broken
}
";
        let leases = bootpd_leases(text);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].0, MacAddr([0x0a, 0x0b, 0x0c, 1, 2, 3]));
        assert_eq!(leases[0].1, "192.168.2.2".parse::<IpAddr>().unwrap());
        assert_eq!(leases[0].2.as_deref(), Some("iPhone"));
        assert_eq!(leases[1].2, None);
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_iw_station_dump() {
        let text = "Station 02:aa:bb:cc:dd:01 (on wlan0)\n\tinactive time:\t30 ms\nStation 02:aa:bb:cc:dd:02 (on wlan0)\n";
        assert_eq!(iw_stations(text), [mac("02:aa:bb:cc:dd:01"), mac("02:aa:bb:cc:dd:02")]);
    }

    #[test]
    fn parses_neigh_and_skips_failed() {
        let json = r#"[
            {"dst":"10.42.0.23","dev":"wlan0","lladdr":"02:aa:bb:cc:dd:01","state":["REACHABLE"]},
            {"dst":"10.42.0.24","dev":"wlan0","state":["FAILED"]},
            {"dst":"fe80::1","dev":"wlan0","lladdr":"02:aa:bb:cc:dd:01","state":["STALE"]}
        ]"#;
        let n = ip_neigh(json);
        assert_eq!(n.len(), 2);
        assert!(ip_neigh("not json").is_empty());
    }

    #[test]
    fn merge_prefers_station_list_for_presence() {
        let neigh = ip_neigh(r#"[{"dst":"10.42.0.23","lladdr":"02:aa:bb:cc:dd:01","state":["STALE"]},
                                 {"dst":"10.42.0.30","lladdr":"02:aa:bb:cc:dd:09","state":["STALE"]}]"#);
        let leases = dnsmasq_leases("1700000000 02:aa:bb:cc:dd:01 10.42.0.23 pixel-7 01:02\n1700000000 02:aa:bb:cc:dd:02 10.42.0.40 * *\n");
        let clients = merge(Some(vec![mac("02:aa:bb:cc:dd:01"), mac("02:aa:bb:cc:dd:02")]), &neigh, &leases);
        assert_eq!(clients.len(), 2, "the stale neighbour that left is not present");
        assert_eq!(clients[0].hostname.as_deref(), Some("pixel-7"));
        assert_eq!(clients[0].addrs, ["10.42.0.23".parse::<IpAddr>().unwrap()]);
        assert_eq!(clients[1].hostname, None);

        assert_eq!(merge(None, &neigh, &leases).len(), 2, "without iw, neighbours define presence");
    }

    #[test]
    fn keyfile_escapes_and_encodes() {
        let text = nm_keyfile(&KeyfileSpec {
            id: "captun-hotspot",
            uuid: "u",
            interface: Some("wlan0"),
            ssid: "My;Net",
            passphrase: " back\\slash",
            band: WifiBand::Ghz5,
            isolate_clients: true,
        });
        assert!(text.contains("ssid=77;121;59;78;101;116;\n"));
        assert!(text.contains("psk=\\sback\\\\slash\n"));
        assert!(text.contains("band=a\n") && text.contains("ap-isolation=1\n") && text.contains("method=shared"));
    }

    #[test]
    fn uuid_shape() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert_ne!(u, uuid_v4());
    }

    #[test]
    fn nmcli_terse_fields() {
        let f = nmcli_fields("GENERAL.STATE:activated\nGENERAL.DEVICES:wlan0\n802-11-wireless.ssid:a\\:b\n");
        assert_eq!(f["GENERAL.STATE"], "activated");
        assert_eq!(f["802-11-wireless.ssid"], "a:b");
    }
}
