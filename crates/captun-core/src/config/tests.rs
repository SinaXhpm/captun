use super::*;
use crate::UdpPolicy;

const EXAMPLE: &str = include_str!("../../../../config/captun.example.toml");

fn invalid(config: &Config) -> Vec<String> {
    match config.validate() {
        Err(ConfigError::Invalid(errors)) => errors,
        other => panic!("expected validation errors, got {other:?}"),
    }
}

#[test]
fn default_is_valid_and_round_trips() {
    let config = Config::default();
    config.validate().unwrap();
    let text = config.to_toml().unwrap();
    assert_eq!(Config::from_toml(&text).unwrap(), config);
}

#[test]
fn empty_file_means_defaults() {
    assert_eq!(Config::from_toml("").unwrap(), Config::default());
}

#[test]
fn example_parses_and_round_trips() {
    let config = Config::from_toml(EXAMPLE).unwrap();
    assert_eq!(config.egresses.len(), 7);
    assert!(matches!(config.egress(&"https-proxy".into()).unwrap().kind, EgressKind::Http { tls: true, .. }));
    assert_eq!(config.egress(&"corp-http".into()).unwrap().udp, UdpPolicy::Via("socks".into()));
    assert_eq!(config.rules[1].action, RuleAction::Route("ethernet".into()));
    assert_eq!(config.rules[2].ports.len(), 2);
    assert!(config.rules[0].schedule.is_some());

    let text = config.to_toml().unwrap();
    assert_eq!(Config::from_toml(&text).unwrap(), config);
}

#[test]
fn unknown_keys_are_rejected() {
    assert!(Config::from_toml("[hotspot]\nssid = \"x\"\npasword = \"typo\"\n").is_err());
}

#[test]
fn access_network_subnet_math() {
    let a = AccessNetworkConfig::default();
    assert_eq!(a.netmask(), "255.255.255.0".parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(a.network(), "10.73.0.0".parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(a.broadcast(), "10.73.0.255".parse::<std::net::Ipv4Addr>().unwrap());
}

#[test]
fn access_network_enabled_with_interface_is_valid() {
    let mut c = Config::default();
    c.access_network.enabled = true;
    c.access_network.interface = Some("Ethernet".into());
    c.validate().unwrap();
}

#[test]
fn access_network_rejects_bad_settings() {
    // Gateway is the network address, not a host.
    let mut c = Config::default();
    c.access_network.gateway = "10.73.0.0".parse().unwrap();
    assert!(invalid(&c).iter().any(|e| e.contains("gateway must be a host")));

    // Gateway falls inside the DHCP range.
    let mut c = Config::default();
    c.access_network.gateway = "10.73.0.50".parse().unwrap();
    assert!(invalid(&c).iter().any(|e| e.contains("must not fall inside the DHCP range")));

    // DHCP start after end.
    let mut c = Config::default();
    c.access_network.dhcp_start = "10.73.0.200".parse().unwrap();
    c.access_network.dhcp_end = "10.73.0.20".parse().unwrap();
    assert!(invalid(&c).iter().any(|e| e.contains("must not come after")));

    // Enabled without an interface.
    let mut c = Config::default();
    c.access_network.enabled = true;
    assert!(invalid(&c).iter().any(|e| e.contains("choose a network adapter")));
}

#[test]
fn hotspot_device_limit_bounds() {
    let mut c = Config::default();
    c.hotspot.max_clients = Some(8);
    c.validate().unwrap();
    for bad in [0, MAX_CLIENT_LIMIT + 1] {
        c.hotspot.max_clients = Some(bad);
        assert!(invalid(&c).iter().any(|e| e.contains("device limit")), "{bad} should be rejected");
    }
}

#[test]
fn device_limit_and_autostart_do_not_change_the_access_point() {
    let a = HotspotConfig::default();
    let b = HotspotConfig { max_clients: Some(4), autostart: !a.autostart, ..a.clone() };
    assert!(a.same_access_point(&b));
    let c = HotspotConfig { ssid: "Other".into(), ..a.clone() };
    assert!(!a.same_access_point(&c));
}

#[test]
fn online_lists_must_be_web_links() {
    let mut c = Config::from_toml(
        r#"
        [[rule]]
        name = "Block ads"
        lists = ["https://cdn.example/ads.txt", "http://lists.example/ips.txt?v=2"]
        action = "reject"
    "#,
    )
    .unwrap();
    c.validate().unwrap();
    for bad in ["ftp://lists.example/a", "https://", "https://user@lists.example/a", "https://lists.example/a b", "lists.example/a"] {
        c.rules[0].lists = vec![bad.into()];
        assert!(invalid(&c).iter().any(|e| e.contains("is not a web link")), "{bad} should be rejected");
    }
    c.rules[0].lists = (0..33).map(|n| format!("https://lists.example/{n}")).collect();
    assert!(invalid(&c).iter().any(|e| e.contains("at most 32")));
}

#[test]
fn http_egress_needs_udp_policy() {
    let mut config = Config::default();
    config.egresses.push(EgressConfig {
        id: "proxy".into(),
        name: None,
        kind: EgressKind::Http {
            server: "127.0.0.1:3128".parse().unwrap(),
            username: None,
            password: None,
            tls: false,
            via: None,
        },
        udp: UdpPolicy::Native,
        enabled: true,
    });
    let errors = invalid(&config);
    assert!(errors[0].contains("cannot carry UDP"), "{errors:?}");

    config.egresses[1].udp = UdpPolicy::Via("direct".into());
    config.validate().unwrap();
}

#[test]
fn proxy_chain_cycle_is_reported() {
    let mut config = Config::default();
    for (id, via) in [("a", "b"), ("b", "a")] {
        config.egresses.push(EgressConfig {
            id: id.into(),
            name: None,
            kind: EgressKind::Socks5 {
                server: "127.0.0.1:1080".parse().unwrap(),
                username: None,
                password: None,
                via: Some(via.into()),
            },
            udp: UdpPolicy::Native,
            enabled: true,
        });
    }
    assert!(invalid(&config).iter().any(|e| e.contains("loops back")));
}

#[test]
fn turned_off_egresses_stay_listed_but_cannot_be_used() {
    let mut config = Config::default();
    config.egresses.push(EgressConfig {
        id: "ethernet".into(),
        name: Some("Ethernet".into()),
        kind: EgressKind::Direct { interface: Some("Ethernet".into()) },
        udp: UdpPolicy::Native,
        enabled: false,
    });
    config.validate().unwrap();
    assert!(toml::to_string(&config.egresses[1]).unwrap().contains("enabled = false"));
    let text = config.to_toml().unwrap();
    assert_eq!(Config::from_toml(&text).unwrap(), config);

    config.network.default_egress = "ethernet".into();
    config.client_mut("02:00:00:00:00:01".parse().unwrap()).egress = Some("ethernet".into());
    let errors = invalid(&config);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors.iter().all(|e| e.contains("is turned off")), "{errors:?}");

    config.egresses[1].enabled = true;
    config.validate().unwrap();
    let written = toml::to_string(&config.egresses[1]).unwrap();
    assert!(!written.contains("enabled"), "on is the default and is not written: {written}");
}

#[test]
fn dangling_references_are_all_reported() {
    let mut config = Config::default();
    config.network.default_egress = "nope".into();
    let profile = config.client_mut("02:00:00:00:00:01".parse().unwrap());
    profile.group = Some("missing".into());
    profile.dns_upstream = Some("missing".into());
    profile.limit = Some(RateLimit { down_kbps: Some(0), up_kbps: None });
    assert_eq!(invalid(&config).len(), 4);
}

#[test]
fn passphrase_rules() {
    assert!(validate_passphrase("short").is_err());
    assert!(validate_passphrase("long enough").is_ok());
    assert!(validate_passphrase("non-ascii-پسورد").is_err());
    assert!(validate_passphrase(&"a".repeat(64)).is_ok(), "64 hex digits is a raw PSK");
    assert!(validate_passphrase(&"g".repeat(64)).is_err());
    assert!(validate_ssid("").is_err());
    assert!(validate_ssid(&"x".repeat(33)).is_err());
}

#[test]
fn save_is_atomic_and_reloadable() {
    let dir = std::env::temp_dir().join(format!("captun-test-{}", std::process::id()));
    let path = dir.join("captun.toml");
    let config = Config::from_toml(EXAMPLE).unwrap();
    config.save(&path).unwrap();
    assert_eq!(Config::load_or_default(&path).unwrap(), config);
    assert!(!path.with_extension("toml.tmp").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn vpn_links_are_checked_when_saved() {
    let with_link = |link: &str| {
        let mut config = Config::default();
        config.egresses.push(EgressConfig {
            id: "vpn".into(),
            name: None,
            kind: EgressKind::Xray { link: Some(link.into()), config_file: None },
            udp: UdpPolicy::Native,
            enabled: true,
        });
        config
    };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    with_link(&format!("vless://{uuid}@vpn.example.com:443?security=tls&type=ws&path=%2Fws")).validate().unwrap();

    let errors = invalid(&with_link(&format!("vless://{uuid}@vpn.example.com:443?security=tls&allowInsecure=1")));
    assert!(errors[0].contains("certificate checks"), "{errors:?}");
    // With the certificate pinned, skipping the CA check is safe and allowed.
    with_link(&format!("vless://{uuid}@vpn.example.com:443?security=tls&allowInsecure=1&pcs=ab12")).validate().unwrap();

    let errors = invalid(&with_link("socks5://1.2.3.4:1080"));
    assert!(errors[0].contains("SOCKS5 or HTTP proxy"), "{errors:?}");
    let errors = invalid(&with_link("vless://nope"));
    assert!(errors[0].starts_with("outbound \"vpn\":"), "{errors:?}");
}
