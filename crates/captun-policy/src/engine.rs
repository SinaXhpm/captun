use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

use captun_core::{
    ClientState, Config, DomainSet, EgressId, MacAddr,
    config::{ClockTime, PortRange, Protocol, RateLimit, RuleAction, Schedule, Weekday},
};

use crate::{hits::HitCounters, lists::RuleList, ranges::RangeSet};

/// Downloaded lists by link, as rules name them in `lists`.
pub type Lists = HashMap<String, Arc<RuleList>>;

/// Local wall-clock time, supplied by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalTime {
    pub weekday: Weekday,
    pub time: ClockTime,
}

/// Everything known about a new flow when it is classified.
#[derive(Clone, Copy, Debug)]
pub struct FlowContext<'a> {
    /// The station the flow comes from. `None` stands for any device, as the
    /// rules tester asks: one with no settings of its own that no rule names.
    pub client: Option<MacAddr>,
    pub protocol: Protocol,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: u16,
    /// Destination name learned from DNS, SNI or the `Host` header.
    pub domain: Option<&'a str>,
    pub now: LocalTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Drop silently.
    Deny,
    /// Refuse actively (TCP RST / ICMP unreachable).
    Reject,
}

/// Whether a station may use the network at all, before any rule runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    /// Waiting for approval: only the hub itself (DNS, portal) is reachable.
    Quarantined,
    /// The hotspot is at its device limit: held until a slot frees up.
    OverLimit,
    /// The device used up its data allowance, which then cuts it off: no
    /// internet until the allowance starts over.
    OverQuota,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    pub egress: EgressId,
    /// Index into `config.rules` of the rule that decided, for logs and the UI.
    pub rule: Option<usize>,
}

/// What a device's lookup of a name should do, from the rules a name alone
/// decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// A rule blocks or refuses the name: the lookup is answered as blocked.
    Block { rule: usize },
    /// Resolve the name through this egress, so it is looked up the way its
    /// traffic will go (and, behind a filter, not answered with a fake).
    Through { egress: EgressId, rule: Option<usize> },
}

/// Where a rule's traffic goes: names, address ranges and online lists, any
/// of which may match.
#[derive(Debug, Default)]
struct Destination {
    names: Option<DomainSet>,
    ranges: Option<RangeSet>,
    /// The rule's lists that have been downloaded; one not downloaded yet
    /// adds nothing (and a rule with nothing else then matches nothing).
    lists: Vec<Arc<RuleList>>,
}

impl Destination {
    fn matches(&self, ip: Option<IpAddr>, name: Option<&str>) -> bool {
        name.is_some_and(|name| self.matches_name(name))
            || ip.is_some_and(|ip| {
                self.ranges.as_ref().is_some_and(|r| r.contains(ip)) || self.lists.iter().any(|l| l.contains(ip))
            })
    }

    fn matches_name(&self, name: &str) -> bool {
        self.names.as_ref().is_some_and(|n| n.matches(name)) || self.lists.iter().any(|l| l.matches_name(name))
    }

    fn has_names(&self) -> bool {
        self.names.is_some() || self.lists.iter().any(|l| l.has_names())
    }
}

#[derive(Debug)]
struct CompiledRule {
    index: usize,
    clients: Vec<MacAddr>,
    groups: Vec<String>,
    /// Set whenever the rule says where traffic goes, even through lists not
    /// downloaded yet: such a rule must match nothing, not everything.
    destination: Option<Destination>,
    ports: Vec<PortRange>,
    protocol: Option<Protocol>,
    schedule: Option<Schedule>,
    action: RuleAction,
}

impl CompiledRule {
    /// The cheap conditions are checked first.
    fn matches(&self, ctx: &FlowContext<'_>, group: Option<&str>) -> bool {
        if self.protocol.is_some_and(|p| p != ctx.protocol) {
            return false;
        }
        if !self.ports.is_empty() && !self.ports.iter().any(|range| range.contains(ctx.dst_port)) {
            return false;
        }
        if !self.applies(ctx.client.as_ref(), group, ctx.now) {
            return false;
        }
        self.destination.as_ref().is_none_or(|d| d.matches(ctx.dst_ip, ctx.domain))
    }

    /// Who and when. `clients` and `groups` together form one "who"
    /// condition: a station listed directly or one in a listed group. Any
    /// device (`None`) is neither.
    fn applies(&self, client: Option<&MacAddr>, group: Option<&str>, now: LocalTime) -> bool {
        if !self.clients.is_empty() || !self.groups.is_empty() {
            let listed = client.is_some_and(|c| self.clients.contains(c));
            let in_group = group.is_some_and(|g| self.groups.iter().any(|x| x == g));
            if !listed && !in_group {
                return false;
            }
        }
        self.schedule.as_ref().is_none_or(|s| s.contains(now.weekday, now.time))
    }
}

/// Per-station settings with group and global fallbacks already applied.
#[derive(Debug)]
struct Resolved {
    state: ClientState,
    group: Option<String>,
    egress: EgressId,
    dns_upstream: String,
    limit: Option<RateLimit>,
    inspect_tls: bool,
}

#[derive(Debug)]
pub struct PolicyEngine {
    rules: Vec<CompiledRule>,
    clients: HashMap<MacAddr, Resolved>,
    default_egress: EgressId,
    default_dns: String,
    quarantine: bool,
    /// Stations held back by the hotspot's device limit (runtime state, not config).
    over_limit: HashSet<MacAddr>,
    /// Stations that used up their data allowance (runtime state too), with
    /// the speed they are slowed to; none means cut off.
    over_quota: HashMap<MacAddr, Option<u64>>,
    /// How often each rule decided, one counter per entry of `config.rules`.
    hits: Arc<HitCounters>,
}

impl PolicyEngine {
    /// Compiles a validated config, with no downloaded lists.
    pub fn new(config: &Config) -> Self {
        Self::build(config, &Lists::new())
    }

    /// Compiles a validated config. References are trusted to resolve; an
    /// unknown group simply contributes no fallbacks, a list not in `lists`
    /// adds nothing to its rule.
    pub fn build(config: &Config, lists: &Lists) -> Self {
        let tls = &config.tls_inspection;
        let clients = config
            .clients
            .iter()
            .map(|profile| {
                let group = profile.group.as_deref().and_then(|id| config.group(id));
                let consented = profile.tls_consent.is_some_and(|c| c.terms_version == tls.terms_version);
                let resolved = Resolved {
                    state: profile.state,
                    group: profile.group.clone(),
                    egress: profile
                        .egress
                        .clone()
                        .or_else(|| group.and_then(|g| g.egress.clone()))
                        .unwrap_or_else(|| config.network.default_egress.clone()),
                    dns_upstream: profile
                        .dns_upstream
                        .clone()
                        .or_else(|| group.and_then(|g| g.dns_upstream.clone()))
                        .unwrap_or_else(|| config.dns.default_upstream.clone()),
                    limit: profile.limit.or_else(|| group.and_then(|g| g.limit)),
                    // All three gates: the global switch, the admin's per-station
                    // toggle, and the station user's consent to the current terms.
                    inspect_tls: tls.enabled && profile.inspect_tls && consented,
                };
                (profile.mac, resolved)
            })
            .collect();

        let rules = config
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.enabled)
            .map(|(index, rule)| CompiledRule {
                index,
                clients: rule.clients.clone(),
                groups: rule.groups.clone(),
                destination: (!rule.domains.is_empty() || !rule.cidrs.is_empty() || !rule.lists.is_empty()).then(|| Destination {
                    names: (!rule.domains.is_empty()).then(|| rule.domains.iter().cloned().collect()),
                    ranges: (!rule.cidrs.is_empty()).then(|| RangeSet::new(&rule.cidrs)),
                    lists: rule.lists.iter().filter_map(|link| lists.get(link).cloned()).collect(),
                }),
                ports: rule.ports.clone(),
                protocol: rule.protocol,
                schedule: rule.schedule.clone(),
                action: rule.action.clone(),
            })
            .collect();

        Self {
            rules,
            clients,
            default_egress: config.network.default_egress.clone(),
            default_dns: config.dns.default_upstream.clone(),
            quarantine: config.network.quarantine_new_clients,
            over_limit: HashSet::new(),
            over_quota: HashMap::new(),
            hits: Arc::new(HitCounters::new(config.rules.len())),
        }
    }

    /// Marks the stations the device limit currently holds back.
    pub fn with_over_limit(mut self, over_limit: HashSet<MacAddr>) -> Self {
        self.over_limit = over_limit;
        self
    }

    /// Marks the stations that used up their data allowance, each with the
    /// speed (kbit/s) it is slowed to, or none to cut it off.
    pub fn with_over_quota(mut self, over_quota: HashMap<MacAddr, Option<u64>>) -> Self {
        self.over_quota = over_quota;
        self
    }

    /// Goes on counting on `hits`, those of the engine this one replaces.
    /// Only right while the rules are the same (the caller knows), since an
    /// index then still means the same rule; counters for another number of
    /// rules are never taken.
    pub fn with_hits(mut self, hits: Arc<HitCounters>) -> Self {
        if hits.len() == self.hits.len() {
            self.hits = hits;
        }
        self
    }

    /// How often each rule decided: the caller counts real traffic on them.
    pub fn hits(&self) -> &Arc<HitCounters> {
        &self.hits
    }

    pub fn admission(&self, client: &MacAddr) -> Admission {
        match self.clients.get(client).map_or(ClientState::Pending, |c| c.state) {
            ClientState::Blocked => Admission::Blocked,
            _ if self.over_limit.contains(client) => Admission::OverLimit,
            _ if self.over_quota.get(client).is_some_and(Option::is_none) => Admission::OverQuota,
            ClientState::Approved => Admission::Allowed,
            ClientState::Pending if self.quarantine => Admission::Quarantined,
            ClientState::Pending => Admission::Allowed,
        }
    }

    pub fn egress_for(&self, client: &MacAddr) -> &EgressId {
        self.own_egress(Some(client))
    }

    /// A station's own egress; the default one for any device.
    fn own_egress(&self, client: Option<&MacAddr>) -> &EgressId {
        client.and_then(|c| self.clients.get(c)).map_or(&self.default_egress, |c| &c.egress)
    }

    pub fn dns_upstream_for(&self, client: &MacAddr) -> &str {
        self.clients.get(client).map_or(&self.default_dns, |c| &c.dns_upstream)
    }

    /// A station's speed limit: its own (or its group's), and the slower
    /// speed it is held to once its data allowance is used up.
    pub fn rate_limit_for(&self, client: &MacAddr) -> Option<RateLimit> {
        let own = self.clients.get(client).and_then(|c| c.limit);
        match self.over_quota.get(client).copied().flatten() {
            None => own,
            Some(slow) => {
                let own = own.unwrap_or_default();
                let tighter = |limit: Option<u64>| Some(limit.map_or(slow, |l| l.min(slow)));
                Some(RateLimit { down_kbps: tighter(own.down_kbps), up_kbps: tighter(own.up_kbps) })
            }
        }
    }

    pub fn inspects_tls(&self, client: &MacAddr) -> bool {
        self.clients.get(client).is_some_and(|c| c.inspect_tls)
    }

    pub fn group_of(&self, client: &MacAddr) -> Option<&str> {
        self.clients.get(client).and_then(|c| c.group.as_deref())
    }

    /// True when some enabled rule matches on names, so the data plane must
    /// learn the destination domain (DNS mapping / SNI) before deciding.
    pub fn needs_domain(&self) -> bool {
        self.rules.iter().any(|r| r.destination.as_ref().is_some_and(Destination::has_names))
    }

    /// Rules applied to a lookup of `name` by a station already admitted:
    /// those a name decides on its own, top to bottom. Rules about ports or a
    /// protocol wait for the connection, and so do rules with only address
    /// ranges (the address is what the lookup is for). A blocked name is not
    /// resolved at all, which also stops what no connection sniffing sees
    /// (QUIC, other apps' own protocols); a name sent another way is looked up
    /// that way too. `None` asks for any device: the default egress, and only
    /// the rules for every device.
    pub fn decide_lookup(&self, client: Option<&MacAddr>, name: &str, now: LocalTime) -> Lookup {
        let own_egress = self.own_egress(client);
        let group = client.and_then(|c| self.group_of(c));
        for rule in &self.rules {
            if rule.protocol.is_some() || !rule.ports.is_empty() || !rule.applies(client, group, now) {
                continue;
            }
            if rule.destination.as_ref().is_some_and(|d| !d.matches_name(name)) {
                continue;
            }
            let rule_index = Some(rule.index);
            return match &rule.action {
                RuleAction::Deny | RuleAction::Reject => Lookup::Block { rule: rule.index },
                RuleAction::Allow => Lookup::Through { egress: own_egress.clone(), rule: rule_index },
                RuleAction::Route(egress) => Lookup::Through { egress: egress.clone(), rule: rule_index },
            };
        }
        Lookup::Through { egress: own_egress.clone(), rule: None }
    }

    /// Admission first, then the rules (`decide_rules`). A flow from no known
    /// station is held back too.
    pub fn decide(&self, ctx: &FlowContext<'_>) -> Decision {
        if ctx.client.is_none_or(|client| self.admission(&client) != Admission::Allowed) {
            return Decision { verdict: Verdict::Deny, egress: self.own_egress(ctx.client.as_ref()).clone(), rule: None };
        }
        self.decide_rules(ctx)
    }

    /// What the rules alone say, whatever the station's admission: rules top
    /// to bottom (first match wins), then the station's own egress. With no
    /// station (`None`), for any device: the default egress, and only the
    /// rules for every device.
    pub fn decide_rules(&self, ctx: &FlowContext<'_>) -> Decision {
        let client = ctx.client.as_ref();
        let own_egress = self.own_egress(client);
        let group = client.and_then(|c| self.group_of(c));
        for rule in &self.rules {
            if rule.matches(ctx, group) {
                let (verdict, egress) = match &rule.action {
                    RuleAction::Allow => (Verdict::Allow, own_egress),
                    RuleAction::Deny => (Verdict::Deny, own_egress),
                    RuleAction::Reject => (Verdict::Reject, own_egress),
                    RuleAction::Route(egress) => (Verdict::Allow, egress),
                };
                return Decision { verdict, egress: egress.clone(), rule: Some(rule.index) };
            }
        }
        Decision { verdict: Verdict::Allow, egress: own_egress.clone(), rule: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
        [network]
        quarantine_new_clients = true
        default_egress = "direct"

        [tls_inspection]
        enabled = true
        terms_version = 2

        [[egress]]
        id = "direct"
        type = "direct"

        [[egress]]
        id = "socks"
        type = "socks5"
        server = "127.0.0.1:1080"

        [[egress]]
        id = "eth"
        type = "direct"
        interface = "Ethernet"

        [[dns.upstream]]
        id = "cloudflare"
        protocol = "udp"
        address = "1.1.1.1"

        [[dns.upstream]]
        id = "kids-dns"
        protocol = "udp"
        address = "1.1.1.3"

        [[group]]
        id = "kids"
        egress = "socks"
        dns_upstream = "kids-dns"
        limit = { down_kbps = 2000 }

        [[client]]
        mac = "02:00:00:00:00:01"
        state = "approved"
        group = "kids"
        inspect_tls = true
        tls_consent = { accepted_at_ms = 1, terms_version = 1 }

        [[client]]
        mac = "02:00:00:00:00:02"
        state = "approved"
        egress = "eth"
        inspect_tls = true
        tls_consent = { accepted_at_ms = 1, terms_version = 2 }

        [[client]]
        mac = "02:00:00:00:00:03"
        state = "blocked"

        [[rule]]
        groups = ["kids"]
        domains = ["games.example"]
        schedule = { start = "21:00", end = "07:00" }
        action = "deny"

        [[rule]]
        enabled = false
        action = "deny"

        [[rule]]
        domains = ["video.example"]
        action = { route = "eth" }

        [[rule]]
        cidrs = ["10.0.0.0/8"]
        ports = ["135-139", 445]
        protocol = "tcp"
        action = "reject"
    "#;

    fn engine() -> PolicyEngine {
        PolicyEngine::new(&Config::from_toml(CONFIG).unwrap())
    }

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, n])
    }

    fn at(hhmm: &str) -> LocalTime {
        LocalTime { weekday: Weekday::Wed, time: hhmm.parse().unwrap() }
    }

    fn flow<'a>(client: u8, domain: Option<&'a str>, port: u16, now: LocalTime) -> FlowContext<'a> {
        FlowContext { client: Some(mac(client)), protocol: Protocol::Tcp, dst_ip: None, dst_port: port, domain, now }
    }

    #[test]
    fn admission() {
        let e = engine();
        assert_eq!(e.admission(&mac(1)), Admission::Allowed);
        assert_eq!(e.admission(&mac(3)), Admission::Blocked);
        assert_eq!(e.admission(&mac(9)), Admission::Quarantined, "unknown stations wait for approval");
        assert_eq!(e.decide(&flow(9, None, 443, at("12:00"))).verdict, Verdict::Deny);
    }

    #[test]
    fn device_limit_holds_even_approved_stations_but_not_over_a_block() {
        let e = engine().with_over_limit([mac(1), mac(3)].into_iter().collect());
        assert_eq!(e.admission(&mac(1)), Admission::OverLimit, "approved, but no free slot");
        assert_eq!(e.admission(&mac(3)), Admission::Blocked, "a block outranks the limit");
        assert_eq!(e.admission(&mac(2)), Admission::Allowed);
        assert_eq!(e.decide(&flow(1, None, 443, at("12:00"))).verdict, Verdict::Deny);
    }

    #[test]
    fn a_used_up_allowance_cuts_off_or_slows_down_but_never_outranks_a_block() {
        let over = [(mac(1), Some(256)), (mac(2), None), (mac(3), None), (mac(9), Some(64))].into_iter().collect();
        let e = engine().with_over_quota(over);
        // Slowed: still allowed, at its own limit or the slow speed, whichever is tighter.
        assert_eq!(e.admission(&mac(1)), Admission::Allowed);
        assert_eq!(e.rate_limit_for(&mac(1)), Some(RateLimit { down_kbps: Some(256), up_kbps: Some(256) }));
        assert_eq!(e.decide(&flow(1, None, 443, at("12:00"))).verdict, Verdict::Allow);
        // Cut off: no internet, as with any other hold.
        assert_eq!(e.admission(&mac(2)), Admission::OverQuota);
        assert_eq!(e.decide(&flow(2, None, 443, at("12:00"))).verdict, Verdict::Deny);
        assert_eq!(e.admission(&mac(3)), Admission::Blocked, "a block outranks the allowance");
        // An unknown device still waits for approval first.
        assert_eq!(e.admission(&mac(9)), Admission::Quarantined);
        assert_eq!(e.rate_limit_for(&mac(9)), Some(RateLimit { down_kbps: Some(64), up_kbps: Some(64) }));
        // Nobody over: the limits as configured.
        assert_eq!(engine().rate_limit_for(&mac(1)).unwrap().down_kbps, Some(2000));
    }

    #[test]
    fn fallbacks_resolve_profile_then_group_then_global() {
        let e = engine();
        assert_eq!(e.egress_for(&mac(1)).as_str(), "socks");
        assert_eq!(e.egress_for(&mac(2)).as_str(), "eth");
        assert_eq!(e.egress_for(&mac(9)).as_str(), "direct");
        assert_eq!(e.dns_upstream_for(&mac(1)), "kids-dns");
        assert_eq!(e.dns_upstream_for(&mac(2)), "cloudflare");
        assert_eq!(e.rate_limit_for(&mac(1)).unwrap().down_kbps, Some(2000));
        assert!(e.rate_limit_for(&mac(2)).is_none());
    }

    #[test]
    fn tls_inspection_needs_current_consent() {
        let e = engine();
        assert!(!e.inspects_tls(&mac(1)), "consent was given to outdated terms");
        assert!(e.inspects_tls(&mac(2)));
        assert!(!e.inspects_tls(&mac(9)));
    }

    #[test]
    fn scheduled_group_rule() {
        let e = engine();
        let night = e.decide(&flow(1, Some("www.games.example"), 443, at("23:30")));
        assert_eq!((night.verdict, night.rule), (Verdict::Deny, Some(0)));

        let day = e.decide(&flow(1, Some("www.games.example"), 443, at("15:00")));
        assert_eq!((day.verdict, day.egress.as_str(), day.rule), (Verdict::Allow, "socks", None));

        let adult = e.decide(&flow(2, Some("games.example"), 443, at("23:30")));
        assert_eq!(adult.verdict, Verdict::Allow);
    }

    #[test]
    fn route_rule_overrides_station_egress() {
        let d = engine().decide(&flow(1, Some("cdn.video.example"), 443, at("12:00")));
        assert_eq!((d.verdict, d.egress.as_str(), d.rule), (Verdict::Allow, "eth", Some(2)));
    }

    #[test]
    fn the_rules_alone_answer_whatever_the_admission() {
        let e = engine().with_over_limit([mac(1)].into_iter().collect());
        let decided = |d: Decision| (d.verdict, d.egress.as_str().to_owned(), d.rule);
        // Blocked (3), held by the device limit (1) and waiting for approval
        // (9, unknown): let through by nothing, yet the rules still answer.
        let blocked = flow(3, Some("cdn.video.example"), 443, at("12:00"));
        assert_eq!(decided(e.decide(&blocked)), (Verdict::Deny, "direct".into(), None));
        assert_eq!(decided(e.decide_rules(&blocked)), (Verdict::Allow, "eth".into(), Some(2)));
        let held = flow(1, Some("games.example"), 443, at("23:30"));
        assert_eq!(e.decide(&held).rule, None);
        assert_eq!(decided(e.decide_rules(&held)), (Verdict::Deny, "socks".into(), Some(0)));
        let waiting = flow(9, None, 443, at("12:00"));
        assert_eq!(e.decide(&waiting).verdict, Verdict::Deny);
        assert_eq!(decided(e.decide_rules(&waiting)), (Verdict::Allow, "direct".into(), None));
        // A station let on the network gets just what the rules say.
        for ctx in [flow(2, Some("games.example"), 443, at("23:30")), flow(2, Some("video.example"), 443, at("12:00"))] {
            assert_eq!(e.decide(&ctx), e.decide_rules(&ctx));
        }
    }

    #[test]
    fn any_device_gets_the_default_egress_and_the_rules_for_everyone() {
        let e = engine();
        let any = |domain, now| FlowContext { client: None, ..flow(1, domain, 443, now) };
        // The kids' night rule names a group, so it is not for any device.
        let games = e.decide_rules(&any(Some("games.example"), at("23:30")));
        assert_eq!((games.verdict, games.egress.as_str(), games.rule), (Verdict::Allow, "direct", None));
        assert_eq!(e.decide_rules(&any(Some("video.example"), at("12:00"))).rule, Some(2));
        // Nothing is let through for no station at all.
        assert_eq!(e.decide(&any(Some("video.example"), at("12:00"))).verdict, Verdict::Deny);
        // Lookups alike.
        let direct = Lookup::Through { egress: EgressId::new("direct"), rule: None };
        assert_eq!(e.decide_lookup(None, "games.example", at("23:30")), direct);
        assert_eq!(e.decide_lookup(Some(&mac(1)), "games.example", at("23:30")), Lookup::Block { rule: 0 });
    }

    #[test]
    fn hit_counters_carry_over_only_to_as_many_rules() {
        let config = Config::from_toml(CONFIG).unwrap();
        let first = PolicyEngine::new(&config);
        first.hits().connection(2, 1_000);
        let next = PolicyEngine::new(&config).with_hits(first.hits().clone());
        assert_eq!(next.hits().snapshot()[2].connections, 1);

        let mut fewer = config.clone();
        fewer.rules.pop();
        let other = PolicyEngine::new(&fewer).with_hits(first.hits().clone());
        assert_eq!(other.hits().snapshot().len(), 3, "one counter per rule");
        assert!(other.hits().snapshot().iter().all(|h| *h == crate::Hits::default()));
    }

    #[test]
    fn network_rule_needs_ip_port_and_protocol() {
        let e = engine();
        let mut ctx = flow(2, None, 445, at("12:00"));
        ctx.dst_ip = Some("10.1.2.3".parse().unwrap());
        assert_eq!(e.decide(&ctx).verdict, Verdict::Reject);

        ctx.protocol = Protocol::Udp;
        assert_eq!(e.decide(&ctx).verdict, Verdict::Allow);

        ctx.protocol = Protocol::Tcp;
        ctx.dst_port = 443;
        assert_eq!(e.decide(&ctx).verdict, Verdict::Allow);

        ctx.dst_port = 137;
        ctx.dst_ip = None;
        assert_eq!(e.decide(&ctx).verdict, Verdict::Allow, "unknown destination IP never matches a CIDR rule");
    }

    const LISTS_CONFIG: &str = r#"
        [network]
        default_egress = "direct"

        [[egress]]
        id = "direct"
        type = "direct"

        [[egress]]
        id = "socks"
        type = "socks5"
        server = "127.0.0.1:1080"

        [[rule]]
        domains = ["ok.ads.example"]
        action = "allow"

        [[rule]]
        lists = ["https://lists.example/ads.txt"]
        action = "reject"

        [[rule]]
        domains = ["telegram.org"]
        cidrs = ["91.108.4.0/22"]
        action = { route = "socks" }

        [[rule]]
        cidrs = ["5.0.0.0/8"]
        action = "deny"

        [[rule]]
        domains = ["mail.example"]
        ports = [25]
        action = "reject"
    "#;

    const ADS: &str = "https://lists.example/ads.txt";

    fn with_lists(downloaded: bool) -> PolicyEngine {
        let mut lists = Lists::new();
        if downloaded {
            lists.insert(ADS.to_owned(), Arc::new(RuleList::parse("0.0.0.0 ads.example\n6.6.6.0/24")));
        }
        PolicyEngine::build(&Config::from_toml(LISTS_CONFIG).unwrap(), &lists)
    }

    fn to<'a>(domain: Option<&'a str>, ip: &str) -> FlowContext<'a> {
        FlowContext { client: Some(mac(1)), protocol: Protocol::Tcp, dst_ip: Some(ip.parse().unwrap()), dst_port: 443, domain, now: at("12:00") }
    }

    #[test]
    fn names_addresses_and_lists_are_one_condition() {
        let e = with_lists(true);
        let socks = |d: Decision| (d.verdict, d.egress.as_str().to_owned(), d.rule);
        // Either a listed name or a listed address is enough.
        assert_eq!(socks(e.decide(&to(None, "91.108.5.1"))), (Verdict::Allow, "socks".into(), Some(2)));
        assert_eq!(socks(e.decide(&to(Some("core.telegram.org"), "1.2.3.4"))), (Verdict::Allow, "socks".into(), Some(2)));
        assert_eq!(socks(e.decide(&to(Some("example.net"), "1.2.3.4"))), (Verdict::Allow, "direct".into(), None));
        // A list's names and addresses alike; a rule above it makes an exception.
        assert_eq!(e.decide(&to(Some("x.ads.example"), "1.2.3.4")).verdict, Verdict::Reject);
        assert_eq!(e.decide(&to(None, "6.6.6.6")).verdict, Verdict::Reject);
        assert_eq!(e.decide(&to(Some("ok.ads.example"), "1.2.3.4")).rule, Some(0));
        assert!(e.needs_domain());
    }

    #[test]
    fn a_rule_whose_lists_are_not_downloaded_matches_nothing() {
        let e = with_lists(false);
        let d = e.decide(&to(Some("x.ads.example"), "6.6.6.6"));
        assert_eq!((d.verdict, d.rule), (Verdict::Allow, None), "not everything");
    }

    #[test]
    fn lookups_follow_the_rules_a_name_decides() {
        let e = with_lists(true);
        let lookup = |name| e.decide_lookup(Some(&mac(1)), name, at("12:00"));
        let through = |egress: &str, rule| Lookup::Through { egress: EgressId::new(egress), rule };
        assert_eq!(lookup("x.ads.example"), Lookup::Block { rule: 1 });
        assert_eq!(lookup("ok.ads.example"), through("direct", Some(0)));
        assert_eq!(lookup("core.telegram.org"), through("socks", Some(2)));
        // Port rules wait for the connection; so do address-only rules.
        assert_eq!(lookup("mail.example"), through("direct", None));
        assert_eq!(lookup("example.net"), through("direct", None));
        assert_eq!(with_lists(false).decide_lookup(Some(&mac(1)), "x.ads.example", at("12:00")), through("direct", None));
    }

    #[test]
    fn disabled_rules_are_skipped_and_domains_flagged() {
        let e = engine();
        assert!(e.needs_domain());
        assert_eq!(e.decide(&flow(2, None, 80, at("12:00"))).verdict, Verdict::Allow);
    }
}
