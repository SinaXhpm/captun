//! Connects the routing engine to the hub: tells which device a flow comes
//! from and whose budget it draws on, turns a flow into a policy decision and
//! the matching egress, counts it against the rule that decided, and provides
//! the current local time for schedules. Also says which open flows a change
//! of settings ends and when a rule's time window has them checked again, and
//! answers the rules tester, which asks the same of a flow that is only
//! imagined.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, Mutex, Weak},
};

use chrono::{Datelike, Local, Timelike};
use captun_core::{
    ClientState, Config, EgressId, MacAddr, TargetAddr,
    config::{ClientProfile, ClockTime, Protocol, RateLimit, RuleConfig, Weekday},
    domain::{is_valid_hostname, normalize_domain},
    time::now_millis,
};
use captun_engine::{Dispatcher, FlowAction, FlowRequest, Forward, SourceKey};
use captun_ipc::{ConnectionOutcome, ErrorCode, IpcError, LookupOutcome, RuleTestResult, RuleVerdict};
use captun_platform::neighbors::Snapshot;
use captun_policy::{Admission, Decision, FlowContext, LocalTime, Lookup, PolicyEngine, Verdict};
use tracing::warn;

use crate::{
    hub::{Hub, lock},
    local_dns::LocalDns,
};

/// The port the rules tester assumes when none is given.
const HTTPS_PORT: u16 = 443;
/// The port of a pasted `http://` link.
const HTTP_PORT: u16 = 80;
/// Longer than anything worth testing, link and all.
const MAX_TEST_TARGET: usize = 2048;

/// Resolves the host's current local weekday and time-of-day for schedule
/// matching.
pub(crate) fn local_now() -> LocalTime {
    let now = Local::now();
    let weekday = Weekday::from_index(now.weekday().num_days_from_monday() as u8).unwrap_or(Weekday::Mon);
    let time = ClockTime::from_minutes((now.hour() * 60 + now.minute()) as u16).unwrap_or_default();
    LocalTime { weekday, time }
}

/// Holds the hub weakly so the engine never keeps it alive past shutdown.
pub(crate) struct PolicyDispatcher(Weak<Hub>);

impl PolicyDispatcher {
    pub(crate) fn new(hub: &Arc<Hub>) -> Self {
        Self(Arc::downgrade(hub))
    }
}

impl Dispatcher for PolicyDispatcher {
    fn needs_domain(&self) -> bool {
        self.0.upgrade().is_some_and(|hub| hub.policy().needs_domain())
    }

    fn dispatch(&self, request: &FlowRequest<'_>) -> FlowAction {
        self.dispatch_device(request).0
    }

    fn dispatch_device(&self, request: &FlowRequest<'_>) -> (FlowAction, Option<MacAddr>) {
        let Some(hub) = self.0.upgrade() else { return (FlowAction::Drop, None) };
        // The device behind the source address, from the device list or the
        // system's neighbor table. Named whatever the decision, so a reset of
        // that device also ends the refusals it is being given.
        let mac = hub.device_at(request.client_ip);
        // DNS the hub answers itself. Its DNS routing sends each query out the
        // device's own egress and applies the device's admission.
        if let Some(handler) = hub.local_dns_for(request.destination) {
            let outbound = Arc::new(LocalDns::new(handler, request.client_ip));
            return (FlowAction::Forward(Forward { client: mac, outbound, down_kbps: None, up_kbps: None }), mac);
        }
        if refused_locally(&hub, request) {
            return (FlowAction::Reject, mac);
        }
        match mac {
            Some(mac) => (forward_for(&hub, mac, request), Some(mac)),
            // A device neither list knows: refused, out loud, rather than sent
            // out the default way, which may not be the one chosen for it (and
            // a flow never changes its way later). It is known within moments,
            // and asks again.
            None => (FlowAction::Reject, None),
        }
    }

    fn still_allowed(&self, request: &FlowRequest<'_>, device: Option<MacAddr>, outbound: &EgressId) -> bool {
        // Gone with the hub: the engine is stopping anyway.
        let Some(hub) = self.0.upgrade() else { return true };
        // The hub's own DNS decides each query by itself.
        if hub.local_dns_for(request.destination).is_some() {
            return true;
        }
        if refused_locally(&hub, request) {
            return false;
        }
        match device {
            // Nothing says another device holds the address now, and still
            // let through the same way. Laxer than a new flow's check: a
            // neighbor entry missing for a moment (a phone asleep) leaves
            // the device's open connections alone.
            Some(mac) if hub.still_at(request.client_ip, mac) => still_forwarded(&hub, mac, request, outbound),
            _ => false,
        }
    }

    fn source_key(&self, ip: IpAddr) -> SourceKey {
        self.0.upgrade().and_then(|hub| admitted_device_at(&hub, ip)).map_or(SourceKey::Unlisted, SourceKey::Device)
    }
}

/// The device at `ip` when the device list has it online and lets it in: not
/// blocked, not waiting for approval, not held back by the device limit. Only
/// such a device gets a budget of its own in the engine; every other address
/// shares one small pool, so made-up addresses cannot take the listed
/// devices' room. Reads memory only: the engine asks on the task that reads
/// every device's packets, for every new connection.
fn admitted_device_at(hub: &Hub, ip: IpAddr) -> Option<MacAddr> {
    let mac = hub.device_at(ip)?;
    let online = lock(&hub.registry).get(&mac).is_some_and(|presence| presence.online);
    (online && hub.policy().admission(&mac) == Admission::Allowed).then_some(mac)
}

/// Device-list entries a warning was given about, at most: a device that
/// keeps changing its hardware address cannot grow the set without end.
const MAX_WARNED: usize = 1024;

/// The system's neighbor table, as the hub reads it to tell devices apart: at
/// most every half second, when a lookup or the monitor's tick asks, and never
/// on an async thread. Tests give entries of their own instead.
#[derive(Debug, Default)]
pub(crate) struct Neighbors {
    snapshot: Snapshot,
    /// The (address, hardware address) pairs already warned about.
    warned: Mutex<HashSet<(IpAddr, MacAddr)>>,
    /// Entries a test gives in place of the system's table.
    #[cfg(test)]
    given: Mutex<Option<HashMap<IpAddr, MacAddr>>>,
}

impl Neighbors {
    /// The device at `ip`, where the device list says `listed` holds it.
    ///
    /// The device list's word counts only when the neighbor table has the
    /// same hardware address there: Captun's own DHCP takes whatever hardware
    /// address a request claims, so a lease alone would let one device pass
    /// for another (a blocked one for an approved one, say). Another hardware
    /// address there, or none yet, is no device: its flow is refused out loud
    /// as an unknown device's is, the refusal makes the system look the device
    /// up, and its next try a moment later is let through. An address the
    /// device list does not have goes by the neighbor table alone: a new
    /// device is refused out loud until the table has it, moments later,
    /// then gets its own outbound and rules, and is never sent the default
    /// way. Never waits for the system.
    pub(crate) fn device(&self, ip: IpAddr, listed: Option<MacAddr>) -> Option<MacAddr> {
        let ip = ip.to_canonical();
        let Some(listed) = listed else { return self.mac_of(ip) };
        if !self.confirms(ip) {
            return Some(listed);
        }
        match self.mac_of(ip) {
            Some(seen) if seen == listed => Some(listed),
            Some(seen) => {
                self.warn_once(ip, listed, seen);
                None
            }
            None => None,
        }
    }

    /// Whether the table names another hardware address than `mac` at `ip`,
    /// where it can vouch for an address at all ([`Self::confirms`]). No
    /// entry says nothing either way: a device that stops answering for a
    /// while (a phone asleep) drops out of the table with nobody else there.
    pub(crate) fn contradicts(&self, ip: IpAddr, mac: MacAddr) -> bool {
        let ip = ip.to_canonical();
        self.confirms(ip) && self.mac_of(ip).is_some_and(|seen| seen != mac)
    }

    /// Starts a read of the table when the one in hand is older than half a
    /// second; never waits for it.
    pub(crate) fn refresh(&self) {
        #[cfg(test)]
        if lock(&self.given).is_some() {
            return;
        }
        drop(self.snapshot.table());
    }

    /// The hardware address the table in hand has at `ip`.
    fn mac_of(&self, ip: IpAddr) -> Option<MacAddr> {
        #[cfg(test)]
        if let Some(given) = &*lock(&self.given) {
            return given.get(&ip.to_canonical()).copied();
        }
        self.snapshot.mac_of(ip)
    }

    /// Whether the table can vouch for the device list at `ip`. The system's
    /// table is read for IPv4 only, and only Windows and Linux give one. The
    /// device list's IPv6 addresses come from the system, never from Captun's
    /// own DHCP, which hands out IPv4 only, so they stand on their own.
    fn confirms(&self, ip: IpAddr) -> bool {
        #[cfg(test)]
        if lock(&self.given).is_some() {
            return ip.is_ipv4();
        }
        cfg!(any(windows, target_os = "linux")) && ip.is_ipv4()
    }

    /// Says once per address and hardware address that a device answers at
    /// an address the device list gives another. Whether it said so now.
    fn warn_once(&self, ip: IpAddr, listed: MacAddr, seen: MacAddr) -> bool {
        let mut warned = lock(&self.warned);
        if warned.contains(&(ip, seen)) {
            return false;
        }
        // Full: start over rather than grow, so a device that keeps changing
        // its hardware address costs a warning now and then, never memory.
        if warned.len() >= MAX_WARNED {
            warned.clear();
        }
        warned.insert((ip, seen));
        drop(warned);
        warn!(
            %ip,
            %listed,
            %seen,
            "the device list gives this address to another device than the one using it; its connections are refused until the two agree"
        );
        true
    }

    /// Uses `entries` in place of the system's table.
    #[cfg(test)]
    pub(crate) fn give(&self, entries: impl IntoIterator<Item = (IpAddr, MacAddr)>) {
        *lock(&self.given) = Some(entries.into_iter().collect());
    }
}

/// Whether the "what devices can reach" settings refuse this flow: this
/// computer, another device or the home network, and never this computer's
/// loopback. The system's own rules drop these first where it has them; this
/// covers what reaches the engine anyway, such as a phone on USB asking its
/// proxy for them. Refused out loud, so apps give up at once.
pub(crate) fn refused_locally(hub: &Hub, request: &FlowRequest<'_>) -> bool {
    match request.destination {
        TargetAddr::Ip(destination) => hub.reach_view().refuses(request.client_ip, destination.ip()),
        // A name asked of a proxy. Some apps write an address as a name, and
        // "localhost" always means this computer's loopback.
        TargetAddr::Domain(name, _) => {
            let name = name.trim_end_matches('.').trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
            match name.parse::<IpAddr>() {
                Ok(ip) => hub.reach_view().refuses(request.client_ip, ip),
                Err(_) => name == "localhost" || name.ends_with(".localhost"),
            }
        }
    }
}

/// Resolves the egress carrying `egress` for `protocol`, honouring the egress's
/// UDP policy. A missing outbound fails closed.
fn outbound_for(hub: &Hub, egress: &captun_core::EgressId, protocol: Protocol) -> Option<Arc<dyn captun_outbound::Outbound>> {
    let outbounds = hub.outbounds();
    let selected = match protocol {
        Protocol::Udp => outbounds.for_udp(egress),
        Protocol::Tcp => outbounds.get(egress),
    };
    selected.cloned()
}

/// What a flow with no outbound to carry it gets. UDP is refused out loud, so
/// apps give up on it at once: blocked QUIC turns into HTTPS over TCP.
fn no_outbound(protocol: Protocol) -> FlowAction {
    match protocol {
        Protocol::Udp => FlowAction::Reject,
        Protocol::Tcp => FlowAction::Drop,
    }
}

/// What `policy` decides for a flow of `mac`, at this moment. Counts nothing:
/// a new connection counts its rule itself.
fn decide_flow(hub: &Hub, policy: &PolicyEngine, mac: MacAddr, request: &FlowRequest<'_>) -> Decision {
    // A connection that does not say its name (QUIC, an app's own protocol)
    // goes by the name this device last looked its address up by. Another
    // device's lookups never decide its way.
    let learned = match (request.domain, request.destination.ip()) {
        (None, Some(ip)) if policy.needs_domain() => hub.name_for(mac, ip),
        _ => None,
    };
    policy.decide(&FlowContext {
        client: Some(mac),
        protocol: request.protocol,
        dst_ip: request.destination.ip(),
        dst_port: request.destination.port(),
        domain: request.domain.or(learned.as_deref()),
        now: local_now(),
    })
}

/// Whether an open flow of `mac`, carried by `outbound`, would still be let
/// through the same outbound under the rules, admission and time in force
/// now. Not a new connection, so no rule hit is counted. Shared by the
/// hotspot dispatcher and reverse tethering.
pub(crate) fn still_forwarded(hub: &Hub, mac: MacAddr, request: &FlowRequest<'_>, outbound: &EgressId) -> bool {
    let decision = decide_flow(hub, &hub.policy(), mac, request);
    decision.verdict == Verdict::Allow
        && outbound_for(hub, &decision.egress, request.protocol).is_some_and(|carrier| carrier.id() == outbound)
}

/// Runs the policy for one known station and builds the forward action, applying
/// its rate limits. Shared by the hotspot dispatcher and reverse tethering.
pub(crate) fn forward_for(hub: &Arc<Hub>, mac: MacAddr, request: &FlowRequest<'_>) -> FlowAction {
    let policy = hub.policy();
    let decision = decide_flow(hub, &policy, mac, request);
    if let Some(rule) = decision.rule {
        policy.hits().connection(rule, now_millis());
    }
    match decision.verdict {
        Verdict::Deny => return FlowAction::Drop,
        Verdict::Reject => return FlowAction::Reject,
        Verdict::Allow => {}
    }
    let limit = policy.rate_limit_for(&mac).unwrap_or_default();
    match outbound_for(hub, &decision.egress, request.protocol) {
        Some(outbound) => {
            FlowAction::Forward(Forward { client: Some(mac), outbound, down_kbps: limit.down_kbps, up_kbps: limit.up_kbps })
        }
        None => no_outbound(request.protocol),
    }
}

/// Which open flows a change of settings ends, so they reconnect under the
/// new settings rather than carry on the old way.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FlowsEnded {
    /// Every flow: what changed can change any device's way.
    All,
    /// Only these devices' flows; none when the list is empty.
    Devices(Vec<MacAddr>),
}

/// What of a device's own settings decides its open flows: whether it is let
/// in, its group, its own outbound and its speed limit (a flow takes its
/// limit when it starts). Its name, its DNS server and HTTPS inspection do
/// not. No settings at all decide as the defaults do.
fn deciding(profile: Option<&ClientProfile>) -> (ClientState, Option<&str>, Option<&EgressId>, Option<RateLimit>) {
    profile.map_or((ClientState::default(), None, None, None), |p| (p.state, p.group.as_deref(), p.egress.as_ref(), p.limit))
}

/// The flows a change from `previous` to `current` ends. Outbounds, rules and
/// network settings can change any device's way, so they end every flow. A
/// device's own settings end only its flows, and only when they change what
/// decides them; a group's outbound or speed limit ends its members' flows.
pub(crate) fn flows_ended_by(previous: &Config, current: &Config) -> FlowsEnded {
    if previous.egresses != current.egresses || previous.rules != current.rules || previous.network != current.network {
        return FlowsEnded::All;
    }
    // A group that came or went changes its members' fallbacks too.
    let group_changed = |id: &str| match (previous.group(id), current.group(id)) {
        (Some(was), Some(is)) => was.egress != is.egress || was.limit != is.limit,
        (was, is) => was.is_some() != is.is_some(),
    };
    let before: HashMap<MacAddr, &ClientProfile> = previous.clients.iter().map(|p| (p.mac, p)).collect();
    let after: HashMap<MacAddr, &ClientProfile> = current.clients.iter().map(|p| (p.mac, p)).collect();
    let mut devices: Vec<MacAddr> = before
        .keys()
        .chain(after.keys().filter(|mac| !before.contains_key(mac)))
        .copied()
        .filter(|mac| {
            let (was, is) = (before.get(mac).copied(), after.get(mac).copied());
            deciding(was) != deciding(is)
                || [was, is].into_iter().flatten().any(|p| p.group.as_deref().is_some_and(group_changed))
        })
        .collect();
    devices.sort_unstable();
    FlowsEnded::Devices(devices)
}

/// When the rules' time windows were last looked at, so the open flows are
/// checked again only when one opens or closes, not at every look.
#[derive(Debug, Default)]
pub(crate) struct OpenWindows {
    last: Option<LocalTime>,
}

impl OpenWindows {
    /// Looks again at `now` under `rules`, the rules in force. True when one
    /// of their windows opened or closed since the last look: the open flows
    /// are to be checked again. Both looks are judged by the rules in force
    /// now, so rules saved just before an edge still have it seen: saving
    /// them ended every flow, but those opened after that and before the edge
    /// were decided on its other side. When the edge came before the save,
    /// the extra check finds nothing to end. A first look only takes note.
    pub(crate) fn look(&mut self, rules: &[RuleConfig], now: LocalTime) -> bool {
        let edge = self.last.is_some_and(|last| open_windows(rules, last) != open_windows(rules, now));
        self.last = Some(now);
        edge
    }
}

/// The enabled rules with a time window that `now` is inside.
fn open_windows(rules: &[RuleConfig], now: LocalTime) -> Vec<usize> {
    rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.enabled && rule.schedule.as_ref().is_some_and(|s| s.contains(now.weekday, now.time)))
        .map(|(index, _)| index)
        .collect()
}

/// What the rules tester was asked about.
enum Probe {
    Name(String),
    Address(IpAddr),
}

/// What was typed into the tester, read.
struct Typed {
    probe: Probe,
    /// The port written after the website or address (`example.com:8080`).
    port: Option<u16>,
    /// The usual port of a pasted link's kind: 80 for `http://`, 443 for
    /// `https://`.
    link_port: Option<u16>,
}

/// The website or address in what was typed, and the port it names. A
/// pasted link is cut down to its host.
fn read_typed(typed: &str) -> Option<Typed> {
    if typed.len() > MAX_TEST_TARGET {
        return None;
    }
    let text = typed.trim();
    let (scheme, text) = match text.split_once("://") {
        // Letters, digits, `+`, `-` and `.`: otherwise the `://` is further
        // along, in a path or query.
        Some((scheme, rest)) if !scheme.is_empty() && scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) => {
            (Some(scheme), rest)
        }
        _ => (None, text),
    };
    let link_port = match scheme {
        Some(s) if s.eq_ignore_ascii_case("http") => Some(HTTP_PORT),
        Some(s) if s.eq_ignore_ascii_case("https") => Some(HTTPS_PORT),
        _ => None,
    };
    let text = text.split(['/', '?', '#']).next().unwrap_or_default();
    let host = text.rsplit_once('@').map_or(text, |(_, host)| host);
    let (host, port) = match host.strip_prefix('[') {
        // `[2001:db8::1]:8080`: nothing but a port may follow the bracket.
        Some(bracketed) => {
            let (host, rest) = bracketed.split_once(']')?;
            match rest {
                "" => (host, None),
                _ => (host, Some(rest.strip_prefix(':')?.parse::<u16>().ok()?)),
            }
        }
        // A bare IPv6 address has colons of its own.
        None if host.parse::<IpAddr>().is_ok() => (host, None),
        None => match host.rsplit_once(':') {
            Some((name, port)) => match port.parse::<u16>() {
                Ok(port) => (name, Some(port)),
                Err(_) => (host, None),
            },
            None => (host, None),
        },
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    let probe = match host.parse::<IpAddr>() {
        Ok(ip) => Probe::Address(ip.to_canonical()),
        Err(_) if is_valid_hostname(host) => Probe::Name(normalize_domain(host).into_owned()),
        Err(_) => return None,
    };
    Some(Typed { probe, port, link_port })
}

/// The port to test: the one asked for, else the one written after the
/// website or address, else the usual one of a pasted link, else 443. Asked
/// for and written differently, it is unclear which was meant.
fn test_port(asked: Option<u16>, typed: &Typed) -> Result<u16, IpcError> {
    let what = match typed.probe {
        Probe::Name(_) => "website",
        Probe::Address(_) => "address",
    };
    let port = match (asked, typed.port) {
        (Some(asked), Some(written)) if asked != written => {
            return Err(IpcError::new(
                ErrorCode::BadRequest,
                format!("Two different ports: {written} after the {what} and {asked} in the port field. Clear one of them."),
            ));
        }
        (asked, written) => asked.or(written).or(typed.link_port).unwrap_or(HTTPS_PORT),
    };
    if port == 0 {
        return Err(IpcError::new(ErrorCode::BadRequest, "A port is a number from 1 to 65535."));
    }
    Ok(port)
}

/// A decision as the tester reports it, carried as a real flow would be
/// (`forward_for`): through the outbound that takes `protocol` for the
/// egress the rules chose, and stopped like one when none does.
fn outcome(hub: &Hub, decision: Decision, protocol: Protocol) -> ConnectionOutcome {
    let rule = decision.rule;
    let stopped = |verdict| ConnectionOutcome { verdict, egress: None, carried_by: None, rule };
    match decision.verdict {
        Verdict::Deny => stopped(RuleVerdict::Deny),
        Verdict::Reject => stopped(RuleVerdict::Reject),
        Verdict::Allow => match outbound_for(hub, &decision.egress, protocol) {
            Some(outbound) => ConnectionOutcome {
                verdict: RuleVerdict::Allow,
                carried_by: Some(outbound.id().clone()),
                egress: Some(decision.egress),
                rule,
            },
            None => ConnectionOutcome {
                verdict: match no_outbound(protocol) {
                    FlowAction::Reject => RuleVerdict::Reject,
                    _ => RuleVerdict::Deny,
                },
                egress: Some(decision.egress),
                carried_by: None,
                rule,
            },
        },
    }
}

/// The rules tester: what the rules do with `target`, a website or an
/// address, for `device` or any device, at this moment. Only the rules
/// answer, so a device that is blocked or waiting still gets their answer;
/// the outbound they choose has its say on UDP, as for real traffic. An
/// address is also tried by the name `device` (or, for any device, a device)
/// last looked it up by. Nothing is counted, looked up or sent.
pub(crate) fn test_rules(
    hub: &Hub,
    target: &str,
    device: Option<MacAddr>,
    port: Option<u16>,
    protocol: Option<Protocol>,
) -> Result<RuleTestResult, IpcError> {
    let typed = read_typed(target).ok_or_else(|| {
        IpcError::new(ErrorCode::BadRequest, "Type a website such as example.com, or an address such as 1.2.3.4.")
    })?;
    let port = test_port(port, &typed)?;
    let protocol = protocol.unwrap_or(Protocol::Tcp);
    let policy = hub.policy();
    let now = local_now();
    let connection = |dst_ip: Option<IpAddr>, domain: Option<&str>| {
        let decision =
            policy.decide_rules(&FlowContext { client: device, protocol, dst_ip, dst_port: port, domain, now });
        outcome(hub, decision, protocol)
    };
    Ok(match typed.probe {
        Probe::Name(name) => RuleTestResult {
            lookup: Some(match policy.decide_lookup(device.as_ref(), &name, now) {
                Lookup::Block { rule } => LookupOutcome { blocked: true, egress: None, rule: Some(rule) },
                Lookup::Through { egress, rule } => LookupOutcome { blocked: false, egress: Some(egress), rule },
            }),
            connection: connection(None, Some(&name)),
            name: Some(name),
            address: None,
            learned_name: None,
            by_learned_name: None,
            port,
            protocol,
        },
        Probe::Address(ip) => {
            // As a connection that does not say its name would go: by the name
            // the device last looked the address up by, or for any device, the
            // name a device last did.
            let learned = device.map_or_else(|| hub.any_name_for(ip), |mac| hub.name_for(mac, ip));
            RuleTestResult {
                name: None,
                address: Some(ip),
                lookup: None,
                connection: connection(Some(ip), None),
                by_learned_name: learned.as_deref().map(|name| connection(Some(ip), Some(name))),
                learned_name: learned.map(|name| name.to_string()),
                port,
                protocol,
            }
        }
    })
}

/// Real connections under the hub's flow control, for tests to see which
/// ones a change ends.
#[cfg(test)]
pub(crate) mod test_flows {
    use std::{
        net::{IpAddr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use captun_core::{EgressId, MacAddr};
    use captun_engine::{
        Dispatcher, EngineHandle, FlowAction, FlowRequest, Forward, InboundConfig, TrafficMeter, serve_inbound,
    };
    use captun_outbound::{Direct, Outbound};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use crate::hub::Hub;

    /// Every connection straight where it asks, counted against `device`;
    /// open ones may go on while `allowed` holds. Stands in for a device's
    /// traffic, to see which connections the hub ends.
    struct Traffic {
        device: MacAddr,
        allowed: bool,
    }

    impl Dispatcher for Traffic {
        fn needs_domain(&self) -> bool {
            false
        }

        fn dispatch(&self, _request: &FlowRequest<'_>) -> FlowAction {
            let outbound: Arc<dyn Outbound> = Arc::new(Direct::new(EgressId::new("direct"), None));
            FlowAction::Forward(Forward { client: Some(self.device), outbound, down_kbps: None, up_kbps: None })
        }

        fn still_allowed(&self, _request: &FlowRequest<'_>, _device: Option<MacAddr>, _outbound: &EgressId) -> bool {
            self.allowed
        }
    }

    /// A TCP echo server, where the stand-in connections go.
    pub(crate) async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut from, mut to) = stream.split();
                    let _ = tokio::io::copy(&mut from, &mut to).await;
                });
            }
        });
        at
    }

    /// One open connection of a device, under the hub's flow control as the
    /// engine's are, kept open with the proxy inbound that carries it.
    pub(crate) struct Open {
        stream: TcpStream,
        _inbound: EngineHandle,
    }

    impl Open {
        /// A connection of `device` to `echo`, which may go on when the open
        /// flows are checked again only if `allowed`.
        pub(crate) async fn new(hub: &Hub, device: MacAddr, allowed: bool, echo: SocketAddr) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            let traffic: Arc<dyn Dispatcher> = Arc::new(Traffic { device, allowed });
            let config = InboundConfig::new(IpAddr::from([10, 9, 9, 9]));
            let inbound = serve_inbound(listener, config, traffic, Arc::new(TrafficMeter::new()), hub.flows().clone());
            let mut stream = TcpStream::connect(at).await.unwrap();
            stream.write_all(format!("CONNECT {echo} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
            let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            let mut open = Self { stream, _inbound: inbound };
            assert!(open.goes_on().await, "the connection did not open");
            open
        }

        /// Whether the connection still carries data, a moment after
        /// whatever might end it.
        pub(crate) async fn goes_on(&mut self) -> bool {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if self.stream.write_all(b"ping").await.is_err() {
                return false;
            }
            let mut back = [0u8; 4];
            let read = tokio::time::timeout(Duration::from_secs(2), self.stream.read_exact(&mut back)).await;
            matches!(read, Ok(Ok(_))) && &back == b"ping"
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use captun_core::{Config, ObservedClient, TargetAddr, config::Protocol};
    use captun_ipc::{Request, Response, RuleHits};
    use tokio::sync::broadcast;

    use super::{
        test_flows::{Open, echo_server},
        *,
    };
    use crate::hub::lock;

    const CONFIG: &str = r#"
        [network]
        default_egress = "direct"

        [[egress]]
        id = "direct"
        type = "direct"

        [[egress]]
        id = "http"
        type = "http"
        server = "127.0.0.1:3128"
        udp = "block"

        [[client]]
        mac = "02:00:00:00:00:01"
        state = "approved"
        egress = "http"

        [[client]]
        mac = "02:00:00:00:00:02"
        state = "blocked"

        [[rule]]
        clients = ["02:00:00:00:00:01"]
        ports = [25]
        action = "reject"
    "#;

    /// Rules about names: one blocks, one sends another way.
    const NAME_RULES: &str = r#"
        [network]
        default_egress = "direct"

        [[egress]]
        id = "direct"
        type = "direct"

        [[egress]]
        id = "http"
        type = "http"
        server = "127.0.0.1:3128"
        udp = "block"

        [[client]]
        mac = "02:00:00:00:00:01"
        state = "approved"

        [[rule]]
        domains = ["ads.example"]
        action = "reject"

        [[rule]]
        domains = ["telegram.org", "whatsapp.net"]
        action = { route = "http" }
    "#;

    /// A hub whose device list has `devices` online, each at its address
    /// (address, hardware address), and whose neighbor table agrees.
    fn hub_of(config: Config, devices: &[(&str, &str)]) -> Arc<Hub> {
        let (events, _) = broadcast::channel(16);
        let hub = Hub::new(None, config, captun_platform::default_backend(), events, None);
        let observed: Vec<ObservedClient> = devices
            .iter()
            .map(|(ip, mac)| ObservedClient { mac: mac.parse().unwrap(), addrs: vec![ip.parse().unwrap()], hostname: None })
            .collect();
        lock(&hub.registry).apply_snapshot(&observed, 1);
        hub.neighbors().give(devices.iter().map(|(ip, mac)| (ip.parse().unwrap(), mac.parse().unwrap())));
        hub
    }

    fn hub_with(config: &str, ip: &str, mac: &str) -> Arc<Hub> {
        hub_of(Config::from_toml(config).unwrap(), &[(ip, mac)])
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// The test devices' hardware addresses, 02:00:00:00:00:nn.
    const fn device(n: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, n])
    }

    fn hub_with_client(ip: &str, mac: &str) -> Arc<Hub> {
        hub_with(CONFIG, ip, mac)
    }

    fn dispatch(hub: &Arc<Hub>, ip: &str, proto: Protocol, dst: &str) -> FlowAction {
        let destination: TargetAddr = dst.parse().unwrap();
        PolicyDispatcher::new(hub).dispatch(&FlowRequest {
            client_ip: ip.parse::<IpAddr>().unwrap(),
            protocol: proto,
            destination: &destination,
            domain: None,
        })
    }

    fn forwarded_egress(action: FlowAction) -> String {
        match action {
            FlowAction::Forward(f) => f.outbound.id().to_string(),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    // Hub::new starts the VPN-link supervisor, which needs a runtime.
    #[tokio::test]
    async fn known_client_uses_its_egress() {
        let hub = hub_with_client("10.0.0.5", "02:00:00:00:00:01");
        assert_eq!(forwarded_egress(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "1.1.1.1:443")), "http");
    }

    #[tokio::test]
    async fn reject_rule_refuses() {
        let hub = hub_with_client("10.0.0.5", "02:00:00:00:00:01");
        assert!(matches!(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "1.1.1.1:25"), FlowAction::Reject));
    }

    #[tokio::test]
    async fn http_egress_blocks_udp() {
        let hub = hub_with_client("10.0.0.5", "02:00:00:00:00:01");
        // TCP goes through; UDP is blocked by the egress's udp policy, out
        // loud, so QUIC gives way to TCP at once.
        assert_eq!(forwarded_egress(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "1.1.1.1:443")), "http");
        assert!(matches!(dispatch(&hub, "10.0.0.5", Protocol::Udp, "1.1.1.1:443"), FlowAction::Reject));
    }

    #[tokio::test]
    async fn blocked_client_is_dropped() {
        let hub = hub_with_client("10.0.0.6", "02:00:00:00:00:02");
        assert!(matches!(dispatch(&hub, "10.0.0.6", Protocol::Tcp, "1.1.1.1:443"), FlowAction::Drop));
    }

    #[tokio::test]
    async fn a_connection_without_a_name_goes_by_the_name_looked_up() {
        let hub = hub_with(NAME_RULES, "10.0.0.5", "02:00:00:00:00:01");
        // Before any lookup, the address alone decides: the device's own way.
        assert_eq!(forwarded_egress(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "157.240.1.53:5222")), "direct");
        hub.learn_name(device(1), "g.whatsapp.net", &["157.240.1.53".parse().unwrap()]);
        assert_eq!(forwarded_egress(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "157.240.1.53:5222")), "http");
        hub.learn_name(device(1), "x.ads.example", &["6.6.6.6".parse().unwrap()]);
        assert!(matches!(dispatch(&hub, "10.0.0.5", Protocol::Udp, "6.6.6.6:443"), FlowAction::Reject));
    }

    #[tokio::test]
    async fn a_connection_goes_by_its_own_devices_lookups_only() {
        let hub = hub_of(
            Config::from_toml(NAME_RULES).unwrap(),
            &[("10.0.0.5", "02:00:00:00:00:01"), ("10.0.0.6", "02:00:00:00:00:02")],
        );
        // Device 2 is given device 1's chat server for a name a rule sends
        // another way: only device 2's connections go by it.
        hub.learn_name(device(2), "g.whatsapp.net", &[ip("157.240.1.53")]);
        assert_eq!(forwarded_egress(dispatch(&hub, "10.0.0.6", Protocol::Tcp, "157.240.1.53:5222")), "http");
        assert_eq!(forwarded_egress(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "157.240.1.53:5222")), "direct");
        // Nor does a name that blocks reach another device.
        hub.learn_name(device(2), "x.ads.example", &[ip("6.6.6.6")]);
        assert!(matches!(dispatch(&hub, "10.0.0.6", Protocol::Tcp, "6.6.6.6:443"), FlowAction::Reject));
        assert_eq!(forwarded_egress(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "6.6.6.6:443")), "direct");

        // A forgotten device's names go with it.
        hub.learn_name(device(9), "g.whatsapp.net", &[ip("157.240.1.53")]);
        hub.handle(Request::ForgetClient { mac: device(9) }).await.unwrap();
        assert_eq!(hub.name_for(device(9), ip("157.240.1.53")), None);
        assert_eq!(hub.name_for(device(2), ip("157.240.1.53")).as_deref(), Some("g.whatsapp.net"));
    }

    #[tokio::test]
    async fn lookups_go_the_way_their_names_are_sent() {
        let hub = hub_with(NAME_RULES, "10.0.0.5", "02:00:00:00:00:01");
        let router = crate::dns::router(&hub);
        let client: IpAddr = "10.0.0.5".parse().unwrap();
        let route = |name| router.route(client, name).unwrap();
        assert!(route("x.ads.example").blocked);
        let telegram = route("core.telegram.org");
        assert_eq!((telegram.outbound.id().as_str(), telegram.blocked, telegram.system_fallback), ("http", false, false));
        let plain = route("example.com");
        assert_eq!((plain.outbound.id().as_str(), plain.blocked, plain.system_fallback), ("direct", false, true));
        assert!(router.route("192.0.2.99".parse().unwrap(), "example.com").is_none(), "a device no list knows");
    }

    #[tokio::test]
    async fn a_source_no_list_knows_is_refused_not_sent_the_default_way() {
        let hub = hub_with_client("10.0.0.5", "02:00:00:00:00:01");
        // A documentation address: in neither the device list nor the
        // system's neighbor table.
        assert!(matches!(dispatch(&hub, "192.0.2.99", Protocol::Tcp, "1.1.1.1:443"), FlowAction::Reject));
    }

    #[tokio::test]
    async fn a_lease_counts_only_when_the_neighbor_table_agrees() {
        let hub = hub_with_client("10.0.0.5", "02:00:00:00:00:01");
        let other = device(0x66);
        assert_eq!(hub.device_at(ip("10.0.0.5")), Some(device(1)));
        assert_eq!(hub.device_at(ip("::ffff:10.0.0.5")), Some(device(1)), "the same address written as IPv6");

        // Another device answers at the address, as when one claims another's
        // lease: no device, so its flows and lookups are refused.
        hub.neighbors().give([(ip("10.0.0.5"), other)]);
        assert_eq!(hub.device_at(ip("10.0.0.5")), None);
        assert!(matches!(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "1.1.1.1:443"), FlowAction::Reject));
        assert!(crate::dns::router(&hub).route(ip("10.0.0.5"), "example.com").is_none());

        // No entry yet: refused too, until the system has looked the device up.
        hub.neighbors().give([]);
        assert_eq!(hub.device_at(ip("10.0.0.5")), None);
        hub.neighbors().give([(ip("10.0.0.5"), device(1))]);
        assert_eq!(forwarded_egress(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "1.1.1.1:443")), "http");

        // An address the device list does not have: the neighbor table alone.
        hub.neighbors().give([(ip("10.0.0.5"), device(1)), (ip("10.0.0.77"), other)]);
        assert_eq!(hub.device_at(ip("10.0.0.77")), Some(other));

        // The device list's IPv6 addresses come from the system, never from
        // Captun's DHCP, and the neighbor table is read for IPv4 only.
        let observed = ObservedClient { mac: device(1), addrs: vec![ip("10.0.0.5"), ip("2001:db8::5")], hostname: None };
        lock(&hub.registry).apply_snapshot(&[observed], 2);
        assert_eq!(hub.device_at(ip("2001:db8::5")), Some(device(1)));
    }

    #[test]
    fn a_device_at_another_ones_address_is_warned_about_once() {
        let neighbors = Neighbors::default();
        let (at, listed) = (ip("10.0.0.5"), device(1));
        assert!(neighbors.warn_once(at, listed, device(0x66)));
        assert!(!neighbors.warn_once(at, listed, device(0x66)), "the same address and hardware address again");
        assert!(neighbors.warn_once(at, listed, device(0x67)), "another hardware address");
        assert!(neighbors.warn_once(ip("10.0.0.6"), listed, device(0x66)), "another address");

        // The pairs warned about are bounded: once full, the set starts over.
        for n in 3..MAX_WARNED {
            let [_, _, high, low] = u32::try_from(n).unwrap().to_be_bytes();
            assert!(neighbors.warn_once(IpAddr::V4(Ipv4Addr::new(10, 1, high, low)), listed, device(0x66)));
        }
        assert_eq!(lock(&neighbors.warned).len(), MAX_WARNED);
        assert!(!neighbors.warn_once(at, listed, device(0x66)), "a full set still knows its pairs");
        assert!(neighbors.warn_once(ip("10.2.0.1"), listed, device(0x66)), "a new pair");
        assert_eq!(lock(&neighbors.warned).len(), 1, "the set started over");
        assert!(neighbors.warn_once(at, listed, device(0x66)), "warned about again after starting over");
    }

    /// Devices in each state the engine's budgets tell apart: 01 approved,
    /// 02 blocked, 03 waiting for approval (no settings), 04 and 05 approved.
    const ADMISSION: &str = r#"
        [network]
        default_egress = "direct"
        quarantine_new_clients = true

        [[egress]]
        id = "direct"
        type = "direct"

        [[client]]
        mac = "02:00:00:00:00:01"
        state = "approved"

        [[client]]
        mac = "02:00:00:00:00:02"
        state = "blocked"

        [[client]]
        mac = "02:00:00:00:00:04"
        state = "approved"

        [[client]]
        mac = "02:00:00:00:00:05"
        state = "approved"
    "#;

    const LISTED: [(&str, &str); 4] = [
        ("10.0.0.5", "02:00:00:00:00:01"),
        ("10.0.0.6", "02:00:00:00:00:02"),
        ("10.0.0.7", "02:00:00:00:00:03"),
        ("10.0.0.8", "02:00:00:00:00:04"),
    ];

    fn admission_hub() -> Arc<Hub> {
        let mut config = Config::from_toml(ADMISSION).unwrap();
        config.hotspot.max_clients = Some(1);
        hub_of(config, &LISTED)
    }

    #[tokio::test]
    async fn only_a_listed_device_let_in_has_a_budget_of_its_own() {
        let hub = admission_hub();
        let key = |text: &str| PolicyDispatcher::new(&hub).source_key(ip(text));
        assert_eq!(key("10.0.0.5"), SourceKey::Device(device(1)));
        assert_eq!(key("10.0.0.6"), SourceKey::Unlisted, "blocked");
        assert_eq!(key("10.0.0.7"), SourceKey::Unlisted, "waiting for approval");
        assert_eq!(key("10.0.0.8"), SourceKey::Device(device(4)), "a slot of its own, for now");
        assert_eq!(key("192.0.2.99"), SourceKey::Unlisted, "an address no device holds");

        // The device limit holds the later arrival back.
        assert!(hub.update_capacity(&[device(1), device(4)]));
        assert_eq!(key("10.0.0.8"), SourceKey::Unlisted, "held back by the device limit");
        assert_eq!(key("10.0.0.5"), SourceKey::Device(device(1)));

        // A listed device's other addresses in the neighbor table, its IPv6
        // one too, are its budget; one of a device not on the list is not.
        let mut table: Vec<(IpAddr, MacAddr)> =
            LISTED.iter().map(|(ip, mac)| (ip.parse().unwrap(), mac.parse().unwrap())).collect();
        table.extend([(ip("2001:db8::5"), device(1)), (ip("10.0.0.50"), device(1)), (ip("10.0.0.9"), device(5))]);
        hub.neighbors().give(table.clone());
        assert_eq!(key("2001:db8::5"), SourceKey::Device(device(1)));
        assert_eq!(key("10.0.0.50"), SourceKey::Device(device(1)));
        assert_eq!(key("10.0.0.9"), SourceKey::Unlisted, "approved, but not on the device list");

        // Another device at a listed address does not get that device's budget.
        table[0].1 = device(0x66);
        hub.neighbors().give(table);
        assert_eq!(key("10.0.0.5"), SourceKey::Unlisted);

        // Nor does anyone once the hub is gone.
        let dispatcher = PolicyDispatcher::new(&hub);
        drop(hub);
        assert_eq!(dispatcher.source_key(ip("10.0.0.8")), SourceKey::Unlisted);
    }

    #[tokio::test]
    async fn every_decision_names_its_device() {
        let hub = admission_hub();
        let decided = |from: &str, to: &str| {
            let destination: TargetAddr = to.parse().unwrap();
            let request = FlowRequest { client_ip: ip(from), protocol: Protocol::Udp, destination: &destination, domain: None };
            let (action, named) = PolicyDispatcher::new(&hub).dispatch_device(&request);
            (format!("{action:?}"), named)
        };
        assert_eq!(decided("10.0.0.6", "1.1.1.1:443"), ("Drop".into(), Some(device(2))), "blocked");
        assert_eq!(decided("10.0.0.7", "1.1.1.1:443"), ("Drop".into(), Some(device(3))), "waiting");
        assert_eq!(decided("10.0.0.5", "127.0.0.1:443").1, Some(device(1)), "this computer's loopback");
        assert_eq!(decided("192.0.2.99", "1.1.1.1:443"), ("Reject".into(), None), "no device");
        let (forwarded, named) = decided("10.0.0.5", "1.1.1.1:443");
        assert!(forwarded.starts_with("Forward"), "{forwarded}");
        assert_eq!(named, Some(device(1)));
    }

    #[tokio::test]
    async fn an_open_flow_goes_on_only_while_it_would_go_the_same_way() {
        let hub = hub_of(Config::from_toml(NAME_RULES).unwrap(), &[("10.0.0.5", "02:00:00:00:00:01"), ("10.0.0.6", "02:00:00:00:00:02")]);
        let dispatcher = PolicyDispatcher::new(&hub);
        let (chat, web): (TargetAddr, TargetAddr) = ("157.240.1.53:5222".parse().unwrap(), "1.1.1.1:443".parse().unwrap());
        fn request(destination: &TargetAddr) -> FlowRequest<'_> {
            FlowRequest { client_ip: "10.0.0.5".parse().unwrap(), protocol: Protocol::Tcp, destination, domain: None }
        }
        let (action, named) = dispatcher.dispatch_device(&request(&chat));
        assert_eq!((forwarded_egress(action), named), ("direct".to_owned(), Some(device(1))));
        let direct = EgressId::new("direct");
        let allowed = |destination, named| dispatcher.still_allowed(&request(destination), named, &direct);
        assert!(allowed(&chat, named));
        assert!(!allowed(&chat, None), "no device at the address");
        assert!(!allowed(&chat, Some(device(2))), "another device at the address");
        assert!(!dispatcher.still_allowed(&request(&chat), named, &EgressId::new("http")), "another outbound");

        // A change that has nothing to do with it.
        let mut config = (*hub.config()).clone();
        config.client_mut(device(1)).alias = Some("Phone".into());
        set_config(&hub, config.clone()).await;
        assert!(allowed(&chat, named));

        // Another device's lookups say nothing about it.
        hub.learn_name(device(2), "g.whatsapp.net", &[ip("157.240.1.53")]);
        assert!(allowed(&chat, named));

        // Its address looked up by a name a rule sends another way. Checking
        // again counts no rule hit: it is not a new connection.
        hub.learn_name(device(1), "g.whatsapp.net", &[ip("157.240.1.53")]);
        assert!(!allowed(&chat, named), "a rule sends it through another outbound now");
        assert_eq!(hits(&hub).await, [RuleHits::default(); 2], "checking again counted a hit");

        // A rule that refuses it.
        assert!(allowed(&web, named));
        let refusing = Config::from_toml(&format!("{NAME_RULES}\n[[rule]]\nports = [443]\naction = \"deny\"\n")).unwrap();
        config.rules = refusing.rules;
        set_config(&hub, config.clone()).await;
        assert!(!allowed(&web, named), "a new rule refuses it");
        config.rules.pop();
        set_config(&hub, config.clone()).await;
        assert!(allowed(&web, named));

        // Held back by the device limit.
        config.hotspot.max_clients = Some(1);
        set_config(&hub, config).await;
        assert!(hub.update_capacity(&[device(2), device(1)]));
        assert!(!allowed(&web, named), "held back by the device limit");
    }

    #[tokio::test]
    async fn an_open_flow_ends_only_when_another_device_is_seen_at_its_address() {
        let hub = hub_with(NAME_RULES, "10.0.0.5", "02:00:00:00:00:01");
        let dispatcher = PolicyDispatcher::new(&hub);
        let web: TargetAddr = "1.1.1.1:443".parse().unwrap();
        let direct = EgressId::new("direct");
        let allowed = |from: &str, mac| {
            let request = FlowRequest { client_ip: ip(from), protocol: Protocol::Tcp, destination: &web, domain: None };
            dispatcher.still_allowed(&request, Some(mac), &direct)
        };
        assert!(allowed("10.0.0.5", device(1)));

        // Its neighbor entry missing for a moment, as while a phone sleeps:
        // a new connection waits for the entry, an open one goes on.
        hub.neighbors().give([]);
        assert!(matches!(dispatch(&hub, "10.0.0.5", Protocol::Tcp, "1.1.1.1:443"), FlowAction::Reject));
        assert!(allowed("10.0.0.5", device(1)), "a missing neighbor entry ended an open connection");

        // Another device answering at the address ends it.
        hub.neighbors().give([(ip("10.0.0.5"), device(0x66))]);
        assert!(!allowed("10.0.0.5", device(1)), "another device at its address");

        // A device the neighbor table alone found keeps its connections while
        // the table has no entry for it, and loses them to another device.
        hub.neighbors().give([(ip("10.0.0.77"), device(3))]);
        assert_eq!(hub.device_at(ip("10.0.0.77")), Some(device(3)));
        hub.neighbors().give([]);
        assert!(allowed("10.0.0.77", device(3)));
        hub.neighbors().give([(ip("10.0.0.77"), device(4))]);
        assert!(!allowed("10.0.0.77", device(3)));

        // The device list giving the address to another device ends it too.
        hub.neighbors().give([]);
        let other = ObservedClient { mac: device(2), addrs: vec![ip("10.0.0.5")], hostname: None };
        lock(&hub.registry).apply_snapshot(&[other], 2);
        assert!(!allowed("10.0.0.5", device(1)), "the device list gives its address to another device");
    }

    #[tokio::test]
    async fn the_phones_open_connections_are_checked_the_same_way() {
        let hub = hub_with(NAME_RULES, "10.0.0.5", "02:00:00:00:00:01");
        let phone = crate::tether::ReverseDispatcher::new(&hub, device(7));
        let allowed = |to: &str, outbound: &str| {
            let destination: TargetAddr = to.parse().unwrap();
            let request = FlowRequest { client_ip: ip("10.9.9.9"), protocol: Protocol::Tcp, destination: &destination, domain: None };
            phone.still_allowed(&request, Some(device(7)), &EgressId::new(outbound))
        };
        assert!(allowed("157.240.1.53:5222", "direct"));
        assert!(!allowed("157.240.1.53:5222", "http"), "another outbound");
        assert!(!allowed("127.0.0.1:5222", "direct"), "this computer's loopback");
        hub.learn_name(device(7), "g.whatsapp.net", &[ip("157.240.1.53")]);
        assert!(!allowed("157.240.1.53:5222", "direct"), "a rule sends it another way now");
        assert_eq!(hits(&hub).await, [RuleHits::default(); 2], "checking again counted a hit");
    }

    #[test]
    fn a_change_ends_the_flows_of_the_devices_it_concerns() {
        let base = Config::from_toml(&format!(
            "{CONFIG}\n[[group]]\nid = \"kids\"\n\n[[client]]\nmac = \"02:00:00:00:00:03\"\ngroup = \"kids\"\n"
        ))
        .unwrap();
        let ended = |change: &dyn Fn(&mut Config)| {
            let mut changed = base.clone();
            change(&mut changed);
            flows_ended_by(&base, &changed)
        };
        let none = FlowsEnded::Devices(Vec::new());
        let only = |n| FlowsEnded::Devices(vec![device(n)]);
        // What does not decide open flows ends none of them.
        assert_eq!(ended(&|c| c.client_mut(device(1)).alias = Some("Phone".into())), none);
        assert_eq!(ended(&|c| c.client_mut(device(1)).inspect_tls = true), none);
        assert_eq!(ended(&|c| c.client_mut(device(1)).dns_upstream = Some("1.1.1.1".into())), none);
        assert_eq!(ended(&|c| c.client_mut(device(9)).alias = Some("New".into())), none, "a name for a new device");
        assert_eq!(ended(&|c| c.groups[0].name = Some("Children".into())), none);
        assert_eq!(ended(&|c| c.groups[0].dns_upstream = Some("1.1.1.1".into())), none);
        assert_eq!(ended(&|c| c.dns.log_queries = !c.dns.log_queries), none);
        // A device's own way: only its flows.
        assert_eq!(ended(&|c| c.client_mut(device(2)).state = ClientState::Approved), only(2));
        assert_eq!(ended(&|c| c.client_mut(device(1)).egress = None), only(1));
        assert_eq!(ended(&|c| c.client_mut(device(1)).limit = Some(RateLimit { down_kbps: Some(512), up_kbps: None })), only(1));
        assert_eq!(ended(&|c| c.client_mut(device(1)).group = Some("kids".into())), only(1));
        assert_eq!(ended(&|c| c.clients.retain(|p| p.mac != device(2))), only(2), "a blocked device forgotten");
        assert_eq!(ended(&|c| c.client_mut(device(9)).state = ClientState::Approved), only(9));
        // A group's way: its members' flows.
        assert_eq!(ended(&|c| c.groups[0].egress = Some("http".into())), only(3));
        assert_eq!(ended(&|c| c.groups[0].limit = Some(RateLimit { down_kbps: None, up_kbps: Some(64) })), only(3));
        // Outbounds, rules and network settings: every flow.
        assert_eq!(ended(&|c| c.rules.clear()), FlowsEnded::All);
        assert_eq!(ended(&|c| c.egresses[1].udp = captun_core::UdpPolicy::Native), FlowsEnded::All);
        assert_eq!(ended(&|c| c.network.quarantine_new_clients = true), FlowsEnded::All);
    }

    #[tokio::test]
    async fn a_change_to_one_device_ends_only_its_connections() {
        let hub = hub_with_client("10.0.0.5", "02:00:00:00:00:01");
        let echo = echo_server().await;
        let (mut first, mut second) = (Open::new(&hub, device(1), true, echo).await, Open::new(&hub, device(2), true, echo).await);
        let profile = |n| hub.config().client(&device(n)).cloned().unwrap();
        let save = |profile| hub.handle(Request::SetClientProfile(profile));

        // A new name, or HTTPS inspection, ends nothing.
        let mut renamed = profile(1);
        renamed.alias = Some("Phone".into());
        renamed.inspect_tls = true;
        save(renamed).await.unwrap();
        assert!(first.goes_on().await, "a new name ended the device's connection");
        assert!(second.goes_on().await, "a new name ended another device's connection");

        // Letting the blocked device in ends only its own.
        let mut let_in = profile(2);
        let_in.state = ClientState::Approved;
        save(let_in).await.unwrap();
        assert!(!second.goes_on().await, "the device let in kept its connection");
        assert!(first.goes_on().await, "another device's connection ended");

        // A speed limit is taken when a connection starts: the device's end.
        let mut limited = profile(1);
        limited.limit = Some(RateLimit { down_kbps: Some(1000), up_kbps: None });
        save(limited).await.unwrap();
        assert!(!first.goes_on().await, "a new speed limit left the connection open");

        // Network settings end every connection.
        let (mut first, mut second) = (Open::new(&hub, device(1), true, echo).await, Open::new(&hub, device(2), true, echo).await);
        let mut config = (*hub.config()).clone();
        config.network.quarantine_new_clients = !config.network.quarantine_new_clients;
        set_config(&hub, config).await;
        assert!(!first.goes_on().await && !second.goes_on().await, "a network change left connections open");
    }

    /// A blanket block at night, and a disabled rule whose window never counts.
    const NIGHT: &str = r#"
        [network]
        default_egress = "direct"

        [[egress]]
        id = "direct"
        type = "direct"

        [[rule]]
        schedule = { start = "22:00", end = "07:00" }
        action = "deny"

        [[rule]]
        enabled = false
        schedule = { start = "21:00", end = "21:30" }
        action = "deny"
    "#;

    fn at(time: &str) -> LocalTime {
        LocalTime { weekday: Weekday::Mon, time: time.parse().unwrap() }
    }

    #[test]
    fn open_flows_are_checked_again_only_when_a_window_opens_or_closes() {
        let night = Config::from_toml(NIGHT).unwrap();
        let mut windows = OpenWindows::default();
        let edges: Vec<bool> = ["20:59", "21:00", "21:59", "22:00", "22:01", "23:59"]
            .into_iter()
            .map(|time| windows.look(&night.rules, at(time)))
            .collect();
        assert_eq!(
            edges,
            [false, false, false, true, false, false],
            "a first look only takes note; the disabled rule never counts"
        );
        assert!(windows.look(&night.rules, LocalTime { weekday: Weekday::Tue, time: "07:00".parse().unwrap() }));

        // Rules saved just before a window opens: connections opened after
        // the save were decided before the edge, so they are checked at it.
        let mut before = night.clone();
        before.rules.remove(0);
        let mut windows = OpenWindows::default();
        assert!(!windows.look(&before.rules, at("21:58")));
        assert!(windows.look(&night.rules, at("22:00")), "the window opened just after the rules were saved");

        // Rules changed with no edge in between: nothing to check again,
        // even though their order, and so their places, changed.
        let mut moved = night.clone();
        moved.rules.swap(0, 1);
        assert!(!windows.look(&moved.rules, at("22:30")));
        assert!(!windows.look(&before.rules, at("22:31")), "a rule taken out inside its window");
        assert!(!windows.look(&night.rules, at("22:32")), "a rule put back inside its window");
    }

    #[tokio::test]
    async fn a_time_window_and_the_device_limit_apply_to_open_connections() {
        let mut config = Config::from_toml(NIGHT).unwrap();
        config.hotspot.max_clients = Some(1);
        let hub = hub_of(config, &[("10.0.0.5", "02:00:00:00:00:01"), ("10.0.0.6", "02:00:00:00:00:02")]);
        let echo = echo_server().await;
        // Connections the rules no longer let through once they are checked again.
        let mut refused = Open::new(&hub, device(1), false, echo).await;
        assert!(!hub.check_schedules_at(at("21:58")), "a first look only takes note");
        assert!(!hub.check_schedules_at(at("21:59")));
        assert!(refused.goes_on().await, "checked again away from a window's edge");
        assert!(hub.check_schedules_at(at("22:00")));
        assert!(!refused.goes_on().await, "the window opened and the connection went on");

        // The device limit holding a device back has open connections checked
        // again; those still let through go on.
        let mut held = Open::new(&hub, device(2), false, echo).await;
        let mut kept = Open::new(&hub, device(1), true, echo).await;
        assert!(!hub.update_capacity(&[device(1)]), "nobody held back yet");
        assert!(held.goes_on().await);
        assert!(hub.update_capacity(&[device(1), device(2)]));
        assert!(!held.goes_on().await, "the device held back kept its connection");
        assert!(kept.goes_on().await, "a device still let in lost its connection");
    }

    #[tokio::test]
    async fn a_window_that_opens_just_after_the_rules_are_saved_applies_to_open_connections() {
        let mut config = Config::from_toml(NIGHT).unwrap();
        let night = std::mem::take(&mut config.rules);
        let hub = hub_of(config.clone(), &[("10.0.0.5", "02:00:00:00:00:01")]);
        let echo = echo_server().await;
        assert!(!hub.check_schedules_at(at("21:58")), "a first look only takes note");

        // The night rule saved at 21:59 ends every connection. One opened
        // after that was decided outside the window; at 22:00 the rules no
        // longer let it through.
        config.rules = night;
        set_config(&hub, config).await;
        let mut opened = Open::new(&hub, device(1), false, echo).await;
        assert!(hub.check_schedules_at(at("22:00")), "the window's opening was missed");
        assert!(!opened.goes_on().await, "a connection opened just before the window outlasted its opening");
    }

    /// Every rule's counts, as the GUI asks for them.
    async fn hits(hub: &Arc<Hub>) -> Vec<RuleHits> {
        match hub.handle(Request::GetRuleHits).await.unwrap() {
            Response::RuleHits(hits) => hits,
            other => panic!("expected rule hits, got {other:?}"),
        }
    }

    async fn set_config(hub: &Arc<Hub>, config: Config) {
        hub.handle(Request::SetConfig(Box::new(config))).await.unwrap();
    }

    #[tokio::test]
    async fn rules_count_the_connections_and_lookups_they_decide() {
        let hub = hub_with(NAME_RULES, "10.0.0.5", "02:00:00:00:00:01");
        assert_eq!(hits(&hub).await, [RuleHits::default(); 2], "one entry per rule, none used yet");
        // No rule decides these: nothing is counted.
        dispatch(&hub, "10.0.0.5", Protocol::Tcp, "1.1.1.1:443");
        let router = crate::dns::router(&hub);
        let client: IpAddr = "10.0.0.5".parse().unwrap();
        router.route(client, "example.com").unwrap();
        assert_eq!(hits(&hub).await, [RuleHits::default(); 2]);

        hub.learn_name(device(1), "g.whatsapp.net", &["157.240.1.53".parse().unwrap()]);
        dispatch(&hub, "10.0.0.5", Protocol::Tcp, "157.240.1.53:5222");
        // Counted even though the outbound then refuses UDP: the rule decided.
        dispatch(&hub, "10.0.0.5", Protocol::Udp, "157.240.1.53:3478");
        router.route(client, "x.ads.example").unwrap();
        let counted = hits(&hub).await;
        assert_eq!((counted[0].connections, counted[0].lookups), (0, 1), "the ads rule blocked one lookup");
        assert_eq!((counted[1].connections, counted[1].lookups), (2, 0), "the WhatsApp rule sent two connections");
        assert!(counted.iter().all(|h| h.last_ms.is_some_and(|ms| ms > 0)));
    }

    #[tokio::test]
    async fn counts_start_over_when_the_rules_change_and_only_then() {
        let hub = hub_with(NAME_RULES, "10.0.0.5", "02:00:00:00:00:01");
        crate::dns::router(&hub).route("10.0.0.5".parse().unwrap(), "x.ads.example").unwrap();

        // Other settings, a device's own and the device limit rebuild the
        // policy too, but leave every rule where it was.
        let mut config = (*hub.config()).clone();
        config.dns.log_queries = !config.dns.log_queries;
        config.hotspot.max_clients = Some(1);
        config.client_mut("02:00:00:00:00:01".parse().unwrap()).alias = Some("Phone".into());
        set_config(&hub, config.clone()).await;
        let stations = ["02:00:00:00:00:01".parse().unwrap(), "02:00:00:00:00:09".parse().unwrap()];
        assert!(hub.update_capacity(&stations), "one station held back");
        assert_eq!(hits(&hub).await[0].lookups, 1);

        // A rule moved shifts what each index means: every count starts over.
        config.rules.swap(0, 1);
        set_config(&hub, config.clone()).await;
        assert_eq!(hits(&hub).await, [RuleHits::default(); 2]);
        crate::dns::router(&hub).route("10.0.0.5".parse().unwrap(), "x.ads.example").unwrap();
        assert_eq!(hits(&hub).await[1].lookups, 1, "counted under its new place");

        // One entry per rule, whatever their number.
        config.rules.pop();
        set_config(&hub, config).await;
        assert_eq!(hits(&hub).await, [RuleHits::default()]);
    }

    /// Rules for the tester: by name, by address, for one device, by port.
    const TESTED_RULES: &str = r#"
        [network]
        default_egress = "direct"
        quarantine_new_clients = true

        [[egress]]
        id = "direct"
        type = "direct"

        [[egress]]
        id = "http"
        type = "http"
        server = "127.0.0.1:3128"
        udp = "block"

        [[egress]]
        id = "proxy"
        type = "http"
        server = "127.0.0.1:3129"
        udp = { via = "direct" }

        [[client]]
        mac = "02:00:00:00:00:01"
        state = "blocked"
        egress = "http"

        [[client]]
        mac = "02:00:00:00:00:03"
        state = "approved"
        egress = "proxy"

        [[rule]]
        name = "No ads"
        domains = ["ads.example"]
        action = "reject"

        [[rule]]
        domains = ["telegram.org"]
        cidrs = ["91.108.4.0/22"]
        action = { route = "http" }

        [[rule]]
        clients = ["02:00:00:00:00:01"]
        domains = ["video.example"]
        action = "deny"

        [[rule]]
        cidrs = ["10.0.0.0/8"]
        ports = [25]
        protocol = "tcp"
        action = "reject"
    "#;

    const BLOCKED: &str = "02:00:00:00:00:01";
    /// Goes out through an HTTP proxy that sends UDP out directly.
    const PROXIED: &str = "02:00:00:00:00:03";

    async fn tested(
        hub: &Arc<Hub>,
        target: &str,
        device: Option<&str>,
        port: Option<u16>,
        protocol: Option<Protocol>,
    ) -> Result<RuleTestResult, IpcError> {
        let device = device.map(|mac| mac.parse().unwrap());
        let request = Request::TestRules { target: target.into(), device, port, protocol };
        hub.handle(request).await.map(|response| match response {
            Response::RuleTest(result) => *result,
            other => panic!("expected a rule test, got {other:?}"),
        })
    }

    fn lookup(blocked: bool, egress: Option<&str>, rule: Option<usize>) -> Option<LookupOutcome> {
        Some(LookupOutcome { blocked, egress: egress.map(Into::into), rule })
    }

    /// Carried by the very outbound the rules chose, if they let it through.
    fn connection(verdict: RuleVerdict, egress: Option<&str>, rule: Option<usize>) -> ConnectionOutcome {
        ConnectionOutcome { verdict, egress: egress.map(Into::into), carried_by: egress.map(Into::into), rule }
    }

    #[tokio::test]
    async fn the_tester_says_what_the_rules_do_with_a_name() {
        let hub = hub_with(TESTED_RULES, "10.0.0.5", BLOCKED);
        let ads = tested(&hub, "https://WWW.Ads.Example/banner?x=1", None, None, None).await.unwrap();
        assert_eq!(ads.name.as_deref(), Some("www.ads.example"), "a pasted link, cut down to its host");
        assert_eq!(ads.lookup, lookup(true, None, Some(0)));
        assert_eq!(ads.connection, connection(RuleVerdict::Reject, None, Some(0)));

        let telegram = tested(&hub, "core.telegram.org", None, None, None).await.unwrap();
        assert_eq!(telegram.lookup, lookup(false, Some("http"), Some(1)));
        assert_eq!(telegram.connection, connection(RuleVerdict::Allow, Some("http"), Some(1)));

        // Any device: the default outbound, and the rule for one device does
        // not apply.
        let video = tested(&hub, "video.example", None, None, None).await.unwrap();
        assert_eq!(video.lookup, lookup(false, Some("direct"), None));
        assert_eq!(video.connection, connection(RuleVerdict::Allow, Some("direct"), None));
        // That device is blocked altogether, yet the rules still answer for it,
        // and its own outbound is its usual way.
        let video = tested(&hub, "video.example", Some(BLOCKED), None, None).await.unwrap();
        assert_eq!(video.lookup, lookup(true, None, Some(2)));
        assert_eq!(video.connection, connection(RuleVerdict::Deny, None, Some(2)));
        let plain = tested(&hub, "example.com", Some(BLOCKED), None, None).await.unwrap();
        assert_eq!(plain.lookup, lookup(false, Some("http"), None));
        assert_eq!(plain.connection, connection(RuleVerdict::Allow, Some("http"), None));
        assert_eq!((plain.address, plain.learned_name, plain.by_learned_name), (None, None, None));

        assert_eq!(hits(&hub).await, [RuleHits::default(); 4], "a test is not counted");
    }

    #[tokio::test]
    async fn the_tester_says_what_the_rules_do_with_an_address() {
        let hub = hub_with(TESTED_RULES, "10.0.0.5", BLOCKED);
        let telegram = tested(&hub, "91.108.5.1", None, None, None).await.unwrap();
        assert_eq!((telegram.address, telegram.lookup), (Some("91.108.5.1".parse().unwrap()), None));
        assert_eq!(telegram.connection, connection(RuleVerdict::Allow, Some("http"), Some(1)));

        // Port 443 and TCP unless asked otherwise, and the answer says which.
        let mail = |port, protocol| tested(&hub, "10.1.2.3", None, port, protocol);
        assert_eq!(mail(Some(25), None).await.unwrap().connection, connection(RuleVerdict::Reject, None, Some(3)));
        let plain = mail(None, None).await.unwrap();
        assert_eq!(plain.connection, connection(RuleVerdict::Allow, Some("direct"), None));
        assert_eq!((plain.port, plain.protocol), (443, Protocol::Tcp));
        let udp = mail(Some(25), Some(Protocol::Udp)).await.unwrap();
        assert_eq!(udp.connection, connection(RuleVerdict::Allow, Some("direct"), None));
        assert_eq!((udp.port, udp.protocol), (25, Protocol::Udp));

        // An address a device looked up by a name: a connection that does not
        // say its name goes by that one. For any device, a device's will do.
        hub.learn_name(BLOCKED.parse().unwrap(), "x.ads.example", &["6.6.6.6".parse().unwrap()]);
        let learned = tested(&hub, "[::ffff:6.6.6.6]:443", None, None, None).await.unwrap();
        assert_eq!(learned.address, Some("6.6.6.6".parse().unwrap()));
        assert_eq!(learned.connection, connection(RuleVerdict::Allow, Some("direct"), None));
        assert_eq!(learned.learned_name.as_deref(), Some("x.ads.example"));
        assert_eq!(learned.by_learned_name, Some(connection(RuleVerdict::Reject, None, Some(0))));
        // For one device, only its own.
        let own = tested(&hub, "6.6.6.6", Some(BLOCKED), None, None).await.unwrap();
        assert_eq!(own.learned_name.as_deref(), Some("x.ads.example"));
        let other = tested(&hub, "6.6.6.6", Some(PROXIED), None, None).await.unwrap();
        assert_eq!((other.learned_name, other.by_learned_name), (None, None));
        // The latest device's name, for any device.
        hub.learn_name(PROXIED.parse().unwrap(), "core.telegram.org", &["6.6.6.6".parse().unwrap()]);
        let latest = tested(&hub, "6.6.6.6", None, None, None).await.unwrap();
        assert_eq!(latest.learned_name.as_deref(), Some("core.telegram.org"));
        assert_eq!(latest.by_learned_name, Some(connection(RuleVerdict::Allow, Some("http"), Some(1))));
    }

    #[tokio::test]
    async fn the_tester_names_the_outbound_that_really_carries_udp() {
        let hub = hub_with(TESTED_RULES, "10.0.0.5", BLOCKED);
        let udp = |target, device| tested(&hub, target, device, None, Some(Protocol::Udp));
        // Sent to an outbound with UDP blocked: refused, as real traffic is,
        // whether a rule or the device's own outbound sent it there.
        let refused = |rule| ConnectionOutcome { verdict: RuleVerdict::Reject, egress: Some("http".into()), carried_by: None, rule };
        assert_eq!(udp("core.telegram.org", None).await.unwrap().connection, refused(Some(1)));
        assert_eq!(udp("example.com", Some(BLOCKED)).await.unwrap().connection, refused(None));
        // An outbound that sends UDP through another one: that one carries it.
        let call = udp("example.com", Some(PROXIED)).await.unwrap();
        let around = ConnectionOutcome {
            verdict: RuleVerdict::Allow,
            egress: Some("proxy".into()),
            carried_by: Some("direct".into()),
            rule: None,
        };
        assert_eq!(call.connection, around);
        // TCP goes through the proxy itself.
        let web = tested(&hub, "example.com", Some(PROXIED), None, None).await.unwrap();
        assert_eq!(web.connection, connection(RuleVerdict::Allow, Some("proxy"), None));
        // The lookup goes the rules' way: the outbound's UDP setting is not
        // what carries it.
        assert_eq!(call.lookup, lookup(false, Some("proxy"), None));
    }

    #[tokio::test]
    async fn the_tester_tests_the_port_written_with_the_website_or_address() {
        let hub = hub_with(TESTED_RULES, "10.0.0.5", BLOCKED);
        let port_of = |target, port| tested(&hub, target, None, port, None);
        // The last rule refuses TCP port 25 to 10.0.0.0/8.
        let mail = port_of("10.1.2.3:25", None).await.unwrap();
        assert_eq!((mail.port, mail.connection), (25, connection(RuleVerdict::Reject, None, Some(3))));
        assert_eq!(port_of("10.1.2.3:25", Some(25)).await.unwrap().port, 25, "the same port twice");
        // A link's usual port, unless the port field says otherwise.
        assert_eq!(port_of("http://10.1.2.3/", None).await.unwrap().port, 80);
        assert_eq!(port_of("HTTPS://10.1.2.3", None).await.unwrap().port, 443);
        let asked = port_of("http://10.1.2.3/", Some(25)).await.unwrap();
        assert_eq!((asked.port, asked.connection.verdict), (25, RuleVerdict::Reject));
        assert_eq!(port_of("[2001:db8::1]:8080", None).await.unwrap().port, 8080);

        // Two different ports, or none that can be: which was meant is unclear.
        for (typed, port) in [("10.1.2.3:25", Some(443)), ("example.com:8080", Some(80)), ("example.com", Some(0)), ("10.1.2.3:0", None)] {
            let error = port_of(typed, port).await.unwrap_err();
            assert_eq!(error.code, ErrorCode::BadRequest, "{typed:?} {port:?}");
        }
        let error = port_of("10.1.2.3:25", Some(443)).await.unwrap_err();
        assert!(error.message.contains("25") && error.message.contains("443"), "{}", error.message);
    }

    #[tokio::test]
    async fn the_tester_refuses_what_is_neither_a_website_nor_an_address() {
        let hub = hub_with(TESTED_RULES, "10.0.0.5", BLOCKED);
        let too_long = "a".repeat(MAX_TEST_TARGET + 1);
        for typed in ["", "   ", "not a website", "http://", "*.example.com", "example.com:99999", "[::1", too_long.as_str()] {
            let error = tested(&hub, typed, None, None, None).await.unwrap_err();
            assert_eq!(error.code, ErrorCode::BadRequest, "{typed:?}");
        }
    }

    #[test]
    fn what_was_typed_is_read_as_a_website_or_an_address() {
        let read = |typed| {
            let Some(Typed { probe, port, link_port }) = read_typed(typed) else { return "nothing".to_owned() };
            let host = match probe {
                Probe::Name(name) => format!("name {name}"),
                Probe::Address(ip) => format!("address {ip}"),
            };
            let port = port.map(|port| format!(" port {port}")).unwrap_or_default();
            let link = link_port.map(|port| format!(" (link {port})")).unwrap_or_default();
            format!("{host}{port}{link}")
        };
        assert_eq!(read(" Example.COM. "), "name example.com");
        assert_eq!(read("example.com:8443"), "name example.com port 8443");
        assert_eq!(read("https://user@www.example.com:443/a/b?c#d"), "name www.example.com port 443 (link 443)");
        assert_eq!(read("Http://example.com"), "name example.com (link 80)");
        assert_eq!(read("ftp://example.com"), "name example.com");
        // A link inside the path is not where the host is.
        assert_eq!(read("example.com/go?to=http://other.example"), "name example.com");
        assert_eq!(read("1.2.3.4"), "address 1.2.3.4");
        assert_eq!(read("1.2.3.4."), "address 1.2.3.4");
        assert_eq!(read("1.2.3.4:80"), "address 1.2.3.4 port 80");
        assert_eq!(read("2001:db8::1"), "address 2001:db8::1");
        assert_eq!(read("[2001:db8::1]"), "address 2001:db8::1");
        assert_eq!(read("http://[2001:db8::1]:8080/"), "address 2001:db8::1 port 8080 (link 80)");
        assert_eq!(read("[2001:db8::1]8080"), "nothing");
        assert_eq!(read("a:b:c"), "nothing");
        assert_eq!(read("exa mple.com"), "nothing");
    }
}
