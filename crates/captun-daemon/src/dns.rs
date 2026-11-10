//! Glue between the DNS server and the hub: which DNS server and outbound
//! each device's query goes through, the names each device learns, and the
//! lookup log, which goes to the GUI a few times a second in batches.

use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use captun_core::{EgressKind, time::now_millis};
use captun_dns::{DnsRoute, DnsRouter, Outcome, QueryEvent, QueryObserver};
use captun_ipc::{DnsQueryBatch, DnsQueryLog, Event};
use captun_policy::{Admission, Lookup};
use tracing::warn;

use crate::{
    engine_glue::local_now,
    hub::{Hub, lock},
};

/// How often the lookups go to the GUI, together.
const LOOKUPS_EVERY: Duration = Duration::from_millis(250);
/// The most lookups waiting for the GUI; past it the oldest are left out,
/// and counted.
const LOOKUPS_KEPT: usize = 500;
/// The most they may take written out, so that a batch stays far below what
/// one message to the GUI may carry (`captun_ipc::MAX_FRAME_BYTES`), however
/// long the answers.
const LOOKUPS_BYTES: usize = 1024 * 1024;

/// Holds the hub weakly so the DNS server never keeps it alive past shutdown.
struct Router(Weak<Hub>);

impl DnsRouter for Router {
    fn route(&self, client: IpAddr, name: &str) -> Option<DnsRoute> {
        let hub = self.0.upgrade()?;
        // A device neither the device list nor the neighbor table knows gets
        // no answer, rather than one fetched the default way (which may not be
        // the one chosen for it); it is known within moments and asks again.
        let mac = hub.device_at(client)?;
        let policy = hub.policy();
        // Only a device let in is answered: one waiting for approval would
        // otherwise get online over DNS alone (a DNS tunnel). It gets REFUSED,
        // as a blocked device and one held back by the device limit do. The
        // blocklist and overrides are answered before this is asked, so a
        // sign-in page could still be given a name through an override.
        if policy.admission(&mac) != Admission::Allowed {
            return None;
        }
        // Queries leave the way the device's rules send the name (its own
        // outbound unless a rule says otherwise), so DNS never leaks around a
        // proxy, a VPN or a chosen network adapter, and a name sent through
        // one is looked up through it too. Only the plain direct way out may
        // fall back to this computer's own DNS, which is what it would use
        // anyway. Through a network adapter that DNS would go this computer's
        // own way instead, around the adapter: a failure there is SERVFAIL,
        // as through a proxy.
        let (egress, blocked, rule) = match policy.decide_lookup(Some(&mac), name, local_now()) {
            Lookup::Block { rule } => (policy.egress_for(&mac).clone(), true, Some(rule)),
            Lookup::Through { egress, rule } => (egress, false, rule),
        };
        if let Some(rule) = rule {
            policy.hits().lookup(rule, now_millis());
        }
        let upstream = policy.dns_upstream_for(&mac).to_owned();
        let outbound = hub.outbounds().get(&egress)?.clone();
        let system_fallback =
            matches!(hub.config().egress(&egress).map(|e| &e.kind), Some(EgressKind::Direct { interface: None }));
        Some(DnsRoute { upstream, outbound, client: Some(mac), system_fallback, blocked })
    }
}

/// Teaches each device the names it looks up, and keeps the lookups for the
/// GUI while one is connected and the lookup log is on.
struct Observer {
    hub: Weak<Hub>,
    lookups: Arc<Mutex<Lookups>>,
}

impl Observer {
    /// An observer for `hub`'s DNS, with the task that sends its lookups to
    /// the GUI. The task ends with the observer, which lives as long as the
    /// DNS it watches, or with the hub.
    fn start(hub: &Arc<Hub>) -> Self {
        let lookups = Arc::new(Mutex::new(Lookups::default()));
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => drop(runtime.spawn(send_lookups(Arc::downgrade(hub), Arc::downgrade(&lookups)))),
            // The service always starts its DNS on its runtime.
            Err(_) => warn!("the DNS started outside the service's runtime; its lookups are not shown"),
        }
        Self { hub: Arc::downgrade(hub), lookups }
    }
}

impl QueryObserver for Observer {
    fn on_query(&self, event: QueryEvent) {
        let Some(hub) = self.hub.upgrade() else { return };
        // Only a device let in learns names: one waiting for approval, or
        // blocked, cannot open connections, so its names would only take room.
        if !event.addrs.is_empty()
            && matches!(event.outcome, Outcome::NoError | Outcome::Cached | Outcome::System)
            && let Some(mac) = event.client
            && hub.policy().admission(&mac) == Admission::Allowed
        {
            hub.learn_name(mac, &event.name, &event.addrs);
        }
        if !hub.has_listeners() || !hub.config().dns.log_queries {
            return;
        }
        lock(&self.lookups).push(DnsQueryLog {
            at_ms: event.at_ms,
            client: event.client,
            client_ip: event.client_ip,
            name: event.name,
            qtype: event.qtype,
            outcome: event.outcome.to_string(),
            answers: event.answers,
            upstream: event.upstream,
            latency_ms: event.latency_ms,
        });
    }
}

/// Every [`LOOKUPS_EVERY`], sends the lookups that came in as one batch, when
/// any did and a GUI is connected. One message per lookup could flood the
/// connection and the window on a busy network.
async fn send_lookups(hub: Weak<Hub>, lookups: Weak<Mutex<Lookups>>) {
    let mut tick = tokio::time::interval(LOOKUPS_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let (Some(hub), Some(lookups)) = (hub.upgrade(), lookups.upgrade()) else { return };
        // Taken whoever listens, so what came in for a GUI that left does
        // not reach the next one as old news.
        let batch = lock(&lookups).take();
        if let Some(batch) = batch
            && hub.has_listeners()
        {
            hub.emit(Event::DnsQueries(batch));
        }
    }
}

/// Lookups waiting for the next batch, oldest first, each with what it takes
/// written out, and how many were left out since the last batch.
#[derive(Debug, Default)]
struct Lookups {
    entries: VecDeque<(DnsQueryLog, usize)>,
    bytes: usize,
    dropped: u32,
}

impl Lookups {
    fn push(&mut self, entry: DnsQueryLog) {
        let size = written_size(&entry);
        self.entries.push_back((entry, size));
        self.bytes += size;
        while self.entries.len() > LOOKUPS_KEPT || self.bytes > LOOKUPS_BYTES {
            let Some((_, size)) = self.entries.pop_front() else { break };
            self.bytes = self.bytes.saturating_sub(size);
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// The batch to send, if anything came in since the last one. Its count
    /// of lookups left out is for this batch alone.
    fn take(&mut self) -> Option<DnsQueryBatch> {
        if self.entries.is_empty() && self.dropped == 0 {
            return None;
        }
        self.bytes = 0;
        let entries = self.entries.drain(..).map(|(entry, _)| entry).collect();
        Some(DnsQueryBatch { entries, dropped: std::mem::take(&mut self.dropped) })
    }
}

/// What `entry` takes written out for the GUI, or a little more, never less:
/// its texts as JSON writes them (a control character takes six bytes), and
/// room for the rest.
fn written_size(entry: &DnsQueryLog) -> usize {
    /// Field names, numbers, the hardware address and the device's address.
    const REST: usize = 256;
    let text = |text: &str| {
        2 + text
            .bytes()
            .map(|b| match b {
                b'"' | b'\\' => 2,
                0..=0x1f => 6,
                _ => 1,
            })
            .sum::<usize>()
    };
    REST + text(&entry.name)
        + text(&entry.qtype)
        + text(&entry.outcome)
        + entry.upstream.as_deref().map_or(0, text)
        + entry.answers.iter().map(|answer| text(answer) + 1).sum::<usize>()
}

pub(crate) fn router(hub: &Arc<Hub>) -> Arc<dyn DnsRouter> {
    Arc::new(Router(Arc::downgrade(hub)))
}

pub(crate) fn observer(hub: &Arc<Hub>) -> Arc<dyn QueryObserver> {
    Arc::new(Observer::start(hub))
}

#[cfg(test)]
mod tests {
    use captun_core::{
        ClientState, Config, MacAddr, ObservedClient,
        config::{DnsConfig, DnsOverride},
    };
    use captun_dns::{DnsHandler, DnsSettings, Transport};
    use captun_ipc::{FrameError, FrameWriter, MAX_FRAME_BYTES, Request, ServerFrame};
    use tokio::{
        io::AsyncReadExt,
        sync::broadcast::{self, error::TryRecvError},
    };

    use super::*;

    /// 01 approved through a network adapter that is not there, 02 blocked,
    /// 03 waiting for approval (no settings), 04 approved, going out directly.
    const DEVICES: &str = r#"
        [network]
        default_egress = "direct"
        quarantine_new_clients = true

        [[egress]]
        id = "direct"
        type = "direct"

        [[egress]]
        id = "cable"
        type = "direct"
        interface = "Captun test adapter that is not there"

        [[client]]
        mac = "02:00:00:00:00:01"
        state = "approved"
        egress = "cable"

        [[client]]
        mac = "02:00:00:00:00:02"
        state = "blocked"

        [[client]]
        mac = "02:00:00:00:00:04"
        state = "approved"

        [[rule]]
        domains = ["ads.example"]
        action = "reject"
    "#;

    /// Where each of them is.
    const AT: [(&str, u8); 4] = [("10.0.0.5", 1), ("10.0.0.6", 2), ("10.0.0.7", 3), ("10.0.0.8", 4)];

    /// The test devices' hardware addresses, 02:00:00:00:00:nn.
    const fn device(n: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, n])
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// A hub whose device list has the devices online at their addresses,
    /// with the neighbor table agreeing, and no GUI connected.
    fn hub() -> Arc<Hub> {
        let (events, _) = broadcast::channel(16);
        let hub = Hub::new(None, Config::from_toml(DEVICES).unwrap(), captun_platform::default_backend(), events, None);
        let observed: Vec<ObservedClient> =
            AT.iter().map(|(at, n)| ObservedClient { mac: device(*n), addrs: vec![ip(at)], hostname: None }).collect();
        lock(&hub.registry).apply_snapshot(&observed, 1);
        hub.neighbors().give(AT.iter().map(|(at, n)| (ip(at), device(*n))));
        hub
    }

    /// The hub's DNS as the service starts it, plus an override for
    /// `printer.home`, so nothing here needs the internet.
    fn handler(hub: &Arc<Hub>, observer: Option<Arc<dyn QueryObserver>>) -> DnsHandler {
        let config = DnsConfig {
            overrides: vec![DnsOverride { domain: "printer.home".parse().unwrap(), addrs: vec![ip("10.1.2.3")] }],
            ..hub.config().dns.clone()
        };
        DnsHandler::new(DnsSettings::from_config(&config).unwrap(), router(hub), observer)
    }

    const NOERROR: u8 = 0;
    const SERVFAIL: u8 = 2;
    const REFUSED: u8 = 5;

    /// An A query for `name`.
    fn query(name: &str) -> Vec<u8> {
        let mut q = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).unwrap());
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    /// The response code `from` gets for an A query for `name`.
    async fn answer_code(handler: &DnsHandler, from: &str, name: &str) -> u8 {
        let answer = handler.handle(&query(name), ip(from), Transport::Udp).await.unwrap();
        answer[3] & 0x0f
    }

    async fn set_config(hub: &Arc<Hub>, config: Config) {
        hub.handle(Request::SetConfig(Box::new(config))).await.unwrap();
    }

    #[tokio::test]
    async fn a_device_waiting_for_approval_is_refused_until_let_in() {
        let hub = hub();
        let dns = handler(&hub, None);
        let route = |from: &str, name: &str| router(&hub).route(ip(from), name);
        // Waiting (03), blocked (02): refused, whatever the name.
        for from in ["10.0.0.7", "10.0.0.6"] {
            assert!(route(from, "example.com").is_none(), "{from}");
            assert_eq!(answer_code(&dns, from, "x.ads.example").await, REFUSED, "{from}");
        }
        // The overrides are still answered.
        assert_eq!(answer_code(&dns, "10.0.0.7", "printer.home").await, NOERROR);

        // Let in, it is answered: here as its rules block the name.
        let mut config = (*hub.config()).clone();
        config.client_mut(device(3)).state = ClientState::Approved;
        set_config(&hub, config).await;
        assert!(route("10.0.0.7", "example.com").is_some());
        assert!(route("10.0.0.7", "x.ads.example").unwrap().blocked);
        assert_ne!(answer_code(&dns, "10.0.0.7", "x.ads.example").await, REFUSED);

        // Held back by the device limit: refused again.
        let mut config = (*hub.config()).clone();
        config.hotspot.max_clients = Some(1);
        set_config(&hub, config).await;
        assert!(hub.update_capacity(&[device(4), device(3)]));
        assert!(route("10.0.0.7", "example.com").is_none(), "held back by the device limit");
        assert!(route("10.0.0.8", "example.com").is_some());
    }

    /// Keeps what the DNS says about each query.
    #[derive(Default)]
    struct Seen(Mutex<Vec<QueryEvent>>);

    impl QueryObserver for Seen {
        fn on_query(&self, event: QueryEvent) {
            lock(&self.0).push(event);
        }
    }

    #[tokio::test]
    async fn only_the_plain_direct_way_out_falls_back_to_this_computers_dns() {
        let hub = hub();
        let through_adapter = router(&hub).route(ip("10.0.0.5"), "example.com").unwrap();
        assert_eq!((through_adapter.outbound.id().as_str(), through_adapter.system_fallback), ("cable", false));
        let direct = router(&hub).route(ip("10.0.0.8"), "example.com").unwrap();
        assert_eq!((direct.outbound.id().as_str(), direct.system_fallback), ("direct", true));

        // The adapter is not there, so its DNS server cannot be reached: the
        // device is told the lookup failed, and this computer's DNS, which
        // would go out its own way, is not asked.
        let seen = Arc::new(Seen::default());
        let dns = handler(&hub, Some(seen.clone()));
        assert_eq!(answer_code(&dns, "10.0.0.5", "example.com").await, SERVFAIL);
        let outcomes: Vec<Outcome> = lock(&seen.0).iter().map(|event| event.outcome).collect();
        assert_eq!(outcomes, [Outcome::Failed]);
    }

    /// An answer to `mac` at its address giving `addrs` for `name`.
    fn answered(mac: u8, name: &str, addrs: &[IpAddr], outcome: Outcome) -> QueryEvent {
        let at = AT.iter().find(|(_, n)| *n == mac).map_or("10.0.0.99", |(at, _)| *at);
        QueryEvent {
            at_ms: u64::from(mac),
            client: Some(device(mac)),
            client_ip: ip(at),
            name: name.into(),
            qtype: "A".into(),
            outcome,
            answers: addrs.iter().map(|addr| format!("A {addr}")).collect(),
            addrs: addrs.to_vec(),
            upstream: Some("cloudflare".into()),
            latency_ms: 3,
        }
    }

    #[tokio::test]
    async fn only_a_device_let_in_learns_the_names_it_looks_up() {
        let hub = hub();
        let observer = Observer::start(&hub);
        let chat = [ip("157.240.1.53")];
        for mac in [1, 2, 3, 4] {
            observer.on_query(answered(mac, "g.whatsapp.net", &chat, Outcome::NoError));
        }
        let learned = |mac| hub.name_for(device(mac), chat[0]).map(|name| name.to_string());
        assert_eq!(learned(1).as_deref(), Some("g.whatsapp.net"));
        assert_eq!(learned(4).as_deref(), Some("g.whatsapp.net"));
        assert_eq!(learned(2), None, "blocked");
        assert_eq!(learned(3), None, "waiting for approval");

        // A failed lookup teaches nothing, a cached one does.
        observer.on_query(answered(4, "other.example", &chat, Outcome::Failed));
        assert_eq!(learned(4).as_deref(), Some("g.whatsapp.net"));
        observer.on_query(answered(4, "cached.example", &chat, Outcome::Cached));
        assert_eq!(learned(4).as_deref(), Some("cached.example"));
    }

    /// The lookups of the batches that reach `events` within `wait`.
    async fn batches(events: &mut broadcast::Receiver<Event>, wait: Duration) -> Vec<DnsQueryBatch> {
        let deadline = tokio::time::Instant::now() + wait;
        let mut seen = Vec::new();
        while let Ok(event) = tokio::time::timeout_at(deadline, events.recv()).await {
            if let Ok(Event::DnsQueries(batch)) = event {
                seen.push(batch);
            }
        }
        seen
    }

    fn times(batch: &DnsQueryBatch) -> Vec<u64> {
        batch.entries.iter().map(|entry| entry.at_ms).collect()
    }

    #[tokio::test]
    async fn lookups_reach_the_gui_in_batches_and_only_while_one_is_connected() {
        let hub = hub();
        let observer = Observer::start(&hub);
        // No GUI: nothing is kept for one.
        observer.on_query(answered(4, "early.example", &[], Outcome::NxDomain));
        assert!(lock(&observer.lookups).entries.is_empty());

        let mut events = hub.subscribe();
        for mac in [1, 3, 4] {
            observer.on_query(answered(mac, "example.com", &[], Outcome::NoError));
        }
        // Not one message per lookup: one batch, oldest first, a tick later.
        assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
        let seen = batches(&mut events, 6 * LOOKUPS_EVERY).await;
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!((times(&seen[0]), seen[0].dropped), (vec![1, 3, 4], 0));

        // Nothing goes with the lookup log off.
        let mut config = (*hub.config()).clone();
        config.dns.log_queries = false;
        set_config(&hub, config).await;
        observer.on_query(answered(4, "quiet.example", &[], Outcome::NoError));
        assert!(batches(&mut events, 4 * LOOKUPS_EVERY).await.is_empty());

        // The observer alone holds its lookups, and the task that sends them
        // ends once they are gone: it ends with the DNS it watches.
        let held = Arc::downgrade(&observer.lookups);
        drop(observer);
        assert!(held.upgrade().is_none());
        let lookups = Arc::new(Mutex::new(Lookups::default()));
        let task = tokio::spawn(send_lookups(Arc::downgrade(&hub), Arc::downgrade(&lookups)));
        tokio::time::sleep(2 * LOOKUPS_EVERY).await;
        assert!(!task.is_finished(), "it sends while the lookups are there");
        drop(lookups);
        tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
    }

    fn lookup(at_ms: u64, answers: Vec<String>) -> DnsQueryLog {
        DnsQueryLog {
            at_ms,
            client: None,
            client_ip: ip("10.0.0.5"),
            name: "example.com".into(),
            qtype: "TXT".into(),
            outcome: "NOERROR".into(),
            answers,
            upstream: None,
            latency_ms: 1,
        }
    }

    /// The line `frame` is written as for the GUI, as the service's
    /// connection writes it, or why it cannot be.
    async fn written(frame: &ServerFrame) -> Result<Vec<u8>, FrameError> {
        let (mut ours, theirs) = tokio::io::duplex(2 * MAX_FRAME_BYTES);
        let mut writer = FrameWriter::<_, ServerFrame>::new(theirs);
        writer.send(frame).await?;
        drop(writer);
        let mut line = Vec::new();
        ours.read_to_end(&mut line).await?;
        Ok(line)
    }

    fn batch_of(entries: Vec<DnsQueryLog>) -> ServerFrame {
        ServerFrame::Event { event: Event::DnsQueries(DnsQueryBatch { entries, dropped: 0 }) }
    }

    #[test]
    fn a_batch_keeps_the_newest_lookups_and_counts_the_rest() {
        let mut lookups = Lookups::default();
        assert_eq!(lookups.take(), None, "nothing came in");
        let total = LOOKUPS_KEPT as u64 + 20;
        for at in 0..total {
            lookups.push(lookup(at, Vec::new()));
        }
        let batch = lookups.take().unwrap();
        assert_eq!((batch.entries.len(), batch.dropped), (LOOKUPS_KEPT, 20));
        assert_eq!(times(&batch), (20..total).collect::<Vec<_>>());
        assert_eq!(lookups.take(), None, "each lookup goes once, and so does the count");
    }

    #[tokio::test]
    async fn a_batch_of_long_answers_still_goes_as_one_message() {
        let mut lookups = Lookups::default();
        // Each character of these answers takes six bytes written out.
        let long = vec![format!("TXT {}", "\u{1}".repeat(8 * 1024))];
        for at in 0..200 {
            lookups.push(lookup(at, long.clone()));
        }
        let batch = lookups.take().unwrap();
        assert!(batch.dropped > 0 && batch.entries.len() + batch.dropped as usize == 200, "{}", batch.dropped);
        assert_eq!(batch.entries.last().map(|entry| entry.at_ms), Some(199), "the newest are kept");
        let line = written(&batch_of(batch.entries)).await.unwrap();
        assert!(line.len() <= LOOKUPS_BYTES + 256, "{}", line.len());
    }

    #[tokio::test]
    async fn a_lookup_is_counted_at_no_less_than_it_takes_written_out() {
        let tricky = DnsQueryLog {
            at_ms: u64::MAX,
            client: Some(MacAddr::new([0xff; 6])),
            client_ip: ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            name: "quote\"back\\slash.example".into(),
            qtype: "TXT".into(),
            outcome: "NOERROR".into(),
            answers: vec!["TXT \u{0}\u{1f}\u{7f}\n\t\"é😀".into(), String::new(), "A 1.2.3.4".into()],
            upstream: Some("my \"dns\"".into()),
            latency_ms: u32::MAX,
        };
        let plain = lookup(1, vec!["A 93.184.215.14".into()]);
        // What one lookup adds to a batch's line.
        let empty = written(&batch_of(Vec::new())).await.unwrap().len();
        for entry in [tricky, plain] {
            let alone = written(&batch_of(vec![entry.clone()])).await.unwrap().len() - empty;
            assert!(written_size(&entry) >= alone, "{} < {alone} for {entry:?}", written_size(&entry));
        }
    }
}
