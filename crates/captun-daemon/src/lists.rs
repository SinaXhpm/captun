//! The online lists rules use. They are downloaded only when the user asks,
//! through the outbound they pick, one update at a time in the background,
//! kept on disk between runs, and handed to the policy engine already
//! compiled. A saved copy is read only when the rules come to name its list,
//! on a blocking thread and never under a lock. A failed download keeps the
//! copy from before.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use captun_core::{Config, time::now_millis};
use captun_ipc::{ListStatus, ListsProgress};
use captun_outbound::Outbound;
use captun_policy::{
    Lists, RuleList,
    lists::{self, Entry},
};
use tracing::{info, warn};

use crate::hub::lock;

/// The largest list taken, unpacked.
const MAX_LIST_BYTES: usize = 48 * 1024 * 1024;
/// How long one list may take to download, through a slow proxy too.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(180);
/// The first line of every saved list.
pub(crate) const TITLE: &str = "# Captun list";

/// One list as held: the copy in use, and how its last download went.
#[derive(Default)]
struct Held {
    list: Option<Arc<RuleList>>,
    updated_ms: Option<u64>,
    error: Option<String>,
}

/// How far the update under way has got, or else how the last one ended.
#[derive(Clone, Copy, Debug, Default)]
struct Run {
    running: bool,
    done: usize,
    total: usize,
}

pub(crate) struct ListStore {
    dir: PathBuf,
    held: Mutex<HashMap<String, Held>>,
    /// Taken for the whole of an update, so one runs at a time and a press
    /// while one runs starts nothing.
    updating: Arc<tokio::sync::Mutex<()>>,
    run: Arc<Mutex<Run>>,
}

/// An update under way (see [`ListStore::try_start`]). No other starts while
/// it lives, and the lists read as updating until it is dropped, however the
/// update ends.
pub(crate) struct Updating {
    run: Arc<Mutex<Run>>,
    _one_at_a_time: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for Updating {
    fn drop(&mut self) {
        // Before the lock is let go (the fields drop after this), so a new
        // update never has its start undone by this one's end.
        lock(&self.run).running = false;
    }
}

/// Every list link the rules name, each once, in the order they appear.
pub(crate) fn links(config: &Config) -> Vec<String> {
    let mut links: Vec<String> = Vec::new();
    for link in config.rules.iter().flat_map(|rule| &rule.lists) {
        if !links.contains(link) {
            links.push(link.clone());
        }
    }
    links
}

impl ListStore {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            held: Mutex::new(HashMap::new()),
            updating: Arc::new(tokio::sync::Mutex::new(())),
            run: Arc::new(Mutex::new(Run::default())),
        }
    }

    /// The lists `config`'s rules use, compiled: the copies held, shared.
    /// Saved copies not read yet are read here, on this thread, which only
    /// start-up needs (`Hub::new`, before anything is served): every change
    /// reads its own first, with [`Self::load_missing`].
    pub(crate) fn compiled(&self, config: &Config) -> Lists {
        let wanted = links(config);
        for link in self.missing(&wanted) {
            let loaded = load(&self.path_for(&link), &link);
            lock(&self.held).entry(link).or_insert(loaded);
        }
        let held = lock(&self.held);
        wanted
            .into_iter()
            .filter_map(|link| {
                let list = held.get(&link)?.list.clone()?;
                Some((link, list))
            })
            .collect()
    }

    /// Reads the saved copies of the lists `config`'s rules use that are not
    /// held yet, each on a blocking thread and none under the lock: a big list
    /// takes seconds, which must hold up neither the async threads nor anyone
    /// asking about the lists. A copy that came in meanwhile (a download)
    /// stays over the saved one.
    pub(crate) async fn load_missing(&self, config: &Config) {
        for link in self.missing(&links(config)) {
            let (path, key) = (self.path_for(&link), link.clone());
            let loaded = match tokio::task::spawn_blocking(move || load(&path, &key)).await {
                Ok(loaded) => loaded,
                Err(e) => {
                    warn!(url = %link, "the saved copy of an online list was not read: {e}");
                    Held { error: Some("the saved copy could not be read".to_owned()), ..Held::default() }
                }
            };
            lock(&self.held).entry(link).or_insert(loaded);
        }
    }

    /// Those of `wanted` not held yet.
    fn missing(&self, wanted: &[String]) -> Vec<String> {
        let held = lock(&self.held);
        wanted.iter().filter(|link| !held.contains_key(*link)).cloned().collect()
    }

    /// Lets go of the lists no rule of `config` uses any more. Only once
    /// `config` is the one in force: a rebuild still on the rules before (for
    /// the device limit, say) would otherwise read them from disk again.
    pub(crate) fn prune(&self, config: &Config) {
        let wanted = links(config);
        lock(&self.held).retain(|link, _| wanted.contains(link));
    }

    /// Whether anything is held for `link`: a list, or how its download went.
    #[cfg(test)]
    pub(crate) fn holds(&self, link: &str) -> bool {
        lock(&self.held).contains_key(link)
    }

    /// How each list `config`'s rules use stands.
    pub(crate) fn statuses(&self, config: &Config) -> Vec<ListStatus> {
        let held = lock(&self.held);
        links(config)
            .into_iter()
            .map(|url| {
                let entry = held.get(&url);
                let list = entry.and_then(|e| e.list.as_ref());
                ListStatus {
                    names: list.map_or(0, |l| l.names()),
                    addresses: list.map_or(0, |l| l.addresses()),
                    updated_ms: entry.and_then(|e| e.updated_ms),
                    error: entry.and_then(|e| e.error.clone()),
                    url,
                }
            })
            .collect()
    }

    /// How each list `config`'s rules use stands, and how far an update is.
    pub(crate) fn progress(&self, config: &Config) -> ListsProgress {
        let run = *lock(&self.run);
        ListsProgress { updating: run.running, done: run.done, total: run.total, lists: self.statuses(config) }
    }

    /// Starts an update of `total` lists; `None` while one is under way, and
    /// then nothing new starts.
    pub(crate) fn try_start(&self, total: usize) -> Option<Updating> {
        let one_at_a_time = self.updating.clone().try_lock_owned().ok()?;
        *lock(&self.run) = Run { running: true, done: 0, total };
        Some(Updating { run: self.run.clone(), _one_at_a_time: one_at_a_time })
    }

    /// Downloads each of `links` through `outbound`, one after another, and
    /// puts each new copy in use and on disk as it comes. `after_each` runs
    /// once a list is through, told whether a new copy of it is in use. The
    /// update is over (`updating` let go) by the time this returns.
    pub(crate) async fn update(
        &self,
        updating: Updating,
        links: Vec<String>,
        outbound: Arc<dyn Outbound>,
        mut after_each: impl FnMut(bool),
    ) {
        for link in links {
            let renewed = self.update_one(&link, outbound.as_ref()).await;
            lock(&updating.run).done += 1;
            after_each(renewed);
        }
        drop(updating);
    }

    /// Downloads `link` through `outbound` and puts the new copy in use and
    /// on disk; a failed download keeps the copy from before. Whether a new
    /// copy is in use.
    async fn update_one(&self, link: &str, outbound: &dyn Outbound) -> bool {
        let (entries, text) = match download(link, outbound).await {
            Ok(read) => read,
            Err(e) => {
                warn!(url = %link, "online list not updated: {e}");
                lock(&self.held).entry(link.to_owned()).or_default().error = Some(e);
                return false;
            }
        };
        let updated_ms = now_millis();
        let path = self.path_for(link);
        let header = format!("{TITLE}\n# url: {link}\n# updated: {updated_ms}\n");
        // Compiling and writing take a moment for a big list: off the async threads.
        let done = tokio::task::spawn_blocking(move || {
            let saved = save(&path, &header, &text);
            (Arc::new(RuleList::new(&entries)), saved)
        })
        .await;
        let (list, saved) = match done {
            Ok(done) => done,
            Err(e) => {
                warn!(url = %link, "online list not put in use: {e}");
                lock(&self.held).entry(link.to_owned()).or_default().error =
                    Some("the downloaded list could not be used".to_owned());
                return false;
            }
        };
        info!(url = %link, names = list.names(), addresses = list.addresses(), "online list updated");
        let error = saved.err().map(|e| format!("in use, but not saved for next time: {e}"));
        lock(&self.held).insert(link.to_owned(), Held { list: Some(list), updated_ms: Some(updated_ms), error });
        true
    }

    fn path_for(&self, link: &str) -> PathBuf {
        self.dir.join(file_name(link))
    }
}

/// The saved copy of `link` at `path`, if there is one. Reading and
/// compiling a big one takes a while: kept off the async threads and out
/// from under the lock.
fn load(path: &Path, link: &str) -> Held {
    match fs::read_to_string(path) {
        Ok(text) => {
            let header: Vec<&str> = text.lines().take(3).collect();
            // Another link whose file name happens to be the same is not this list.
            if !header.iter().any(|line| line.strip_prefix("# url: ") == Some(link)) {
                return Held::default();
            }
            let updated_ms = header.iter().find_map(|line| line.strip_prefix("# updated: ")?.trim().parse().ok());
            Held { list: Some(Arc::new(RuleList::parse(&text))), updated_ms, error: None }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Held::default(),
        Err(e) => Held { error: Some(format!("the saved copy cannot be read: {e}")), ..Held::default() },
    }
}

/// The name the saved copy of `link` has in the lists folder.
pub(crate) fn file_name(link: &str) -> String {
    format!("{:016x}.list", fnv1a(link))
}

/// A stable name for a link's file (FNV-1a), the same in every build.
fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3))
}

/// The list at `link`, read: its entries, and the same written one per line.
async fn download(link: &str, outbound: &dyn Outbound) -> Result<(Vec<Entry>, String), String> {
    const ANOTHER_WAY: &str = "the source may be blocked this way: pick another outbound under Download through";
    let body = match tokio::time::timeout(DOWNLOAD_TIMEOUT, captun_outbound::fetch(outbound, link, MAX_LIST_BYTES)).await {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => {
            use io::ErrorKind::*;
            return Err(match e.kind() {
                ConnectionRefused | ConnectionReset | ConnectionAborted | TimedOut | HostUnreachable | NetworkUnreachable => {
                    format!("{e} ({ANOTHER_WAY})")
                }
                _ => e.to_string(),
            });
        }
        Err(_) => return Err(format!("no answer within {} seconds ({ANOTHER_WAY})", DOWNLOAD_TIMEOUT.as_secs())),
    };
    tokio::task::spawn_blocking(move || {
        let entries = lists::entries(&String::from_utf8_lossy(&body));
        if entries.is_empty() {
            return Err("the download holds nothing a rule can use; is the link right?".to_owned());
        }
        let text = lists::canonical(&entries);
        Ok((entries, text))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Writes the copy beside its old one, then swaps it in, so a crash midway
/// leaves the old copy whole. The copy is always a new file: whatever was
/// left under its name (by a crash, or a link put there) is removed as
/// itself first, never written through. On Windows Administrators own it,
/// so a later run takes it for the service's own however it was started.
pub(crate) fn save(path: &Path, header: &str, text: &str) -> io::Result<()> {
    use std::io::Write;

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let partial = path.with_extension("partial");
    match fs::remove_file(&partial) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = fs::OpenOptions::new();
    // Fails if anything is there again, a link included (never followed).
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        /// `FILE_FLAG_OPEN_REPARSE_POINT`: a link is opened as itself.
        const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(OPEN_REPARSE_POINT);
    }
    let mut file = options.open(&partial)?;
    file.write_all(header.as_bytes())?;
    file.write_all(text.as_bytes())?;
    drop(file);
    // What the service makes may otherwise belong to the user it runs as (a
    // policy, or the shell it was started from, decides), and a run started
    // another way would then move the copy aside as someone else's. Without
    // administrator rights (a development run, the tests) this fails, and the
    // copy keeps the owner it was made with.
    #[cfg(windows)]
    if let Ok(copy) = captun_ipc::open_for_security(&partial) {
        let _ = captun_ipc::protect(&copy, crate::paths::FILE_SDDL);
    }
    fs::rename(&partial, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
        [network]
        default_egress = "direct"

        [[egress]]
        id = "direct"
        type = "direct"

        [[rule]]
        lists = ["https://lists.example/ads.txt", "https://lists.example/bad-ips.txt"]
        action = "reject"

        [[rule]]
        enabled = false
        lists = ["https://lists.example/ads.txt", "https://lists.example/other.txt"]
        action = "deny"
    "#;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("captun-lists-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn links_are_listed_once_in_order() {
        let config = Config::from_toml(RULES).unwrap();
        assert_eq!(
            links(&config),
            ["https://lists.example/ads.txt", "https://lists.example/bad-ips.txt", "https://lists.example/other.txt"]
        );
    }

    #[test]
    fn a_saved_copy_is_used_on_the_next_run_and_only_for_its_own_link() {
        let dir = temp_dir("saved");
        let config = Config::from_toml(RULES).unwrap();
        let store = ListStore::new(dir.clone());
        let ads = "https://lists.example/ads.txt";
        save(&store.path_for(ads), &format!("# Captun list\n# url: {ads}\n# updated: 1234\n"), "ads.example\n6.6.6.0/24\n").unwrap();
        // A file under another link's name, as if two links shared one.
        let other = "https://lists.example/other.txt";
        save(&store.path_for(other), "# Captun list\n# url: https://elsewhere.example/x\n", "x.example\n").unwrap();

        let compiled = store.compiled(&config);
        assert_eq!(compiled.len(), 1, "only the list saved under its own link");
        let statuses = store.statuses(&config);
        assert_eq!((statuses[0].names, statuses[0].addresses, statuses[0].updated_ms), (1, 1, Some(1234)));
        assert_eq!((statuses[1].names, statuses[1].updated_ms), (0, None), "never downloaded");
        assert_eq!(statuses[2].names, 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_change_reads_the_saved_copies_it_needs_and_keeps_newer_ones() {
        let dir = temp_dir("missing");
        let config = Config::from_toml(RULES).unwrap();
        let store = ListStore::new(dir.clone());
        let (ads, bad_ips) = ("https://lists.example/ads.txt", "https://lists.example/bad-ips.txt");
        let header = |link: &str| format!("{TITLE}\n# url: {link}\n# updated: 1234\n");
        save(&store.path_for(ads), &header(ads), "ads.example\n6.6.6.0/24\n").unwrap();
        save(&store.path_for(bad_ips), &header(bad_ips), "6.6.6.0/24\n").unwrap();
        // A download that came in while the saved copies were being read.
        let fresh = RuleList::new(&lists::entries("fresh.example\nnew.example\n"));
        lock(&store.held)
            .insert(bad_ips.to_owned(), Held { list: Some(Arc::new(fresh)), updated_ms: Some(99), error: None });

        store.load_missing(&config).await;
        let statuses = store.statuses(&config);
        assert_eq!((statuses[0].names, statuses[0].addresses, statuses[0].updated_ms), (1, 1, Some(1234)));
        assert_eq!((statuses[1].names, statuses[1].updated_ms), (2, Some(99)), "the newer copy stays");
        assert_eq!(statuses[2].names, 0, "never downloaded");
        assert_eq!(store.compiled(&config).len(), 2);

        // Once a change that drops a rule is in force, the lists only it
        // used are let go...
        let mut fewer = config.clone();
        fewer.rules.remove(0);
        store.prune(&fewer);
        let mut held: Vec<String> = lock(&store.held).keys().cloned().collect();
        held.sort();
        assert_eq!(held, [ads, "https://lists.example/other.txt"]);
        // ...and a change that names one again reads its saved copy again.
        store.load_missing(&config).await;
        let statuses = store.statuses(&config);
        assert_eq!((statuses[1].addresses, statuses[1].updated_ms), (1, Some(1234)));
        let _ = fs::remove_dir_all(dir);
    }

    /// Serves `body` as the list at lists.example and turns every other
    /// server down, as an outbound would.
    #[derive(Debug)]
    struct Canned {
        id: captun_core::EgressId,
        body: &'static str,
    }

    #[async_trait::async_trait]
    impl Outbound for Canned {
        fn id(&self) -> &captun_core::EgressId {
            &self.id
        }

        async fn connect_tcp(&self, target: &captun_core::TargetAddr) -> io::Result<captun_outbound::BoxStream> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if !matches!(target, captun_core::TargetAddr::Domain(host, 80) if host == "lists.example") {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "the server turned the connection down"));
            }
            let (here, mut there) = tokio::io::duplex(64 * 1024);
            let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", self.body.len(), self.body);
            tokio::spawn(async move {
                let mut request = [0; 1024];
                let _ = there.read(&mut request).await;
                let _ = there.write_all(answer.as_bytes()).await;
            });
            Ok(Box::new(here))
        }

        async fn udp_session(&self) -> io::Result<Box<dyn captun_outbound::UdpSession>> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    #[tokio::test]
    async fn an_update_runs_alone_and_says_how_far_it_is() {
        let dir = temp_dir("update");
        let (ads, down) = ("http://lists.example/ads.txt", "http://down.example/list.txt");
        let config = Config::from_toml(&format!(
            "[network]\ndefault_egress = \"direct\"\n[[egress]]\nid = \"direct\"\ntype = \"direct\"\n[[rule]]\nlists = [\"{ads}\", \"{down}\"]\naction = \"reject\"\n"
        ))
        .unwrap();
        let store = ListStore::new(dir.clone());
        let outbound: Arc<dyn Outbound> = Arc::new(Canned { id: "direct".into(), body: "ads.example\n6.6.6.0/24\n" });

        let updating = store.try_start(2).unwrap();
        assert!(store.try_start(2).is_none(), "one at a time");
        let started = store.progress(&config);
        assert_eq!((started.updating, started.done, started.total), (true, 0, 2));

        let mut seen = Vec::new();
        store
            .update(updating, links(&config), outbound, |renewed| {
                let now = store.progress(&config);
                seen.push((renewed, now.updating, now.done, now.lists[0].names));
                assert!(store.try_start(2).is_none(), "nothing new starts while it runs");
            })
            .await;
        // Each list is in use as soon as it is through, before the next is tried.
        assert_eq!(seen, [(true, true, 1, 1), (false, true, 2, 1)]);

        let over = store.progress(&config);
        assert_eq!((over.updating, over.done, over.total), (false, 2, 2));
        assert_eq!((over.lists[0].names, over.lists[0].addresses, over.lists[0].error.as_deref()), (1, 1, None));
        assert!(over.lists[0].updated_ms.is_some());
        let why = over.lists[1].error.as_deref().unwrap();
        assert!(why.contains("Download through"), "{why}");
        assert_eq!(store.compiled(&config).len(), 1);
        let saved = fs::read_to_string(store.path_for(ads)).unwrap();
        assert!(saved.starts_with(&format!("{TITLE}\n# url: {ads}\n")), "{saved}");

        // An update whose task went away before it finished reads as over too.
        drop(store.try_start(1).unwrap());
        assert!(!store.progress(&config).updating);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_copy_is_written_afresh_never_through_what_was_left_under_its_name() {
        let dir = temp_dir("afresh");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(file_name("https://lists.example/ads.txt"));
        let partial = path.with_extension("partial");
        // Left by a crash midway.
        fs::write(&partial, "half a list").unwrap();
        save(&path, "# Captun list\n", "ads.example\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "# Captun list\nads.example\n");
        assert!(!partial.exists());

        // A link under the unfinished copy's name: removed as a link, and the
        // file it points to stays as it was. (Making one on Windows needs
        // Developer Mode or elevation; without, there is nothing to check.)
        let elsewhere = dir.join("elsewhere.txt");
        fs::write(&elsewhere, "untouched").unwrap();
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&elsewhere, &partial);
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&elsewhere, &partial);
        if linked.is_ok() {
            save(&path, "# Captun list\n", "other.example\n").unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), "# Captun list\nother.example\n");
            assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "untouched");
            assert!(fs::symlink_metadata(&path).unwrap().is_file(), "the copy is a file of its own");
        }
        let _ = fs::remove_dir_all(dir);
    }

    /// Downloads every ready-made list for real, straight out. Run by hand:
    /// `cargo test -p captun-daemon real_lists -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "downloads from the internet"]
    async fn real_lists_download_and_read() {
        let direct = captun_outbound::Direct::new("direct".into(), None);
        let hagezi = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest";
        for link in [
            format!("{hagezi}/wildcard/multi-onlydomains.txt"),
            "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt".into(),
            format!("{hagezi}/wildcard/tif.medium-onlydomains.txt"),
            "https://www.spamhaus.org/drop/drop_v4.json".into(),
            "https://www.spamhaus.org/drop/drop_v6.json".into(),
            format!("{hagezi}/ips/tif.txt"),
            "https://core.telegram.org/resources/cidr.txt".into(),
            "https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/domains.txt".into(),
            "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt".into(),
            "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv6-aggregated.txt".into(),
        ] {
            let started = std::time::Instant::now();
            match download(&link, &direct).await {
                Ok((entries, text)) => {
                    let list = RuleList::new(&entries);
                    println!(
                        "ok   {link}\n     {} names, {} ranges, {} KB on disk, {:?}",
                        list.names(),
                        list.addresses(),
                        text.len() / 1024,
                        started.elapsed()
                    );
                }
                Err(e) => println!("FAIL {link}\n     {e}"),
            }
        }
    }

    #[test]
    fn file_names_stay_the_same_across_builds() {
        assert_eq!(fnv1a(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a("a"), 0xaf63_dc4c_8601_ec8c);
    }
}
