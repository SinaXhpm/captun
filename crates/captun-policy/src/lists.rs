//! Online lists of names and addresses that rules can use: ad and malware
//! blocklists, a country's or a service's addresses. Lists come in many
//! formats (hosts files, adblock filters, dnsmasq, plain lists, Clash and
//! Xray rule files, JSON lines); each line is read for what it names and the
//! rest is skipped. Names are kept as 64-bit fingerprints, so a list of a
//! million names takes megabytes rather than tens of them.
//!
//! A downloaded list is trusted less than what the user typed: it can never
//! name a whole top-level domain, a private or special-use address range, or
//! a range wide enough to sweep up the internet at large.

use std::{
    collections::HashSet,
    fmt::Write as _,
    hash::{BuildHasherDefault, DefaultHasher, Hash, Hasher},
    net::IpAddr,
};

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use ipnet::IpNet;
use captun_core::{
    DomainPattern,
    domain::{is_valid_hostname, normalize_domain},
};

use crate::ranges::RangeSet;

/// Entries one list may hold; the rest of a longer list is ignored.
pub const MAX_ENTRIES: usize = 2_000_000;
/// Keywords one list may hold. They are looked for together, in one pass over
/// a name, by a matcher that grows with them, so they stay few.
const MAX_KEYWORDS: usize = 1000;
/// The shortest keyword a list may use: shorter ones would catch names at random.
const MIN_KEYWORD: usize = 4;
/// The longest: no name is longer, so a longer keyword could never be found.
const MAX_KEYWORD: usize = 253;
/// The widest ranges a list may name.
const MIN_PREFIX_V4: u8 = 8;
const MIN_PREFIX_V6: u8 = 16;

/// Private, local and special-use IPv4 space (network, prefix length).
const SPECIAL_V4: [(u32, u8); 13] = [
    (0x0000_0000, 8),  // 0.0.0.0/8, "this network"
    (0x0A00_0000, 8),  // 10.0.0.0/8
    (0x6440_0000, 10), // 100.64.0.0/10, carrier-grade NAT
    (0x7F00_0000, 8),  // 127.0.0.0/8, loopback
    (0xA9FE_0000, 16), // 169.254.0.0/16, link-local
    (0xAC10_0000, 12), // 172.16.0.0/12
    (0xC000_0000, 24), // 192.0.0.0/24
    (0xC000_0200, 24), // 192.0.2.0/24, documentation
    (0xC0A8_0000, 16), // 192.168.0.0/16
    (0xC612_0000, 15), // 198.18.0.0/15, benchmarking
    (0xC633_6400, 24), // 198.51.100.0/24, documentation
    (0xCB00_7100, 24), // 203.0.113.0/24, documentation
    (0xE000_0000, 3),  // 224.0.0.0/3, multicast, reserved and broadcast
];

/// The same for IPv6.
const SPECIAL_V6: [(u128, u8); 5] = [
    (0, 8),                  // ::/8: unspecified, loopback, IPv4-mapped, NAT64
    (0x2001_0db8 << 96, 32), // 2001:db8::/32, documentation
    (0xfc00 << 112, 7),      // fc00::/7, unique local
    (0xfe80 << 112, 10),     // fe80::/10, link-local
    (0xff00 << 112, 8),      // ff00::/8, multicast
];

/// One thing a list names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// A name pattern, as in a rule's own websites.
    Name(DomainPattern),
    /// A name, with its subdomains, that the list itself leaves out (adblock's
    /// `@@||name^`), although a wider entry covers it.
    Except(String),
    /// An address range.
    Net(IpNet),
}

/// Every entry `text` names, in order, up to [`MAX_ENTRIES`]. Lines that name
/// nothing a list may use are skipped: comments, cosmetic and page filters,
/// regular expressions, private addresses, whole top-level domains.
pub fn entries(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        if is_full(&out) {
            break;
        }
        read_line(line, &mut out);
    }
    // Every entry is added through `push`, which keeps the limit; this keeps
    // the promise above should a new way of adding one ever skip it.
    out.truncate(MAX_ENTRIES);
    out
}

/// The entries one per line, in a form [`entries`] reads back the same, for
/// the copy of a list kept on disk.
pub fn canonical(entries: &[Entry]) -> String {
    let mut out = String::with_capacity(entries.len() * 24);
    for entry in entries {
        let _ = match entry {
            Entry::Name(pattern) => writeln!(out, "{pattern}"),
            Entry::Except(name) => writeln!(out, "@@||{name}^"),
            Entry::Net(net) => writeln!(out, "{net}"),
        };
    }
    out
}

fn read_line(line: &str, out: &mut Vec<Entry>) {
    let line = line.trim().trim_start_matches('\u{feff}');
    // Comments in each format's own style, and adblock's cosmetic filters.
    if line.is_empty()
        || line.starts_with(['#', '!', ';', '['])
        || line.starts_with("//")
        || ["##", "#@#", "#?#", "#$#"].iter().any(|mark| line.contains(mark))
    {
        return;
    }
    // One JSON object per line, as Spamhaus publishes: the address in it.
    if line.starts_with('{') {
        if let Some(net) = line.split('"').find_map(parse_net) {
            push_net(net, out);
        }
        return;
    }
    let line = cut_comment(line).trim();
    // Adblock: `||name^` takes a name and its subdomains, `@@||name^` leaves
    // one out; rules for pages or by regular expression say nothing of names.
    if let Some(rest) = line.strip_prefix("@@||") {
        if let Some(name) = adblock_name(rest) {
            push(Entry::Except(name), out);
        }
        return;
    }
    if let Some(rest) = line.strip_prefix("||") {
        if let Some(name) = adblock_name(rest) {
            push(Entry::Name(DomainPattern::Suffix(name)), out);
        }
        return;
    }
    if line.starts_with(['@', '|', '/']) {
        return;
    }
    // dnsmasq: `address=/name/0.0.0.0`, `server=/name/…`, `local=/name/`.
    // Every part but the last is a name. They are read as they come rather
    // than gathered first, since one line may hold millions of them.
    for prefix in ["address=/", "server=/", "local=/"] {
        if let Some(rest) = line.strip_prefix(prefix) {
            if let Some((names, _)) = rest.rsplit_once('/') {
                for name in names.split('/') {
                    push_pattern(name, out);
                    if is_full(out) {
                        break;
                    }
                }
            }
            return;
        }
    }
    // Clash rules, in a YAML list or not: `DOMAIN-SUFFIX,name`, `DOMAIN,name`,
    // `DOMAIN-KEYWORD,word`, `IP-CIDR,range,no-resolve`. Any other line with
    // commas is read by its first field.
    let line = line.strip_prefix("- ").unwrap_or(line).trim().trim_matches(['\'', '"']);
    let line = match line.split_once(',') {
        Some((kind, rest)) => {
            let value = rest.split(',').next().unwrap_or("").trim();
            match kind.trim().to_ascii_uppercase().as_str() {
                "DOMAIN-SUFFIX" => return push_pattern(value, out),
                "DOMAIN" => return push_pattern(&format!("full:{value}"), out),
                "DOMAIN-KEYWORD" => return push_pattern(&format!("keyword:{value}"), out),
                "IP-CIDR" | "IP-CIDR6" => {
                    if let Some(net) = parse_net(value) {
                        push_net(net, out);
                    }
                    return;
                }
                _ => kind.trim(),
            }
        }
        None => line,
    };
    let mut words = line.split_whitespace();
    let Some(first) = words.next() else { return };
    // A hosts file: an address, then the names given to it, as many as the
    // line holds.
    if first.parse::<IpAddr>().is_ok() {
        let mut named = false;
        for word in words {
            named = true;
            push_pattern(word, out);
            if is_full(out) {
                break;
            }
        }
        if named {
            return;
        }
    }
    if let Some(net) = parse_net(first) {
        push_net(net, out);
        return;
    }
    // Xray and V2Ray lists put attributes (`@ads`) after the entry; their
    // `regexp:` and `include:` entries are not followed. Clash and Surge
    // write a name with its subdomains as `+.name` or `.name`.
    if first.starts_with("regexp:") || first.starts_with("include:") {
        return;
    }
    let first = first.strip_prefix("+.").or_else(|| first.strip_prefix('.')).unwrap_or(first);
    push_pattern(first, out);
}

/// The line up to a trailing comment (` # …`, or `; …` as in Spamhaus' text files).
fn cut_comment(line: &str) -> &str {
    let end = [line.find(" #"), line.find("\t#"), line.find(';')].into_iter().flatten().min().unwrap_or(line.len());
    &line[..end]
}

/// The name in an adblock rule after its `||`, when the rule is about that
/// name as a whole: no path, no wildcard and no options but `important`.
fn adblock_name(rest: &str) -> Option<String> {
    let (body, options) = rest.split_once('$').unwrap_or((rest, ""));
    if !(options.is_empty() || options == "important") {
        return None;
    }
    let body = body.trim_end_matches('|');
    let name = body.strip_suffix('^').unwrap_or(body);
    if name.contains(['*', '/', ':', '^', '|']) {
        return None;
    }
    let name = normalize_domain(name);
    (is_valid_hostname(&name) && is_list_name(&name)).then(|| name.into_owned())
}

/// Adds `entry` while the list has room. The limit is kept here and not only
/// between lines, because one line may name any number of entries: a hosts
/// line can give one address millions of names.
fn push(entry: Entry, out: &mut Vec<Entry>) {
    if !is_full(out) {
        out.push(entry);
    }
}

fn is_full(out: &[Entry]) -> bool {
    out.len() >= MAX_ENTRIES
}

fn push_pattern(value: &str, out: &mut Vec<Entry>) {
    let Ok(pattern) = value.parse::<DomainPattern>() else { return };
    let usable = match &pattern {
        DomainPattern::Suffix(name) | DomainPattern::Full(name) => is_list_name(name),
        DomainPattern::Keyword(word) => is_list_keyword(word),
    };
    if usable {
        push(Entry::Name(pattern), out);
    }
}

/// A keyword a downloaded list may use: long enough not to catch names at
/// random, and no longer than a name, made only of what a name (in lower
/// case, as every name is matched) can hold. Any other could never be found
/// in a real name, and would only cost room and time.
fn is_list_keyword(word: &str) -> bool {
    (MIN_KEYWORD..=MAX_KEYWORD).contains(&word.len())
        && word.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'_'))
}

/// A name a downloaded list may use: under a top-level domain, never one as
/// a whole, nor an address written as a name, nor a name for this computer.
fn is_list_name(name: &str) -> bool {
    let Some((_, top)) = name.rsplit_once('.') else { return false };
    !top.bytes().all(|b| b.is_ascii_digit()) && !matches!(top, "local" | "localdomain" | "localhost")
}

fn parse_net(text: &str) -> Option<IpNet> {
    let text = text.trim();
    text.parse::<IpNet>().ok().map(|net| net.trunc()).or_else(|| text.parse::<IpAddr>().ok().map(IpNet::from))
}

fn push_net(net: IpNet, out: &mut Vec<Entry>) {
    if is_public_range(&net) {
        push(Entry::Net(net), out);
    }
}

/// A range a downloaded list may name: no wider than a /8 (/16 for IPv6),
/// and clear of private, local and special-use space, so that no list can cut
/// devices off from this computer or the home network.
fn is_public_range(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => {
            let (start, end) = (u32::from(n.network()), u32::from(n.broadcast()));
            n.prefix_len() >= MIN_PREFIX_V4
                && SPECIAL_V4.iter().all(|&(base, len)| {
                    let last = base | u32::MAX.checked_shr(u32::from(len)).unwrap_or(0);
                    end < base || last < start
                })
        }
        IpNet::V6(n) => {
            let (start, end) = (u128::from(n.network()), u128::from(n.broadcast()));
            n.prefix_len() >= MIN_PREFIX_V6
                && SPECIAL_V6.iter().all(|&(base, len)| {
                    let last = base | u128::MAX.checked_shr(u32::from(len)).unwrap_or(0);
                    end < base || last < start
                })
        }
    }
}

/// A set of name fingerprints. They are hashes already, so the set uses them
/// as they are.
type Fingerprints = HashSet<u64, BuildHasherDefault<AsIs>>;

#[derive(Default)]
struct AsIs(u64);

impl Hasher for AsIs {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

fn fingerprint(name: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    hasher.finish()
}

/// Whether `name`, or a domain above it, is in `set`. `whole` is `name`'s own
/// fingerprint, worked out once by the caller for every set it asks.
fn in_set(set: &Fingerprints, name: &str, whole: u64) -> bool {
    !set.is_empty()
        && (set.contains(&whole) || name.match_indices('.').any(|(i, _)| set.contains(&fingerprint(&name[i + 1..]))))
}

/// A list ready to match against, built once per download and shared by every
/// rule that uses it.
#[derive(Debug, Default)]
pub struct RuleList {
    /// Names that count with their subdomains.
    suffixes: Fingerprints,
    /// Names that count exactly.
    exact: Fingerprints,
    /// Every keyword, looked for all at once in one pass over a name, however
    /// many there are; `None` when the list has none.
    keywords: Option<AhoCorasick>,
    /// Names the list leaves out, with their subdomains.
    except: Fingerprints,
    ranges: RangeSet,
    names: usize,
    addresses: usize,
}

impl RuleList {
    pub fn new(entries: &[Entry]) -> Self {
        let mut list = Self::default();
        let mut seen = HashSet::new();
        let mut keywords = Vec::new();
        let mut nets = Vec::new();
        for entry in entries {
            match entry {
                Entry::Name(DomainPattern::Suffix(name)) => {
                    list.suffixes.insert(fingerprint(name));
                }
                Entry::Name(DomainPattern::Full(name)) => {
                    list.exact.insert(fingerprint(name));
                }
                // Checked again here, since entries can be made by hand too:
                // the matcher's size rests on these limits.
                Entry::Name(DomainPattern::Keyword(word)) => {
                    if keywords.len() < MAX_KEYWORDS && is_list_keyword(word) && seen.insert(word.as_str()) {
                        keywords.push(word.as_str());
                    }
                }
                Entry::Except(name) => {
                    list.except.insert(fingerprint(name));
                }
                Entry::Net(net) => nets.push(*net),
            }
        }
        // Always the contiguous NFA: it grows with the keywords' length, about
        // 13 bytes per byte. The DFA the builder would pick for up to 100
        // keywords takes 20 times that for long ones (6 MB for 100 of
        // MAX_KEYWORD bytes), a size a list could reach on purpose. Names are
        // short, so the DFA's speed would hardly show.
        // Building fails only past limits far beyond MAX_KEYWORDS keywords of
        // MAX_KEYWORD bytes each; were it to, the list would go without them,
        // and its count would say so.
        if !keywords.is_empty() {
            list.keywords = AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                .build(&keywords)
                .ok();
        }
        let keyword_count = list.keywords.as_ref().map_or(0, AhoCorasick::patterns_len);
        list.suffixes.shrink_to_fit();
        list.exact.shrink_to_fit();
        list.except.shrink_to_fit();
        list.names = list.suffixes.len() + list.exact.len() + keyword_count;
        list.addresses = nets.len();
        list.ranges = RangeSet::new(&nets);
        list
    }

    /// Reads a list in any of the formats [`entries`] knows.
    pub fn parse(text: &str) -> Self {
        Self::new(&entries(text))
    }

    /// Names the list holds (patterns, not counting the ones it leaves out).
    pub fn names(&self) -> usize {
        self.names
    }

    /// Address ranges the list holds, as written in it.
    pub fn addresses(&self) -> usize {
        self.addresses
    }

    pub(crate) fn has_names(&self) -> bool {
        self.names > 0
    }

    pub(crate) fn matches_name(&self, name: &str) -> bool {
        if self.names == 0 {
            return false;
        }
        let name = normalize_domain(name);
        let name = name.as_ref();
        let whole = fingerprint(name);
        let listed = self.exact.contains(&whole)
            || in_set(&self.suffixes, name, whole)
            || self.keywords.as_ref().is_some_and(|keywords| keywords.is_match(name));
        listed && !in_set(&self.except, name, whole)
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        !self.ranges.is_empty() && self.ranges.contains(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names_of(text: &str) -> Vec<String> {
        entries(text)
            .into_iter()
            .map(|e| match e {
                Entry::Name(p) => p.to_string(),
                Entry::Except(n) => format!("except {n}"),
                Entry::Net(n) => n.to_string(),
            })
            .collect()
    }

    #[test]
    fn every_common_format_is_read() {
        let text = "\
# a hosts file
0.0.0.0 0.0.0.0
127.0.0.1 localhost localhost.localdomain
0.0.0.0 ads.example.com tracker.example.net # two names
:: v6.example.org
! adblock
||adserver.example^
||Banner.Example.ORG^$important
@@||ok.adserver.example^
||thirdparty.example^$third-party
||path.example^/ads
/regex-ads/
example.com##.banner
address=/dnsmasq.example/0.0.0.0
server=/a.example/b.example/1.2.3.4
DOMAIN-SUFFIX,clash.example
  - DOMAIN,full.clash.example
- DOMAIN-KEYWORD,adwords
IP-CIDR,8.8.4.0/24,no-resolve
domain:xray.example @ads
full:exact.example
regexp:^ads\\.
include:other
+.surge.example
.dot.example
1.2.3.0/24 ; SBL1
{\"cidr\":\"5.6.0.0/16\",\"sblid\":\"SBL2\",\"rir\":\"ripe\"}
{\"type\":\"metadata\",\"timestamp\":1700000000}
9.9.9.9
plain.example
";
        assert_eq!(
            names_of(text),
            [
                "ads.example.com",
                "tracker.example.net",
                "v6.example.org",
                "adserver.example",
                "banner.example.org",
                "except ok.adserver.example",
                "dnsmasq.example",
                "a.example",
                "b.example",
                "clash.example",
                "full:full.clash.example",
                "keyword:adwords",
                "8.8.4.0/24",
                "xray.example",
                "full:exact.example",
                "surge.example",
                "dot.example",
                "1.2.3.0/24",
                "5.6.0.0/16",
                "9.9.9.9/32",
                "plain.example",
            ]
        );
    }

    #[test]
    fn a_list_cannot_reach_local_space_or_whole_domains() {
        let text = "\
com
||ir^
10.0.0.0/8
192.168.137.1
172.20.0.0/16
100.64.1.0/24
169.254.0.0/16
224.0.0.1
0.0.0.0/0
1.0.0.0/7
fd00::/8
fe80::1
::1
2001:db8::/48
2000::/3
keyword:ad
0.0.0.0 printer.local
";
        assert_eq!(names_of(text), Vec::<String>::new());
        // A public range next to private space is fine; one reaching into it is not.
        assert_eq!(names_of("11.0.0.0/8\n172.0.0.0/8\n2a0a:f280::/32"), ["11.0.0.0/8", "2a0a:f280::/32"]);
    }

    #[test]
    fn names_match_with_subdomains_and_exceptions() {
        let list = RuleList::parse("ads.example\nfull:exact.example\nkeyword:tracker\n@@||ok.ads.example^\n5.6.0.0/16");
        assert_eq!((list.names(), list.addresses()), (3, 1));
        for hit in ["ads.example", "x.y.ADS.example.", "exact.example", "cdn.tracker-net.io"] {
            assert!(list.matches_name(hit), "{hit} should match");
        }
        for miss in ["notads.example", "sub.exact.example", "ok.ads.example", "a.ok.ads.example", "example"] {
            assert!(!list.matches_name(miss), "{miss} should not match");
        }
        assert!(list.contains("5.6.7.8".parse().unwrap()));
        assert!(!list.contains("5.7.0.0".parse().unwrap()));
        assert!(!RuleList::default().matches_name("ads.example"));
    }

    #[test]
    fn the_copy_on_disk_reads_back_the_same() {
        let first = entries("0.0.0.0 a.example\n||b.example^\n@@||c.b.example^\nfull:d.example\nkeyword:track\n1.2.3.0/24\n2a0a:f280::/32");
        assert_eq!(entries(&canonical(&first)), first);
    }

    #[test]
    fn dnsmasq_lines_name_every_part_but_the_last() {
        let text = "local=/l.example/\naddress=/x.example\nserver=/a.example//b.example/1.1.1.1\naddress=/\nserver=//c.example/";
        assert_eq!(names_of(text), ["l.example", "a.example", "b.example", "c.example"]);
    }

    /// One line naming more than a list may hold stops at the limit while it
    /// is read. It is the last line, so nothing after it could stop it either.
    #[test]
    fn one_line_cannot_pass_the_entry_limit() {
        let kept = Entry::Name(DomainPattern::Suffix("a.io".into()));
        let more: String = (0..10).map(|i| format!(" b{i}.io")).collect();
        let hosts = format!("0.0.0.0{}{more}", " a.io".repeat(MAX_ENTRIES));
        let read = entries(&hosts);
        assert_eq!(read.len(), MAX_ENTRIES);
        assert!(read.iter().all(|entry| *entry == kept), "the first names are the ones kept");
        drop((hosts, read));

        let more: String = (0..10).map(|i| format!("b{i}.io/")).collect();
        let dnsmasq = format!("address=/{}{more}0.0.0.0", "a.io/".repeat(MAX_ENTRIES));
        let read = entries(&dnsmasq);
        assert_eq!(read.len(), MAX_ENTRIES);
        assert!(read.iter().all(|entry| *entry == kept), "the first names are the ones kept");
    }

    #[test]
    fn a_keyword_is_found_anywhere_in_a_name() {
        let list = RuleList::parse("keyword:tracker\nkeyword:track\nkeyword:tracker\n@@||ok.tracker.io^");
        assert_eq!(list.names(), 2, "a keyword given twice counts once");
        for hit in ["cdn.tracker-net.io", "tracker.io", "adtracker", "x.TRACKING.example."] {
            assert!(list.matches_name(hit), "{hit} should match");
        }
        for miss in ["trac.io", "tra-cker.io", "ok.tracker.io", "a.ok.tracker.io"] {
            assert!(!list.matches_name(miss), "{miss} should not match");
        }
    }

    #[test]
    fn keywords_that_could_never_be_found_are_skipped() {
        let longest = "k".repeat(MAX_KEYWORD);
        let text = format!(
            "keyword:{longest}\nkeyword:{longest}k\nkeyword:ads*\nkeyword:ad/s\nkeyword:\u{e4}ds-x\nkeyword:Track_Er.x-1\n\
             - DOMAIN-KEYWORD,ad$serv\nDOMAIN-KEYWORD,adserv\nkeyword:abc\n"
        );
        assert_eq!(names_of(&text), [format!("keyword:{longest}"), "keyword:track_er.x-1".into(), "keyword:adserv".into()]);
        // Entries made by hand are held to the same limits.
        let by_hand = [
            Entry::Name(DomainPattern::Keyword("k".repeat(MAX_KEYWORD + 1))),
            Entry::Name(DomainPattern::Keyword("ad serv".into())),
            Entry::Name(DomainPattern::Keyword("ads".into())),
        ];
        assert_eq!(RuleList::new(&by_hand).names(), 0);
    }

    #[test]
    fn a_thousand_keywords_are_found_in_one_pass() {
        let mut text: String = (0..MAX_KEYWORDS).map(|i| format!("keyword:kw{i:04}\n")).collect();
        // One past the limit, and one already there: neither is added.
        text.push_str("keyword:overflow\nkeyword:kw0007\n");
        let list = RuleList::parse(&text);
        assert_eq!(list.names(), MAX_KEYWORDS);
        for hit in ["kw0000.example", "x.kw0999.example", "akw0500b.io", "cdn-kw0042.net", "X.KW0001.Example."] {
            assert!(list.matches_name(hit), "{hit} should match");
        }
        for miss in ["kw1000.example", "kw099.example", "k.w0001.io", "overflow.example", "example.com"] {
            assert!(!list.matches_name(miss), "{miss} should not match");
        }
    }

    /// The keywords a hostile list could pick to make the matcher as big as it
    /// can: as many and as long as allowed, sharing nothing. Its size stays in
    /// step with theirs, with no jump at any count.
    #[test]
    fn the_keyword_matcher_stays_small() {
        const ALLOWED: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-._";
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut word = || -> String {
            (0..MAX_KEYWORD)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    char::from(ALLOWED[(seed % ALLOWED.len() as u64) as usize])
                })
                .collect()
        };
        for count in [1, 100, 101, MAX_KEYWORDS] {
            let words: Vec<String> = (0..count).map(|_| word()).collect();
            let text: String = words.iter().map(|w| format!("keyword:{w}\n")).collect();
            let list = RuleList::parse(&text);
            assert_eq!(list.names(), count);
            let matcher = list.keywords.as_ref().unwrap();
            assert!(
                matcher.memory_usage() <= 16 * count * MAX_KEYWORD + 64 * 1024,
                "{count} keywords take {} bytes",
                matcher.memory_usage()
            );
            let last = &words[count - 1];
            assert!(list.matches_name(&format!("x.{last}.io")));
            assert!(!list.matches_name(&format!("x.{}.io", &last[1..])));
        }
    }
}
