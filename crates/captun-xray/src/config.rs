//! Turns parsed VPN links into Xray-core's JSON configuration: one loopback
//! SOCKS5 inbound per outbound (random credentials, UDP on), routed 1:1 to
//! that outbound, and a blackhole for anything that matches no rule, so the
//! sidecar can never send traffic out on its own.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};

use captun_core::link::{Security, Transport, TransportKind, VpnLink, VpnProtocol, xray_settings_problem};
use serde_json::{Map, Value, json};

/// Outbound files are small; anything larger is not one.
const MAX_OUTBOUND_FILE: u64 = 256 * 1024;
/// How long reading the outbound files may take, all of them together. A file
/// on this computer's own drive takes milliseconds; another program can make
/// opening it wait for as long as it likes (an opportunistic lock it never
/// lets go), and the service, which reads them while applying settings, must
/// not wait with it.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// What reads one file: [`read_outbound_file`], or a stand-in in tests.
type Reader = fn(&Path) -> Result<String, String>;

/// One file's read, running on a thread of its own; whoever asks for the same
/// file while it runs waits for it.
#[derive(Default)]
struct Slot {
    result: Mutex<Option<Result<String, String>>>,
    done: Condvar,
}

/// The reads running now, by file. A read stuck on a held file is not started
/// again while it lasts, so applying settings again and again leaves at most
/// one stuck thread per file.
static READING: Mutex<Vec<(PathBuf, Arc<Slot>)>> = Mutex::new(Vec::new());

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The JSON outbound for one VPN link (without its tag).
pub fn outbound_for_link(link: &VpnLink) -> Value {
    let (protocol, settings) = match &link.protocol {
        VpnProtocol::Vless { id, flow, encryption } => {
            let mut user = json!({ "id": id.expose(), "encryption": encryption });
            if let Some(flow) = flow {
                user["flow"] = json!(flow);
            }
            ("vless", json!({ "vnext": [{ "address": link.host, "port": link.port, "users": [user] }] }))
        }
        VpnProtocol::Vmess { id, cipher } => (
            "vmess",
            json!({ "vnext": [{ "address": link.host, "port": link.port, "users": [{ "id": id.expose(), "security": cipher }] }] }),
        ),
        VpnProtocol::Trojan { password } => (
            "trojan",
            json!({ "servers": [{ "address": link.host, "port": link.port, "password": password.expose() }] }),
        ),
        VpnProtocol::Shadowsocks { method, password } => (
            "shadowsocks",
            json!({ "servers": [{ "address": link.host, "port": link.port, "method": method, "password": password.expose() }] }),
        ),
        VpnProtocol::Hysteria2 { .. } => {
            ("hysteria", json!({ "version": 2, "address": link.host, "port": link.port }))
        }
    };

    let mut outbound = json!({ "protocol": protocol, "settings": settings });
    if !matches!(link.protocol, VpnProtocol::Shadowsocks { .. }) {
        outbound["streamSettings"] = stream_settings(link);
    }
    outbound
}

fn set(map: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(value) = value {
        map.insert(key.into(), json!(value));
    }
}

fn stream_settings(link: &VpnLink) -> Value {
    let t = &link.transport;
    let mut stream = Map::new();
    let network = match t.kind {
        TransportKind::Tcp => "tcp",
        TransportKind::Ws => "ws",
        TransportKind::Grpc => "grpc",
        TransportKind::HttpUpgrade => "httpupgrade",
        TransportKind::Xhttp => "xhttp",
        TransportKind::Kcp => "kcp",
        TransportKind::Hysteria => "hysteria",
    };
    stream.insert("network".into(), json!(network));
    if let Some((key, value)) = transport_settings(link, t) {
        stream.insert(key.into(), value);
    }

    match &link.security {
        Security::None => {
            stream.insert("security".into(), json!("none"));
        }
        Security::Tls(tls) => {
            let mut s = Map::new();
            set(&mut s, "serverName", &tls.server_name);
            if !tls.alpn.is_empty() {
                s.insert("alpn".into(), json!(tls.alpn));
            }
            set(&mut s, "fingerprint", &tls.fingerprint);
            set(&mut s, "pinnedPeerCertSha256", &tls.pinned_cert_sha256);
            set(&mut s, "verifyPeerCertByName", &tls.verify_name);
            stream.insert("security".into(), json!("tls"));
            stream.insert("tlsSettings".into(), Value::Object(s));
        }
        Security::Reality(r) => {
            let mut s = Map::new();
            set(&mut s, "serverName", &r.server_name);
            // REALITY needs a browser fingerprint; Chrome's is the usual default.
            s.insert("fingerprint".into(), json!(r.fingerprint.as_deref().unwrap_or("chrome")));
            s.insert("publicKey".into(), json!(r.public_key));
            set(&mut s, "shortId", &r.short_id);
            set(&mut s, "spiderX", &r.spider_x);
            set(&mut s, "mldsa65Verify", &r.mldsa65_verify);
            stream.insert("security".into(), json!("reality"));
            stream.insert("realitySettings".into(), Value::Object(s));
        }
    }

    if let VpnProtocol::Hysteria2 { obfs_password: Some(password), .. } = &link.protocol {
        stream.insert(
            "finalmask".into(),
            json!({ "udp": [{ "type": "salamander", "settings": { "password": password.expose() } }] }),
        );
    }
    Value::Object(stream)
}

fn transport_settings(link: &VpnLink, t: &Transport) -> Option<(&'static str, Value)> {
    let mut s = Map::new();
    let key = match t.kind {
        TransportKind::Tcp => {
            if t.header_type.as_deref() != Some("http") {
                return None;
            }
            let mut request = json!({ "path": [t.path.as_deref().unwrap_or("/")] });
            if let Some(host) = &t.host {
                let hosts: Vec<&str> = host.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
                request["headers"] = json!({ "Host": hosts });
            }
            s.insert("header".into(), json!({ "type": "http", "request": request }));
            "tcpSettings"
        }
        TransportKind::Ws | TransportKind::HttpUpgrade => {
            set(&mut s, "path", &t.path);
            set(&mut s, "host", &t.host);
            if t.kind == TransportKind::Ws { "wsSettings" } else { "httpupgradeSettings" }
        }
        TransportKind::Grpc => {
            set(&mut s, "serviceName", &t.service_name);
            set(&mut s, "authority", &t.authority);
            if t.mode.as_deref() == Some("multi") {
                s.insert("multiMode".into(), json!(true));
            }
            "grpcSettings"
        }
        TransportKind::Xhttp => {
            set(&mut s, "path", &t.path);
            set(&mut s, "host", &t.host);
            set(&mut s, "mode", &t.mode);
            // Parsing already checked it, and this again: a JSON object with
            // nothing in it that makes Xray use files.
            if let Some(extra) = t
                .extra
                .as_deref()
                .and_then(|e| serde_json::from_str::<Value>(e).ok())
                .filter(|e| e.is_object() && xray_settings_problem(e).is_none())
            {
                s.insert("extra".into(), extra);
            }
            "xhttpSettings"
        }
        TransportKind::Kcp => {
            if let Some(header) = &t.header_type {
                s.insert("header".into(), json!({ "type": header }));
            }
            set(&mut s, "seed", &t.seed);
            "kcpSettings"
        }
        TransportKind::Hysteria => {
            let VpnProtocol::Hysteria2 { auth, .. } = &link.protocol else { return None };
            s.insert("version".into(), json!(2));
            s.insert("auth".into(), json!(auth.expose()));
            "hysteriaSettings"
        }
    };
    Some((key, Value::Object(s)))
}

/// Reads a user-supplied outbound file: either one outbound object or a full
/// Xray config, whose first outbound is used. Errors never quote the file's
/// contents, which may hold keys.
///
/// The service reads it with full rights, so it must be an ordinary file on
/// one of this computer's own drives: a network path would make Windows sign
/// in to that computer as the service, and a link could lead anywhere. A read
/// that takes longer than three seconds is given up on, so a caller on an
/// async thread is held up for at most that long.
pub fn outbound_from_file(path: &Path) -> Result<Value, String> {
    outbounds_from_files(&[path]).pop().unwrap_or_else(|| Err(format!("cannot read {}", path.display())))
}

/// [`outbound_from_file`] for several files, one result per path, read at the
/// same time: the three seconds are for all of them together, not for each.
pub(crate) fn outbounds_from_files(paths: &[&Path]) -> Vec<Result<Value, String>> {
    read_all(paths, READ_TIMEOUT, read_outbound_file)
        .into_iter()
        .zip(paths)
        .map(|(text, path)| text.and_then(|text| parse_outbound(path, &text)))
        .collect()
}

fn parse_outbound(path: &Path, text: &str) -> Result<Value, String> {
    let value: Value =
        serde_json::from_str(text).map_err(|e| format!("{} is not valid JSON (line {})", path.display(), e.line()))?;
    let outbound = match value.get("outbounds").and_then(Value::as_array) {
        Some(list) => list.first().cloned(),
        None => Some(value),
    };
    match outbound {
        // Its settings reach Xray as they are, so they get the same check as
        // a link's: nothing that makes Xray use files.
        Some(o) if o.get("protocol").is_some_and(Value::is_string) => match xray_settings_problem(&o) {
            Some(problem) => Err(format!("Captun does not use the outbound in {}: {problem}", path.display())),
            None => Ok(o),
        },
        _ => Err(format!("{} holds no Xray outbound (an object with a \"protocol\")", path.display())),
    }
}

/// Reads every file with `read`, each on a thread of its own, and gives up on
/// those not done within `limit` of the start. A read still stuck then is
/// left to end on its own; only its result is dropped.
fn read_all(paths: &[&Path], limit: Duration, read: Reader) -> Vec<Result<String, String>> {
    let deadline = Instant::now() + limit;
    // All started before any is waited for, so they share the one limit.
    let started: Vec<_> = paths.iter().map(|path| start_read(path, read)).collect();
    started.into_iter().zip(paths).map(|(slot, path)| slot.and_then(|slot| wait_for(&slot, path, deadline))).collect()
}

/// Starts reading `path`, or joins the read of it already running.
fn start_read(path: &Path, read: Reader) -> Result<Arc<Slot>, String> {
    let mut reading = lock(&READING);
    if let Some((_, slot)) = reading.iter().find(|(running, _)| running == path) {
        return Ok(slot.clone());
    }
    let slot = Arc::new(Slot::default());
    let (owned, filled) = (path.to_path_buf(), slot.clone());
    thread::Builder::new()
        .name("xray-outbound-file".into())
        .spawn(move || {
            let result = read(&owned);
            // Off the list first: a later request reads the file afresh.
            lock(&READING).retain(|(_, running)| !Arc::ptr_eq(running, &filled));
            *lock(&filled.result) = Some(result);
            filled.done.notify_all();
        })
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    // Still under the list's lock, so the thread can only take itself off
    // after this.
    reading.push((path.to_path_buf(), slot.clone()));
    Ok(slot)
}

fn wait_for(slot: &Slot, path: &Path, deadline: Instant) -> Result<String, String> {
    let mut result = lock(&slot.result);
    loop {
        if let Some(result) = result.as_ref() {
            return result.clone();
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!(
                "{} could not be read in time: another program is holding it. Close that program, or copy the file to another folder",
                path.display()
            ));
        }
        result = match slot.done.wait_timeout(result, left) {
            Ok((guard, _)) => guard,
            Err(poisoned) => poisoned.into_inner().0,
        };
    }
}

fn read_outbound_file(path: &Path) -> Result<String, String> {
    let file = open_outbound_file(path)?;
    let mut text = String::new();
    file.take(MAX_OUTBOUND_FILE + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if text.len() as u64 > MAX_OUTBOUND_FILE {
        return Err(format!("{} is too large to be an Xray outbound", path.display()));
    }
    Ok(text)
}

fn open_outbound_file(path: &Path) -> Result<fs::File, String> {
    let not_ordinary = || {
        format!(
            "{} is a link, a folder or a synced (cloud) file; copy the Xray config file into an ordinary folder on this computer",
            path.display()
        )
    };
    if !on_local_drive(path) {
        return Err(format!(
            "{}: the Xray config file must be on this computer's own drive, not a network folder",
            path.display()
        ));
    }
    // Refuses pipes and devices before anything opens them (opening a pipe
    // can wait forever).
    let meta = fs::symlink_metadata(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    if is_link(&meta) || !meta.is_file() {
        return Err(not_ordinary());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, SECURITY_IDENTIFICATION};
        // A link is opened as itself, never followed; and should the name
        // still reach a pipe, its server may learn who is reading but cannot
        // act as the service.
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).security_qos_flags(SECURITY_IDENTIFICATION);
    }
    let file = options.open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // What was opened, in case the name was swapped since the look above.
    let meta = file.metadata().map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if is_link(&meta) || !meta.is_file() {
        return Err(not_ordinary());
    }
    Ok(file)
}

/// On Windows, whether `path` starts with a drive letter (`C:\…`), the same
/// rule the settings are checked against: not `\\server\share`, `\\?\` or `\\.\`.
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

fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// One loopback inbound feeding one outbound.
#[derive(Debug)]
pub struct Route<'a> {
    pub tag: &'a str,
    pub outbound: &'a Value,
    pub port: u16,
    pub user: &'a str,
    pub pass: &'a str,
}

/// The whole sidecar configuration.
pub fn full_config(routes: &[Route<'_>]) -> Value {
    let mut inbounds = Vec::with_capacity(routes.len());
    let mut outbounds = vec![json!({ "tag": "unrouted", "protocol": "blackhole" })];
    let mut rules = Vec::with_capacity(routes.len());
    for route in routes {
        let inbound_tag = format!("in-{}", route.tag);
        let outbound_tag = format!("out-{}", route.tag);
        inbounds.push(json!({
            "tag": inbound_tag,
            "listen": "127.0.0.1",
            "port": route.port,
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [{ "user": route.user, "pass": route.pass }],
                "udp": true,
                "ip": "127.0.0.1",
            },
        }));
        let mut outbound = route.outbound.clone();
        if let Some(map) = outbound.as_object_mut() {
            map.insert("tag".into(), json!(outbound_tag));
        }
        outbounds.push(outbound);
        rules.push(json!({ "type": "field", "inboundTag": [inbound_tag], "outboundTag": outbound_tag }));
    }
    json!({
        "log": { "loglevel": "warning", "access": "none" },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "domainStrategy": "AsIs", "rules": rules },
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use captun_core::ShareLink;

    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn outbound(link: &str) -> Value {
        match ShareLink::parse(link).unwrap() {
            ShareLink::Vpn(vpn) => outbound_for_link(&vpn),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn vless_reality_becomes_xray_json() {
        let o = outbound(&format!(
            "vless://{UUID}@203.0.113.7:443?flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&pbk=KEY&sid=ab&type=tcp"
        ));
        assert_eq!(o["protocol"], "vless");
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["encryption"], "none");
        assert_eq!(o["streamSettings"]["security"], "reality");
        assert_eq!(o["streamSettings"]["realitySettings"]["fingerprint"], "chrome");
        assert_eq!(o["streamSettings"]["realitySettings"]["publicKey"], "KEY");
        assert!(o["streamSettings"].get("tcpSettings").is_none());
    }

    #[test]
    fn transports_land_in_their_settings_blocks() {
        let ws = outbound(&format!("vless://{UUID}@h.example:443?type=ws&security=tls&path=%2Fp&host=h.example&pcs=AB"));
        assert_eq!(ws["streamSettings"]["wsSettings"]["path"], "/p");
        assert_eq!(ws["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"], "AB");

        let grpc = outbound(&format!("vless://{UUID}@h.example:443?type=grpc&security=tls&serviceName=svc&mode=multi"));
        assert_eq!(grpc["streamSettings"]["grpcSettings"]["multiMode"], true);

        let xhttp = outbound(&format!("vless://{UUID}@h.example:443?type=xhttp&security=tls&extra=%7B%22a%22%3A1%7D"));
        assert_eq!(xhttp["streamSettings"]["xhttpSettings"]["extra"]["a"], 1);

        let hy = outbound("hysteria2://pw@hy.example:8443?obfs=salamander&obfs-password=ob");
        assert_eq!(hy["protocol"], "hysteria");
        assert_eq!(hy["streamSettings"]["hysteriaSettings"]["auth"], "pw");
        assert_eq!(hy["streamSettings"]["finalmask"]["udp"][0]["settings"]["password"], "ob");

        let ss = outbound("ss://aes-256-gcm:pw@1.2.3.4:8388");
        assert!(ss.get("streamSettings").is_none());
    }

    #[test]
    fn full_config_routes_each_inbound_to_its_own_outbound_and_drops_the_rest() {
        let o = outbound("trojan://pw@t.example:443");
        let config = full_config(&[Route { tag: "a", outbound: &o, port: 40001, user: "u", pass: "p" }]);
        assert_eq!(config["outbounds"][0]["protocol"], "blackhole", "unmatched traffic must go nowhere");
        assert_eq!(config["outbounds"][1]["tag"], "out-a");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["settings"]["auth"], "password");
        assert_eq!(config["routing"]["rules"][0]["inboundTag"][0], "in-a");
        assert_eq!(config["routing"]["rules"][0]["outboundTag"], "out-a");
    }

    #[test]
    fn outbound_files_are_read_without_echoing_them() {
        let dir = std::env::temp_dir().join(format!("captun-xray-file-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let full = dir.join("full.json");
        fs::write(&full, r#"{"outbounds":[{"protocol":"freedom"}]}"#).unwrap();
        assert_eq!(outbound_from_file(&full).unwrap()["protocol"], "freedom");

        let bad = dir.join("bad.json");
        fs::write(&bad, "secret-token-123 not json").unwrap();
        let err = outbound_from_file(&bad).unwrap_err();
        assert!(!err.contains("secret-token-123"), "{err}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn outbound_files_that_make_xray_use_files_are_refused() {
        let dir = std::env::temp_dir().join(format!("captun-xray-files-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cases = [
            (
                r#"{"outbounds":[{"protocol":"vless","streamSettings":{"tlsSettings":{"certificates":[{"KeyFile":"k.pem"}]}}}]}"#,
                "keyFile",
            ),
            (r#"{"protocol":"trojan","streamSettings":{"realitySettings":{"masterKeyLog":"/x"}}}"#, "masterKeyLog"),
            (r#"{"protocol":"freedom","settings":{"redirect":"\\\\host\\share"}}"#, "network"),
        ];
        for (i, (text, named)) in cases.into_iter().enumerate() {
            let file = dir.join(format!("{i}.json"));
            fs::write(&file, text).unwrap();
            let err = outbound_from_file(&file).unwrap_err();
            assert!(err.contains(named), "{text}: {err}");
        }
        let fine = dir.join("fine.json");
        fs::write(&fine, r#"{"protocol":"vless","streamSettings":{"wsSettings":{"path":"//ws"}}}"#).unwrap();
        assert_eq!(outbound_from_file(&fine).unwrap()["protocol"], "vless");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_ordinary_files_are_read() {
        let dir = std::env::temp_dir().join(format!("captun-xray-kinds-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("folder.json")).unwrap();
        let err = outbound_from_file(&dir.join("folder.json")).unwrap_err();
        assert!(err.contains("ordinary folder"), "{err}");
        assert!(outbound_from_file(&dir.join("missing.json")).unwrap_err().starts_with("cannot open"));

        // A link to a good file is refused, wherever it leads.
        let target = dir.join("real.json");
        fs::write(&target, r#"{"protocol":"freedom"}"#).unwrap();
        let link = dir.join("link.json");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&target, &link).is_ok();
        // Making a link on Windows needs a right not every account has.
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&target, &link).is_ok();
        if linked {
            let err = outbound_from_file(&link).unwrap_err();
            assert!(err.contains("is a link"), "{err}");
        }
        assert_eq!(outbound_from_file(&target).unwrap()["protocol"], "freedom");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_that_hang_are_given_up_on_together() {
        fn stuck(_: &Path) -> Result<String, String> {
            thread::sleep(Duration::from_secs(5));
            Ok(r#"{"protocol":"freedom"}"#.into())
        }
        fn quick(_: &Path) -> Result<String, String> {
            Ok("text".into())
        }
        let limit = Duration::from_millis(500);
        let (a, b) = (Path::new("together-held-a.json"), Path::new("together-held-b.json"));

        let started = Instant::now();
        let results = read_all(&[a, b], limit, stuck);
        let took = started.elapsed();
        assert!(took < limit * 2 - Duration::from_millis(100), "one limit for both, not one each: {took:?}");
        for result in results {
            assert!(result.unwrap_err().contains("could not be read in time"));
        }

        let quick_one = Path::new("together-quick.json");
        assert_eq!(read_all(&[quick_one], READ_TIMEOUT, quick), vec![Ok("text".to_owned())]);
    }

    #[test]
    fn a_file_still_held_is_not_read_twice_at_once() {
        static STARTED: AtomicUsize = AtomicUsize::new(0);
        static LET_GO: AtomicBool = AtomicBool::new(false);
        fn held(_: &Path) -> Result<String, String> {
            STARTED.fetch_add(1, Ordering::SeqCst);
            while !LET_GO.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
            Ok("text".into())
        }
        let path = Path::new("held-twice.json");
        let limit = Duration::from_millis(100);

        // Asked for twice in one go, and again while it is still stuck.
        assert!(read_all(&[path, path], limit, held).iter().all(Result::is_err));
        assert!(read_all(&[path], limit, held)[0].is_err());
        assert_eq!(STARTED.load(Ordering::SeqCst), 1, "one stuck read, not three");

        // Let go: a request waiting for it gets its result, and the next
        // one reads the file afresh.
        let waiting = thread::spawn(move || read_all(&[path], Duration::from_secs(10), held));
        let joined = || {
            lock(&READING).iter().find(|(running, _)| running == path).map_or(0, |(_, slot)| Arc::strong_count(slot))
        };
        // The list's and the reading thread's, plus the waiting request's.
        let deadline = Instant::now() + Duration::from_secs(10);
        while joined() < 3 {
            assert!(Instant::now() < deadline, "the request never joined the running read");
            thread::sleep(Duration::from_millis(10));
        }
        LET_GO.store(true, Ordering::SeqCst);
        assert_eq!(waiting.join().unwrap(), vec![Ok("text".to_owned())]);
        assert_eq!(read_all(&[path], READ_TIMEOUT, held), vec![Ok("text".to_owned())]);
        assert_eq!(STARTED.load(Ordering::SeqCst), 2);
    }

    #[cfg(windows)]
    #[test]
    fn network_and_device_paths_are_refused_before_anything_is_opened() {
        for path in [r"\\server\share\outbound.json", r"\\?\C:\outbound.json", r"\\.\pipe\outbound"] {
            let err = outbound_from_file(Path::new(path)).unwrap_err();
            assert!(err.contains("not a network folder"), "{path}: {err}");
        }
    }
}
