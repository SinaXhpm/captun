//! Share links: the one-line `scheme://…` form proxy and VPN-link providers
//! hand out. Parsing here only understands the link; turning a VPN link into
//! Xray's configuration is the sidecar's job, and plain proxies become native
//! [`EgressKind`]s.
//!
//! Links come from the clipboard, so everything is treated as untrusted:
//! bounded in size, decoded strictly, and rejected with a plain reason.

use std::fmt;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{EgressKind, Secret, TargetAddr, domain::is_valid_hostname};

/// Longer than any real link (REALITY + xhttp extras stay well under 4 KiB).
const MAX_LINK_LEN: usize = 8 * 1024;

/// Schemes run by the Xray sidecar.
pub const VPN_LINK_SCHEMES: [&str; 6] = ["vless", "vmess", "trojan", "ss", "hysteria2", "hy2"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct LinkError(String);

fn err<T>(message: impl Into<String>) -> Result<T, LinkError> {
    Err(LinkError(message.into()))
}

/// Xray settings that make it open a file on this computer: a TLS client
/// certificate or key to read, or a log of TLS session keys to write.
const XRAY_FILE_SETTINGS: [&str; 3] = ["certificateFile", "keyFile", "masterKeyLog"];

/// Why settings for Xray from a VPN link or an outbound file are not passed on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XraySettingsProblem {
    /// A setting that makes Xray read or write a file on this computer.
    #[error("\"{0}\" makes Xray read or write a file on this computer")]
    UsesFile(&'static str),
    /// A value starting with two slashes (`\\server\share`, `//server/share`,
    /// `\\.\device`): Windows signs in to a network path with the user's
    /// account.
    #[error("a setting names a network or device path")]
    NetworkPath,
    /// A name with other characters than ASCII, which could spell one of the
    /// file settings to Xray (see [`xray_settings_problem`]).
    #[error("a setting's name has characters Xray's settings never use")]
    UnusualName,
}

/// Why `value`, settings for Xray that a VPN link or an outbound file holds,
/// must not reach Xray, if it must not. A link comes from whoever shared it,
/// and Xray runs with the service's rights on Windows (at low integrity, so
/// it can still read what an administrator can) and as the user elsewhere.
/// So nothing in it may make Xray open files here: no setting in
/// [`XRAY_FILE_SETTINGS`] at any depth, and no value starting with two
/// slashes either way, except a URL `path`. Xray reads its settings with
/// Go's JSON, which matches names ignoring case, Unicode case folding
/// included ("ſ" is an "s" to it, the Kelvin sign "K" a "k"), so names are
/// compared ignoring ASCII case and names with other characters are refused.
pub fn xray_settings_problem(value: &serde_json::Value) -> Option<XraySettingsProblem> {
    use serde_json::Value;
    // Each value with the name it is under; an array's items are under the
    // array's name. Parsed JSON is at most 128 levels deep.
    let mut pending = vec![(None, value)];
    while let Some((name, value)) = pending.pop() {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    if !key.is_ascii() {
                        return Some(XraySettingsProblem::UnusualName);
                    }
                    if let Some(setting) = XRAY_FILE_SETTINGS.iter().copied().find(|s| s.eq_ignore_ascii_case(key)) {
                        return Some(XraySettingsProblem::UsesFile(setting));
                    }
                    pending.push((Some(key.as_str()), inner));
                }
            }
            Value::Array(items) => pending.extend(items.iter().map(|item| (name, item))),
            Value::String(text) if !name.is_some_and(|n| n.eq_ignore_ascii_case("path")) => {
                let mut start = text.trim_start().chars();
                if matches!((start.next(), start.next()), (Some('\\' | '/'), Some('\\' | '/'))) {
                    return Some(XraySettingsProblem::NetworkPath);
                }
            }
            _ => {}
        }
    }
    None
}

/// A parsed share link.
#[derive(Debug, Clone, PartialEq)]
pub enum ShareLink {
    /// `socks5://`, `socks5h://` or `socks://`.
    Socks5 { server: TargetAddr, username: Option<String>, password: Option<Secret>, name: Option<String> },
    /// `http://` or `https://` (the proxy itself is reached over TLS).
    Http { server: TargetAddr, username: Option<String>, password: Option<Secret>, tls: bool, name: Option<String> },
    Vpn(Box<VpnLink>),
}

/// A link for a protocol the Xray sidecar carries.
#[derive(Debug, Clone, PartialEq)]
pub struct VpnLink {
    pub protocol: VpnProtocol,
    pub host: String,
    pub port: u16,
    /// The name after `#`, as the provider labelled the server.
    pub name: Option<String>,
    pub transport: Transport,
    pub security: Security,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VpnProtocol {
    Vless { id: Secret, flow: Option<String>, encryption: String },
    Vmess { id: Secret, cipher: String },
    Trojan { password: Secret },
    Shadowsocks { method: String, password: Secret },
    Hysteria2 { auth: Secret, obfs_password: Option<Secret> },
}

impl VpnProtocol {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Vless { .. } => "VLESS",
            Self::Vmess { .. } => "VMess",
            Self::Trojan { .. } => "Trojan",
            Self::Shadowsocks { .. } => "Shadowsocks",
            Self::Hysteria2 { .. } => "Hysteria2",
        }
    }
}

/// How the protocol's bytes travel (Xray's `network`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transport {
    pub kind: TransportKind,
    pub host: Option<String>,
    pub path: Option<String>,
    /// gRPC service name.
    pub service_name: Option<String>,
    /// gRPC `multi`, or the xhttp mode.
    pub mode: Option<String>,
    /// gRPC `:authority`.
    pub authority: Option<String>,
    /// mKCP / TCP header obfuscation (`none`, `http`, …).
    pub header_type: Option<String>,
    /// mKCP seed.
    pub seed: Option<String>,
    /// xhttp `extra`: a JSON object, checked to parse as one and to hold
    /// nothing that makes Xray use files ([`xray_settings_problem`]).
    pub extra: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransportKind {
    #[default]
    Tcp,
    Ws,
    Grpc,
    HttpUpgrade,
    Xhttp,
    Kcp,
    /// QUIC, used by Hysteria2.
    Hysteria,
}

impl TransportKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Ws => "WebSocket",
            Self::Grpc => "gRPC",
            Self::HttpUpgrade => "HTTPUpgrade",
            Self::Xhttp => "XHTTP",
            Self::Kcp => "mKCP",
            Self::Hysteria => "QUIC",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Security {
    #[default]
    None,
    Tls(TlsOptions),
    Reality(RealityOptions),
}

impl Security {
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls(_) => "TLS",
            Self::Reality(_) => "REALITY",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsOptions {
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
    /// SHA-256 of the server's certificate, for self-signed servers.
    pub pinned_cert_sha256: Option<String>,
    /// Check the certificate against this name instead of the SNI (`vcn`).
    pub verify_name: Option<String>,
    /// The link asked to skip certificate checks. Xray no longer allows that,
    /// so validation turns this into a clear error instead of a silent hole.
    pub insecure: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RealityOptions {
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    pub public_key: String,
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
    pub mldsa65_verify: Option<String>,
}

/// What the GUI shows about a pasted link before it is saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkSummary {
    /// The outbound type the link becomes: `socks5`, `http` or `xray`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The protocol in plain words, e.g. "VLESS" or "HTTPS proxy".
    pub protocol: String,
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Plain proxies only: the password, so the form can be filled in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl fmt::Display for VpnLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} via {}", self.protocol.label(), self.transport.kind.label())?;
        if self.security != Security::None {
            write!(f, " + {}", self.security.label())?;
        }
        Ok(())
    }
}

impl ShareLink {
    pub fn parse(link: &str) -> Result<Self, LinkError> {
        let link = link.trim();
        if link.is_empty() {
            return err("the link is empty");
        }
        if link.len() > MAX_LINK_LEN {
            return err("the link is too long");
        }
        if link.chars().any(char::is_control) {
            return err("the link contains control characters");
        }
        let Some((scheme, _)) = link.split_once("://") else {
            return err("this is not a link: it should start with something like vless:// or socks5://");
        };
        match scheme.to_ascii_lowercase().as_str() {
            "socks5" | "socks5h" | "socks" => parse_proxy(link, false),
            "http" => parse_proxy(link, false),
            "https" => parse_proxy(link, true),
            "vmess" => parse_vmess(link),
            "ss" => parse_shadowsocks(link),
            "vless" | "trojan" | "hysteria2" | "hy2" => parse_url_link(link),
            other => err(format!(
                "links starting with {other}:// are not supported; use socks5, http, https, vless, vmess, trojan, ss or hysteria2"
            )),
        }
    }

    /// The outbound kind a link becomes. VPN links keep the original text,
    /// which the sidecar re-parses, so nothing is lost in translation.
    pub fn to_egress_kind(&self, original: &str) -> EgressKind {
        match self {
            Self::Socks5 { server, username, password, .. } => EgressKind::Socks5 {
                server: server.clone(),
                username: username.clone(),
                password: password.clone(),
                via: None,
            },
            Self::Http { server, username, password, tls, .. } => EgressKind::Http {
                server: server.clone(),
                username: username.clone(),
                password: password.clone(),
                tls: *tls,
                via: None,
            },
            Self::Vpn(_) => EgressKind::Xray { link: Some(Secret::new(original.trim())), config_file: None },
        }
    }

    pub fn summary(&self) -> LinkSummary {
        match self {
            Self::Socks5 { server, username, password, name } => LinkSummary {
                kind: "socks5".into(),
                protocol: "SOCKS5 proxy".into(),
                server: server.to_string(),
                name: name.clone(),
                transport: None,
                security: None,
                username: username.clone(),
                password: password.clone(),
                tls: false,
            },
            Self::Http { server, username, password, tls, name } => LinkSummary {
                kind: "http".into(),
                protocol: if *tls { "HTTPS proxy" } else { "HTTP proxy" }.into(),
                server: server.to_string(),
                name: name.clone(),
                transport: None,
                security: tls.then(|| "TLS".into()),
                username: username.clone(),
                password: password.clone(),
                tls: *tls,
            },
            Self::Vpn(vpn) => LinkSummary {
                kind: "xray".into(),
                protocol: vpn.protocol.label().into(),
                server: host_port(&vpn.host, vpn.port),
                name: vpn.name.clone(),
                transport: Some(vpn.transport.kind.label().into()),
                security: (vpn.security != Security::None).then(|| vpn.security.label().into()),
                username: None,
                password: None,
                tls: false,
            },
        }
    }
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// Checks a host from a link: a hostname or an IP address, nothing else.
fn check_host(host: &str) -> Result<String, LinkError> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return Ok(bare.to_owned());
    }
    if is_valid_hostname(bare) {
        return Ok(bare.to_ascii_lowercase());
    }
    err(format!("{host:?} is not a valid server address"))
}

fn target(host: &str, port: u16) -> TargetAddr {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => TargetAddr::Ip(std::net::SocketAddr::new(ip, port)),
        Err(_) => TargetAddr::Domain(host.to_owned(), port),
    }
}

fn url_host_port(url: &Url, default_port: Option<u16>) -> Result<(String, u16), LinkError> {
    let host = match url.host_str() {
        Some(h) if !h.is_empty() => check_host(h)?,
        _ => return err("the link has no server address"),
    };
    let port = match url.port().or(default_port) {
        Some(0) | None => return err("the link has no server port"),
        Some(p) => p,
    };
    Ok((host, port))
}

fn decode(component: &str) -> Result<String, LinkError> {
    percent_encoding::percent_decode_str(component)
        .decode_utf8()
        .map(|s| s.into_owned())
        .or_else(|_| err("the link has text that is not valid UTF-8"))
}

fn fragment(url: &Url) -> Option<String> {
    url.fragment().and_then(|f| decode(f).ok()).map(|f| f.trim().to_owned()).filter(|f| !f.is_empty())
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

fn parse_url(link: &str) -> Result<Url, LinkError> {
    Url::parse(link).or_else(|e| err(format!("the link is malformed ({e})")))
}

fn parse_proxy(link: &str, tls: bool) -> Result<ShareLink, LinkError> {
    let url = parse_url(link)?;
    let scheme = url.scheme().to_owned();
    let default_port = match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        _ => Some(1080),
    };
    let (host, port) = url_host_port(&url, default_port)?;
    let server = target(&host, port);
    let username = non_empty(Some(decode(url.username())?));
    let password = url.password().map(decode).transpose()?.filter(|p| !p.is_empty()).map(Secret::new);
    if password.is_some() && username.is_none() {
        return err("the link has a password but no username");
    }
    let name = fragment(&url);
    Ok(if scheme.starts_with("socks") {
        ShareLink::Socks5 { server, username, password, name }
    } else {
        ShareLink::Http { server, username, password, tls, name }
    })
}

/// Query parameters, decoded. Repeated keys keep the last value.
struct Query(Vec<(String, String)>);

impl Query {
    fn of(url: &Url) -> Self {
        Self(url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect())
    }

    fn get(&self, key: &str) -> Option<String> {
        self.0.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.trim().to_owned()).filter(|v| !v.is_empty())
    }

    fn flag(&self, key: &str) -> bool {
        matches!(self.get(key).as_deref(), Some("1" | "true" | "True" | "TRUE"))
    }
}

fn transport_from(kind: &str, q: &Query) -> Result<Transport, LinkError> {
    let kind = match kind.to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => TransportKind::Tcp,
        "ws" | "websocket" => TransportKind::Ws,
        "grpc" | "gun" => TransportKind::Grpc,
        "httpupgrade" => TransportKind::HttpUpgrade,
        "xhttp" | "splithttp" => TransportKind::Xhttp,
        "kcp" | "mkcp" => TransportKind::Kcp,
        "h2" | "http" => return err("this link uses the HTTP/2 transport, which Xray has removed; ask for an XHTTP link"),
        "quic" => return err("this link uses the QUIC transport, which Xray has removed; ask for an XHTTP link"),
        other => return err(format!("the link uses an unknown transport {other:?}")),
    };
    let extra = q.get("extra");
    if let Some(extra) = &extra {
        let Some(settings) = serde_json::from_str::<serde_json::Value>(extra).ok().filter(serde_json::Value::is_object)
        else {
            return err("the link's xhttp \"extra\" settings are not a JSON object");
        };
        if let Some(problem) = xray_settings_problem(&settings) {
            return err(format!("Captun does not use this link's xhttp \"extra\" settings: {problem}"));
        }
    }
    Ok(Transport {
        kind,
        host: q.get("host"),
        path: q.get("path"),
        service_name: q.get("serviceName"),
        mode: q.get("mode"),
        authority: q.get("authority"),
        header_type: q.get("headerType"),
        seed: q.get("seed"),
        extra,
    })
}

fn split_list(value: Option<String>) -> Vec<String> {
    value
        .map(|v| v.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

fn security_from(kind: &str, q: &Query, sni_fallback: Option<&str>) -> Result<Security, LinkError> {
    let server_name = q.get("sni").or_else(|| q.get("peer")).or_else(|| sni_fallback.map(str::to_owned));
    let fingerprint = q.get("fp");
    match kind.to_ascii_lowercase().as_str() {
        "" | "none" => Ok(Security::None),
        "tls" | "xtls" => Ok(Security::Tls(TlsOptions {
            server_name,
            alpn: split_list(q.get("alpn")),
            fingerprint,
            pinned_cert_sha256: q.get("pcs").or_else(|| q.get("pinnedPeerCertSha256")).or_else(|| q.get("pinSHA256")),
            verify_name: q.get("vcn").or_else(|| q.get("verifyPeerCertByName")),
            insecure: q.flag("allowInsecure") || q.flag("insecure"),
        })),
        "reality" => {
            let Some(public_key) = q.get("pbk").or_else(|| q.get("password")) else {
                return err("the REALITY link has no public key (pbk)");
            };
            Ok(Security::Reality(RealityOptions {
                server_name,
                fingerprint,
                public_key,
                short_id: q.get("sid"),
                spider_x: q.get("spx"),
                mldsa65_verify: q.get("pqv"),
            }))
        }
        other => err(format!("the link uses an unknown security setting {other:?}")),
    }
}

/// `vless://`, `trojan://` and `hysteria2://`: credentials in the user part,
/// everything else in the query.
fn parse_url_link(link: &str) -> Result<ShareLink, LinkError> {
    let url = parse_url(link)?;
    let scheme = url.scheme().to_ascii_lowercase();
    let q = Query::of(&url);
    let (host, port) = url_host_port(&url, if scheme.starts_with("hy") { Some(443) } else { None })?;
    let user = decode(url.username())?;
    let name = fragment(&url);

    let (protocol, transport, security) = match scheme.as_str() {
        "vless" => {
            check_uuid(&user)?;
            let flow = q.get("flow");
            let encryption = q.get("encryption").unwrap_or_else(|| "none".into());
            let transport = transport_from(&q.get("type").unwrap_or_default(), &q)?;
            let security = security_from(&q.get("security").unwrap_or_default(), &q, None)?;
            if flow.is_some() && !matches!(transport.kind, TransportKind::Tcp) {
                return err("the link asks for an XTLS flow over a transport other than TCP, which Xray does not allow");
            }
            (VpnProtocol::Vless { id: Secret::new(user), flow, encryption }, transport, security)
        }
        "trojan" => {
            if user.is_empty() {
                return err("the Trojan link has no password");
            }
            let transport = transport_from(&q.get("type").unwrap_or_default(), &q)?;
            // Trojan without TLS is not Trojan; providers often leave it implied.
            let security = security_from(&q.get("security").unwrap_or_else(|| "tls".into()), &q, None)?;
            (VpnProtocol::Trojan { password: Secret::new(user) }, transport, security)
        }
        _ => {
            // hysteria2://auth@host:port — the auth may also be user:pass.
            let auth = match url.password() {
                Some(pass) => format!("{user}:{}", decode(pass)?),
                None => user,
            };
            if auth.is_empty() {
                return err("the Hysteria2 link has no password");
            }
            let obfs_password = match q.get("obfs").as_deref() {
                None | Some("none") => None,
                Some("salamander") => match q.get("obfs-password") {
                    Some(p) => Some(Secret::new(p)),
                    None => return err("the Hysteria2 link turns on obfuscation without its password"),
                },
                Some(other) => return err(format!("the Hysteria2 link uses an unknown obfuscation {other:?}")),
            };
            let mut tls = TlsOptions {
                server_name: q.get("sni").or_else(|| Some(host.clone())),
                alpn: vec!["h3".into()],
                fingerprint: None,
                pinned_cert_sha256: q.get("pinSHA256").or_else(|| q.get("pcs")),
                verify_name: q.get("vcn"),
                insecure: q.flag("insecure") || q.flag("allowInsecure"),
            };
            if let Some(alpn) = q.get("alpn") {
                tls.alpn = split_list(Some(alpn));
            }
            let transport = Transport { kind: TransportKind::Hysteria, ..Transport::default() };
            (VpnProtocol::Hysteria2 { auth: Secret::new(auth), obfs_password }, transport, Security::Tls(tls))
        }
    };
    Ok(ShareLink::Vpn(Box::new(VpnLink { protocol, host, port, name, transport, security })))
}

fn check_uuid(id: &str) -> Result<(), LinkError> {
    let bytes = id.as_bytes();
    let canonical = bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    // Xray also maps any 1-30 character string to a UUID (v5); allow that form.
    let custom = (1..=30).contains(&id.len()) && id.chars().all(|c| !c.is_whitespace());
    if canonical || custom { Ok(()) } else { err("the link's user ID is not a valid UUID") }
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD].iter().find_map(|engine| engine.decode(&text).ok())
}

/// The fields of a v2rayN `vmess://` JSON blob. Numbers sometimes arrive as
/// strings, so those are read as either.
#[derive(Deserialize)]
struct VmessJson {
    #[serde(default)]
    ps: Option<String>,
    add: String,
    port: NumOrString,
    id: String,
    #[serde(default)]
    aid: Option<NumOrString>,
    #[serde(default)]
    scy: Option<String>,
    #[serde(default)]
    net: Option<String>,
    #[serde(default, rename = "type")]
    header_type: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    tls: Option<String>,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    alpn: Option<String>,
    #[serde(default)]
    fp: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NumOrString {
    Num(u64),
    Str(String),
}

impl NumOrString {
    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Num(n) => Some(*n),
            Self::Str(s) => s.trim().parse().ok(),
        }
    }
}

fn parse_vmess(link: &str) -> Result<ShareLink, LinkError> {
    let body = &link["vmess://".len()..];
    let body = body.split('#').next().unwrap_or_default();
    let Some(bytes) = decode_base64(body) else {
        return err("the VMess link is not valid base64");
    };
    let json: VmessJson = serde_json::from_slice(&bytes).or_else(|_| err("the VMess link does not hold valid settings"))?;
    if json.aid.as_ref().and_then(NumOrString::as_u64).unwrap_or(0) > 0 {
        return err("the VMess link uses the old alterId login, which Xray has removed; ask for an AEAD (alterId 0) link");
    }
    let port = json.port.as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0);
    let Some(port) = port else {
        return err("the VMess link has no valid server port");
    };
    let host = check_host(json.add.trim())?;
    check_uuid(json.id.trim())?;

    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut push = |k: &str, v: &Option<String>| {
        if let Some(v) = v {
            pairs.push((k.to_owned(), v.clone()));
        }
    };
    push("host", &json.host);
    push("path", &json.path);
    push("sni", &json.sni);
    push("alpn", &json.alpn);
    push("fp", &json.fp);
    let net = json.net.clone().unwrap_or_default();
    // For gRPC the path field carries the service name; for TCP/mKCP `type` is the header.
    match net.as_str() {
        "grpc" => push("serviceName", &json.path),
        _ => push("headerType", &json.header_type),
    }
    if net == "grpc" {
        push("mode", &json.header_type);
    }
    let q = Query(pairs);
    let transport = transport_from(&net, &q)?;
    let security = security_from(json.tls.as_deref().unwrap_or_default(), &q, None)?;
    let cipher = json.scy.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "auto".into());
    let name = non_empty(json.ps).or_else(|| link.split_once('#').and_then(|(_, f)| decode(f).ok()));
    Ok(ShareLink::Vpn(Box::new(VpnLink {
        protocol: VpnProtocol::Vmess { id: Secret::new(json.id.trim()), cipher },
        host,
        port,
        name: non_empty(name),
        transport,
        security,
    })))
}

/// `ss://` in SIP002 form (`ss://userinfo@host:port#name`, userinfo either
/// base64 or percent-encoded `method:password`) or the legacy all-base64 form.
fn parse_shadowsocks(link: &str) -> Result<ShareLink, LinkError> {
    let rest = &link["ss://".len()..];
    let (body, name) = match rest.split_once('#') {
        Some((body, frag)) => (body, decode(frag).ok().map(|f| f.trim().to_owned()).filter(|f| !f.is_empty())),
        None => (rest, None),
    };
    let (body, query) = body.split_once('?').unwrap_or((body, ""));
    let body = body.trim_end_matches('/');
    if query.split('&').any(|pair| pair.starts_with("plugin=")) {
        return err("this Shadowsocks link needs a plugin (obfs or v2ray-plugin), which Xray cannot run");
    }

    let (userinfo, hostport) = match body.rsplit_once('@') {
        Some((userinfo, hostport)) => {
            let userinfo = match decode_base64(userinfo).and_then(|b| String::from_utf8(b).ok()) {
                Some(decoded) if decoded.contains(':') => decoded,
                _ => decode(userinfo)?,
            };
            (userinfo, hostport.to_owned())
        }
        None => {
            let Some(decoded) = decode_base64(body).and_then(|b| String::from_utf8(b).ok()) else {
                return err("the Shadowsocks link is not valid");
            };
            match decoded.rsplit_once('@') {
                Some((userinfo, hostport)) => (userinfo.to_owned(), hostport.to_owned()),
                None => return err("the Shadowsocks link has no server address"),
            }
        }
    };
    let Some((method, password)) = userinfo.split_once(':') else {
        return err("the Shadowsocks link has no encryption method");
    };
    if method.is_empty() || password.is_empty() {
        return err("the Shadowsocks link is missing its method or password");
    }
    let target: TargetAddr = hostport.parse().or_else(|_| err("the Shadowsocks link has no valid server address"))?;
    let host = check_host(&target.host())?;
    Ok(ShareLink::Vpn(Box::new(VpnLink {
        protocol: VpnProtocol::Shadowsocks { method: method.to_ascii_lowercase(), password: Secret::new(password) },
        host,
        port: target.port(),
        name,
        transport: Transport::default(),
        security: Security::None,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn vpn(link: &str) -> VpnLink {
        match ShareLink::parse(link) {
            Ok(ShareLink::Vpn(v)) => *v,
            other => panic!("expected a VPN link, got {other:?}"),
        }
    }

    #[test]
    fn plain_proxies_become_native_outbounds() {
        let link = ShareLink::parse("socks5://alice:p%40ss@10.0.0.2:1080#Home").unwrap();
        let ShareLink::Socks5 { server, username, password, name } = &link else { panic!("{link:?}") };
        assert_eq!(server.to_string(), "10.0.0.2:1080");
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_ref().map(Secret::expose), Some("p@ss"));
        assert_eq!(name.as_deref(), Some("Home"));

        let https = ShareLink::parse("https://proxy.example.com").unwrap();
        assert!(matches!(&https, ShareLink::Http { tls: true, server, .. } if server.port() == 443));
        assert!(matches!(https.to_egress_kind(""), EgressKind::Http { tls: true, .. }));
        assert!(matches!(ShareLink::parse("http://1.2.3.4:3128").unwrap(), ShareLink::Http { tls: false, .. }));
        assert!(ShareLink::parse("socks5://:secret@host:1080").is_err());
    }

    #[test]
    fn vless_reality_vision() {
        let v = vpn(&format!(
            "vless://{UUID}@203.0.113.7:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&type=tcp#My%20Server"
        ));
        assert_eq!(v.host, "203.0.113.7");
        assert_eq!(v.port, 443);
        assert_eq!(v.name.as_deref(), Some("My Server"));
        assert!(matches!(&v.protocol, VpnProtocol::Vless { flow: Some(f), encryption, .. } if f == "xtls-rprx-vision" && encryption == "none"));
        let Security::Reality(r) = &v.security else { panic!("{:?}", v.security) };
        assert_eq!(r.server_name.as_deref(), Some("www.microsoft.com"));
        assert_eq!(r.short_id.as_deref(), Some("6ba85179e30d4fc2"));
        assert_eq!(v.to_string(), "VLESS via TCP + REALITY");
    }

    #[test]
    fn vless_websocket_tls_and_bad_combinations() {
        let v = vpn(&format!("vless://{UUID}@cdn.example.com:443?type=ws&security=tls&path=%2Fray%3Fed%3D2048&host=cdn.example.com&alpn=h2%2Chttp%2F1.1"));
        assert_eq!(v.transport.kind, TransportKind::Ws);
        assert_eq!(v.transport.path.as_deref(), Some("/ray?ed=2048"));
        let Security::Tls(tls) = &v.security else { panic!() };
        assert_eq!(tls.alpn, ["h2", "http/1.1"]);

        assert!(ShareLink::parse(&format!("vless://{UUID}@h.example:443?type=ws&flow=xtls-rprx-vision")).is_err());
        assert!(ShareLink::parse(&format!("vless://{UUID}@h.example:443?type=h2")).is_err());
        assert!(ShareLink::parse(&format!("vless://{UUID}@h.example")).is_err(), "no port");
        assert!(ShareLink::parse("vless://not a uuid at all, far too long@h.example:443").is_err());
        assert!(ShareLink::parse(&format!("vless://{UUID}@h.example:443?security=reality")).is_err(), "no pbk");
    }

    #[test]
    fn vmess_base64_json() {
        let json = format!(
            r#"{{"v":"2","ps":"Tokyo","add":"vm.example.com","port":"8443","id":"{UUID}","aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/ws","tls":"tls","sni":"vm.example.com"}}"#
        );
        let v = vpn(&format!("vmess://{}", STANDARD.encode(json)));
        assert_eq!((v.host.as_str(), v.port), ("vm.example.com", 8443));
        assert_eq!(v.name.as_deref(), Some("Tokyo"));
        assert_eq!(v.transport.kind, TransportKind::Ws);
        assert!(matches!(v.security, Security::Tls(_)));

        let legacy = format!(r#"{{"add":"a.example","port":443,"id":"{UUID}","aid":64}}"#);
        assert!(ShareLink::parse(&format!("vmess://{}", STANDARD.encode(legacy))).is_err());
        assert!(ShareLink::parse("vmess://%%%").is_err());
    }

    #[test]
    fn trojan_defaults_to_tls() {
        let v = vpn("trojan://s3cret@t.example.com:443?sni=t.example.com#T");
        assert!(matches!(&v.protocol, VpnProtocol::Trojan { password } if password.expose() == "s3cret"));
        assert!(matches!(v.security, Security::Tls(_)));
    }

    #[test]
    fn shadowsocks_forms() {
        let sip002 = format!("ss://{}@198.51.100.4:8388#SS", URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:pw"));
        let v = vpn(&sip002);
        assert!(matches!(&v.protocol, VpnProtocol::Shadowsocks { method, password } if method == "chacha20-ietf-poly1305" && password.expose() == "pw"));
        assert_eq!(v.port, 8388);

        let ss2022 = vpn("ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2BBnQ%3D%3D@ss.example.com:443");
        assert!(matches!(&ss2022.protocol, VpnProtocol::Shadowsocks { password, .. } if password.expose() == "YctPZ6U7xPPcU+gp3u+BnQ=="));

        let legacy = format!("ss://{}#Old", STANDARD.encode("aes-256-gcm:pw@192.0.2.1:8000"));
        assert_eq!(vpn(&legacy).host, "192.0.2.1");

        let with_plugin = sip002.replace("#SS", "/?plugin=obfs-local%3Bobfs%3Dhttp#SS");
        assert!(ShareLink::parse(&with_plugin).is_err());
    }

    #[test]
    fn hysteria2() {
        let v = vpn("hysteria2://letmein@hy.example.com:8443/?sni=real.example.com&obfs=salamander&obfs-password=x#HY");
        assert!(matches!(&v.protocol, VpnProtocol::Hysteria2 { auth, obfs_password: Some(_) } if auth.expose() == "letmein"));
        assert_eq!(v.transport.kind, TransportKind::Hysteria);
        let Security::Tls(tls) = &v.security else { panic!() };
        assert_eq!(tls.server_name.as_deref(), Some("real.example.com"));
        assert_eq!(tls.alpn, ["h3"]);
        assert_eq!(vpn("hy2://pw@hy.example.com").port, 443);
    }

    #[test]
    fn junk_is_rejected_with_a_reason() {
        for junk in ["", "hello", "ftp://x", "vless://", "socks5://", "ss://@@@", "vless://\u{7}@h:1"] {
            assert!(ShareLink::parse(junk).is_err(), "{junk:?} parsed");
        }
        assert!(ShareLink::parse(&format!("socks5://h.example:1/{}", "a".repeat(MAX_LINK_LEN))).is_err());
    }

    #[test]
    fn summaries_hide_vpn_secrets() {
        let s = ShareLink::parse(&format!("vless://{UUID}@h.example.com:443?security=tls&type=grpc&serviceName=x")).unwrap().summary();
        assert_eq!(s.kind, "xray");
        assert_eq!(s.protocol, "VLESS");
        assert_eq!(s.transport.as_deref(), Some("gRPC"));
        assert!(s.password.is_none() && !format!("{s:?}").contains(UUID));
    }

    #[test]
    fn xray_settings_that_open_files_are_found_however_they_are_written() {
        use serde_json::json;
        let problem = |v: serde_json::Value| xray_settings_problem(&v);
        // Deep inside, in an array, in any ASCII case.
        let deep = json!({ "downloadSettings": { "tlsSettings": { "masterKeyLog": "C:\\x.bat" } } });
        assert_eq!(problem(deep), Some(XraySettingsProblem::UsesFile("masterKeyLog")));
        let listed = json!({ "tlsSettings": { "certificates": [{ "CERTIFICATEFILE": "c.pem" }] } });
        assert_eq!(problem(listed), Some(XraySettingsProblem::UsesFile("certificateFile")));
        assert_eq!(problem(json!({ "keyfile": "" })), Some(XraySettingsProblem::UsesFile("keyFile")));
        // Spelled with letters Go's JSON folds to ASCII ones: the long s and
        // the Kelvin sign.
        assert_eq!(problem(json!({ "ma\u{17f}terKeyLog": "x" })), Some(XraySettingsProblem::UnusualName));
        assert_eq!(problem(json!({ "\u{212a}eyFile": "x" })), Some(XraySettingsProblem::UnusualName));
        // Network and device paths under any other name, either slash.
        for path in [r"\\host\share\c.pem", "//host/share/c.pem", r"\\.\pipe\x", r"/\host\x", "  \\\\host\\x"] {
            assert_eq!(problem(json!({ "s": [{ "redirect": path }] })), Some(XraySettingsProblem::NetworkPath), "{path}");
        }
        // What links really hold passes, a URL path with two slashes too.
        let fine = json!({
            "path": "//double", "headers": { "User-Agent": "Mozilla/5.0" }, "xPaddingBytes": "100-1000",
            "xmux": { "maxConcurrency": "16-32" },
            "downloadSettings": { "address": "cdn.example", "port": 443, "network": "xhttp", "security": "tls",
                "tlsSettings": { "serverName": "cdn.example", "alpn": ["h2"] },
                "xhttpSettings": { "path": ["//dl"], "mode": "stream-one" } },
        });
        assert_eq!(problem(fine), None);
    }

    #[test]
    fn a_link_whose_extra_settings_open_files_is_refused() {
        let extra = r#"{"downloadSettings":{"tlsSettings":{"masterKeyLog":"C:\\Windows\\System32\\x.bat"}}}"#;
        let encoded = percent_encoding::utf8_percent_encode(extra, percent_encoding::NON_ALPHANUMERIC).to_string();
        let link = format!("vless://{UUID}@h.example:443?type=xhttp&security=tls&extra={encoded}");
        let e = ShareLink::parse(&link).unwrap_err().to_string();
        assert!(e.contains("masterKeyLog") && e.contains("extra"), "{e}");

        let fine = percent_encoding::utf8_percent_encode(r#"{"xPaddingBytes":"100-1000"}"#, percent_encoding::NON_ALPHANUMERIC);
        let v = vpn(&format!("vless://{UUID}@h.example:443?type=xhttp&security=tls&extra={fine}"));
        assert_eq!(v.transport.extra.as_deref(), Some(r#"{"xPaddingBytes":"100-1000"}"#));
    }
}
