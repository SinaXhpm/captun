//! What the About dialog shows and does: the version, the project's links,
//! and whether a newer release is out. Everything here runs in the GUI with
//! the user's own rights; the service is not involved.

use std::{io, sync::Arc, time::Duration};

use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;

/// The project's home on the web: its GitHub page.
pub(crate) const WEBSITE: &str = "https://github.com/SinaXhpm/captun";
/// The GitHub repository, `owner/name`. Releases published there are what
/// "Check for updates" compares against.
pub(crate) const REPOSITORY: &str = "SinaXhpm/captun";

const API_HOST: &str = "api.github.com";
const TIMEOUT: Duration = Duration::from_secs(12);
/// Far more than a release description needs.
const MAX_RESPONSE: usize = 1 << 20;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AppInfo {
    pub(crate) version: String,
    pub(crate) website: String,
    pub(crate) repository: String,
}

pub(crate) fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        website: WEBSITE.into(),
        repository: format!("https://github.com/{REPOSITORY}"),
    }
}

/// Only the project's own pages may be opened from the GUI, so a page can
/// never be talked into launching anything else.
pub(crate) fn may_open(url: &str) -> bool {
    let repo = format!("https://github.com/{REPOSITORY}");
    url == WEBSITE || url == repo || url.starts_with(&format!("{repo}/releases"))
}

/// Opens `url` in the default browser. The URL is allow-listed and passed as
/// one argument, never through a shell.
pub(crate) fn open(url: &str) -> io::Result<()> {
    if !may_open(url) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "only Captun's own pages can be opened"));
    }
    #[cfg(windows)]
    let mut command = {
        let mut c = std::process::Command::new(rundll32());
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("/usr/bin/open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    let mut child = command.spawn()?;
    // Reap it so it never lingers as a zombie.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// Windows' own `rundll32.exe`, by its full path, so a `rundll32.exe` in the
/// current folder or early on `PATH` is never the one started.
#[cfg(windows)]
fn rundll32() -> std::path::PathBuf {
    system_program(std::env::var_os("SystemRoot"), "rundll32.exe")
}

/// `<Windows folder>\System32\<name>`, the Windows folder taken from
/// `system_root` (`%SystemRoot%`) when that is a full path.
#[cfg(any(windows, test))]
fn system_program(system_root: Option<std::ffi::OsString>, name: &str) -> std::path::PathBuf {
    let windows = system_root
        .map(std::path::PathBuf::from)
        .filter(|root| root.is_absolute())
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    windows.join("System32").join(name)
}

/// What "Check for updates" found.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct UpdateInfo {
    pub(crate) current: String,
    /// The newest published release, if there is any.
    pub(crate) latest: Option<String>,
    pub(crate) newer: bool,
    /// The release's page, to download from.
    pub(crate) url: Option<String>,
    pub(crate) notes: Option<String>,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    body: Option<String>,
}

pub(crate) async fn check_update() -> Result<UpdateInfo, String> {
    let current = env!("CARGO_PKG_VERSION").to_owned();
    let path = format!("/repos/{REPOSITORY}/releases/latest");
    let (status, body) = timeout(TIMEOUT, https_get(API_HOST, &path))
        .await
        .map_err(|_| "GitHub did not answer in time".to_owned())?
        .map_err(|e| format!("cannot reach GitHub: {e}"))?;
    match status {
        200 => {}
        // No release yet (or the repository is not public yet).
        404 => return Ok(UpdateInfo { current, latest: None, newer: false, url: None, notes: None }),
        403 | 429 => return Err("GitHub is limiting requests from this network; try again later".into()),
        other => return Err(format!("GitHub answered {other}")),
    }
    let release: Release = serde_json::from_slice(&body).map_err(|e| format!("unexpected answer from GitHub: {e}"))?;
    let latest = release.tag_name.trim_start_matches(['v', 'V']).to_owned();
    let newer = is_newer(&latest, &current);
    // Only a page of our own repository is ever offered for opening.
    let url = may_open(&release.html_url).then_some(release.html_url);
    let notes = release.body.map(|b| b.chars().take(600).collect());
    Ok(UpdateInfo { current, latest: Some(latest), newer, url, notes })
}

/// `1.2.3` against `1.2.0`, ignoring anything after the numbers (`-beta`).
fn is_newer(candidate: &str, current: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.split(['-', '+']).next().unwrap_or_default().split('.').map(|p| p.parse().unwrap_or(0)).collect()
    }
    let (a, b) = (parts(candidate), parts(current));
    let len = a.len().max(b.len());
    let at = |v: &[u64], i: usize| v.get(i).copied().unwrap_or(0);
    (0..len).map(|i| at(&a, i).cmp(&at(&b, i))).find(|o| o.is_ne()) == Some(std::cmp::Ordering::Greater)
}

fn tls_config() -> io::Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A plain HTTPS GET, enough for one small JSON document.
async fn https_get(host: &str, path: &str) -> io::Result<(u16, Vec<u8>)> {
    let tcp = TcpStream::connect((host, 443)).await?;
    let name = ServerName::try_from(host.to_owned()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut tls = TlsConnector::from(tls_config()?).connect(name, tcp).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Captun/{}\r\nAccept: application/vnd.github+json\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    tls.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    (&mut tls).take(MAX_RESPONSE as u64 + 1).read_to_end(&mut raw).await?;
    if raw.len() > MAX_RESPONSE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "answer too large"));
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> io::Result<(u16, Vec<u8>)> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_owned());
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let head_len = match response.parse(raw).map_err(|_| bad("malformed answer"))? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err(bad("incomplete answer")),
    };
    let status = response.code.unwrap_or(0);
    let chunked = response.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding") && String::from_utf8_lossy(h.value).to_ascii_lowercase().contains("chunked")
    });
    let body = &raw[head_len..];
    Ok((status, if chunked { dechunk(body).ok_or_else(|| bad("malformed chunked answer"))? } else { body.to_vec() }))
}

fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("1.0", "0.9.9"));
        assert!(is_newer("0.1.10", "0.1.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0-beta", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
    }

    #[test]
    fn only_the_projects_own_pages_open() {
        assert!(may_open(WEBSITE));
        assert!(may_open(&format!("https://github.com/{REPOSITORY}")));
        assert!(may_open(&format!("https://github.com/{REPOSITORY}/releases/tag/v1.0.0")));
        assert!(!may_open("https://example.com"));
        assert!(!may_open(&format!("https://github.com/{REPOSITORY}-evil")));
        assert!(!may_open("file:///C:/Windows/System32/calc.exe"));
    }

    #[test]
    fn system_programs_are_started_from_the_windows_folder() {
        let path = |root: Option<&str>| system_program(root.map(Into::into), "rundll32.exe");
        #[cfg(windows)]
        assert_eq!(path(Some(r"D:\WINDOWS")), std::path::Path::new(r"D:\WINDOWS\System32\rundll32.exe"));
        // Missing or not a full path: Windows' usual folder, never the current one.
        for root in [None, Some(""), Some(r"Windows")] {
            assert_eq!(path(root), std::path::Path::new(r"C:\Windows").join("System32").join("rundll32.exe"));
        }
        #[cfg(windows)]
        assert!(rundll32().is_absolute());
    }

    #[test]
    fn answers_parse_plain_and_chunked() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_response(plain).unwrap(), (200, b"{}".to_vec()));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap(), (200, b"{\"a\":1}".to_vec()));
        assert_eq!(parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap().0, 404);
    }
}
