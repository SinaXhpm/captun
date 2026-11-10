use std::net::IpAddr;

use captun_core::domain::is_valid_hostname;

use crate::Sniff;

const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequestHead {
    pub method: String,
    pub path: String,
    /// `Host` without the port, lowercased; `None` when absent or malformed.
    pub host: Option<String>,
}

pub fn parse_http_request(buf: &[u8]) -> Sniff<HttpRequestHead> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(buf) {
        Ok(httparse::Status::Complete(_)) => {
            let host = request
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("host"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .and_then(host_without_port);
            Sniff::Found(HttpRequestHead {
                method: request.method.unwrap_or_default().to_owned(),
                path: request.path.unwrap_or_default().to_owned(),
                host,
            })
        }
        Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => Sniff::NeedMore,
        Ok(httparse::Status::Partial) | Err(_) => Sniff::NoMatch,
    }
}

fn host_without_port(value: &str) -> Option<String> {
    let value = value.trim();
    let host = if let Some(rest) = value.strip_prefix('[') {
        rest.split_once(']').map(|(ip, _)| ip)?
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
            _ => value,
        }
    };
    if host.parse::<IpAddr>().is_ok() || is_valid_hostname(host) {
        Some(host.trim_end_matches('.').to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_head() {
        let Sniff::Found(head) = parse_http_request(b"POST /api?x=1 HTTP/1.1\r\nhost: API.example.com\r\nX: y\r\n\r\nbody")
        else {
            panic!()
        };
        assert_eq!(head.method, "POST");
        assert_eq!(head.path, "/api?x=1");
        assert_eq!(head.host.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn host_forms() {
        assert_eq!(host_without_port("example.com:8080").as_deref(), Some("example.com"));
        assert_eq!(host_without_port("[2001:db8::1]:80").as_deref(), Some("2001:db8::1"));
        assert_eq!(host_without_port("10.0.0.1").as_deref(), Some("10.0.0.1"));
        assert_eq!(host_without_port("bad host"), None);
    }

    #[test]
    fn partial_and_garbage() {
        assert_eq!(parse_http_request(b"GET / HTTP/1.1\r\nHost: a"), Sniff::NeedMore);
        assert_eq!(parse_http_request(b"G"), Sniff::NeedMore);
        assert_eq!(parse_http_request(b"GET\x00/ HTTP/1.1\r\n\r\n"), Sniff::NoMatch);
        let huge = [b"GET / HTTP/1.1\r\nX: ".as_slice(), &[b'a'; MAX_HEAD]].concat();
        assert_eq!(parse_http_request(&huge), Sniff::NoMatch);
    }
}
