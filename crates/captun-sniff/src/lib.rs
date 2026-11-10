//! Protocol sniffing on the first bytes a station sends: the TLS ClientHello
//! (SNI, ALPN, ECH) and the HTTP/1.x request head (`Host`). The input is
//! attacker-controlled, so every parser is bounds-checked, never panics, and
//! distinguishes "need more bytes" from "this is not that protocol".

mod http;
mod reader;
pub mod test_support;
mod tls;

pub use http::{HttpRequestHead, parse_http_request};
pub use tls::{ClientHello, parse_client_hello};

/// How many bytes a caller should be willing to buffer before giving up:
/// enough for a post-quantum ClientHello split over several records.
pub const MAX_SNIFF_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sniff<T> {
    Found(T),
    /// The prefix is consistent with the protocol but incomplete.
    NeedMore,
    NoMatch,
}

impl<T> Sniff<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Sniff<U> {
        match self {
            Self::Found(v) => Sniff::Found(f(v)),
            Self::NeedMore => Sniff::NeedMore,
            Self::NoMatch => Sniff::NoMatch,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Detected {
    Tls(ClientHello),
    Http(HttpRequestHead),
}

impl Detected {
    /// The destination name the station asked for, if it said.
    pub fn host(&self) -> Option<&str> {
        match self {
            Self::Tls(hello) => hello.sni.as_deref(),
            Self::Http(head) => head.host.as_deref(),
        }
    }
}

/// Classifies the first bytes of a TCP stream.
pub fn sniff(buf: &[u8]) -> Sniff<Detected> {
    match buf.first() {
        None => Sniff::NeedMore,
        Some(0x16) => parse_client_hello(buf).map(Detected::Tls),
        Some(b) if b.is_ascii_uppercase() => parse_http_request(buf).map(Detected::Http),
        Some(_) => Sniff::NoMatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatches_by_first_byte() {
        assert_eq!(sniff(b""), Sniff::NeedMore);
        assert_eq!(sniff(b"\x00\x01binary"), Sniff::NoMatch);
        let Sniff::Found(found) = sniff(b"GET / HTTP/1.1\r\nHost: Example.org:8080\r\n\r\n") else { panic!() };
        assert_eq!(found.host(), Some("example.org"));
    }

    /// Cheap deterministic fuzzing: random and mutated inputs must never panic.
    #[test]
    fn survives_garbage() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seed = crate::test_support::client_hello_record(Some("fuzz.example"), &["h2"]);
        for _ in 0..20_000 {
            let len = (next() % 600) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if next() % 2 == 0 {
                buf = seed.clone();
                for _ in 0..(next() % 8) {
                    let i = (next() as usize) % buf.len();
                    buf[i] = next() as u8;
                }
                buf.truncate((next() as usize) % (buf.len() + 1));
            }
            if let Some(first) = buf.first_mut()
                && next() % 3 == 0
            {
                *first = 0x16;
            }
            let _ = sniff(&buf);
        }
    }
}
