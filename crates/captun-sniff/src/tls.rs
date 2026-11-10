use captun_core::domain::is_valid_hostname;

use crate::{Sniff, reader::Reader};

const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// RFC 8446 allows a record body of 2^14 bytes plus expansion.
const MAX_RECORD: usize = 16_384 + 256;
/// Hellos with large post-quantum key shares are ~2 KB; anything near this
/// limit is not a real browser.
const MAX_HELLO: usize = 64 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// Lowercased `server_name`, only if it is a syntactically valid hostname.
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    /// Encrypted ClientHello in use: `sni` is then only the public outer name.
    pub ech: bool,
}

/// Parses a ClientHello from the start of a TCP stream, reassembling it when
/// it is split across several TLS records (common with post-quantum keys).
pub fn parse_client_hello(buf: &[u8]) -> Sniff<ClientHello> {
    let mut handshake = Vec::new();
    let mut pos = 0;
    loop {
        let Some(header) = buf.get(pos..pos + 5) else { return Sniff::NeedMore };
        if header[0] != CONTENT_HANDSHAKE || header[1] != 0x03 {
            return Sniff::NoMatch;
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len == 0 || len > MAX_RECORD {
            return Sniff::NoMatch;
        }
        let body_start = pos + 5;
        let end = body_start + len;
        handshake.extend_from_slice(&buf[body_start..end.min(buf.len())]);

        if handshake.len() >= 4 {
            if handshake[0] != HANDSHAKE_CLIENT_HELLO {
                return Sniff::NoMatch;
            }
            let hello_len = usize::from(handshake[1]) << 16 | usize::from(handshake[2]) << 8 | usize::from(handshake[3]);
            if hello_len > MAX_HELLO {
                return Sniff::NoMatch;
            }
            if let Some(body) = handshake.get(4..4 + hello_len) {
                return parse_body(body).map_or(Sniff::NoMatch, Sniff::Found);
            }
        }
        if end > buf.len() {
            return Sniff::NeedMore;
        }
        pos = end;
    }
}

fn parse_body(body: &[u8]) -> Option<ClientHello> {
    let mut r = Reader::new(body);
    r.u16()?; // legacy_version
    r.bytes(32)?; // random
    r.vec8()?; // legacy_session_id
    r.vec16()?; // cipher_suites
    r.vec8()?; // legacy_compression_methods

    let mut hello = ClientHello::default();
    if r.is_empty() {
        return Some(hello);
    }
    let mut extensions = Reader::new(r.vec16()?);
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        match kind {
            EXT_SERVER_NAME => hello.sni = parse_server_name(data),
            EXT_ALPN => hello.alpn = parse_alpn(data),
            EXT_ENCRYPTED_CLIENT_HELLO => hello.ech = true,
            _ => {}
        }
    }
    Some(hello)
}

fn parse_server_name(data: &[u8]) -> Option<String> {
    let mut list = Reader::new(Reader::new(data).vec16()?);
    while !list.is_empty() {
        let name_type = list.u8()?;
        let name = list.vec16()?;
        if name_type == 0 {
            let name = std::str::from_utf8(name).ok()?;
            return is_valid_hostname(name).then(|| name.trim_end_matches('.').to_ascii_lowercase());
        }
    }
    None
}

fn parse_alpn(data: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();
    let Some(list) = Reader::new(data).vec16() else { return protocols };
    let mut list = Reader::new(list);
    while let Some(proto) = list.vec8() {
        if let Ok(proto) = std::str::from_utf8(proto) {
            protocols.push(proto.to_owned());
        }
    }
    protocols
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{client_hello, client_hello_record, records};

    #[test]
    fn extracts_sni_and_alpn() {
        let Sniff::Found(hello) = parse_client_hello(&client_hello_record(Some("WWW.Example.com"), &["h2", "http/1.1"]))
        else {
            panic!()
        };
        assert_eq!(hello.sni.as_deref(), Some("www.example.com"));
        assert_eq!(hello.alpn, ["h2", "http/1.1"]);
        assert!(!hello.ech);
    }

    #[test]
    fn reassembles_hello_split_over_records() {
        let split = records(&client_hello(Some("split.example"), &[]), 40);
        let Sniff::Found(hello) = parse_client_hello(&split) else { panic!() };
        assert_eq!(hello.sni.as_deref(), Some("split.example"));
    }

    #[test]
    fn every_strict_prefix_needs_more() {
        let full = records(&client_hello(Some("prefix.example"), &["h2"]), 50);
        for cut in 0..full.len() {
            assert_eq!(parse_client_hello(&full[..cut]), Sniff::NeedMore, "cut at {cut}");
        }
    }

    #[test]
    fn rejects_non_hello() {
        assert_eq!(parse_client_hello(b"\x17\x03\x03\x00\x05hello"), Sniff::NoMatch, "application data");
        assert_eq!(parse_client_hello(b"\x16\x03\x03\x00\x04\x02\x00\x00\x00"), Sniff::NoMatch, "ServerHello");
        assert_eq!(parse_client_hello(b"\x16\x03\x03\x00\x00"), Sniff::NoMatch, "empty record");
    }

    #[test]
    fn invalid_sni_is_dropped() {
        let Sniff::Found(hello) = parse_client_hello(&client_hello_record(Some("bad name!"), &[])) else { panic!() };
        assert_eq!(hello.sni, None);
        let Sniff::Found(hello) = parse_client_hello(&client_hello_record(None, &[])) else { panic!() };
        assert_eq!(hello.sni, None);
    }
}
