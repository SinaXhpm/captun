//! Builders for synthetic protocol messages, used by this crate's own tests and
//! by other crates (the routing engine) that need a realistic TLS ClientHello.
//! Not part of the runtime path.

const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;

fn vec16(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend(vec16(data));
    out
}

/// A TLS ClientHello handshake message (without record framing) offering the
/// given SNI and ALPN protocols.
pub fn client_hello(sni: Option<&str>, alpn: &[&str]) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend([0x11; 32]);
    body.push(0);
    body.extend(vec16(&[0x13, 0x01, 0x13, 0x02]));
    body.extend([1, 0]);

    let mut extensions = Vec::new();
    if let Some(name) = sni {
        let mut entry = vec![0];
        entry.extend(vec16(name.as_bytes()));
        extensions.extend(extension(EXT_SERVER_NAME, &vec16(&entry)));
    }
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for p in alpn {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        extensions.extend(extension(EXT_ALPN, &vec16(&list)));
    }
    // supported_versions: TLS 1.3
    extensions.extend(extension(0x002b, &[2, 0x03, 0x04]));
    body.extend(vec16(&extensions));

    let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend(body);
    handshake
}

/// Wraps a handshake message in TLS records, splitting it into `chunk`-sized
/// record bodies (use `usize::MAX` for a single record).
pub fn records(handshake: &[u8], chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in handshake.chunks(chunk.max(1)) {
        out.extend([CONTENT_HANDSHAKE, 0x03, 0x01]);
        out.extend(vec16(piece));
    }
    out
}

/// A complete, single-record ClientHello ready to write onto a stream.
pub fn client_hello_record(sni: Option<&str>, alpn: &[&str]) -> Vec<u8> {
    records(&client_hello(sni, alpn), usize::MAX)
}
