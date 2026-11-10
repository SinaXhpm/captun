//! A bounds-checked DHCPv4 (RFC 2131) codec. It parses frames that arrive by
//! broadcast from any device on the wire, so every read is length-checked and the
//! parser never panics — the same discipline as Captun's other wire parsers.
//!
//! Only Ethernet clients (htype 1, hlen 6) are handled; anything else parses to a
//! message the server simply ignores.

use std::net::Ipv4Addr;

/// Standard DHCP ports.
pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

/// `op` field values.
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
/// Ethernet hardware type and address length.
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;
/// Bytes up to and including `file`, before the options magic cookie.
const FIXED_HEADER: usize = 236;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// The broadcast flag in the `flags` field.
const FLAG_BROADCAST: u16 = 0x8000;
/// The longest hostname kept: one DNS label.
const MAX_HOSTNAME: usize = 63;

// DHCP option codes we read or write.
const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQUEST: u8 = 55;
const OPT_END: u8 = 255;

/// The DHCP message type (option 53).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Other(u8),
}

impl MessageType {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            other => Self::Other(other),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
            Self::Other(v) => v,
        }
    }
}

/// A parsed DHCP message (the fields Captun's server needs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DhcpMessage {
    pub(crate) op: u8,
    pub(crate) xid: u32,
    pub(crate) flags: u16,
    pub(crate) ciaddr: Ipv4Addr,
    pub(crate) giaddr: Ipv4Addr,
    /// Client hardware (MAC) address; only Ethernet (6 bytes) is supported.
    pub(crate) chaddr: [u8; 6],
    pub(crate) message_type: Option<MessageType>,
    pub(crate) requested_ip: Option<Ipv4Addr>,
    pub(crate) server_id: Option<Ipv4Addr>,
    pub(crate) hostname: Option<String>,
}

impl DhcpMessage {
    /// Whether the client asked for the reply to be broadcast (or has no address
    /// yet, so a unicast reply could not reach it).
    pub(crate) fn wants_broadcast(&self) -> bool {
        self.flags & FLAG_BROADCAST != 0 || self.ciaddr.is_unspecified()
    }

    /// Parses a DHCP packet. Returns `None` for anything too short, not a BOOT
    /// request, without the options cookie, or not an Ethernet client.
    pub(crate) fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < FIXED_HEADER + MAGIC_COOKIE.len() {
            return None;
        }
        let op = buf[0];
        if op != BOOTREQUEST {
            return None;
        }
        if buf[1] != HTYPE_ETHERNET || buf[2] != HLEN_ETHERNET {
            return None;
        }
        let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let flags = u16::from_be_bytes([buf[10], buf[11]]);
        let ciaddr = ipv4_at(buf, 12)?;
        let giaddr = ipv4_at(buf, 24)?;
        let mut chaddr = [0u8; 6];
        chaddr.copy_from_slice(buf.get(28..34)?);

        if buf[FIXED_HEADER..FIXED_HEADER + 4] != MAGIC_COOKIE {
            return None;
        }

        let mut message = Self {
            op,
            xid,
            flags,
            ciaddr,
            giaddr,
            chaddr,
            message_type: None,
            requested_ip: None,
            server_id: None,
            hostname: None,
        };
        message.parse_options(&buf[FIXED_HEADER + 4..]);
        Some(message)
    }

    fn parse_options(&mut self, mut opts: &[u8]) {
        while let Some((&code, rest)) = opts.split_first() {
            match code {
                OPT_PAD => {
                    opts = rest;
                    continue;
                }
                OPT_END => break,
                _ => {}
            }
            let Some((&len, rest)) = rest.split_first() else { break };
            let len = len as usize;
            if rest.len() < len {
                break;
            }
            let (value, tail) = rest.split_at(len);
            match code {
                OPT_MESSAGE_TYPE => {
                    if let Some(&t) = value.first() {
                        self.message_type = Some(MessageType::from_u8(t));
                    }
                }
                OPT_REQUESTED_IP => self.requested_ip = ipv4_from(value),
                OPT_SERVER_ID => self.server_id = ipv4_from(value),
                OPT_HOSTNAME => {
                    // Keep only printable ASCII, so a hostile hostname can't carry
                    // control characters into logs or the UI, and no more than a
                    // DNS label holds, so it can't fill them either.
                    let name: String = value
                        .iter()
                        .copied()
                        .take_while(|b| *b != 0)
                        .map(char::from)
                        .filter(|c| c.is_ascii_graphic() || *c == ' ')
                        .take(MAX_HOSTNAME)
                        .collect();
                    if !name.is_empty() {
                        self.hostname = Some(name);
                    }
                }
                _ => {}
            }
            opts = tail;
        }
    }
}

fn ipv4_at(buf: &[u8], offset: usize) -> Option<Ipv4Addr> {
    let bytes = buf.get(offset..offset + 4)?;
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn ipv4_from(value: &[u8]) -> Option<Ipv4Addr> {
    (value.len() == 4).then(|| Ipv4Addr::new(value[0], value[1], value[2], value[3]))
}

/// What a reply advertises to the client.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReplyParams {
    pub(crate) message_type: MessageType,
    /// The address being offered/confirmed (0.0.0.0 in a NAK).
    pub(crate) your_ip: Ipv4Addr,
    pub(crate) server_id: Ipv4Addr,
    pub(crate) subnet_mask: Ipv4Addr,
    pub(crate) router: Ipv4Addr,
    pub(crate) dns: Ipv4Addr,
    pub(crate) lease_secs: u32,
}

/// Builds a BOOTREPLY for `request` with `params`, echoing xid/flags/giaddr and
/// the client MAC as RFC 2131 requires.
pub(crate) fn build_reply(request: &DhcpMessage, params: &ReplyParams) -> Vec<u8> {
    let mut buf = vec![0u8; FIXED_HEADER];
    buf[0] = BOOTREPLY;
    buf[1] = HTYPE_ETHERNET;
    buf[2] = HLEN_ETHERNET;
    buf[4..8].copy_from_slice(&request.xid.to_be_bytes());
    buf[10..12].copy_from_slice(&request.flags.to_be_bytes());
    // yiaddr
    buf[16..20].copy_from_slice(&params.your_ip.octets());
    // giaddr echoed back
    buf[24..28].copy_from_slice(&request.giaddr.octets());
    // chaddr
    buf[28..34].copy_from_slice(&request.chaddr);

    buf.extend_from_slice(&MAGIC_COOKIE);
    push_opt(&mut buf, OPT_MESSAGE_TYPE, &[params.message_type.to_u8()]);
    push_opt(&mut buf, OPT_SERVER_ID, &params.server_id.octets());
    if params.message_type != MessageType::Nak {
        push_opt(&mut buf, OPT_LEASE_TIME, &params.lease_secs.to_be_bytes());
        push_opt(&mut buf, OPT_SUBNET_MASK, &params.subnet_mask.octets());
        push_opt(&mut buf, OPT_ROUTER, &params.router.octets());
        push_opt(&mut buf, OPT_DNS, &params.dns.octets());
    }
    let _ = OPT_PARAM_REQUEST;
    buf.push(OPT_END);
    buf
}

fn push_opt(buf: &mut Vec<u8>, code: u8, value: &[u8]) {
    buf.push(code);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal DISCOVER with a message-type option and a hostname.
    fn discover_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; FIXED_HEADER];
        buf[0] = BOOTREQUEST;
        buf[1] = HTYPE_ETHERNET;
        buf[2] = HLEN_ETHERNET;
        buf[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        buf[10..12].copy_from_slice(&FLAG_BROADCAST.to_be_bytes());
        buf[28..34].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        buf.extend_from_slice(&MAGIC_COOKIE);
        push_opt(&mut buf, OPT_MESSAGE_TYPE, &[1]); // DISCOVER
        push_opt(&mut buf, OPT_HOSTNAME, b"phone\x07bad"); // control char stripped
        push_opt(&mut buf, OPT_REQUESTED_IP, &Ipv4Addr::new(10, 0, 0, 50).octets());
        buf.push(OPT_END);
        buf
    }

    #[test]
    fn parses_a_discover() {
        let msg = DhcpMessage::parse(&discover_bytes()).expect("should parse");
        assert_eq!(msg.message_type, Some(MessageType::Discover));
        assert_eq!(msg.chaddr, [0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(msg.xid, 0xdead_beef);
        assert!(msg.wants_broadcast());
        assert_eq!(msg.requested_ip, Some(Ipv4Addr::new(10, 0, 0, 50)));
        assert_eq!(msg.hostname.as_deref(), Some("phonebad"));
    }

    #[test]
    fn rejects_short_and_non_ethernet_and_cookieless() {
        assert!(DhcpMessage::parse(&[0u8; 10]).is_none(), "too short");
        let mut no_cookie = vec![0u8; FIXED_HEADER + 4];
        no_cookie[0] = BOOTREQUEST;
        no_cookie[1] = HTYPE_ETHERNET;
        no_cookie[2] = HLEN_ETHERNET;
        assert!(DhcpMessage::parse(&no_cookie).is_none(), "bad magic cookie");
        let mut reply = discover_bytes();
        reply[0] = BOOTREPLY;
        assert!(DhcpMessage::parse(&reply).is_none(), "replies are not requests");
    }

    #[test]
    fn long_hostnames_are_cut_to_one_dns_label() {
        let mut buf = discover_bytes();
        buf.pop(); // OPT_END
        let long = [b"\x01".as_slice(), &[b'a'; 200]].concat();
        push_opt(&mut buf, OPT_HOSTNAME, &long);
        buf.push(OPT_END);
        let msg = DhcpMessage::parse(&buf).expect("should parse");
        assert_eq!(msg.hostname, Some("a".repeat(MAX_HOSTNAME)), "control bytes do not count toward the limit");
        let mut exact = discover_bytes();
        exact.pop();
        push_opt(&mut exact, OPT_HOSTNAME, &[b'b'; MAX_HOSTNAME]);
        exact.push(OPT_END);
        assert_eq!(DhcpMessage::parse(&exact).unwrap().hostname.map(|h| h.len()), Some(MAX_HOSTNAME));
    }

    #[test]
    fn truncated_option_does_not_panic() {
        let mut buf = vec![0u8; FIXED_HEADER];
        buf[0] = BOOTREQUEST;
        buf[1] = HTYPE_ETHERNET;
        buf[2] = HLEN_ETHERNET;
        buf.extend_from_slice(&MAGIC_COOKIE);
        buf.push(OPT_HOSTNAME);
        buf.push(200); // claims 200 bytes that are not there
        buf.extend_from_slice(b"short");
        // Must not panic, and simply yields no hostname.
        let msg = DhcpMessage::parse(&buf).expect("header still valid");
        assert_eq!(msg.hostname, None);
    }

    #[test]
    fn builds_offer_that_round_trips_key_fields() {
        let request = DhcpMessage::parse(&discover_bytes()).unwrap();
        let params = ReplyParams {
            message_type: MessageType::Offer,
            your_ip: Ipv4Addr::new(10, 0, 0, 50),
            server_id: Ipv4Addr::new(10, 0, 0, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(10, 0, 0, 1),
            dns: Ipv4Addr::new(10, 0, 0, 1),
            lease_secs: 3600,
        };
        let bytes = build_reply(&request, &params);
        // yiaddr and chaddr echoed.
        assert_eq!(&bytes[16..20], &[10, 0, 0, 50]);
        assert_eq!(&bytes[28..34], &request.chaddr);
        assert_eq!(&bytes[4..8], &request.xid.to_be_bytes());
        // Options present: message type 2 (OFFER), server id, mask, router, dns.
        let opts = &bytes[FIXED_HEADER + 4..];
        assert_eq!(opts[0], OPT_MESSAGE_TYPE);
        assert_eq!(opts[2], 2);
        assert!(opts.contains(&OPT_END));
    }

    #[test]
    fn nak_omits_lease_options() {
        let request = DhcpMessage::parse(&discover_bytes()).unwrap();
        let params = ReplyParams {
            message_type: MessageType::Nak,
            your_ip: Ipv4Addr::UNSPECIFIED,
            server_id: Ipv4Addr::new(10, 0, 0, 1),
            subnet_mask: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            dns: Ipv4Addr::UNSPECIFIED,
            lease_secs: 0,
        };
        let bytes = build_reply(&request, &params);
        // No subnet-mask option in a NAK.
        assert!(!contains_option(&bytes[FIXED_HEADER + 4..], OPT_SUBNET_MASK));
        assert!(contains_option(&bytes[FIXED_HEADER + 4..], OPT_MESSAGE_TYPE));
    }

    fn contains_option(mut opts: &[u8], code: u8) -> bool {
        while let Some((&c, rest)) = opts.split_first() {
            if c == OPT_END {
                return false;
            }
            if c == OPT_PAD {
                opts = rest;
                continue;
            }
            let Some((&len, rest)) = rest.split_first() else { return false };
            if c == code {
                return true;
            }
            if rest.len() < len as usize {
                return false;
            }
            opts = &rest[len as usize..];
        }
        false
    }
}
