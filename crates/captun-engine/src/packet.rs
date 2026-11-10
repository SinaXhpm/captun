//! Reading the IP packets devices send, and writing the UDP and ICMP packets
//! the engine answers with. TCP packets stay whole: the TCP stack reads and
//! writes those itself.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
        TcpPacket, UdpPacket, UdpRepr,
    },
};

/// The two ends of a flow: the device's address, then the address it is
/// trying to reach.
pub(crate) type Tuple = (SocketAddr, SocketAddr);

/// What a packet from a device carries, as far as the engine is concerned.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Packet<'a> {
    Tcp {
        tuple: Tuple,
        /// A SYN without ACK: the device is opening a connection.
        opening: bool,
    },
    Udp {
        tuple: Tuple,
        payload: &'a [u8],
    },
    /// Fragments, other protocols, and anything malformed.
    Other,
}

const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const HOP_LIMIT: u8 = 64;

pub(crate) fn parse(bytes: &[u8]) -> Packet<'_> {
    match bytes.first().map(|b| b >> 4) {
        Some(4) => {
            let Ok(ip) = Ipv4Packet::new_checked(bytes) else { return Packet::Other };
            // Devices do not fragment TCP, and the rare fragmented datagram is
            // not worth reassembling.
            if ip.more_frags() || ip.frag_offset() != 0 {
                return Packet::Other;
            }
            transport(ip.next_header(), IpAddr::V4(ip.src_addr()), IpAddr::V4(ip.dst_addr()), ip.payload())
        }
        Some(6) => {
            let Ok(ip) = Ipv6Packet::new_checked(bytes) else { return Packet::Other };
            // Extension headers are left out, like fragments above.
            transport(ip.next_header(), IpAddr::V6(ip.src_addr()), IpAddr::V6(ip.dst_addr()), ip.payload())
        }
        _ => Packet::Other,
    }
}

fn transport(protocol: IpProtocol, src: IpAddr, dst: IpAddr, payload: &[u8]) -> Packet<'_> {
    if !unicast(src) || !unicast(dst) {
        return Packet::Other;
    }
    match protocol {
        IpProtocol::Tcp => match TcpPacket::new_checked(payload) {
            Ok(tcp) if tcp.src_port() != 0 && tcp.dst_port() != 0 => Packet::Tcp {
                tuple: (SocketAddr::new(src, tcp.src_port()), SocketAddr::new(dst, tcp.dst_port())),
                opening: tcp.syn() && !tcp.ack(),
            },
            _ => Packet::Other,
        },
        IpProtocol::Udp => match UdpPacket::new_checked(payload) {
            Ok(udp) if udp.src_port() != 0 && udp.dst_port() != 0 => Packet::Udp {
                tuple: (SocketAddr::new(src, udp.src_port()), SocketAddr::new(dst, udp.dst_port())),
                payload: udp.payload(),
            },
            _ => Packet::Other,
        },
        _ => Packet::Other,
    }
}

/// An address a device's packet can carry from or to: not "none", not a
/// group, not a broadcast, and not loopback, which no packet from a network
/// may claim.
fn unicast(addr: IpAddr) -> bool {
    !addr.is_unspecified()
        && !addr.is_multicast()
        && !addr.is_loopback()
        && match addr {
            IpAddr::V4(v4) => !v4.is_broadcast(),
            IpAddr::V6(_) => true,
        }
}

/// The packets carrying the datagram `payload` from `from` (the internet side)
/// to `to` (the device). An IPv4 datagram too big for one packet is split into
/// fragments; an IPv6 one is dropped (no packets), as a router would.
pub(crate) fn udp_datagram(from: SocketAddr, to: SocketAddr, payload: &[u8], ident: u16, mtu: usize) -> Vec<Vec<u8>> {
    match (from.ip(), to.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => udp_v4((src, from.port()), (dst, to.port()), payload, ident, mtu),
        (IpAddr::V6(src), IpAddr::V6(dst)) => udp_v6((src, from.port()), (dst, to.port()), payload, mtu).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn udp_v4(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8], ident: u16, mtu: usize) -> Vec<Vec<u8>> {
    let len = UDP_HEADER + payload.len();
    if IPV4_HEADER + len > usize::from(u16::MAX) || mtu <= IPV4_HEADER + UDP_HEADER {
        return Vec::new();
    }
    let caps = ChecksumCapabilities::default();
    // The whole datagram first: its checksum covers every fragment.
    let mut datagram = vec![0u8; len];
    UdpRepr { src_port: src.1, dst_port: dst.1 }.emit(
        &mut UdpPacket::new_unchecked(&mut datagram[..]),
        &IpAddress::Ipv4(src.0),
        &IpAddress::Ipv4(dst.0),
        payload.len(),
        |buf| buf.copy_from_slice(payload),
        &caps,
    );
    // Fragments other than the last carry a multiple of 8 bytes.
    let room = mtu - IPV4_HEADER;
    let chunk = if len <= room { len } else { room & !7 };
    datagram
        .chunks(chunk)
        .enumerate()
        .map(|(i, piece)| {
            let offset = i * chunk;
            let mut buf = vec![0u8; IPV4_HEADER + piece.len()];
            let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
            Ipv4Repr {
                src_addr: src.0,
                dst_addr: dst.0,
                next_header: IpProtocol::Udp,
                payload_len: piece.len(),
                hop_limit: HOP_LIMIT,
            }
            .emit(&mut ip, &caps);
            ip.set_ident(ident);
            ip.set_dont_frag(false);
            ip.set_more_frags(offset + piece.len() < len);
            // Below 64 KiB, so it fits.
            ip.set_frag_offset(u16::try_from(offset).unwrap_or(0));
            ip.fill_checksum();
            ip.payload_mut().copy_from_slice(piece);
            buf
        })
        .collect()
}

fn udp_v6(src: (Ipv6Addr, u16), dst: (Ipv6Addr, u16), payload: &[u8], mtu: usize) -> Option<Vec<u8>> {
    let len = UDP_HEADER + payload.len();
    if IPV6_HEADER + len > mtu {
        return None;
    }
    let mut buf = vec![0u8; IPV6_HEADER + len];
    let mut ip = Ipv6Packet::new_unchecked(&mut buf[..]);
    Ipv6Repr { src_addr: src.0, dst_addr: dst.0, next_header: IpProtocol::Udp, payload_len: len, hop_limit: HOP_LIMIT }
        .emit(&mut ip);
    UdpRepr { src_port: src.1, dst_port: dst.1 }.emit(
        &mut UdpPacket::new_unchecked(ip.payload_mut()),
        &IpAddress::Ipv6(src.0),
        &IpAddress::Ipv6(dst.0),
        payload.len(),
        |buf| buf.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    Some(buf)
}

/// An ICMP "port unreachable" telling the device that its datagram `payload`
/// on `tuple` was refused, so its app gives up at once. IPv4 only: an IPv6
/// refusal stays silent.
pub(crate) fn port_unreachable(tuple: Tuple, payload: &[u8]) -> Option<Vec<u8>> {
    let (SocketAddr::V4(device), SocketAddr::V4(server)) = tuple else { return None };
    let refused_len = UDP_HEADER + payload.len();
    // An ICMP error quotes the refused packet's IP header and first 8 bytes,
    // which for UDP is its header.
    let mut quoted = [0u8; UDP_HEADER];
    let mut udp = UdpPacket::new_unchecked(&mut quoted[..]);
    udp.set_src_port(device.port());
    udp.set_dst_port(server.port());
    udp.set_len(u16::try_from(refused_len).unwrap_or(u16::MAX));
    udp.set_checksum(0);
    let icmp = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::PortUnreachable,
        header: Ipv4Repr {
            src_addr: *device.ip(),
            dst_addr: *server.ip(),
            next_header: IpProtocol::Udp,
            payload_len: refused_len,
            hop_limit: HOP_LIMIT,
        },
        data: &quoted,
    };
    let caps = ChecksumCapabilities::default();
    let mut buf = vec![0u8; IPV4_HEADER + icmp.buffer_len()];
    let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
    Ipv4Repr {
        src_addr: *server.ip(),
        dst_addr: *device.ip(),
        next_header: IpProtocol::Icmp,
        payload_len: icmp.buffer_len(),
        hop_limit: HOP_LIMIT,
    }
    .emit(&mut ip, &caps);
    icmp.emit(&mut Icmpv4Packet::new_unchecked(ip.payload_mut()), &caps);
    Some(buf)
}

#[cfg(test)]
mod tests {
    use smoltcp::wire::Icmpv4Message;

    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_reply_parses_back_with_the_ends_swapped() {
        let (device, server) = (addr("192.168.137.80:40000"), addr("1.1.1.1:53"));
        let packets = udp_datagram(server, device, b"answer", 7, 1500);
        assert_eq!(packets.len(), 1);
        let ip = Ipv4Packet::new_checked(&packets[0][..]).unwrap();
        assert!(ip.verify_checksum());
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert!(udp.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr())));
        assert_eq!(parse(&packets[0]), Packet::Udp { tuple: (server, device), payload: b"answer" });
    }

    #[test]
    fn a_big_ipv4_datagram_is_split_into_fragments() {
        let payload: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
        let packets = udp_datagram(addr("8.8.8.8:443"), addr("10.0.0.5:5000"), &payload, 0x1234, 1500);
        assert_eq!(packets.len(), 3);

        let mut datagram = Vec::new();
        for (i, packet) in packets.iter().enumerate() {
            assert!(packet.len() <= 1500);
            let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
            assert!(ip.verify_checksum());
            assert_eq!(ip.ident(), 0x1234);
            assert_eq!(usize::from(ip.frag_offset()), datagram.len());
            assert_eq!(ip.more_frags(), i < 2);
            // Fragments are not handed on: the engine does not reassemble.
            assert_eq!(parse(packet), Packet::Other);
            datagram.extend_from_slice(ip.payload());
        }
        let udp = UdpPacket::new_checked(&datagram[..]).unwrap();
        assert!(udp.verify_checksum(&IpAddress::v4(8, 8, 8, 8), &IpAddress::v4(10, 0, 0, 5)));
        assert_eq!(udp.payload(), &payload[..]);
    }

    #[test]
    fn ipv6_replies_fit_one_packet_or_are_dropped() {
        let (server, device) = (addr("[2001:db8::1]:443"), addr("[2001:db8::5]:5000"));
        let small = udp_datagram(server, device, &[1; 1000], 0, 1500);
        assert_eq!(small.len(), 1);
        assert_eq!(parse(&small[0]), Packet::Udp { tuple: (server, device), payload: &[1; 1000] });
        assert!(udp_datagram(server, device, &[1; 1460], 0, 1500).is_empty());
    }

    #[test]
    fn a_refusal_quotes_the_refused_datagram() {
        let tuple = (addr("192.168.137.80:40000"), addr("8.8.8.8:443"));
        let packet = port_unreachable(tuple, &[0; 100]).unwrap();
        let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
        assert_eq!((ip.src_addr(), ip.dst_addr()), (Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(192, 168, 137, 80)));
        let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
        assert!(icmp.verify_checksum());
        assert_eq!((icmp.msg_type(), icmp.msg_code()), (Icmpv4Message::DstUnreachable, 3));
        // The refused datagram's IP header as it was, full length included
        // (which is how the device finds the socket), then its UDP header.
        let quoted = icmp.data();
        assert_eq!(quoted.len(), IPV4_HEADER + UDP_HEADER);
        let original = Ipv4Packet::new_unchecked(quoted);
        assert_eq!(
            (original.src_addr(), original.dst_addr(), original.total_len()),
            (Ipv4Addr::new(192, 168, 137, 80), Ipv4Addr::new(8, 8, 8, 8), 128)
        );
        let udp = UdpPacket::new_unchecked(&quoted[IPV4_HEADER..]);
        assert_eq!((udp.src_port(), udp.dst_port(), udp.len()), (40000, 443, 108));
        assert!(port_unreachable((addr("[2001:db8::5]:1"), addr("[2001:db8::1]:2")), b"x").is_none());
    }

    #[test]
    fn only_unicast_tcp_and_udp_are_flows() {
        // A broadcast from the device, such as a DHCP request.
        let packet = udp_datagram(addr("10.0.0.5:68"), addr("255.255.255.255:67"), b"x", 0, 1500);
        assert_eq!(parse(&packet[0]), Packet::Other);
        assert_eq!(parse(&[0x45, 0, 0]), Packet::Other);
        assert_eq!(parse(&[]), Packet::Other);
        // Nothing from a network may reach this computer's loopback.
        for to in ["127.0.0.1:8080", "[::1]:8080"] {
            let from = if to.starts_with('[') { "[2001:db8::5]:5000" } else { "10.0.0.5:5000" };
            let packet = udp_datagram(addr(from), addr(to), b"x", 0, 1500);
            assert_eq!(parse(&packet[0]), Packet::Other, "{to}");
        }
    }
}
