//! Small helpers for building responses with hickory-proto.

use std::net::IpAddr;

use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{RData, Record, RecordType},
};

/// Payload size we advertise in our own OPT records. 1232 is the DNS Flag
/// Day 2020 value that avoids IP fragmentation on virtually every path.
pub(crate) const ADVERTISED_PAYLOAD: u16 = 1232;

/// Hard cap on UDP responses regardless of what the client advertises.
pub(crate) const MAX_UDP_PAYLOAD: u16 = 4096;

pub(crate) const HEADER_LEN: usize = 12;

pub(crate) fn header_id(wire: &[u8]) -> Option<u16> {
    (wire.len() >= HEADER_LEN).then(|| u16::from_be_bytes([wire[0], wire[1]]))
}

/// QR bit: set on responses. Responses arriving at the server are dropped,
/// which stops reflection loops between two resolvers.
pub(crate) fn is_response(wire: &[u8]) -> bool {
    wire.len() > 2 && wire[2] & 0x80 != 0
}

pub(crate) fn is_truncated(wire: &[u8]) -> bool {
    wire.len() > 2 && wire[2] & 0x02 != 0
}

/// FORMERR for bytes that have a DNS header but do not parse as a message.
pub(crate) fn format_error(wire: &[u8]) -> Option<Vec<u8>> {
    let id = header_id(wire)?;
    let op_code = OpCode::from_u8((wire[2] >> 3) & 0x0f);
    Message::error_msg(id, op_code, ResponseCode::FormErr).to_vec().ok()
}

/// An empty response to `request` carrying its question and RD flag.
pub(crate) fn response_to(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(request.op_code())
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_checking_disabled(request.checking_disabled())
        .set_response_code(code)
        .add_queries(request.queries().iter().cloned());
    response
}

/// An OPT record advertising our payload size, for clients that sent one.
pub(crate) fn our_edns() -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(ADVERTISED_PAYLOAD);
    edns
}

/// Human-readable answers for the query log, e.g. `A 93.184.216.34`.
pub(crate) fn describe_answers(message: &Message) -> Vec<String> {
    const MAX_LOGGED: usize = 16;
    message
        .answers()
        .iter()
        .filter(|r| r.record_type() != RecordType::OPT)
        .take(MAX_LOGGED)
        .map(|r| format!("{} {}", r.record_type(), r.data()))
        .collect()
}

/// The addresses a response gives (A and AAAA answers, whatever name or alias
/// they are filed under).
pub(crate) fn answered_addrs(message: &Message) -> Vec<IpAddr> {
    message
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        })
        .collect()
}

/// Applies `f` to every TTL-bearing record (OPT's TTL field holds flags).
pub(crate) fn for_each_record_mut(message: &mut Message, mut f: impl FnMut(&mut Record)) {
    for record in message.answers_mut() {
        f(record);
    }
    for record in message.name_servers_mut() {
        f(record);
    }
    for record in message.additionals_mut().iter_mut().filter(|r| r.record_type() != RecordType::OPT) {
        f(record);
    }
}
