use wl_model::DetailNode;

use super::{field, node};
use crate::decode::parse::Packet;
use crate::decode::read::be16;
use crate::decode::transport::{Icmp, Segment, Tcp, Udp};

const FLAG_NAMES: [&str; 8] = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"];

pub fn segment(pkt: &Packet, bytes: &[u8]) -> Option<DetailNode> {
    let total = bytes.len();
    Some(match &pkt.segment {
        Segment::Tcp(t) => tcp(t, bytes),
        Segment::Udp(u) => udp(u, bytes),
        Segment::Icmp(i) => icmp(i, total),
        Segment::None => return None,
    })
}

fn tcp(t: &Tcp, bytes: &[u8]) -> DetailNode {
    let (at, total) = (t.offset, bytes.len());
    let names: Vec<&str> = FLAG_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| t.flags & (1 << i) != 0)
        .map(|(_, n)| *n)
        .collect();
    let mut children = vec![
        field(format!("Source Port: {}", t.src), at, 2, total),
        field(format!("Destination Port: {}", t.dst), at + 2, 2, total),
        field(
            format!("Sequence Number (raw): {}", t.seq),
            at + 4,
            4,
            total,
        ),
    ];
    if t.has(Tcp::ACK) {
        children.push(field(
            format!("Acknowledgment Number (raw): {}", t.ack),
            at + 8,
            4,
            total,
        ));
    }
    children.push(field(
        format!(
            "Header Length: {} bytes ({})",
            t.header_len,
            t.header_len / 4
        ),
        at + 12,
        1,
        total,
    ));
    children.push(field(
        format!("Flags: 0x{:03x} ({})", t.flags, names.join(", ")),
        at + 13,
        1,
        total,
    ));
    children.push(field(format!("Window: {}", t.window), at + 14, 2, total));
    if t.payload_len > 0 {
        let start = at + t.header_len;
        children.push(field(
            format!("TCP payload ({} bytes)", t.payload_len),
            start,
            t.payload.len(),
            total,
        ));
    }
    let ack = if t.has(Tcp::ACK) {
        format!(", Ack: {}", t.ack)
    } else {
        String::new()
    };
    node(
        format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: {}, Seq: {}{}, Len: {}",
            t.src, t.dst, t.seq, ack, t.payload_len
        ),
        Some((at, (at + t.header_len).min(total))),
        children,
    )
}

fn udp(u: &Udp, bytes: &[u8]) -> DetailNode {
    let (at, total) = (u.offset, bytes.len());
    let mut children = vec![
        field(format!("Source Port: {}", u.src), at, 2, total),
        field(format!("Destination Port: {}", u.dst), at + 2, 2, total),
        field(format!("Length: {}", u.length), at + 4, 2, total),
    ];
    if !u.payload.is_empty() {
        children.push(field(
            format!("UDP payload ({} bytes)", u.payload.len()),
            at + 8,
            u.payload.len(),
            total,
        ));
    }
    node(
        format!(
            "User Datagram Protocol, Src Port: {}, Dst Port: {}",
            u.src, u.dst
        ),
        Some((at, (at + 8).min(total))),
        children,
    )
}

fn icmp(i: &Icmp, total: usize) -> DetailNode {
    let at = i.offset;
    let mut children = vec![
        field(format!("Type: {}", i.kind), at, 1, total),
        field(format!("Code: {}", i.code), at + 1, 1, total),
    ];
    if matches!((i.v6, i.kind), (false, 0 | 8) | (true, 128 | 129))
        && let (Some(id), Some(seq)) = (be16(i.body, 0), be16(i.body, 2))
    {
        children.push(field(format!("Identifier: {id}"), at + 4, 2, total));
        children.push(field(format!("Sequence Number: {seq}"), at + 6, 2, total));
    }
    let name = if i.v6 {
        "Internet Control Message Protocol v6"
    } else {
        "Internet Control Message Protocol"
    };
    node(name.into(), Some((at, (at + 4).min(total))), children)
}
