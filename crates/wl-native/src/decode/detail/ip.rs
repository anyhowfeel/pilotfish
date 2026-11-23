use wl_model::DetailNode;

use super::{field, node};
use crate::decode::net::Ip;
use crate::decode::read::{be16, tail};

pub fn ip(ip: &Ip, bytes: &[u8]) -> DetailNode {
    let at = ip.offset;
    let total = bytes.len();
    let range = Some((at, (at + ip.header_len).min(total)));
    let proto = format!("{} ({})", proto_name(ip.proto), ip.proto);
    if ip.version == 4 {
        let head = tail(bytes, at);
        let flags = be16(head, 6).unwrap_or(0);
        let id = be16(head, 4).unwrap_or(0);
        node(
            format!(
                "Internet Protocol Version 4, Src: {}, Dst: {}",
                ip.src, ip.dst
            ),
            range,
            vec![
                field(
                    format!(
                        "Header Length: {} bytes ({})",
                        ip.header_len,
                        ip.header_len / 4
                    ),
                    at,
                    1,
                    total,
                ),
                field(
                    format!("Total Length: {}", be16(head, 2).unwrap_or(0)),
                    at + 2,
                    2,
                    total,
                ),
                field(
                    format!("Identification: 0x{id:04x} ({id})"),
                    at + 4,
                    2,
                    total,
                ),
                field(
                    format!(
                        "Flags: 0x{:x}{}{}",
                        flags >> 13,
                        if flags & 0x4000 != 0 {
                            ", Don't fragment"
                        } else {
                            ""
                        },
                        if flags & 0x2000 != 0 {
                            ", More fragments"
                        } else {
                            ""
                        },
                    ),
                    at + 6,
                    2,
                    total,
                ),
                field(
                    format!("Fragment Offset: {}", (flags & 0x1fff) * 8),
                    at + 6,
                    2,
                    total,
                ),
                field(format!("Time to Live: {}", ip.ttl), at + 8, 1, total),
                field(format!("Protocol: {proto}"), at + 9, 1, total),
                field(format!("Source Address: {}", ip.src), at + 12, 4, total),
                field(
                    format!("Destination Address: {}", ip.dst),
                    at + 16,
                    4,
                    total,
                ),
            ],
        )
    } else {
        node(
            format!(
                "Internet Protocol Version 6, Src: {}, Dst: {}",
                ip.src, ip.dst
            ),
            range,
            vec![
                field(
                    format!("Payload Length: {}", ip.payload_len + ip.header_len - 40),
                    at + 4,
                    2,
                    total,
                ),
                field(format!("Next Header: {proto}"), at + 6, 1, total),
                field(format!("Hop Limit: {}", ip.ttl), at + 7, 1, total),
                field(format!("Source Address: {}", ip.src), at + 8, 16, total),
                field(
                    format!("Destination Address: {}", ip.dst),
                    at + 24,
                    16,
                    total,
                ),
            ],
        )
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "Other",
    }
}
