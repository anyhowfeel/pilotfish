//! ICMP and ICMPv6 info text.

use super::Label;
use crate::decode::fmt;
use crate::decode::net::Ip;
use crate::decode::read::{be16, mac_at};
use crate::decode::transport::Icmp;

pub fn label(ip: &Ip, i: &Icmp) -> Label {
    if i.v6 {
        Label::new("ICMPv6", v6(ip, i))
    } else {
        Label::new("ICMP", v4(ip, i))
    }
}

fn echo_ids(body: &[u8]) -> Option<(u16, u16)> {
    Some((be16(body, 0)?, be16(body, 2)?))
}

fn v4(ip: &Ip, i: &Icmp) -> String {
    match (i.kind, i.code) {
        (8 | 0, _) => {
            let name = if i.kind == 8 {
                "Echo (ping) request "
            } else {
                "Echo (ping) reply   "
            };
            match echo_ids(i.body) {
                Some((id, seq)) => format!(
                    "{name} id=0x{id:04x}, seq={seq}/{}, ttl={}",
                    seq.swap_bytes(),
                    ip.ttl
                ),
                None => name.trim_end().to_string(),
            }
        }
        (3, c) => format!("Destination unreachable ({})", unreachable_v4(c)),
        (11, 0) => "Time-to-live exceeded (Time to live exceeded in transit)".into(),
        (11, _) => "Time-to-live exceeded (Fragment reassembly time exceeded)".into(),
        (4, _) => "Source quench (flow control)".into(),
        (5, c) => format!("Redirect             ({})", redirect(c)),
        (13, _) => "Timestamp request".into(),
        (14, _) => "Timestamp reply".into(),
        (9, _) => "Router advertisement".into(),
        (10, _) => "Router solicitation".into(),
        (k, c) => format!("Unknown (type {k}, code {c})"),
    }
}

fn unreachable_v4(code: u8) -> &'static str {
    match code {
        0 => "Network unreachable",
        1 => "Host unreachable",
        2 => "Protocol unreachable",
        3 => "Port unreachable",
        4 => "Fragmentation needed",
        5 => "Source route failed",
        9 => "Network administratively prohibited",
        10 => "Host administratively prohibited",
        13 => "Communication administratively filtered",
        _ => "Unknown",
    }
}

fn redirect(code: u8) -> &'static str {
    match code {
        0 => "Redirect for network",
        1 => "Redirect for host",
        2 => "Redirect for TOS and network",
        _ => "Redirect for TOS and host",
    }
}

fn v6(ip: &Ip, i: &Icmp) -> String {
    match i.kind {
        128 | 129 => {
            let name = if i.kind == 128 {
                "Echo (ping) request"
            } else {
                "Echo (ping) reply"
            };
            match echo_ids(i.body) {
                Some((id, seq)) => format!("{name} id=0x{id:04x}, seq={seq}, hop limit={}", ip.ttl),
                None => name.into(),
            }
        }
        1 => format!("Destination Unreachable ({})", unreachable_v6(i.code)),
        2 => "Packet Too Big".into(),
        3 => match i.code {
            0 => "Time Exceeded (In-transit)".into(),
            _ => "Time Exceeded (Fragment reassembly)".into(),
        },
        4 => "Parameter Problem".into(),
        133 => with_link_addr("Router Solicitation", " from ", i.body, 4, 1),
        134 => with_link_addr("Router Advertisement", " from ", i.body, 12, 1),
        135 => {
            let target = target(i.body, 4).unwrap_or_default();
            with_link_addr(
                &format!("Neighbor Solicitation for {target}"),
                " from ",
                i.body,
                20,
                1,
            )
        }
        136 => neighbor_advertisement(i.body),
        130 => "Multicast Listener Query".into(),
        131 => "Multicast Listener Report".into(),
        132 => "Multicast Listener Done".into(),
        143 => "Multicast Listener Report Message v2".into(),
        k => format!("Unknown (type {k})"),
    }
}

fn unreachable_v6(code: u8) -> &'static str {
    match code {
        0 => "No route to destination",
        1 => "Administratively prohibited",
        2 => "Beyond scope of source address",
        3 => "Address unreachable",
        4 => "Port unreachable",
        5 => "Source address failed ingress/egress policy",
        6 => "Reject route to destination",
        _ => "Unknown",
    }
}

fn target(body: &[u8], at: usize) -> Option<String> {
    let b: [u8; 16] = body.get(at..at + 16)?.try_into().ok()?;
    Some(fmt::ipv6(&b.into()))
}

fn neighbor_advertisement(body: &[u8]) -> String {
    let flags = body.first().copied().unwrap_or(0);
    let set: Vec<&str> = [(0x80, "rtr"), (0x40, "sol"), (0x20, "ovr")]
        .into_iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| n)
        .collect();
    let head = format!(
        "Neighbor Advertisement {} ({})",
        target(body, 4).unwrap_or_default(),
        set.join(", ")
    );
    with_link_addr(&head, " is at ", body, 20, 2)
}

/// Appends the first link-layer address option of type `want` found from `from` on.
fn with_link_addr(head: &str, join: &str, body: &[u8], from: usize, want: u8) -> String {
    let mut at = from;
    while let (Some(&kind), Some(&units)) = (body.get(at), body.get(at + 1)) {
        if units == 0 {
            break;
        }
        if kind == want
            && let Some(m) = mac_at(body, at + 2)
        {
            return format!("{head}{join}{}", fmt::mac(&m));
        }
        at += usize::from(units) * 8;
    }
    head.to_string()
}
