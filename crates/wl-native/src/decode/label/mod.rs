//! Protocol and Info text of a packet, worded like Wireshark's packet list.

mod arp;
mod dns;
mod http;
mod icmp;
mod tcp;
mod tls;
mod tls_hello;
mod udp;
mod udp_apps;

use super::link::Net;
use super::net::{Ip, NetLayer};
use super::parse::Packet;
use super::streams::Stream;
use super::transport::{ICMP, ICMPV6, Segment, TCP, UDP};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub protocol: &'static str,
    pub info: String,
}

impl Label {
    pub fn new(protocol: &'static str, info: impl Into<String>) -> Self {
        Label {
            protocol,
            info: info.into(),
        }
    }
}

/// `stream` is the stream state of the packet's conversation and the side it travels on, when it
/// has a TCP or UDP header.
pub fn describe(p: &Packet, stream: Option<(&mut Stream, usize)>) -> Label {
    match (&p.net, &p.segment) {
        (NetLayer::Arp(a), _) => arp::label(a),
        (NetLayer::Ip(ip), _) if ip.frag.is_some() => fragment(ip),
        (NetLayer::Ip(ip), Segment::Tcp(t)) => tcp::label(ip, t, stream),
        (NetLayer::Ip(_), Segment::Udp(u)) => udp::label(u),
        (NetLayer::Ip(ip), Segment::Icmp(i)) => icmp::label(ip, i),
        (NetLayer::Ip(ip), Segment::None) => Label::new(ip_name(ip.version), ""),
        (NetLayer::Broken(Net::Arp), _) => Label::new("ARP", "Malformed Packet"),
        (NetLayer::Broken(n), _) => Label::new(
            ip_name(if *n == Net::Ipv6 { 6 } else { 4 }),
            "Malformed Packet",
        ),
        (NetLayer::None, _) if p.link.ethernet => Label::new("Ethernet", ""),
        (NetLayer::None, _) => Label::new("Raw", ""),
    }
}

fn ip_name(version: u8) -> &'static str {
    if version == 6 { "IPv6" } else { "IPv4" }
}

fn fragment(ip: &Ip) -> Label {
    let proto = match ip.proto {
        ICMP => "ICMP 1".to_string(),
        TCP => "TCP 6".to_string(),
        UDP => "UDP 17".to_string(),
        ICMPV6 => "ICMPv6 58".to_string(),
        n => format!("Unknown {n}"),
    };
    let (off, id) = ip.frag.map_or((0, 0), |f| (f.offset, f.id));
    Label::new(
        ip_name(ip.version),
        format!("Fragmented IP protocol (proto={proto}, off={off}, ID={id:04x})"),
    )
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
