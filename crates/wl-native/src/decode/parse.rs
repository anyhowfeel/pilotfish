//! Runs the link, network and transport parsers over one frame. Shared by the row decoder and the
//! detail pane so both read a packet the same way.

use std::net::IpAddr;

use super::link::{self, Link, Net};
use super::net::{self, Ip, NetLayer};
use super::read::be16;
use super::streams::Tuple;
use super::transport::{self, Icmp, Segment};
use crate::reader::LinkType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub link: Link,
    pub net: NetLayer<'a>,
    pub segment: Segment<'a>,
    /// For an ICMP error: the conversation of the packet it quotes. Wireshark takes the ports and
    /// the stream number of such a packet from the quoted header.
    pub quoted: Option<Tuple>,
    /// For an ICMP error: the IP header it quotes, which Wireshark dissects as a second IP layer.
    pub inner: Option<Ip<'a>>,
}

const REDIRECT: u8 = 5;

/// Offset of the flags byte inside a TCP header.
const TCP_FLAGS_AT: usize = 13;

pub fn packet(link_type: LinkType, data: &[u8]) -> Packet<'_> {
    let link = link::parse(link_type, data);
    let net = net::parse(link.net, data, link.offset);
    let segment = match &net {
        NetLayer::Ip(ip) => transport::parse(ip),
        _ => Segment::None,
    };
    let inner = match &segment {
        Segment::Icmp(i) if is_error(i) => quoted_ip(i),
        _ => None,
    };
    let quoted = inner.as_ref().and_then(quoted);
    Packet {
        link,
        net,
        segment,
        quoted,
        inner,
    }
}

fn is_error(i: &Icmp) -> bool {
    if i.v6 {
        (1..=4).contains(&i.kind)
    } else {
        matches!(i.kind, 3 | 4 | 5 | 11 | 12)
    }
}

fn quoted_ip<'a>(i: &Icmp<'a>) -> Option<Ip<'a>> {
    let net = match i.body.get(4)? >> 4 {
        4 => Net::Ipv4,
        6 => Net::Ipv6,
        _ => return None,
    };
    match net::parse(net, i.body, 4) {
        NetLayer::Ip(ip) => Some(ip),
        _ => None,
    }
}

/// The first four bytes after the quoted IP header hold the ports.
fn quoted(ip: &Ip) -> Option<Tuple> {
    if ip.frag.is_some_and(|f| f.offset != 0) {
        return None;
    }
    let udp = match ip.proto {
        transport::UDP => true,
        transport::TCP => false,
        _ => return None,
    };
    let (src, dst) = (be16(ip.payload, 0)?, be16(ip.payload, 2)?);
    Some(Tuple {
        udp,
        src: (ip.src, src),
        dst: (ip.dst, dst),
        syn_seq: None,
    })
}

impl Packet<'_> {
    pub fn ip(&self) -> Option<&Ip<'_>> {
        match &self.net {
            NetLayer::Ip(ip) => Some(ip),
            _ => None,
        }
    }

    /// Ports of this packet's header, or of the packet an ICMP error quotes.
    pub fn ports(&self) -> Option<(u16, u16)> {
        match &self.segment {
            Segment::Tcp(t) => Some((t.src, t.dst)),
            Segment::Udp(u) => Some((u.src, u.dst)),
            _ => self.quoted.as_ref().map(|q| (q.src.1, q.dst.1)),
        }
    }

    /// The flags byte of the TCP header an ICMP error quotes. Wireshark reads it, and numbers the
    /// conversation, only when the quote reaches it and the message is not a redirect.
    pub fn quoted_tcp_flags(&self) -> Option<u8> {
        let redirect = matches!(&self.segment, Segment::Icmp(i) if !i.v6 && i.kind == REDIRECT);
        let ip = self.inner.as_ref()?;
        let first = ip.frag.is_none_or(|f| f.offset == 0);
        let flags = ip.payload.get(TCP_FLAGS_AT).copied();
        flags.filter(|_| first && ip.proto == transport::TCP && !redirect)
    }

    pub fn addrs(&self) -> Option<(IpAddr, IpAddr)> {
        self.ip().map(|ip| (ip.src, ip.dst))
    }
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
