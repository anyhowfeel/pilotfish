//! Network layer: IPv4, IPv6 with its extension headers, and ARP over Ethernet / IPv4.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};

use super::link::Net;
use super::read::{be16, be32, mac_at, tail};

const MAX_EXT_HEADERS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frag {
    /// Byte offset of this fragment inside the datagram.
    pub offset: u32,
    pub more: bool,
    pub id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ip<'a> {
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Protocol of the payload after the extension headers.
    pub proto: u8,
    /// The protocol field of the base header; tshark's `ip.proto` / `ipv6.nxt`.
    pub first_proto: u8,
    pub ttl: u8,
    pub frag: Option<Frag>,
    /// Frame offset of the header, and the length of the base header plus extensions.
    pub offset: usize,
    pub header_len: usize,
    /// Payload length the header declares, which can exceed what was captured.
    pub payload_len: usize,
    /// The captured part of the payload.
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetLayer<'a> {
    Ip(Ip<'a>),
    Arp(Arp),
    /// The link layer announced `Net` but the header is cut short or inconsistent.
    Broken(Net),
    None,
}

pub fn parse(net: Net, data: &[u8], offset: usize) -> NetLayer<'_> {
    let rest = tail(data, offset);
    let layer = match net {
        Net::Ipv4 => ipv4(rest, offset),
        Net::Ipv6 => ipv6(rest, offset),
        Net::Arp => arp(rest).map(NetLayer::Arp),
        Net::Other => return NetLayer::None,
    };
    layer.unwrap_or(NetLayer::Broken(net))
}

fn ipv4(rest: &[u8], offset: usize) -> Option<NetLayer<'_>> {
    let h = Ipv4HeaderSlice::from_slice(rest).ok()?;
    let hl = h.slice().len();
    let total = usize::from(h.total_len());
    let declared = if total > hl {
        total - hl
    } else {
        rest.len() - hl
    };
    let end = (hl + declared).min(rest.len());
    let frag_offset = u32::from(h.fragments_offset().value()) * 8;
    let frag = (frag_offset != 0 || h.more_fragments()).then(|| Frag {
        offset: frag_offset,
        more: h.more_fragments(),
        id: u32::from(h.identification()),
    });
    Some(NetLayer::Ip(Ip {
        version: 4,
        src: IpAddr::V4(h.source_addr()),
        dst: IpAddr::V4(h.destination_addr()),
        proto: h.protocol().0,
        first_proto: h.protocol().0,
        ttl: h.ttl(),
        frag,
        offset,
        header_len: hl,
        payload_len: declared,
        payload: &rest[hl..end],
    }))
}

fn ipv6(rest: &[u8], offset: usize) -> Option<NetLayer<'_>> {
    let h = Ipv6HeaderSlice::from_slice(rest).ok()?;
    let base_proto = h.next_header().0;
    let (proto, ext_len, frag) = extension_headers(base_proto, tail(rest, 40));
    let hl = 40 + ext_len;
    let declared = match usize::from(h.payload_length()) {
        0 => rest.len().saturating_sub(40),
        n => n,
    }
    .saturating_sub(ext_len);
    let end = (hl + declared).min(rest.len());
    Some(NetLayer::Ip(Ip {
        version: 6,
        src: IpAddr::V6(Ipv6Addr::from(h.source())),
        dst: IpAddr::V6(Ipv6Addr::from(h.destination())),
        proto,
        first_proto: base_proto,
        ttl: h.hop_limit(),
        frag,
        offset,
        header_len: hl,
        payload_len: declared,
        payload: rest.get(hl..end).unwrap_or(&[]),
    }))
}

/// Walks the extension chain; returns the payload protocol, the bytes consumed and the fragment
/// header if there was one. A chain cut short ends the walk with what was understood.
fn extension_headers(first: u8, mut d: &[u8]) -> (u8, usize, Option<Frag>) {
    let (mut nxt, mut used, mut frag) = (first, 0, None);
    for _ in 0..MAX_EXT_HEADERS {
        let len = match nxt {
            0 | 43 | 60 => d.get(1).map(|l| (usize::from(*l) + 1) * 8),
            51 => d.get(1).map(|l| (usize::from(*l) + 2) * 4),
            44 => Some(8),
            _ => None,
        };
        let Some(len) = len.filter(|l| *l <= d.len()) else {
            break;
        };
        if nxt == 44 {
            let word = be16(d, 2).unwrap_or(0);
            frag = Some(Frag {
                offset: u32::from(word >> 3) * 8,
                more: word & 1 == 1,
                id: be32(d, 4).unwrap_or(0),
            });
        }
        nxt = d[0];
        used += len;
        d = &d[len..];
    }
    (nxt, used, frag)
}

fn arp(rest: &[u8]) -> Option<Arp> {
    let ethernet_ipv4 =
        be16(rest, 0)? == 1 && be16(rest, 2)? == 0x0800 && rest.get(4)? == &6 && rest.get(5)? == &4;
    if !ethernet_ipv4 {
        return None;
    }
    let ip = |at| be32(rest, at).map(Ipv4Addr::from);
    Some(Arp {
        op: be16(rest, 6)?,
        sender_mac: mac_at(rest, 8)?,
        sender_ip: ip(14)?,
        target_mac: mac_at(rest, 18)?,
        target_ip: ip(24)?,
    })
}

#[cfg(test)]
#[path = "net_tests.rs"]
mod tests;
