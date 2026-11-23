//! Link layer: Ethernet with stacked VLAN tags, Linux cooked captures, BSD null and raw IP.

use super::read::{be16, mac_at};
use crate::reader::LinkType;

const VLAN_TAGS: [u16; 3] = [0x8100, 0x88a8, 0x9100];
/// A longer stack is not a real network; the cap keeps a crafted frame from looping.
const MAX_VLAN_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    Ipv4,
    Ipv6,
    Arp,
    /// A network protocol this decoder does not read, or no room for one.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub src: Option<[u8; 6]>,
    pub dst: Option<[u8; 6]>,
    /// True when the addresses come from an Ethernet header, so `eth.*` filters apply.
    pub ethernet: bool,
    /// Ethertype after the VLAN tags, Ethernet only.
    pub ethertype: Option<u16>,
    /// Outermost VLAN id.
    pub vlan: Option<u16>,
    pub net: Net,
    /// Offset of the network header; past the end of the data when the frame is cut short.
    pub offset: usize,
    /// False when the frame is too short for its own link header.
    pub complete: bool,
}

impl Link {
    fn empty(net: Net) -> Self {
        Link {
            src: None,
            dst: None,
            ethernet: false,
            ethertype: None,
            vlan: None,
            net,
            offset: 0,
            complete: false,
        }
    }
}

fn net_of(ethertype: u16) -> Net {
    match ethertype {
        0x0800 => Net::Ipv4,
        0x86dd => Net::Ipv6,
        0x0806 => Net::Arp,
        _ => Net::Other,
    }
}

fn net_of_ip_version(first: Option<&u8>) -> Net {
    match first.map(|b| b >> 4) {
        Some(4) => Net::Ipv4,
        Some(6) => Net::Ipv6,
        _ => Net::Other,
    }
}

pub fn parse(link: LinkType, data: &[u8]) -> Link {
    match link {
        LinkType::Ethernet => ethernet(data),
        LinkType::LinuxSll => sll(data),
        LinkType::LinuxSll2 => sll2(data),
        LinkType::Null => null(data),
        LinkType::RawIp => Link {
            complete: !data.is_empty(),
            ..Link::empty(net_of_ip_version(data.first()))
        },
        LinkType::Other(_) => Link::empty(Net::Other),
    }
}

fn ethernet(data: &[u8]) -> Link {
    let (Some(dst), Some(src), Some(mut ty)) = (mac_at(data, 0), mac_at(data, 6), be16(data, 12))
    else {
        return Link {
            ethernet: true,
            ..Link::empty(Net::Other)
        };
    };
    let (mut offset, mut vlan, mut depth) = (14, None, 0);
    while VLAN_TAGS.contains(&ty) && depth < MAX_VLAN_DEPTH {
        let (Some(tci), Some(inner)) = (be16(data, offset), be16(data, offset + 2)) else {
            return Link {
                src: Some(src),
                dst: Some(dst),
                ethernet: true,
                vlan,
                offset: data.len(),
                ..Link::empty(Net::Other)
            };
        };
        vlan.get_or_insert(tci & 0x0fff);
        ty = inner;
        offset += 4;
        depth += 1;
    }
    Link {
        src: Some(src),
        dst: Some(dst),
        ethernet: true,
        ethertype: (ty >= 0x0600).then_some(ty),
        vlan,
        net: if ty < 0x0600 { Net::Other } else { net_of(ty) },
        offset,
        complete: true,
    }
}

fn cooked_addr(data: &[u8], halen_at: usize, addr_at: usize) -> Option<[u8; 6]> {
    (be16(data, halen_at)? == 6)
        .then(|| mac_at(data, addr_at))
        .flatten()
}

fn sll(data: &[u8]) -> Link {
    let Some(proto) = be16(data, 14) else {
        return Link::empty(Net::Other);
    };
    Link {
        src: cooked_addr(data, 4, 6),
        offset: 16,
        complete: true,
        ..Link::empty(net_of(proto))
    }
}

fn sll2(data: &[u8]) -> Link {
    let Some(proto) = be16(data, 0) else {
        return Link::empty(Net::Other);
    };
    let src = data
        .get(11)
        .filter(|halen| **halen == 6)
        .and_then(|_| mac_at(data, 12));
    Link {
        src,
        offset: 20,
        complete: true,
        ..Link::empty(net_of(proto))
    }
}

fn null(data: &[u8]) -> Link {
    let Some(raw) = data.get(..4) else {
        return Link::empty(Net::Other);
    };
    let le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let family = if le > 0xffff { le.swap_bytes() } else { le };
    let net = match family {
        2 => Net::Ipv4,
        10 | 24 | 28 | 30 => Net::Ipv6,
        _ => Net::Other,
    };
    Link {
        offset: 4,
        complete: true,
        ..Link::empty(net)
    }
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod tests;
