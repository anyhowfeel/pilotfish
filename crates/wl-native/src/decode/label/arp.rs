//! ARP info text.

use super::Label;
use crate::decode::fmt;
use crate::decode::net::Arp;

const REQUEST: u16 = 1;
const REPLY: u16 = 2;

pub fn label(a: &Arp) -> Label {
    let info = match a.op {
        REQUEST if a.sender_ip.is_unspecified() => {
            format!("Who has {}? (ARP Probe)", a.target_ip)
        }
        REQUEST if a.sender_ip == a.target_ip && a.target_mac == [0; 6] => {
            format!("ARP Announcement for {}", a.sender_ip)
        }
        REQUEST if a.sender_ip == a.target_ip => {
            format!("Gratuitous ARP for {} (Request)", a.sender_ip)
        }
        REQUEST => format!("Who has {}? Tell {}", a.target_ip, a.sender_ip),
        REPLY if a.sender_ip == a.target_ip => {
            format!("Gratuitous ARP for {} (Reply)", a.sender_ip)
        }
        REPLY => format!("{} is at {}", a.sender_ip, fmt::mac(&a.sender_mac)),
        op => format!("Opcode {op}"),
    };
    Label::new("ARP", info)
}

#[cfg(test)]
#[path = "arp_tests.rs"]
mod tests;
