//! Values written in a filter, and the values a packet offers, with how they compare.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::field::Kind;

/// What a packet holds for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Val {
    Num(u64),
    Ip(IpAddr),
    Mac([u8; 6]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lit {
    Num(u64),
    /// An address with the length of the prefix it must share; a plain address has the full length.
    Net(IpAddr, u8),
    Mac([u8; 6]),
}

impl Lit {
    /// `None` when `word` is not a value of `kind`, which includes numbers out of range: tshark
    /// rejects those filters, so the native side must not accept them either.
    pub fn parse(kind: Kind, word: &str) -> Option<Lit> {
        match kind {
            Kind::Int(max) => number(word).filter(|n| *n <= max).map(Lit::Num),
            Kind::Bool => match word {
                "1" | "true" => Some(Lit::Num(1)),
                "0" | "false" => Some(Lit::Num(0)),
                _ => None,
            },
            Kind::Ipv4 => net(word, false),
            Kind::Ipv6 => net(word, true),
            Kind::Mac => mac(word).map(Lit::Mac),
            Kind::Proto => None,
        }
    }

    pub fn equals(&self, v: &Val) -> bool {
        match (self, v) {
            (Lit::Num(a), Val::Num(b)) => a == b,
            (Lit::Mac(a), Val::Mac(b)) => a == b,
            (Lit::Net(net, prefix), Val::Ip(ip)) => within(*net, *prefix, *ip),
            _ => false,
        }
    }

    /// The order of the packet's value against this literal; only numbers have one.
    pub fn order(&self, v: &Val) -> Option<Ordering> {
        match (self, v) {
            (Lit::Num(a), Val::Num(b)) => Some(b.cmp(a)),
            _ => None,
        }
    }
}

fn number(word: &str) -> Option<u64> {
    if let Some(hex) = word.strip_prefix("0x") {
        let digits = !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        return digits.then(|| u64::from_str_radix(hex, 16).ok()).flatten();
    }
    // Wireshark reads a leading zero as octal, which the native side does not mimic.
    let plain = word == "0" || !word.starts_with('0');
    (plain && word.bytes().all(|b| b.is_ascii_digit()))
        .then(|| word.parse().ok())
        .flatten()
}

fn net(word: &str, v6: bool) -> Option<Lit> {
    let (addr, prefix) = match word.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (word, None),
    };
    let ip: IpAddr = if v6 {
        IpAddr::V6(addr.parse::<Ipv6Addr>().ok()?)
    } else {
        IpAddr::V4(addr.parse::<Ipv4Addr>().ok()?)
    };
    let max = if v6 { 128 } else { 32 };
    let prefix = match prefix {
        None => max,
        Some(p) => number(p).filter(|p| *p <= u64::from(max))? as u8,
    };
    Some(Lit::Net(ip, prefix))
}

fn mac(word: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = word.split(':');
    for byte in &mut out {
        let p = parts.next().filter(|p| p.len() == 2)?;
        *byte = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn within(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}
