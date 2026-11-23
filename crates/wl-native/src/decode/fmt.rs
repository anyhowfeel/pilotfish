//! Address text the way tshark prints it.

use std::fmt::Write;
use std::net::{IpAddr, Ipv6Addr};

pub fn mac(m: &[u8; 6]) -> String {
    let mut s = String::with_capacity(17);
    for (i, b) in m.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The `inet_ntop` layout Wireshark uses: the longest zero run becomes `::`, and an
/// IPv4-compatible or IPv4-mapped address ends in dotted decimal.
pub fn ipv6(a: &Ipv6Addr) -> String {
    let g = a.segments();
    let (mut base, mut len, mut i) = (0, 0, 0);
    while i < 8 {
        if g[i] != 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < 8 && g[i] == 0 {
            i += 1;
        }
        if i - start > len {
            (base, len) = (start, i - start);
        }
    }
    if len < 2 {
        len = 0;
    }
    let mut s = String::with_capacity(39);
    for i in 0..8 {
        if len > 0 && (base..base + len).contains(&i) {
            if i == base {
                s.push(':');
            }
            continue;
        }
        if i != 0 {
            s.push(':');
        }
        if i == 6 && base == 0 && (len == 6 || (len == 5 && g[5] == 0xffff)) {
            let _ = write!(
                s,
                "{}.{}.{}.{}",
                g[6] >> 8,
                g[6] & 0xff,
                g[7] >> 8,
                g[7] & 0xff
            );
            return s;
        }
        let _ = write!(s, "{:x}", g[i]);
    }
    if len > 0 && base + len == 8 {
        s.push(':');
    }
    s
}

pub fn ip(a: &IpAddr) -> String {
    match a {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => ipv6(v),
    }
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
#[path = "fmt_tests.rs"]
mod tests;
