//! DNS and mDNS messages, read only as far as the Info column needs.

use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::decode::fmt;
use crate::decode::read::{be16, be32};

const HEADER: usize = 12;
/// Pointer hops allowed in one name; a loop in a crafted message ends here.
const MAX_JUMPS: usize = 16;
const MAX_NAME: usize = 255;
/// Records listed in the Info text.
const MAX_RECORDS: usize = 32;

/// Info text for a DNS message, `None` when the payload is too short to be one.
pub fn info(msg: &[u8], mdns: bool) -> Option<String> {
    let id = be16(msg, 0)?;
    let flags = be16(msg, 2)?;
    let count = |i: usize| be16(msg, 4 + 2 * i).map(usize::from);
    let (questions, others) = (count(0)?, count(1)? + count(2)? + count(3)?);
    let response = flags & 0x8000 != 0;
    let mut out = String::from(opcode(flags >> 11 & 0xf));
    if response {
        out.push_str(" response");
    }
    let _ = write!(out, " 0x{id:04x}");
    if response && let Some(r) = rcode(flags & 0xf) {
        let _ = write!(out, " {r}");
    }
    let mut at = HEADER;
    for _ in (0..questions).take(MAX_RECORDS) {
        let Some((name, next)) = name(msg, at) else {
            return Some(out);
        };
        let (Some(ty), Some(class)) = (be16(msg, next), be16(msg, next + 2)) else {
            return Some(out);
        };
        let _ = write!(out, " {} {name}", type_name(ty));
        if mdns {
            let q = if class & 0x8000 != 0 { "QU" } else { "QM" };
            let _ = write!(out, ", \"{q}\" question");
        }
        at = next + 4;
    }
    for _ in (0..others).take(MAX_RECORDS) {
        let Some(next) = record(msg, at, &mut out) else {
            break;
        };
        at = next;
    }
    Some(out)
}

fn opcode(op: u16) -> &'static str {
    match op {
        0 => "Standard query",
        1 => "Inverse query",
        2 => "Server status request",
        4 => "Notify",
        5 => "Update",
        _ => "Unknown operation",
    }
}

fn rcode(rc: u16) -> Option<&'static str> {
    match rc {
        0 => None,
        1 => Some("Format error"),
        2 => Some("Server failure"),
        3 => Some("No such name"),
        4 => Some("Not implemented"),
        5 => Some("Refused"),
        _ => Some("Unknown error"),
    }
}

pub fn type_name(t: u16) -> String {
    let n = match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        252 => "AXFR",
        255 => "ANY",
        _ => return format!("Unknown ({t})"),
    };
    n.to_string()
}

/// Reads a possibly compressed name at `at`; returns it and the offset just past it in the
/// original position (not past a followed pointer).
fn name(msg: &[u8], at: usize) -> Option<(String, usize)> {
    let (mut pos, mut end, mut jumps) = (at, None, 0);
    let mut out = String::new();
    loop {
        let len = *msg.get(pos)?;
        match len {
            0 => {
                let next = end.unwrap_or(pos + 1);
                if out.is_empty() {
                    out.push_str("<Root>");
                }
                return Some((out, next));
            }
            l if l & 0xc0 == 0xc0 => {
                let target = usize::from(be16(msg, pos)? & 0x3fff);
                end.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None;
                }
                pos = target;
            }
            l if l & 0xc0 != 0 => return None,
            l => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(l))?;
                if !out.is_empty() {
                    out.push('.');
                }
                for &b in label {
                    if b.is_ascii_graphic() || b == b' ' {
                        out.push(char::from(b));
                    } else {
                        let _ = write!(out, "\\{b:03}");
                    }
                }
                if out.len() > MAX_NAME {
                    return None;
                }
                pos += 1 + usize::from(l);
            }
        }
    }
}

/// Appends one resource record to `out`; returns the offset after it.
fn record(msg: &[u8], at: usize, out: &mut String) -> Option<usize> {
    let (_, p) = name(msg, at)?;
    let ty = be16(msg, p)?;
    let rdlen = usize::from(be16(msg, p + 8)?);
    let data = p + 10;
    msg.get(data..data + rdlen)?;
    let _ = write!(out, " {}", type_name(ty));
    if let Some(text) = rdata(msg, ty, data, rdlen) {
        let _ = write!(out, " {text}");
    }
    Some(data + rdlen)
}

fn rdata(msg: &[u8], ty: u16, at: usize, len: usize) -> Option<String> {
    match ty {
        1 if len == 4 => Some(Ipv4Addr::from(be32(msg, at)?).to_string()),
        28 if len == 16 => {
            let b: [u8; 16] = msg.get(at..at + 16)?.try_into().ok()?;
            Some(fmt::ipv6(&Ipv6Addr::from(b)))
        }
        2 | 5 | 12 => name(msg, at).map(|(n, _)| n),
        15 => {
            let (n, _) = name(msg, at + 2)?;
            Some(format!("{} {n}", be16(msg, at)?))
        }
        6 => {
            let (m, next) = name(msg, at)?;
            let (r, _) = name(msg, next)?;
            Some(format!("{m} {r}"))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
