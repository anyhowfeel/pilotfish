//! UDP protocols identified by well-known port and payload shape: DHCP, NTP, SSDP and QUIC.

use std::fmt::Write;

use super::Label;
use crate::decode::fmt;
use crate::decode::read::{be32, tail};

pub fn dhcp(p: &[u8]) -> Option<Label> {
    if be32(p, 236)? != 0x6382_5363 {
        return None;
    }
    let xid = be32(p, 4)?;
    let mut opts = tail(p, 240);
    let mut kind = None;
    while let Some(&code) = opts.first() {
        match code {
            0 => opts = &opts[1..],
            255 => break,
            _ => {
                let len = usize::from(*opts.get(1)?);
                if code == 53 {
                    kind = opts.get(2).copied();
                }
                opts = tail(opts, 2 + len);
            }
        }
    }
    let name = match kind? {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => return None,
    };
    Some(Label::new(
        "DHCP",
        format!("DHCP {name:<8} - Transaction ID 0x{xid:x}"),
    ))
}

pub fn ntp(p: &[u8]) -> Option<Label> {
    let b = *p.first()?;
    (p.len() >= 48).then_some(())?;
    let mode = match b & 7 {
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "reserved for NTP control message",
        7 => "reserved for private use",
        _ => "reserved",
    };
    Some(Label::new(
        "NTP",
        format!("NTP Version {}, {mode}", (b >> 3) & 7),
    ))
}

pub fn ssdp(p: &[u8]) -> Option<Label> {
    let starts = [&b"M-SEARCH "[..], b"NOTIFY ", b"HTTP/1.1 200"];
    if !starts.iter().any(|s| p.starts_with(s)) {
        return None;
    }
    let end = p
        .iter()
        .position(|b| *b == b'\r' || *b == b'\n')
        .unwrap_or(p.len());
    Some(Label::new(
        "SSDP",
        format!("{} ", String::from_utf8_lossy(&p[..end.min(256)])),
    ))
}

/// A QUIC long header packet (first bit and fixed bit set).
pub fn quic(p: &[u8]) -> Option<Label> {
    let b = *p.first()?;
    if b & 0xc0 != 0xc0 {
        return None;
    }
    let version = be32(p, 1)?;
    let dcid_len = usize::from(*p.get(5)?);
    let dcid = p.get(6..6 + dcid_len)?;
    let kind = if version == 0 {
        "Version Negotiation"
    } else {
        match (b >> 4) & 3 {
            0 => "Initial",
            1 => "0-RTT",
            2 => "Handshake",
            _ => "Retry",
        }
    };
    let mut info = String::from(kind);
    let _ = write!(info, ", DCID={}", fmt::hex(dcid));
    Some(Label::new("QUIC", info))
}

#[cfg(test)]
#[path = "udp_apps_tests.rs"]
mod tests;
