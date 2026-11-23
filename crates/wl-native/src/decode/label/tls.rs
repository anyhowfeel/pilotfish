//! TLS records found by their header, with the record and handshake names Wireshark prints.

use super::Label;
use super::tls_hello::{client_hello_version, server_hello_version, server_name};
use crate::decode::read::{be16, tail};
use crate::decode::streams::Stream;

const HEADER: usize = 5;
const MAX_RECORDS: usize = 16;

fn version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSLv3",
        0x0301 => "TLSv1",
        0x0302 => "TLSv1.1",
        0x0303 => "TLSv1.2",
        0x0304 => "TLSv1.3",
        _ => "TLS",
    }
}

fn record_header(d: &[u8]) -> Option<(u8, u16, usize)> {
    let ct = *d.first()?;
    let version = be16(d, 1)?;
    let len = usize::from(be16(d, 3)?);
    ((20..=23).contains(&ct) && (0x0300..=0x0304).contains(&version)).then_some((ct, version, len))
}

/// Labels a TCP payload as TLS. `None` when it does not look like TLS or ends inside a record
/// without completing one, in which case Wireshark shows the segment as plain TCP.
pub fn label(payload: &[u8], stream: Option<(&mut Stream, usize)>) -> Option<Label> {
    let mut scratch = Stream::new(0);
    let (st, dir) = stream.unwrap_or((&mut scratch, 0));
    let mut rest = payload;
    let mut parts: Vec<String> = Vec::new();
    let mut first_version = None;
    let pending = st.half[dir].pending as usize;
    if pending > 0 {
        let take = pending.min(rest.len());
        st.half[dir].pending = u32::try_from(pending - take).unwrap_or(0);
        rest = &rest[take..];
        if st.half[dir].pending == 0 {
            parts.push(continuation_name(st.half[dir].pending_ct));
            first_version = Some(st.half[dir].pending_version);
        }
    }
    for _ in 0..MAX_RECORDS {
        if rest.is_empty() {
            break;
        }
        let Some((ct, version, len)) = record_header(rest) else {
            break;
        };
        let body = tail(rest, HEADER);
        first_version.get_or_insert(client_hello_version(ct, body).unwrap_or(version));
        if body.len() < len {
            st.half[dir].pending = u32::try_from(len - body.len()).unwrap_or(0);
            st.half[dir].pending_ct = ct;
            st.half[dir].pending_version = version;
            break;
        }
        parts.push(record_name(ct, &body[..len], st, dir));
        rest = &body[len..];
    }
    if parts.is_empty() {
        return None;
    }
    let version = st.tls.or(first_version).unwrap_or(0);
    Some(Label::new(version_name(version), parts.join(", ")))
}

fn continuation_name(ct: u8) -> String {
    match ct {
        23 => "Application Data".into(),
        20 => "Change Cipher Spec".into(),
        21 => "Alert".into(),
        _ => "Handshake".into(),
    }
}

fn record_name(ct: u8, body: &[u8], st: &mut Stream, dir: usize) -> String {
    match ct {
        20 => {
            st.half[dir].ccs = true;
            "Change Cipher Spec".into()
        }
        21 if st.half[dir].ccs => "Encrypted Alert".into(),
        21 => alert(body),
        23 => "Application Data".into(),
        _ if st.half[dir].ccs => "Encrypted Handshake Message".into(),
        _ => handshake(body, st),
    }
}

fn alert(body: &[u8]) -> String {
    let (Some(level), Some(desc)) = (body.first(), body.get(1)) else {
        return "Alert".into();
    };
    let level = match level {
        1 => "Warning",
        2 => "Fatal",
        _ => return "Alert".into(),
    };
    let desc = match desc {
        0 => "Close Notify",
        10 => "Unexpected Message",
        20 => "Bad Record MAC",
        40 => "Handshake Failure",
        42 => "Bad Certificate",
        45 => "Certificate Expired",
        46 => "Certificate Unknown",
        47 => "Illegal Parameter",
        48 => "Unknown CA",
        50 => "Decode Error",
        51 => "Decrypt Error",
        70 => "Protocol Version",
        80 => "Internal Error",
        90 => "User Canceled",
        109 => "Missing Extension",
        112 => "Unrecognized Name",
        _ => return "Alert".into(),
    };
    format!("Alert (Level: {level}, Description: {desc})")
}

fn handshake_name(t: u8) -> &'static str {
    match t {
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        5 => "End of Early Data",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        22 => "Certificate Status",
        24 => "Key Update",
        _ => "Handshake",
    }
}

fn handshake(mut body: &[u8], st: &mut Stream) -> String {
    let mut names: Vec<String> = Vec::new();
    while let (Some(&t), Some(len)) = (body.first(), len24(body, 1)) {
        let msg = body.get(4..4 + len);
        let sni = msg.filter(|_| t == 1).and_then(server_name);
        names.push(match sni {
            Some(host) => format!("Client Hello (SNI={host})"),
            None => handshake_name(t).to_string(),
        });
        if t == 2
            && let Some(v) = msg.and_then(server_hello_version)
        {
            st.tls = Some(v);
        }
        body = tail(body, 4 + len);
        if names.len() >= MAX_RECORDS {
            break;
        }
    }
    if names.is_empty() {
        "Handshake".into()
    } else {
        names.join(", ")
    }
}

fn len24(d: &[u8], at: usize) -> Option<usize> {
    let b = d.get(at..at + 3)?;
    Some(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
