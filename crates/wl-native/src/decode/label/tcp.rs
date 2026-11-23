//! TCP segments: the Info text with Wireshark's relative sequence numbers, and the application
//! protocol carried when the payload shows one.

use std::fmt::Write;

use super::{Label, http, tls};
use crate::decode::net::Ip;
use crate::decode::read::be32;
use crate::decode::streams::Stream;
use crate::decode::transport::Tcp;

const FLAG_NAMES: [&str; 8] = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"];
const REASSEMBLY: &str = " [TCP segment of a reassembled PDU]";

pub fn label(_ip: &Ip, t: &Tcp, stream: Option<(&mut Stream, usize)>) -> Label {
    let mut scratch = Stream::new(0);
    let (st, dir) = stream.unwrap_or((&mut scratch, 0));
    track(st, dir, t);
    let mut info = summary(st, dir, t);
    if (t.has(Tcp::FIN) || t.has(Tcp::RST))
        && let Some(l) = http::close(st)
    {
        return l;
    }
    if t.payload.is_empty() {
        return Label::new("TCP", info);
    }
    let http_body = st.half[dir].pending > 0 && st.half[dir].pending_ct == 0;
    if !http_body && let Some(l) = tls::label(t.payload, Some((st, dir))) {
        return l;
    }
    if !http_body && st.half[dir].pending > 0 {
        info.push_str(REASSEMBLY);
        return Label::new("TCP", info);
    }
    match http::label(t.payload, st, dir) {
        http::Outcome::Message(l) => l,
        http::Outcome::Partial(line) => Label::new("TCP", line),
        http::Outcome::Body | http::Outcome::NotHttp => Label::new("TCP", info),
    }
}

/// Records what the segment tells about its side of the stream.
fn track(st: &mut Stream, dir: usize, t: &Tcp) {
    st.closed |= t.has(Tcp::FIN) || t.has(Tcp::RST);
    let half = &mut st.half[dir];
    if t.has(Tcp::SYN) {
        half.base = Some(t.seq);
        half.shift = options(t.options).find_map(|o| match o {
            Opt::WindowScale(s) => Some(s),
            _ => None,
        });
    } else if half.base.is_none() {
        // Wireshark counts a stream it joined late from the packet before the first one seen.
        half.base = Some(t.seq.wrapping_sub(1));
    }
    let peer = &mut st.half[1 - dir];
    if t.has(Tcp::ACK) && peer.base.is_none() {
        peer.base = Some(t.ack.wrapping_sub(1));
    }
}

fn rel(value: u32, base: Option<u32>) -> u32 {
    value.wrapping_sub(base.unwrap_or(0))
}

fn summary(st: &Stream, dir: usize, t: &Tcp) -> String {
    let (own, peer) = (&st.half[dir], &st.half[1 - dir]);
    let flags: Vec<&str> = FLAG_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| t.flags & (1 << i) != 0)
        .map(|(_, n)| *n)
        .collect();
    let flags = if flags.is_empty() {
        "<None>".to_string()
    } else {
        flags.join(", ")
    };
    let mut s = format!(
        "{} \u{2192} {} [{flags}] Seq={}",
        t.src,
        t.dst,
        rel(t.seq, own.base)
    );
    if t.has(Tcp::ACK) {
        let _ = write!(s, " Ack={}", rel(t.ack, peer.base));
    }
    let scale = match (own.shift, peer.shift) {
        (Some(shift), Some(_)) if !t.has(Tcp::SYN) => u32::from(shift.min(14)),
        _ => 0,
    };
    let _ = write!(
        s,
        " Win={} Len={}",
        u32::from(t.window) << scale,
        t.payload_len
    );
    for o in options(t.options) {
        match o {
            Opt::Mss(v) => {
                let _ = write!(s, " MSS={v}");
            }
            Opt::WindowScale(v) => {
                let _ = write!(s, " WS={}", 1u32 << v.min(14));
            }
            Opt::SackPermitted => s.push_str(" SACK_PERM"),
            Opt::Timestamps(a, b) => {
                let _ = write!(s, " TSval={a} TSecr={b}");
            }
            Opt::Sack(l, r) => {
                let _ = write!(s, " SLE={} SRE={}", rel(l, peer.base), rel(r, peer.base));
            }
        }
    }
    s
}

enum Opt {
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    Timestamps(u32, u32),
    Sack(u32, u32),
}

/// The options Wireshark prints in the Info column; others are skipped.
fn options(mut d: &[u8]) -> impl Iterator<Item = Opt> + '_ {
    std::iter::from_fn(move || {
        loop {
            let kind = *d.first()?;
            if kind == 0 {
                return None;
            }
            if kind == 1 {
                d = &d[1..];
                continue;
            }
            let len = usize::from(*d.get(1)?);
            let body = d.get(2..len.max(2))?;
            d = &d[len.max(2)..];
            let opt = match (kind, body.len()) {
                (2, 2) => Some(Opt::Mss(u16::from_be_bytes([body[0], body[1]]))),
                (3, 1) => Some(Opt::WindowScale(body[0])),
                (4, 0) => Some(Opt::SackPermitted),
                (8, 8) => Some(Opt::Timestamps(be32(body, 0)?, be32(body, 4)?)),
                (5, n) if n >= 8 => Some(Opt::Sack(be32(body, 0)?, be32(body, 4)?)),
                _ => None,
            };
            if let Some(o) = opt {
                return Some(o);
            }
        }
    })
}

#[cfg(test)]
#[path = "tcp_tests.rs"]
mod tests;
