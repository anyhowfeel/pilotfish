//! Decodes a capture natively and lists every difference from tshark's rows.

use std::collections::HashMap;
use std::net::IpAddr;

use wl_model::PacketRow;
use wl_native::decode::Decoder;
use wl_native::reader::PacketMeta;

use super::reference::{Reference, strip_analysis};

/// Labels the decoder can produce. When tshark names one of these, ours must match exactly.
const VOCAB: [&str; 18] = [
    "ARP", "ICMP", "ICMPv6", "TCP", "UDP", "DNS", "MDNS", "HTTP", "TLSv1", "TLSv1.1", "TLSv1.2",
    "TLSv1.3", "DHCP", "NTP", "SSDP", "QUIC", "IPv4", "IPv6",
];
/// Protocols whose Info text is compared as well.
const INFO_CHECKED: [&str; 6] = ["ARP", "ICMP", "ICMPv6", "TCP", "UDP", "DNS"];

/// `(capture, frame, field, reason)` of a difference that is a documented limit.
pub type Allowed = (&'static str, u64, &'static str, &'static str);

/// Wireshark reassembles IP fragments and shows the transport header, the stream number and the
/// application protocol only on the last one. The decoder reads the ports from the first
/// fragment, as the requirement for fragments says, and numbers no fragmented datagram.
const FRAGMENT: &str = "wireshark reports the reassembled datagram on its last fragment";
pub const ALLOWED: &[Allowed] = &[
    ("synthetic:fragments", 1, "src_port", FRAGMENT),
    ("synthetic:fragments", 1, "dst_port", FRAGMENT),
    ("synthetic:fragments", 1, "transport", FRAGMENT),
    ("synthetic:fragments", 2, "src_port", FRAGMENT),
    ("synthetic:fragments", 2, "dst_port", FRAGMENT),
    ("synthetic:fragments", 2, "stream", FRAGMENT),
    ("synthetic:fragments", 2, "protocol", FRAGMENT),
    ("synthetic:fragments", 2, "info", FRAGMENT),
];

#[derive(Default)]
pub struct Counts {
    pub frames: usize,
    pub mismatches: Vec<String>,
    pub protocol_compared: usize,
    pub protocol_not_ours: usize,
    pub info_compared: usize,
    pub info_differs: usize,
}

impl Counts {
    pub fn summary(&self, name: &str) -> String {
        format!(
            "{name}: {} frames, {} mismatches, protocol compared {} (tshark names {} others), info differs {}/{}",
            self.frames,
            self.mismatches.len(),
            self.protocol_compared,
            self.protocol_not_ours,
            self.info_differs,
            self.info_compared
        )
    }
}

/// Decodes `cap` with the decoder and compares the rows.
pub fn compare(
    name: &str,
    cap: &[(PacketMeta, Vec<u8>)],
    reference: &HashMap<u64, Reference>,
    allowed: &[Allowed],
) -> Counts {
    let mut decoder = Decoder::default();
    let first_epoch = cap.first().map_or(0.0, |p| p.0.epoch);
    let rows: Vec<PacketRow> = cap
        .iter()
        .map(|(meta, data)| decoder.decode(meta, data, first_epoch).row)
        .collect();
    compare_rows(name, &rows, reference, allowed)
}

pub fn compare_rows(
    name: &str,
    rows: &[PacketRow],
    reference: &HashMap<u64, Reference>,
    allowed: &[Allowed],
) -> Counts {
    let mut c = Counts::default();
    for row in rows {
        c.frames += 1;
        let Some(r) = reference.get(&row.no) else {
            c.mismatches
                .push(format!("{name} #{}: not in tshark output", row.no));
            continue;
        };
        let mut bad = |field: &str, ours: String, theirs: String| {
            let known = allowed
                .iter()
                .any(|(f, n, fld, _)| *f == name && *n == row.no && *fld == field);
            if !known {
                c.mismatches.push(format!(
                    "{name} #{} {field}: ours {ours:?}, tshark {theirs:?}",
                    row.no
                ));
            }
        };
        let (src, dst) = (
            r.either("ip.src", "ipv6.src"),
            r.either("ip.dst", "ipv6.dst"),
        );
        for (field, ours, theirs) in [("src_ip", row.src_ip, src), ("dst_ip", row.dst_ip, dst)] {
            if ours != theirs.parse::<IpAddr>().ok() {
                bad(field, format!("{ours:?}"), theirs.into());
            }
        }
        for (field, ours, theirs) in [("src", &*row.src, src), ("dst", &*row.dst, dst)] {
            if !theirs.is_empty() && ours != theirs {
                bad(field, ours.into(), theirs.into());
            }
        }
        let port = |a, b| r.either(a, b).parse::<u16>().ok();
        let (sp, dp) = (
            port("tcp.srcport", "udp.srcport"),
            port("tcp.dstport", "udp.dstport"),
        );
        if row.src_port != sp {
            bad("src_port", format!("{:?}", row.src_port), format!("{sp:?}"));
        }
        if row.dst_port != dp {
            bad("dst_port", format!("{:?}", row.dst_port), format!("{dp:?}"));
        }
        let len = r.get("frame.len").parse::<u32>().ok();
        if Some(row.len) != len {
            bad("len", row.len.to_string(), format!("{len:?}"));
        }
        let stream = r.either("tcp.stream", "udp.stream").parse::<u32>().ok();
        if row.stream != stream {
            bad("stream", format!("{:?}", row.stream), format!("{stream:?}"));
        }
        if row.transport != r.transport() {
            bad(
                "transport",
                format!("{:?}", row.transport),
                format!("{:?}", r.transport()),
            );
        }
        let epoch = r.get("frame.time_epoch").parse::<f64>().unwrap_or(f64::NAN);
        if (row.epoch - epoch).abs() > 1e-5 {
            bad("epoch", row.epoch.to_string(), epoch.to_string());
        }
        let theirs = r.get("_ws.col.protocol");
        if !VOCAB.contains(&theirs) {
            c.protocol_not_ours += 1;
            continue;
        }
        c.protocol_compared += 1;
        if &*row.protocol != theirs {
            bad("protocol", row.protocol.to_string(), theirs.into());
        }
        if INFO_CHECKED.contains(&theirs)
            && let Some(want) = strip_analysis(r.get("_ws.col.info"))
        {
            c.info_compared += 1;
            if want != *row.info {
                c.info_differs += 1;
                bad("info", row.info.to_string(), want);
            }
        }
    }
    c
}
