//! `tshark -T fields` line -> `PacketRow`.

use std::net::IpAddr;
use std::sync::Arc;

use wl_model::{PacketRow, Transport};

use crate::interner::Interner;

/// Maximum characters kept for `_ws.col.Info` so pathological packets cannot blow up memory or UI.
pub const MAX_INFO_CHARS: usize = 2048;

/// Column order is part of the contract with `parse_line`.
const FIELDS: [&str; 20] = [
    "frame.number",
    "frame.time_epoch",
    "frame.time_relative",
    "_ws.col.def_src",
    "_ws.col.def_dst",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "ip.proto",
    "ipv6.nxt",
    "_ws.col.protocol",
    "frame.len",
    "_ws.col.info",
    "tcp.stream",
    "udp.stream",
];

/// Fixed column layout so user Wireshark preferences cannot change what we read.
const COLUMN_FORMAT: &str = "gui.column.format:\"No.\",\"%m\",\"Time\",\"%t\",\"Source\",\"%s\",\"Destination\",\"%d\",\"Protocol\",\"%p\",\"Length\",\"%L\",\"Info\",\"%i\"";

/// tshark arguments that make it print one tab separated line per packet.
pub fn field_args() -> Vec<String> {
    let base = [
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=f",
        "-o",
    ];
    let mut a: Vec<String> = base.into_iter().map(String::from).collect();
    a.push(COLUMN_FORMAT.into());
    for f in FIELDS {
        a.push("-e".into());
        a.push(f.into());
    }
    a
}

fn non_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

fn first_of<'a>(a: &'a str, b: &'a str) -> Option<&'a str> {
    non_empty(a).or_else(|| non_empty(b))
}

fn transport(f: &[&str; FIELDS.len()]) -> Transport {
    if !f[9].is_empty() || !f[11].is_empty() {
        return Transport::Tcp;
    }
    if !f[10].is_empty() || !f[12].is_empty() {
        return Transport::Udp;
    }
    match first_of(f[13], f[14]).and_then(|p| p.parse::<u8>().ok()) {
        Some(6) => Transport::Tcp,
        Some(17) => Transport::Udp,
        Some(1 | 58) => Transport::Icmp,
        _ => Transport::Other,
    }
}

fn cap_info(s: &str) -> Arc<str> {
    if s.len() <= MAX_INFO_CHARS {
        return Arc::from(s);
    }
    match s.char_indices().nth(MAX_INFO_CHARS) {
        None => Arc::from(s),
        Some((cut, _)) => {
            let mut out = String::with_capacity(cut + 3);
            out.push_str(&s[..cut]);
            out.push('\u{2026}');
            Arc::from(out)
        }
    }
}

/// Parses one output line; `None` for blank/garbled lines.
pub fn parse_line(line: &str, interner: &mut Interner) -> Option<PacketRow> {
    let line = line.trim_end_matches(['\n', '\r']);
    let mut iter = line.split('\t');
    let mut f = [""; FIELDS.len()];
    for slot in &mut f {
        *slot = iter.next()?;
    }
    // Fast path: exact 20 columns (zero heap allocation). Slow path: literal tab inside Info.
    let (info, tcp_stream, udp_stream) = match iter.next() {
        None => (cap_info(f[17]), f[18], f[19]),
        Some(extra) => {
            let mut tail = vec![f[17], f[18], f[19], extra];
            tail.extend(iter);
            let n = tail.len();
            let joined = tail[..n - 2].join(" ");
            (cap_info(&joined), tail[n - 2], tail[n - 1])
        }
    };
    let ip = |a: &str, b: &str| first_of(a, b).and_then(|s| s.parse::<IpAddr>().ok());
    let port = |a: &str, b: &str| first_of(a, b).and_then(|s| s.parse::<u16>().ok());
    Some(PacketRow {
        no: f[0].parse().ok()?,
        epoch: f[1].parse().unwrap_or(0.0),
        rel: f[2].parse().unwrap_or(0.0),
        src: interner.intern(f[3]),
        dst: interner.intern(f[4]),
        src_ip: ip(f[5], f[6]),
        dst_ip: ip(f[7], f[8]),
        src_port: port(f[9], f[10]),
        dst_port: port(f[11], f[12]),
        transport: transport(&f),
        protocol: interner.intern(f[15]),
        len: f[16].parse().unwrap_or(0),
        info,
        stream: first_of(tcp_stream, udp_stream).and_then(|s| s.parse().ok()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_ipv4() {
        let l = "7\t1700000000.5\t0.25\t10.0.0.1\t10.0.0.2\t10.0.0.1\t\t10.0.0.2\t\t443\t\t51000\t\t6\t\tTLSv1.3\t1514\tApplication Data\t3\t\n";
        let r = parse_line(l, &mut Interner::default()).unwrap();
        assert_eq!((r.no, r.len, r.stream), (7, 1514, Some(3)));
        assert_eq!(r.transport, Transport::Tcp);
        assert_eq!((r.src_port, r.dst_port), (Some(443), Some(51000)));
        assert_eq!(r.src_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(&*r.protocol, "TLSv1.3");
        assert!((r.rel - 0.25).abs() < 1e-9);
    }

    #[test]
    fn parses_udp_ipv6_and_interns() {
        let l = "1\t1.0\t0.0\tfe80::1\tff02::fb\t\tfe80::1\t\tff02::fb\t\t5353\t\t5353\t\t17\tMDNS\t90\tStandard query\t\t0\n";
        let mut i = Interner::default();
        let (a, b) = (
            parse_line(l, &mut i).unwrap(),
            parse_line(l, &mut i).unwrap(),
        );
        assert_eq!((a.transport, a.stream), (Transport::Udp, Some(0)));
        assert_eq!(a.dst_ip, Some("ff02::fb".parse().unwrap()));
        assert!(Arc::ptr_eq(&a.protocol, &b.protocol) && Arc::ptr_eq(&a.src, &b.src));
    }

    #[test]
    fn non_ip_arp_and_icmpv6() {
        let arp = "2\t1.0\t0.1\taa:bb:cc:dd:ee:ff\tBroadcast\t\t\t\t\t\t\t\t\t\t\tARP\t42\tWho has 10.0.0.1?\t\t\n";
        let r = parse_line(arp, &mut Interner::default()).unwrap();
        assert_eq!(&*r.src, "aa:bb:cc:dd:ee:ff");
        assert_eq!((r.src_ip, r.transport), (None, Transport::Other));

        let icmp6 = "3\t1.0\t0.1\tfe80::1\tff02::1\t\tfe80::1\t\tff02::1\t\t\t\t\t\t58\tICMPv6\t86\tNeighbor Solicitation\t\t\n";
        let r6 = parse_line(icmp6, &mut Interner::default()).unwrap();
        assert_eq!(r6.transport, Transport::Icmp);
        assert_eq!(r6.src_ip, Some("fe80::1".parse().unwrap()));
    }

    #[test]
    fn caps_huge_info_utf8_safely_and_handles_non_utf8() {
        let huge = "é".repeat(MAX_INFO_CHARS + 500);
        let l = format!(
            "4\t1.0\t0.1\t10.0.0.1\t10.0.0.2\t10.0.0.1\t\t10.0.0.2\t\t\t\t\t\t1\t\tICMP\t98\t{huge}\t\t\n"
        );
        let r = parse_line(&l, &mut Interner::default()).unwrap();
        assert_eq!(r.info.chars().count(), MAX_INFO_CHARS + 1);
        assert!(r.info.ends_with('\u{2026}'));

        let mut raw = b"5\t1.0\t0.2\t10.0.0.1\t10.0.0.2\t10.0.0.1\t\t10.0.0.2\t\t80\t\t5000\t\t6\t\tHTTP\t60\tHEAD\t9\t\n".to_vec();
        let pos = raw.windows(4).position(|w| w == b"HEAD").unwrap();
        raw[pos..pos + 4].copy_from_slice(&[0xff, 0xfe, b'o', b'k']);
        let r2 = parse_line(&String::from_utf8_lossy(&raw), &mut Interner::default()).unwrap();
        assert_eq!((r2.no, r2.stream), (5, Some(9)));
        assert!(r2.info.contains('\u{fffd}') && r2.info.ends_with("ok"));
    }

    #[test]
    fn literal_tab_in_info_preserves_stream_and_garbage_is_rejected() {
        let l = "6\t1.0\t0.2\t10.0.0.1\t10.0.0.2\t10.0.0.1\t\t10.0.0.2\t\t80\t\t5000\t\t6\t\tHTTP\t60\tGET\t/index\t42\t\n";
        let r = parse_line(l, &mut Interner::default()).unwrap();
        assert_eq!((&*r.info, r.stream), ("GET /index", Some(42)));

        let mut i = Interner::default();
        assert!(parse_line("\n", &mut i).is_none());
        assert!(parse_line("a\tb\n", &mut i).is_none());
        assert!(parse_line(&"\t".repeat(20), &mut i).is_none());
    }
}
