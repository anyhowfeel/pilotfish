//! Shared parsing helpers of the flow / TCP-graph passes: TCP flag bits, tshark analysis
//! markers found in the Info column, and the `sport -> dport` prefix of Info.

use wl_model::FlowFlags;

/// `tcp.flags` printed as `0x0012` -> SYN|ACK etc.
pub fn tcp_flags(hex: &str) -> FlowFlags {
    let Ok(bits) = u16::from_str_radix(hex.trim().trim_start_matches("0x"), 16) else {
        return FlowFlags::default();
    };
    [
        (0x01, FlowFlags::FIN),
        (0x02, FlowFlags::SYN),
        (0x04, FlowFlags::RST),
        (0x08, FlowFlags::PSH),
        (0x10, FlowFlags::ACK),
    ]
    .into_iter()
    .filter(|(bit, _)| bits & bit != 0)
    .fold(FlowFlags::default(), |acc, (_, f)| acc.with(f))
}

/// Findings of the TCP analysis, read from the Info column markers (`[TCP Retransmission]` ...):
/// the underlying `tcp.analysis.*` fields are empty flag fields in `-T fields` output.
pub fn analysis_flags(info: &str) -> FlowFlags {
    if !info.contains("[TCP") && !info.contains("[ACKed") {
        return FlowFlags::default();
    }
    let table = [
        ("Retransmission]", FlowFlags::RETRANS),
        ("Dup ACK", FlowFlags::DUP_ACK),
        ("Out-Of-Order]", FlowFlags::OUT_OF_ORDER),
        ("ZeroWindow", FlowFlags::ZERO_WINDOW),
        ("Previous segment not captured]", FlowFlags::LOST),
    ];
    table
        .into_iter()
        .filter(|(m, _)| info.contains(m))
        .fold(FlowFlags::default(), |acc, (_, f)| acc.with(f))
}

/// Drops the `1234 \u{2192} 80 ` of a TCP/UDP Info (the arrow already shows the ports). Analysis
/// markers tshark puts in front of it (`[TCP Dup ACK 3#1] 1 \u{2192} 2 ...`) are kept.
pub fn strip_ports(info: &str) -> String {
    let (mut head, mut rest) = ("", info);
    while rest.starts_with("[TCP") || rest.starts_with("[ACKed") {
        let Some(end) = rest.find("] ") else { break };
        head = &info[..info.len() - rest.len() + end + 1];
        rest = &rest[end + 2..];
    }
    let body = match rest.split_once(" \u{2192} ") {
        Some((p, tail)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            tail[tail.bytes().take_while(u8::is_ascii_digit).count()..].trim_start()
        }
        _ => rest,
    };
    match (head.is_empty(), body.is_empty()) {
        (true, _) => body.to_owned(),
        (false, true) => head.to_owned(),
        _ => format!("{head} {body}"),
    }
}

/// Drops the `Seq= Ack= Win= Len=` tokens of a TCP Info: the diagram shows them in its own
/// annotation column, so the arrow label keeps only flags and options.
pub fn drop_numbers(info: &str) -> String {
    let skip = |t: &str| {
        ["Seq=", "Ack=", "Win=", "Len="]
            .iter()
            .any(|p| t.starts_with(p))
    };
    let mut out = String::with_capacity(info.len());
    for tok in info.split(' ').filter(|t| !skip(t)) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(tok);
    }
    out
}

pub fn port(a: &str, b: &str) -> Option<u16> {
    [a, b].into_iter().find_map(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_bits() {
        let f = tcp_flags("0x0012");
        assert!(f.contains(FlowFlags::SYN) && f.contains(FlowFlags::ACK));
        assert!(!f.contains(FlowFlags::FIN));
        assert!(tcp_flags("0x0019").contains(FlowFlags::FIN.with(FlowFlags::PSH)));
        assert_eq!(tcp_flags(""), FlowFlags::default());
    }

    #[test]
    fn analysis_markers() {
        let f = analysis_flags("80 \u{2192} 1 [TCP Fast Retransmission] [ACK] Seq=1");
        assert!(f.contains(FlowFlags::RETRANS));
        assert!(analysis_flags("[TCP Dup ACK 5#2] 1 \u{2192} 2").contains(FlowFlags::DUP_ACK));
        assert!(analysis_flags("[TCP Previous segment not captured]").contains(FlowFlags::LOST));
        assert_eq!(analysis_flags("GET / HTTP/1.1"), FlowFlags::default());
    }

    #[test]
    fn numbers_are_dropped_from_tcp_info() {
        assert_eq!(
            drop_numbers("[ACK] Seq=1 Ack=2 Win=3 Len=0 MSS=1460"),
            "[ACK] MSS=1460"
        );
        assert_eq!(drop_numbers("GET /a HTTP/1.1"), "GET /a HTTP/1.1");
    }

    #[test]
    fn port_prefix_is_stripped_only_for_ports() {
        assert_eq!(strip_ports("47985 \u{2192} 443 [SYN] Seq=0"), "[SYN] Seq=0");
        assert_eq!(
            strip_ports("[TCP Dup ACK 14#1] 51000 \u{2192} 8080 [ACK] Seq=32"),
            "[TCP Dup ACK 14#1] [ACK] Seq=32"
        );
        assert_eq!(strip_ports("Client Hello (SNI=x)"), "Client Hello (SNI=x)");
        assert_eq!(strip_ports("abc \u{2192} 4 x"), "abc \u{2192} 4 x");
    }
}
