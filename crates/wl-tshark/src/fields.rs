//! Display filter field catalog loaded lazily from `tshark -G fields`, with instant built-ins.

use std::io::{BufRead, BufReader};

use wl_model::{CaptureError, FilterField};

use crate::error::{from_stderr, io_error};
use crate::process::{self, StderrTap, Tools};

/// Parses a single tab-separated line of `tshark -G fields`.
///
/// Format:
/// - `P\t<name>\t<abbrev>`
/// - `F\t<name>\t<abbrev>\t<FT_TYPE>\t...`
pub fn parse_field_line(line: &str) -> Option<FilterField> {
    let mut cols = line.split('\t');
    let kind = cols.next()?;
    let name = cols.next()?.trim();
    let abbrev = cols.next()?.trim();
    if abbrev.is_empty() {
        return None;
    }
    let field_type = match kind {
        "P" => "PROTOCOL",
        "F" => cols.next().unwrap_or("FT_NONE").trim(),
        _ => return None,
    };
    Some(FilterField {
        abbrev: abbrev.to_owned(),
        name: name.to_owned(),
        field_type: field_type.to_owned(),
    })
}

/// Streams `tshark -G fields` and returns up to `limit` parsed fields (or all when `None`).
pub fn load_fields(tools: &Tools, limit: Option<usize>) -> Result<Vec<FilterField>, CaptureError> {
    let args = vec!["-G".to_owned(), "fields".to_owned()];
    let mut child = process::spawn(&tools.tshark, &args, false)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CaptureError::Other("tshark stdout unavailable".into()))?;
    let stderr_tap = child.stderr.take().map(StderrTap::spawn);

    let mut fields = Vec::with_capacity(limit.unwrap_or(16_384).min(65_536));
    let reader = BufReader::new(stdout);
    for line_res in reader.lines() {
        let line = line_res.map_err(|e| io_error("read tshark -G fields", &e))?;
        if let Some(f) = parse_field_line(&line) {
            fields.push(f);
            if limit.is_some_and(|cap| fields.len() >= cap) {
                let _ = child.kill();
                break;
            }
        }
    }
    let status = child
        .wait()
        .map_err(|e| io_error("wait tshark -G fields", &e))?;
    let stderr = stderr_tap.map(StderrTap::finish).unwrap_or_default();
    if limit.is_none() && !status.success() {
        return Err(from_stderr(&stderr));
    }
    Ok(fields)
}

/// Curated instant-fallback catalog of high-frequency display filter fields.
pub fn builtin_fields() -> Vec<FilterField> {
    const COMMON: &[(&str, &str, &str)] = &[
        ("frame.number", "Frame Number", "FT_UINT32"),
        ("frame.len", "Frame length on the wire", "FT_UINT32"),
        (
            "frame.time_relative",
            "Time since reference or first frame",
            "FT_RELATIVE_TIME",
        ),
        (
            "frame.time_delta",
            "Time delta from previous captured frame",
            "FT_RELATIVE_TIME",
        ),
        ("eth.src", "Ethernet Source", "FT_ETHER"),
        ("eth.dst", "Ethernet Destination", "FT_ETHER"),
        ("eth.addr", "Ethernet Address", "FT_ETHER"),
        ("arp.opcode", "ARP Opcode", "FT_UINT16"),
        ("ip.src", "Source Address", "FT_IPv4"),
        ("ip.dst", "Destination Address", "FT_IPv4"),
        ("ip.addr", "Source or Destination Address", "FT_IPv4"),
        ("ip.ttl", "Time to Live", "FT_UINT8"),
        ("ip.proto", "Protocol", "FT_UINT8"),
        ("ipv6.src", "Source Address", "FT_IPv6"),
        ("ipv6.dst", "Destination Address", "FT_IPv6"),
        ("ipv6.addr", "Source or Destination Address", "FT_IPv6"),
        ("tcp.port", "Source or Destination Port", "FT_UINT16"),
        ("tcp.srcport", "Source Port", "FT_UINT16"),
        ("tcp.dstport", "Destination Port", "FT_UINT16"),
        ("tcp.stream", "Stream index", "FT_UINT32"),
        ("tcp.flags.syn", "Syn", "FT_BOOLEAN"),
        ("tcp.flags.ack", "Acknowledgment", "FT_BOOLEAN"),
        ("tcp.flags.fin", "Fin", "FT_BOOLEAN"),
        ("tcp.flags.reset", "Reset", "FT_BOOLEAN"),
        ("tcp.window_size", "Calculated window size", "FT_UINT32"),
        (
            "tcp.analysis.retransmission",
            "This frame is a (suspected) retransmission",
            "FT_NONE",
        ),
        (
            "tcp.analysis.lost_segment",
            "Previous segment(s) not captured",
            "FT_NONE",
        ),
        ("tcp.analysis.dup_ack", "Duplicate ACK", "FT_NONE"),
        ("tcp.analysis.zero_window", "Zero window", "FT_NONE"),
        (
            "tcp.analysis.ack_rtt",
            "The RTT to ACK the segment",
            "FT_RELATIVE_TIME",
        ),
        ("udp.port", "Source or Destination Port", "FT_UINT16"),
        ("udp.srcport", "Source Port", "FT_UINT16"),
        ("udp.dstport", "Destination Port", "FT_UINT16"),
        ("udp.stream", "Stream index", "FT_UINT32"),
        ("udp.length", "Length", "FT_UINT16"),
        ("icmp.type", "ICMP Type", "FT_UINT8"),
        ("icmp.code", "ICMP Code", "FT_UINT8"),
        ("icmpv6.type", "ICMPv6 Type", "FT_UINT8"),
        ("dns.qry.name", "DNS Query Name", "FT_STRING"),
        ("dns.qry.type", "DNS Query Type", "FT_UINT16"),
        ("dns.flags.rcode", "Reply code", "FT_UINT16"),
        ("dns.flags.response", "Response", "FT_BOOLEAN"),
        ("dns.a", "Address", "FT_IPv4"),
        ("dns.aaaa", "AAAA Address", "FT_IPv6"),
        ("http.request.method", "Request Method", "FT_STRING"),
        ("http.request.uri", "Request URI", "FT_STRING"),
        ("http.host", "Host", "FT_STRING"),
        ("http.response.code", "Status Code", "FT_UINT16"),
        ("http.user_agent", "User-Agent", "FT_STRING"),
        ("http.content_type", "Content-Type", "FT_STRING"),
        (
            "tls.handshake.extensions_server_name",
            "Server Name (SNI)",
            "FT_STRING",
        ),
        ("tls.handshake.type", "Handshake Protocol Type", "FT_UINT8"),
        ("tls.record.version", "TLS Record Version", "FT_UINT16"),
        ("quic.dcid", "Destination Connection ID", "FT_BYTES"),
        ("_ws.malformed", "Malformed Packet", "PROTOCOL"),
        ("_ws.expert.severity", "Expert Info Severity", "FT_UINT32"),
    ];
    COMMON
        .iter()
        .map(|(abbrev, name, field_type)| FilterField {
            abbrev: (*abbrev).to_owned(),
            name: (*name).to_owned(),
            field_type: (*field_type).to_owned(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_protocol_and_field_lines() {
        let p = parse_field_line("P\tTransmission Control Protocol\ttcp").unwrap();
        assert_eq!(p.abbrev, "tcp");
        assert_eq!(p.field_type, "PROTOCOL");

        let f = parse_field_line("F\tSource Port\ttcp.srcport\tFT_UINT16\ttcp\tBASE_PT_TCP\t0x0\t")
            .unwrap();
        assert_eq!(f.abbrev, "tcp.srcport");
        assert_eq!(f.name, "Source Port");
        assert_eq!(f.field_type, "FT_UINT16");

        assert!(parse_field_line("X\tignored\tfoo").is_none());
        assert!(parse_field_line("").is_none());
    }

    #[test]
    fn builtins_are_nonempty_and_unique() {
        let list = builtin_fields();
        assert!(list.len() >= 50);
        assert!(
            list.iter()
                .any(|f| f.abbrev == "tcp.analysis.retransmission")
        );
        assert!(list.iter().any(|f| f.abbrev == "dns.qry.name"));
    }
}
