//! Click-to-filter parser & context menu for dissected `DetailNode` fields.

use eframe::egui::Ui;
use wl_model::DetailNode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterCombine {
    Replace,
    Not,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldFilterCandidate {
    pub field: String,
    pub value: Option<String>,
    pub label: String,
}

fn infer_proto(parent_layer: Option<&str>) -> Option<&'static str> {
    let l = parent_layer?.to_ascii_lowercase();
    const MAP: &[(&str, &str)] = &[
        ("transmission control", "tcp"),
        ("user datagram", "udp"),
        ("version 6", "ipv6"),
        ("version 4", "ip"),
        ("ethernet", "eth"),
        ("hypertext", "http"),
        ("domain name", "dns"),
        ("mdns", "dns"),
        ("transport layer security", "tls"),
        ("icmpv6", "icmpv6"),
        ("icmp", "icmp"),
        ("frame", "frame"),
    ];
    MAP.iter()
        .find(|(pat, proto)| l.contains(pat) || l.starts_with(proto))
        .map(|(_, p)| *p)
}

fn is_mac(s: &str) -> bool {
    s.len() == 17 && s.bytes().filter(|&b| b == b':').count() == 5
}

fn is_unquoted(v: &str) -> bool {
    v.parse::<u64>().is_ok()
        || v.parse::<f64>().is_ok()
        || v.parse::<std::net::IpAddr>().is_ok()
        || is_mac(v)
        || v.starts_with("0x")
}

fn clean_value(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches("\\r\\n");
    let first = trimmed.split_whitespace().next().unwrap_or(trimmed);
    if is_unquoted(first) {
        return first.to_owned();
    }
    if let Some(open) = trimmed.rfind('(')
        && let Some(inner) = trimmed[open + 1..].strip_suffix(')')
        && is_mac(inner)
    {
        return inner.to_owned();
    }
    trimmed.to_owned()
}

fn map_label_key(key: &str, value: &str, proto: Option<&str>) -> Option<String> {
    if !key.is_empty()
        && key.contains('.')
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_'))
    {
        return Some(key.to_owned());
    }
    const EXACT: &[(&str, &str)] = &[
        ("frame number", "frame.number"),
        ("frame length", "frame.len"),
        ("time to live", "ip.ttl"),
        ("protocol", "ip.proto"),
        ("host", "http.host"),
        ("request method", "http.request.method"),
        ("request uri", "http.request.uri"),
        ("status code", "http.response.code"),
        ("user-agent", "http.user_agent"),
        ("content-type", "http.content_type"),
        ("query name", "dns.qry.name"),
        ("server name", "tls.handshake.extensions_server_name"),
    ];
    let k = key.to_ascii_lowercase();
    if let Some((_, field)) = EXACT.iter().find(|(name, _)| *name == k) {
        return Some((*field).into());
    }
    let ip_p = if value.parse::<std::net::Ipv6Addr>().is_ok() {
        "ipv6"
    } else if value.parse::<std::net::Ipv4Addr>().is_ok() {
        "ip"
    } else if is_mac(value) {
        "eth"
    } else {
        proto.unwrap_or("ip")
    };
    let p = proto.unwrap_or("tcp");
    let mapped = match k.as_str() {
        "source port" | "src port" => format!("{p}.srcport"),
        "destination port" | "dst port" => format!("{p}.dstport"),
        "source" | "source address" => format!("{ip_p}.src"),
        "destination" | "destination address" => format!("{ip_p}.dst"),
        "stream index" => format!("{p}.stream"),
        "name" if proto == Some("dns") => "dns.qry.name".into(),
        "type" if matches!(proto, Some("icmp" | "icmpv6")) => format!("{p}.type"),
        "code" if matches!(proto, Some("icmp" | "icmpv6")) => format!("{p}.code"),
        _ => return None,
    };
    Some(mapped)
}

/// Extracts a Wireshark display-filter candidate from a `DetailNode`.
pub fn extract_filter_candidate(
    node: &DetailNode,
    parent_layer: Option<&str>,
    pdml_name: Option<&str>,
) -> Option<FieldFilterCandidate> {
    let explicit = pdml_name.filter(|n| !n.is_empty()).map(ToOwned::to_owned);
    if let Some((raw_k, raw_v)) = node.label.split_once(':') {
        let value = clean_value(raw_v);
        let field =
            explicit.or_else(|| map_label_key(raw_k.trim(), &value, infer_proto(parent_layer)))?;
        return Some(FieldFilterCandidate {
            field,
            value: (!value.is_empty()).then_some(value),
            label: node.label.clone(),
        });
    }
    let field = explicit.or_else(|| infer_proto(Some(&node.label)).map(ToOwned::to_owned))?;
    Some(FieldFilterCandidate {
        field,
        value: None,
        label: node.label.clone(),
    })
}

fn fmt_val(v: &str) -> String {
    if is_unquoted(v) {
        v.to_owned()
    } else {
        format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// Builds a Wireshark display-filter expression combining `candidate` with `current_filter`.
pub fn build_expression(c: &FieldFilterCandidate, current: &str, mode: FilterCombine) -> String {
    let atom = match &c.value {
        Some(v) => format!("{} == {}", c.field, fmt_val(v)),
        None => c.field.clone(),
    };
    let cur = current.trim();
    match mode {
        FilterCombine::Replace => atom,
        FilterCombine::Not => match &c.value {
            Some(v) => format!("{} != {}", c.field, fmt_val(v)),
            None => format!("!({})", c.field),
        },
        FilterCombine::And if !cur.is_empty() => format!("({cur}) && ({atom})"),
        FilterCombine::Or if !cur.is_empty() => format!("({cur}) || ({atom})"),
        FilterCombine::And | FilterCombine::Or => atom,
    }
}

/// Renders click-to-filter context-menu buttons and returns the chosen expression.
pub fn detail_filter_menu(ui: &mut Ui, c: &FieldFilterCandidate, current: &str) -> Option<String> {
    let mut result = None;
    for (label, mode) in [
        ("Apply as Filter (==)", FilterCombine::Replace),
        ("Filter Not Selected (!=)", FilterCombine::Not),
        ("And Selected (&&)", FilterCombine::And),
        ("Or Selected (||)", FilterCombine::Or),
    ] {
        let expr = build_expression(c, current, mode);
        if ui.button(label).on_hover_text(&expr).clicked() {
            result = Some(expr);
            ui.close();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_ports_ips_http_and_combines_expressions() {
        let mk = |l: &str| DetailNode {
            label: l.into(),
            range: None,
            children: vec![],
        };
        let p = extract_filter_candidate(
            &mk("Source Port: 443"),
            Some("Transmission Control Protocol"),
            None,
        )
        .unwrap();
        assert_eq!(
            build_expression(&p, "", FilterCombine::Replace),
            "tcp.srcport == 443"
        );
        assert_eq!(
            build_expression(&p, "", FilterCombine::Not),
            "tcp.srcport != 443"
        );
        assert_eq!(
            build_expression(&p, "ip.src == 10.0.0.1", FilterCombine::And),
            "(ip.src == 10.0.0.1) && (tcp.srcport == 443)"
        );
        let host = extract_filter_candidate(
            &mk("Host: example.com\\r\\n"),
            Some("Hypertext Transfer Protocol"),
            None,
        )
        .unwrap();
        assert_eq!(
            build_expression(&host, "", FilterCombine::Replace),
            "http.host == \"example.com\""
        );
        let ip = extract_filter_candidate(&mk("Destination: 192.168.1.1"), None, None).unwrap();
        assert_eq!(
            build_expression(&ip, "", FilterCombine::Replace),
            "ip.dst == 192.168.1.1"
        );
        let pdml = extract_filter_candidate(&mk("Custom: hello \"world\""), None, Some("my.field"))
            .unwrap();
        assert_eq!(
            build_expression(&pdml, "tcp", FilterCombine::Or),
            "(tcp) || (my.field == \"hello \\\"world\\\"\")"
        );
    }
}
