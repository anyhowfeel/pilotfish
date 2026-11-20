//! Pure display-filter field catalog, token extraction, and completion replacement.

use wl_model::FilterField;

/// Fast in-memory catalog supporting O(log N) prefix and substring lookup.
#[derive(Debug, Clone)]
pub struct FieldCatalog {
    fields: Vec<FilterField>,
}

impl Default for FieldCatalog {
    fn default() -> Self {
        Self::from_fields(default_builtin_fields())
    }
}

impl FieldCatalog {
    pub fn from_fields(mut fields: Vec<FilterField>) -> Self {
        fields.sort_by(|a, b| a.abbrev.cmp(&b.abbrev));
        fields.dedup_by(|a, b| a.abbrev == b.abbrev);
        Self { fields }
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Returns up to `max` matches: exact prefix matches first, then substring matches.
    pub fn suggest(&self, query: &str, max: usize) -> Vec<&FilterField> {
        let q = query.trim().to_ascii_lowercase();
        if q.is_empty() || max == 0 {
            return Vec::new();
        }
        let mut results: Vec<&FilterField> = Vec::with_capacity(max);
        let start = self
            .fields
            .partition_point(|f| f.abbrev.as_str() < q.as_str());
        for f in &self.fields[start..] {
            if !f.abbrev.starts_with(&q) {
                break;
            }
            results.push(f);
            if results.len() >= max {
                return results;
            }
        }
        for f in &self.fields {
            if results.len() >= max {
                break;
            }
            if !f.abbrev.starts_with(&q)
                && (f.abbrev.contains(&q) || f.name.to_ascii_lowercase().contains(&q))
            {
                results.push(f);
            }
        }
        results
    }
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// Extracts `(byte_start, byte_end, token)` around `cursor_char` in a filter expression.
pub fn active_token(expr: &str, cursor_char: usize) -> (usize, usize, &str) {
    let byte_cursor = expr
        .char_indices()
        .nth(cursor_char)
        .map_or(expr.len(), |(i, _)| i);
    let prefix = &expr[..byte_cursor];
    let start = prefix
        .rfind(|c: char| !is_token_char(c))
        .map_or(0, |i| i + 1);
    let suffix = &expr[byte_cursor..];
    let end = byte_cursor
        + suffix
            .find(|c: char| !is_token_char(c))
            .unwrap_or(suffix.len());
    (start, end, &expr[start..end])
}

/// Replaces the active token at `cursor_char` with `abbrev` and returns `(new_expr, new_cursor)`.
pub fn apply_completion(expr: &str, cursor_char: usize, abbrev: &str) -> (String, usize) {
    let (start, end, _) = active_token(expr, cursor_char);
    let mut out = String::with_capacity(expr.len() + abbrev.len());
    out.push_str(&expr[..start]);
    out.push_str(abbrev);
    out.push_str(&expr[end..]);
    let new_cursor = out[..start + abbrev.len()].chars().count();
    (out, new_cursor)
}

fn default_builtin_fields() -> Vec<FilterField> {
    const COMMON: &[(&str, &str, &str)] = &[
        ("dns.qry.name", "DNS Query Name", "FT_STRING"),
        ("dns.flags.rcode", "DNS Reply Code", "FT_UINT16"),
        ("eth.src", "Ethernet Source", "FT_ETHER"),
        ("eth.dst", "Ethernet Destination", "FT_ETHER"),
        ("frame.number", "Frame Number", "FT_UINT32"),
        ("frame.len", "Frame Length", "FT_UINT32"),
        ("http.host", "HTTP Host", "FT_STRING"),
        ("http.request.method", "HTTP Request Method", "FT_STRING"),
        ("http.response.code", "HTTP Status Code", "FT_UINT16"),
        ("icmp.type", "ICMP Type", "FT_UINT8"),
        ("ip.addr", "IPv4 Address", "FT_IPv4"),
        ("ip.dst", "IPv4 Destination", "FT_IPv4"),
        ("ip.src", "IPv4 Source", "FT_IPv4"),
        ("ipv6.addr", "IPv6 Address", "FT_IPv6"),
        (
            "tcp.analysis.retransmission",
            "TCP Retransmission",
            "FT_NONE",
        ),
        ("tcp.dstport", "TCP Destination Port", "FT_UINT16"),
        ("tcp.flags.reset", "TCP Reset Flag", "FT_BOOLEAN"),
        ("tcp.flags.syn", "TCP SYN Flag", "FT_BOOLEAN"),
        ("tcp.port", "TCP Port", "FT_UINT16"),
        ("tcp.srcport", "TCP Source Port", "FT_UINT16"),
        ("tcp.stream", "TCP Stream Index", "FT_UINT32"),
        (
            "tls.handshake.extensions_server_name",
            "TLS Server Name (SNI)",
            "FT_STRING",
        ),
        ("udp.port", "UDP Port", "FT_UINT16"),
        ("udp.stream", "UDP Stream Index", "FT_UINT32"),
    ];
    COMMON
        .iter()
        .map(|(a, n, t)| FilterField {
            abbrev: (*a).into(),
            name: (*n).into(),
            field_type: (*t).into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_replaces_active_token() {
        let expr = "ip.src == 10.0.0.1 && tcp.an";
        let (s, e, tok) = active_token(expr, expr.chars().count());
        assert_eq!(tok, "tcp.an");
        assert_eq!(&expr[s..e], "tcp.an");

        let (next, cur) =
            apply_completion(expr, expr.chars().count(), "tcp.analysis.retransmission");
        assert_eq!(next, "ip.src == 10.0.0.1 && tcp.analysis.retransmission");
        assert_eq!(cur, next.chars().count());
    }

    #[test]
    fn ranks_prefix_before_substring() {
        let cat = FieldCatalog::default();
        let hits = cat.suggest("tcp.s", 5);
        assert!(!hits.is_empty());
        assert!(hits[0].abbrev.starts_with("tcp.s"));

        let fuzzy = cat.suggest("retransmission", 5);
        assert!(
            fuzzy
                .iter()
                .any(|f| f.abbrev == "tcp.analysis.retransmission")
        );
    }
}
