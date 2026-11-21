//! Pure display-filter field catalog, token extraction, and completion replacement.

use std::collections::HashSet;

use wl_kit::text::contains_ci;
use wl_model::FilterField;

/// In-memory catalog: sorted for binary-searched prefix lookup, with curated fields ranked first.
#[derive(Debug, Clone)]
pub struct FieldCatalog {
    fields: Vec<FilterField>,
    common: HashSet<String>,
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
        let common = default_builtin_fields()
            .into_iter()
            .map(|f| f.abbrev)
            .collect();
        Self { fields, common }
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Up to `max` matches: prefix matches first (exact, then curated, then shortest), then
    /// substring matches in the field name or abbreviation.
    pub fn suggest(&self, query: &str, max: usize) -> Vec<&FilterField> {
        let q = query.trim().to_ascii_lowercase();
        if q.is_empty() || max == 0 {
            return Vec::new();
        }
        let start = self
            .fields
            .partition_point(|f| f.abbrev.as_str() < q.as_str());
        let mut prefixed: Vec<&FilterField> = self.fields[start..]
            .iter()
            .take_while(|f| f.abbrev.starts_with(&q))
            .collect();
        prefixed.sort_by_key(|f| {
            (
                f.abbrev != q,
                !self.common.contains(&f.abbrev),
                f.abbrev.len(),
            )
        });
        prefixed.truncate(max);
        if prefixed.len() < max {
            let rest = self.fields.iter().filter(|f| {
                !f.abbrev.starts_with(&q) && (f.abbrev.contains(&q) || contains_ci(&f.name, &q))
            });
            prefixed.extend(rest.take(max - prefixed.len()));
        }
        prefixed
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
        ("ip.proto", "IPv4 Protocol", "FT_UINT8"),
        ("ip.ttl", "IPv4 Time to Live", "FT_UINT8"),
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

    fn field(abbrev: &str) -> FilterField {
        FilterField {
            abbrev: abbrev.into(),
            name: abbrev.into(),
            field_type: "FT_STRING".into(),
        }
    }

    #[test]
    fn exact_then_curated_then_shortest_prefix() {
        let cat = FieldCatalog::from_fields(
            [
                "ip.addr",
                "ip.addr.extra.long",
                "ip.dst",
                "ip.dsfield",
                "ip.dsthost",
                "ipv6.addr",
            ]
            .map(field)
            .to_vec(),
        );
        let order = |q| {
            cat.suggest(q, 10)
                .iter()
                .map(|f| f.abbrev.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(order("ip.addr")[..2], ["ip.addr", "ip.addr.extra.long"]);
        assert_eq!(order("ip.d"), ["ip.dst", "ip.dsfield", "ip.dsthost"]);
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
