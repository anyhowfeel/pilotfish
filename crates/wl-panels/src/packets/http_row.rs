//! Pure label logic for the detail tree: CRLF noise removal, `Key: value` split, HTTP start lines,
//! and the per-sibling-group key column width that keeps values aligned.

const METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
];
/// Keys longer than this are prose, not field names: the label is not split.
const MAX_KEY_CHARS: usize = 44;

/// Removes trailing real or literal (`\r\n`, escaped `\\r\\n`) line endings and surrounding spaces.
pub fn clean(label: &str) -> &str {
    let mut s = label.trim_end();
    loop {
        let before = s;
        for tail in ["\\\\r\\\\n", "\\r\\n", "\\n", "\\r"] {
            if let Some(t) = s.strip_suffix(tail) {
                s = t.trim_end();
            }
        }
        if s == before {
            return s;
        }
    }
}

/// Parsed first line of an HTTP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start<'a> {
    Request {
        method: &'a str,
        uri: &'a str,
        version: &'a str,
    },
    Response {
        version: &'a str,
        code: u16,
        reason: &'a str,
    },
}

/// Recognises `GET /x HTTP/1.1` and `HTTP/1.1 200 OK` (already cleaned of CRLF).
pub fn parse_start(label: &str) -> Option<Start<'_>> {
    if let Some(rest) = label.strip_prefix("HTTP/") {
        let (ver_tail, rest) = rest.split_once(' ')?;
        let (code, reason) = rest.split_once(' ').unwrap_or((rest, ""));
        let code: u16 = code.parse().ok().filter(|c| (100..600).contains(c))?;
        let version = &label[..5 + ver_tail.len()];
        return Some(Start::Response {
            version,
            code,
            reason,
        });
    }
    let (method, rest) = label.split_once(' ')?;
    if !METHODS.contains(&method) {
        return None;
    }
    let (uri, version) = rest.rsplit_once(' ')?;
    version.starts_with("HTTP/").then_some(Start::Request {
        method,
        uri,
        version,
    })
}

/// Splits `Key: value` at the first ": ". Bracketed notes and long prose are left whole.
pub fn split_kv(label: &str) -> Option<(&str, &str)> {
    if label.starts_with('[') {
        return None;
    }
    let (k, v) = label.split_once(": ")?;
    (!k.is_empty() && k.chars().count() <= MAX_KEY_CHARS).then_some((k, v))
}

/// For each visible row `(depth, measured key width if it is a Key: value row)`, the shared key
/// column width of its sibling group (rows with the same parent), capped at `cap`.
pub fn sibling_key_widths(rows: &[(u16, Option<f32>)], cap: f32) -> Vec<f32> {
    let mut parents: Vec<Option<usize>> = Vec::with_capacity(rows.len());
    let mut stack: Vec<(u16, usize)> = Vec::new();
    for (i, (d, _)) in rows.iter().enumerate() {
        while stack.last().is_some_and(|(sd, _)| sd >= d) {
            stack.pop();
        }
        parents.push(stack.last().map(|&(_, p)| p));
        stack.push((*d, i));
    }
    let mut widest: std::collections::HashMap<Option<usize>, f32> = Default::default();
    for (p, (_, w)) in parents.iter().zip(rows) {
        if let Some(w) = w {
            let e = widest.entry(*p).or_insert(0.0);
            *e = e.max(*w);
        }
    }
    parents
        .iter()
        .map(|p| widest.get(p).copied().unwrap_or(0.0).min(cap))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_crlf_in_all_spellings() {
        assert_eq!(clean("Host: a.com\\r\\n"), "Host: a.com");
        assert_eq!(clean("Host: a.com\\\\r\\\\n"), "Host: a.com");
        assert_eq!(clean("Host: a.com\r\n"), "Host: a.com");
        assert_eq!(clean("GET / HTTP/1.1\\r\\n  "), "GET / HTTP/1.1");
        assert_eq!(clean("Frame 1"), "Frame 1");
    }

    #[test]
    fn start_lines() {
        assert_eq!(
            parse_start("GET /a?b=1 HTTP/1.1"),
            Some(Start::Request {
                method: "GET",
                uri: "/a?b=1",
                version: "HTTP/1.1"
            })
        );
        assert_eq!(
            parse_start("HTTP/1.1 404 Not Found"),
            Some(Start::Response {
                version: "HTTP/1.1",
                code: 404,
                reason: "Not Found"
            })
        );
        assert_eq!(
            parse_start("HTTP/1.0 200"),
            Some(Start::Response {
                version: "HTTP/1.0",
                code: 200,
                reason: ""
            })
        );
        assert_eq!(parse_start("Host: x"), None);
        assert_eq!(parse_start("GET nothing"), None);
        assert_eq!(parse_start("HTTP/1.1 abc"), None);
    }

    #[test]
    fn key_value_split() {
        assert_eq!(split_kv("Host: a.com:80"), Some(("Host", "a.com:80")));
        assert_eq!(split_kv("[Expert Info (Chat): x: y]"), None);
        assert_eq!(split_kv("Frame 1"), None);
        assert_eq!(split_kv(&format!("{}: v", "k".repeat(60))), None);
    }

    #[test]
    fn key_column_is_shared_per_parent() {
        // 0 parent | 1,2 kv children | 3 nested under 2 | 4 sibling kv (wider) | 5 new parent
        let rows = [
            (0, None),
            (1, Some(30.0)),
            (1, Some(50.0)),
            (2, Some(10.0)),
            (1, Some(40.0)),
            (0, None),
        ];
        let w = sibling_key_widths(&rows, 200.0);
        assert_eq!(w[1], 50.0);
        assert_eq!(w[2], 50.0);
        assert_eq!(w[4], 50.0);
        assert_eq!(w[3], 10.0);
        assert_eq!(sibling_key_widths(&rows, 20.0)[1], 20.0);
    }
}
