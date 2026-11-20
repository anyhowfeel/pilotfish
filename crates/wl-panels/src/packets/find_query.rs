//! Find Packet query model and its translation into an execution plan (pure, tested).
//! List-column string/regex searches run locally on the rows; everything that needs packet
//! bytes or a display filter becomes a tshark filter expression run by the backend.

use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FindMode {
    Filter,
    #[default]
    Text,
    Hex,
    Regex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FindScope {
    #[default]
    List,
    Details,
    Bytes,
}

impl FindMode {
    pub const ALL: [FindMode; 4] = [
        FindMode::Filter,
        FindMode::Text,
        FindMode::Hex,
        FindMode::Regex,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FindMode::Filter => "Display filter",
            FindMode::Text => "String",
            FindMode::Hex => "Hex",
            FindMode::Regex => "Regex",
        }
    }

    /// Whether the scope selector applies (filters and hex always address the whole frame).
    pub fn uses_scope(self) -> bool {
        matches!(self, FindMode::Text | FindMode::Regex)
    }
}

impl FindScope {
    pub const ALL: [FindScope; 3] = [FindScope::List, FindScope::Details, FindScope::Bytes];

    pub fn label(self) -> &'static str {
        match self {
            FindScope::List => "Packet list",
            FindScope::Details => "Packet details",
            FindScope::Bytes => "Packet bytes",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FindQuery {
    pub mode: FindMode,
    pub scope: FindScope,
    pub case_sensitive: bool,
    pub text: String,
}

#[derive(Debug)]
pub enum Plan {
    Empty,
    /// Match packet-list columns of the loaded rows.
    Local(Regex),
    /// Ask the backend for every frame matching this display filter.
    Backend(String),
    Invalid(String),
}

/// Quotes `s` as a display-filter string literal.
pub fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `aa bb:0xcc` -> `aa:bb:cc` (even number of hex digits required).
pub fn hex_bytes(text: &str) -> Option<String> {
    let t: String = text
        .split(|c: char| c.is_whitespace() || c == ':' || c == '-')
        .map(|p| p.trim_start_matches("0x"))
        .collect();
    if t.is_empty() || !t.len().is_multiple_of(2) || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let pairs: Vec<&str> = (0..t.len()).step_by(2).map(|i| &t[i..i + 2]).collect();
    Some(pairs.join(":"))
}

fn build_regex(pattern: &str, case_sensitive: bool) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .build()
        .map_err(|e| {
            let msg = e.to_string();
            let last = msg.lines().last().unwrap_or("bad regex");
            last.trim_start_matches("error: ").to_owned()
        })
}

fn matches_expr(pattern: &str, case_sensitive: bool) -> String {
    let flag = if case_sensitive { "(?-i)" } else { "(?i)" };
    format!("frame matches {}", quote(&format!("{flag}{pattern}")))
}

pub fn plan(q: &FindQuery) -> Plan {
    if q.text.trim().is_empty() {
        return Plan::Empty;
    }
    let local = q.scope == FindScope::List;
    match q.mode {
        FindMode::Filter => Plan::Backend(q.text.trim().to_owned()),
        FindMode::Hex => match hex_bytes(&q.text) {
            Some(h) => Plan::Backend(format!("frame contains {h}")),
            None => Plan::Invalid("Hex needs an even number of hex digits".into()),
        },
        FindMode::Text if local => match build_regex(&regex::escape(&q.text), q.case_sensitive) {
            Ok(r) => Plan::Local(r),
            Err(e) => Plan::Invalid(e),
        },
        FindMode::Text if q.case_sensitive => {
            Plan::Backend(format!("frame contains {}", quote(&q.text)))
        }
        FindMode::Text => Plan::Backend(matches_expr(&regex::escape(&q.text), false)),
        FindMode::Regex => match build_regex(&q.text, q.case_sensitive) {
            Ok(r) if local => Plan::Local(r),
            Ok(_) => Plan::Backend(matches_expr(&q.text, q.case_sensitive)),
            Err(e) => Plan::Invalid(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(mode: FindMode, scope: FindScope, case: bool, text: &str) -> FindQuery {
        FindQuery {
            mode,
            scope,
            case_sensitive: case,
            text: text.into(),
        }
    }

    #[test]
    fn hex_is_normalised() {
        assert_eq!(hex_bytes("de AD:0xbe ef").as_deref(), Some("de:AD:be:ef"));
        assert_eq!(hex_bytes("abc"), None);
        assert_eq!(hex_bytes("zz"), None);
        assert_eq!(hex_bytes("  "), None);
    }

    #[test]
    fn quoting_escapes_backslash_and_quote() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn plans_by_mode_and_scope() {
        use FindMode::*;
        use FindScope::*;
        assert!(matches!(plan(&q(Text, List, false, "")), Plan::Empty));
        assert!(matches!(plan(&q(Text, List, false, "a.b")), Plan::Local(_)));
        let Plan::Backend(b) = plan(&q(Text, Bytes, true, "x\"y")) else {
            panic!()
        };
        assert_eq!(b, r#"frame contains "x\"y""#);
        let Plan::Backend(b) = plan(&q(Text, Details, false, "a.b")) else {
            panic!()
        };
        assert_eq!(b, r#"frame matches "(?i)a\\.b""#);
        let Plan::Backend(b) = plan(&q(Regex, Bytes, true, r"\d+")) else {
            panic!()
        };
        assert_eq!(b, r#"frame matches "(?-i)\\d+""#);
        assert!(matches!(
            plan(&q(Regex, List, false, "(")),
            Plan::Invalid(_)
        ));
        let Plan::Backend(b) = plan(&q(Hex, List, false, "de ad")) else {
            panic!()
        };
        assert_eq!(b, "frame contains de:ad");
        assert!(matches!(plan(&q(Hex, List, false, "d")), Plan::Invalid(_)));
        let Plan::Backend(b) = plan(&q(Filter, Bytes, false, " tcp.port == 1 ")) else {
            panic!()
        };
        assert_eq!(b, "tcp.port == 1");
    }

    #[test]
    fn local_case_toggle() {
        let Plan::Local(r) = plan(&q(FindMode::Text, FindScope::List, false, "dns")) else {
            panic!()
        };
        assert!(r.is_match("DNS query"));
        let Plan::Local(r) = plan(&q(FindMode::Text, FindScope::List, true, "dns")) else {
            panic!()
        };
        assert!(!r.is_match("DNS query"));
    }
}
