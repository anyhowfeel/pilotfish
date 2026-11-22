//! What is being typed in a display filter: a field name, or the value of a comparison.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind<'a> {
    Field,
    /// Right-hand side of `field <operator>`.
    Value {
        field: &'a str,
    },
}

/// The token under the cursor with its byte range in the expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Active<'a> {
    pub start: usize,
    pub end: usize,
    pub token: &'a str,
    pub kind: Kind<'a>,
}

const SYMBOL_OPS: [&str; 6] = ["==", "!=", ">=", "<=", ">", "<"];
const WORD_OPS: [&str; 4] = ["eq", "ne", "contains", "matches"];

fn is_field_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

fn is_value_char(c: char) -> bool {
    !c.is_whitespace()
        && !matches!(
            c,
            '=' | '!' | '<' | '>' | '&' | '|' | '(' | ')' | '{' | '}' | ',' | '"'
        )
}

fn expand(expr: &str, cursor: usize, keep: fn(char) -> bool) -> (usize, usize) {
    let start = expr[..cursor].rfind(|c: char| !keep(c)).map_or(0, |i| {
        i + expr[i..].chars().next().map_or(1, char::len_utf8)
    });
    let end = cursor
        + expr[cursor..]
            .find(|c: char| !keep(c))
            .unwrap_or(expr.len() - cursor);
    (start, end)
}

/// The field a comparison operator ending `before` applies to, if there is one.
fn field_before(before: &str) -> Option<&str> {
    let t = before.trim_end();
    let without_op = SYMBOL_OPS
        .iter()
        .find_map(|op| t.strip_suffix(op))
        .or_else(|| {
            WORD_OPS.iter().find_map(|op| {
                t.strip_suffix(op)
                    .filter(|rest| rest.ends_with(char::is_whitespace))
            })
        })?;
    let name = without_op.trim_end();
    let start = name.rfind(|c: char| !is_field_char(c)).map_or(0, |i| i + 1);
    (start < name.len()).then(|| &name[start..])
}

/// `text` wrapped in the double quotes the expression does not already have around the token.
pub fn quoted_insert(expr: &str, a: &Active, text: &str) -> String {
    let open = if expr[..a.start].ends_with('"') {
        ""
    } else {
        "\""
    };
    let close = if expr[a.end..].starts_with('"') {
        ""
    } else {
        "\""
    };
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    format!("{open}{escaped}{close}")
}

/// Token at `cursor_char` and whether it is a field or a value.
pub fn active(expr: &str, cursor_char: usize) -> Active<'_> {
    let cursor = expr
        .char_indices()
        .nth(cursor_char)
        .map_or(expr.len(), |(i, _)| i);
    let (vstart, vend) = expand(expr, cursor, is_value_char);
    let before = expr[..vstart].trim_end_matches('"');
    if let Some(field) = field_before(before) {
        return Active {
            start: vstart,
            end: vend,
            token: &expr[vstart..vend],
            kind: Kind::Value { field },
        };
    }
    let (start, end) = expand(expr, cursor, is_field_char);
    Active {
        start,
        end,
        token: &expr[start..end],
        kind: Kind::Field,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at_end(expr: &str) -> Active<'_> {
        active(expr, expr.chars().count())
    }

    #[test]
    fn a_bare_word_is_a_field() {
        let a = at_end("ip.src == 10.0.0.1 && tcp.an");
        assert_eq!((a.token, a.kind), ("tcp.an", Kind::Field));
    }

    #[test]
    fn after_an_operator_it_is_a_value_of_that_field() {
        for (expr, token) in [
            ("ip.addr==10.", "10."),
            ("ip.addr == ", ""),
            ("a == 1 && ip.dst != fe80::1", "fe80::1"),
            ("tcp.port >= 80", "80"),
            ("http.host contains exa", "exa"),
        ] {
            let a = at_end(expr);
            assert_eq!(a.token, token, "{expr}");
            assert!(matches!(a.kind, Kind::Value { .. }), "{expr}");
        }
        assert_eq!(
            at_end("x && ip.addr==10.").kind,
            Kind::Value { field: "ip.addr" }
        );
    }

    #[test]
    fn quoted_values_exclude_the_quote() {
        let a = at_end(r#"dns.qry.name == "exa"#);
        assert_eq!(
            (a.token, a.kind),
            (
                "exa",
                Kind::Value {
                    field: "dns.qry.name"
                }
            )
        );
    }

    #[test]
    fn a_field_after_a_value_is_a_field_again() {
        assert_eq!(at_end("ip.addr == 1.2.3.4 && tc").kind, Kind::Field);
        assert_eq!(at_end("ip.addr == 1.2.3.4 && tc").token, "tc");
    }

    #[test]
    fn cursor_in_the_middle_selects_the_surrounding_token() {
        let expr = "ip.addr == 10.0.0.1 && tcp";
        let a = active(expr, 14);
        assert_eq!(a.token, "10.0.0.1");
        assert_eq!(&expr[a.start..a.end], "10.0.0.1");
    }

    #[test]
    fn quotes_are_added_only_where_missing() {
        for (expr, want) in [
            ("http.host == ex", "\"a.test\""),
            ("http.host == \"ex", "a.test\""),
            ("http.host == \"ex\"", "a.test"),
        ] {
            let a = at_end(expr);
            let a = if expr.ends_with('"') {
                active(expr, expr.len() - 1)
            } else {
                a
            };
            assert_eq!(quoted_insert(expr, &a, "a.test"), want, "{expr}");
        }
    }

    #[test]
    fn quotes_and_backslashes_in_names_are_escaped() {
        let expr = "dns.qry.name == we";
        let a = at_end(expr);
        let name = r#"we"i\rd"#;
        assert_eq!(quoted_insert(expr, &a, name), r#""we\"i\\rd""#);
    }
}
