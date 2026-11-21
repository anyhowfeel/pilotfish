//! A readable text rendering of an HTML body: no tags, line breaks for blocks, bullets for list
//! items, link targets in brackets. Not a renderer, just enough to read a page in the detail pane.

/// True when `body` looks like an HTML document.
pub fn is_html(body: &str) -> bool {
    let head: String = body.trim_start().chars().take(15).collect();
    let head = head.to_ascii_lowercase();
    head.starts_with("<!doctype html") || head.starts_with("<html")
}

const BLOCKS: [&str; 22] = [
    "p",
    "div",
    "br",
    "tr",
    "ul",
    "ol",
    "table",
    "section",
    "header",
    "footer",
    "hr",
    "pre",
    "blockquote",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "form",
    "article",
    "title",
];

fn tag_name(inner: &str) -> (String, bool) {
    let closing = inner.starts_with('/');
    let name: String = inner
        .trim_start_matches('/')
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    (name.to_ascii_lowercase(), closing)
}

fn attr<'a>(inner: &'a str, name: &str) -> Option<&'a str> {
    let lower = inner.to_ascii_lowercase();
    let at = lower.find(&format!("{name}="))? + name.len() + 1;
    let rest = &inner[at..];
    let quote = rest.chars().next().filter(|c| matches!(c, '"' | '\''))?;
    let body = &rest[1..];
    body.find(quote).map(|end| &body[..end])
}

fn decode_entities(s: &str) -> String {
    [
        ("&nbsp;", " "),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&amp;", "&"),
    ]
    .iter()
    .fold(s.to_owned(), |acc, (from, to)| acc.replace(from, to))
}

/// Index just after the closing tag of a raw-text element (`script`, `style`) opened before `from`.
fn skip_raw_text(html: &str, from: usize, name: &str) -> usize {
    let lower = html[from..].to_ascii_lowercase();
    match lower.find(&format!("</{name}")) {
        Some(i) => html[from + i..]
            .find('>')
            .map_or(html.len(), |j| from + i + j + 1),
        None => html.len(),
    }
}

pub fn to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let (mut i, mut href, mut link_start) = (0, None::<String>, 0);
    let mut pre = false;
    while i < html.len() {
        let Some(lt) = html[i..].find('<') else {
            push_text(&mut out, &html[i..], pre);
            break;
        };
        push_text(&mut out, &html[i..i + lt], pre);
        let tag_at = i + lt;
        let Some(gt) = html[tag_at..].find('>') else {
            push_text(&mut out, &html[tag_at..], pre);
            break;
        };
        let inner = &html[tag_at + 1..tag_at + gt];
        i = tag_at + gt + 1;
        if inner.starts_with('!') {
            continue;
        }
        let (name, closing) = tag_name(inner);
        match (name.as_str(), closing) {
            ("script" | "style", false) => i = skip_raw_text(html, i, &name),
            ("li", false) => out.push_str("\n\u{2022} "),
            ("a", false) => {
                href = attr(inner, "href").map(str::to_owned);
                link_start = out.len();
            }
            ("a", true) => {
                if let Some(h) = href.take()
                    && out[link_start..].trim() != h
                    && !h.starts_with('#')
                {
                    out.push_str(&format!(" ({h})"));
                }
            }
            ("pre", c) => {
                pre = !c;
                out.push('\n');
            }
            (n, _) if BLOCKS.contains(&n) => out.push('\n'),
            _ => {}
        }
    }
    tidy(&decode_entities(&out))
}

fn push_text(out: &mut String, text: &str, pre: bool) {
    if pre {
        out.push_str(text);
        return;
    }
    for word in text.split_whitespace() {
        if !out.is_empty() && !out.ends_with(['\n', ' ', '\u{2022}']) {
            out.push(' ');
        }
        out.push_str(word);
    }
    if text.ends_with(char::is_whitespace) && !out.ends_with(['\n', ' ']) {
        out.push(' ');
    }
}

/// Trims every line and keeps at most one blank line in a row.
fn tidy(s: &str) -> String {
    let mut out = String::new();
    let mut blank = true;
    for line in s.lines().map(str::trim_end) {
        if line.trim().is_empty() {
            if !blank {
                out.push('\n');
            }
            blank = true;
        } else {
            out.push_str(line.trim_start());
            out.push('\n');
            blank = false;
        }
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_html_documents() {
        assert!(is_html("  <!DOCTYPE HTML>\n<html>"));
        assert!(is_html("<html lang=en>"));
        assert!(!is_html("{\"a\":1}"));
        assert!(!is_html("<xml/>"));
    }

    #[test]
    fn directory_listing_becomes_a_readable_list() {
        let html = "<!DOCTYPE HTML>\n<html><head><style>:root{color:red}</style>\
                    <title>Directory listing for /</title></head>\n<body>\n\
                    <h1>Directory listing for /</h1>\n<hr>\n<ul>\n\
                    <li><a href=\"acl/\">acl/</a></li>\n<li><a href=\"a b/\">name</a></li>\n</ul></body></html>";
        let t = to_text(html);
        assert!(
            t.starts_with("Directory listing for /\n\nDirectory listing for /"),
            "{t}"
        );
        assert!(t.contains("\u{2022} acl/\n"), "{t}");
        assert!(t.contains("\u{2022} name (a b/)"), "{t}");
        assert!(!t.contains("color"), "style must be dropped: {t}");
        assert!(!t.contains('<'), "{t}");
    }

    #[test]
    fn entities_scripts_and_blank_lines() {
        let t = to_text("<p>a &amp; b &lt;c&gt;</p><script>var x = '<p>';</script><p>end</p>");
        assert_eq!(t, "a & b <c>\n\nend");
    }
}
