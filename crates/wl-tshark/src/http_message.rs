//! tshark's `http` JSON layer -> `HttpMessage` (clean start line, ordered headers, body preview).

use serde_json::Value;
use wl_model::HttpMessage;

use crate::json_ordered::Ordered;

/// Body preview cap in bytes.
pub const PREVIEW_MAX: usize = 4096;

/// Removes real and escaped (`\r\n` spelled out by tshark) line endings at both ends.
fn strip_crlf(s: &str) -> &str {
    let mut t = s;
    loop {
        let n = t
            .trim_matches(['\r', '\n'])
            .trim_end_matches("\\r\\n")
            .trim_end_matches("\\n");
        if n.len() == t.len() {
            return n;
        }
        t = n;
    }
}

fn start_line(layer: &Ordered) -> String {
    layer
        .0
        .iter()
        .find(|(k, v)| v.is_object() && k.contains("HTTP/"))
        .map(|(k, _)| strip_crlf(k).to_string())
        .unwrap_or_default()
}

fn headers(layer: &Ordered) -> Vec<(String, String)> {
    layer
        .0
        .iter()
        .filter(|(k, _)| k == "http.request.line" || k == "http.response.line")
        .filter_map(|(_, v)| v.as_str())
        .map(|raw| {
            let line = strip_crlf(raw);
            match line.split_once(':') {
                Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
                None => (line.trim().to_string(), String::new()),
            }
        })
        .collect()
}

/// `68:65:6c` (or plain `68656c`) -> bytes.
fn decode_hex(s: &str) -> Vec<u8> {
    let mut nibbles = s.chars().filter_map(|c| c.to_digit(16));
    let mut out = Vec::with_capacity(s.len() / 3 + 1);
    while let (Some(hi), Some(lo)) = (nibbles.next(), nibbles.next()) {
        out.push((hi * 16 + lo) as u8);
    }
    out
}

fn is_text(s: &str) -> bool {
    !s.chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

/// Text preview of the first `PREVIEW_MAX` bytes; None for binary data.
pub fn preview(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let cut = &body[..body.len().min(PREVIEW_MAX)];
    let text = match std::str::from_utf8(cut) {
        Ok(t) => t,
        // A multi-byte character may be split by the cap; keep the valid prefix.
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&cut[..e.valid_up_to()]).ok()?,
        Err(_) => return None,
    };
    if !is_text(text) {
        return None;
    }
    let mut out = text.to_string();
    if body.len() > cut.len() {
        out.push_str(&format!("\n... [truncated, {} bytes total]", body.len()));
    }
    Some(out)
}

fn header_content_length(h: &[(String, String)]) -> Option<u64> {
    h.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
}

pub fn message(layer: &Ordered) -> HttpMessage {
    let headers = headers(layer);
    let body = layer.first_str("http.file_data").map(decode_hex);
    let body_len = match &body {
        Some(b) if !b.is_empty() => b.len() as u64,
        _ => header_content_length(&headers).unwrap_or(0),
    };
    HttpMessage {
        start_line: start_line(layer),
        headers,
        body_preview: body.as_deref().and_then(preview),
        body_len,
    }
}

/// True when the layer is a request (has a request line), false for a response.
pub fn is_request(layer: &Ordered) -> bool {
    layer.0.iter().any(|(k, v)| {
        matches!(v, Value::Object(_)) && k.contains("HTTP/") && !k.starts_with("HTTP/")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(json: &str) -> Ordered {
        serde_json::from_str(json).expect("json")
    }

    #[test]
    fn builds_clean_message() {
        let l = layer(
            r#"{"HTTP/1.0 200 OK\\r\\n":{"http.response.code":"200"},
                "http.server":"S",
                "http.response.line":"Server: SimpleHTTP/0.6 Python\r\n",
                "http.response.line":"Content-type: text/html\r\n",
                "http.response.line":"X-Odd: a:b\r\n",
                "http.file_data":"68:65:6c:6c:6f:0a"}"#,
        );
        let m = message(&l);
        assert_eq!(m.start_line, "HTTP/1.0 200 OK");
        assert_eq!(
            m.headers[0],
            ("Server".into(), "SimpleHTTP/0.6 Python".into())
        );
        assert_eq!(m.headers[2], ("X-Odd".into(), "a:b".into()));
        assert!(
            m.headers
                .iter()
                .all(|(n, v)| !n.contains('\r') && !v.contains('\n'))
        );
        assert_eq!(
            (m.body_preview.as_deref(), m.body_len),
            (Some("hello\n"), 6)
        );
        assert!(!is_request(&l));
        assert!(is_request(&layer(r#"{"GET / HTTP/1.1\\r\\n":{}}"#)));
    }

    #[test]
    fn preview_caps_and_rejects_binary() {
        let big = vec![b'a'; PREVIEW_MAX + 10];
        let p = preview(&big).expect("text");
        assert!(p.contains("truncated") && p.len() < PREVIEW_MAX + 60);
        assert!(preview(&[0, 1, 2, 3]).is_none());
        let split = "é".repeat(PREVIEW_MAX); // 2 bytes each: cap lands mid-char only if odd
        assert!(preview(split.as_bytes()).is_some());
    }

    #[test]
    fn content_length_fallback_without_body() {
        let l =
            layer(r#"{"GET / HTTP/1.1\\r\\n":{},"http.request.line":"Content-Length: 12\r\n"}"#);
        assert_eq!(message(&l).body_len, 12);
    }
}
