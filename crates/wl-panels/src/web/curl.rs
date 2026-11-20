//! "Copy as curl": builds a POSIX-shell curl command from an exchange and its request message.

use wl_model::{HttpExchange, HttpMessage};

/// Headers curl sets itself; copying them would only make the command noisy or wrong.
const SKIP: [&str; 3] = ["host", "content-length", "connection"];

/// Single-quotes `s` for a POSIX shell.
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn curl_command(ex: &HttpExchange, req: Option<&HttpMessage>) -> String {
    let mut parts = vec!["curl".to_owned()];
    match ex.method.as_ref() {
        "" | "GET" => {}
        "HEAD" => parts.push("-I".into()),
        m => parts.push(format!("-X {}", quote(m))),
    }
    parts.push(quote(&ex.full_url()));
    if let Some(r) = req {
        for (k, v) in &r.headers {
            if !SKIP.contains(&k.to_ascii_lowercase().as_str()) {
                parts.push(format!("-H {}", quote(&format!("{k}: {v}"))));
            }
        }
        if let Some(b) = r.body_preview.as_deref().filter(|b| !b.is_empty())
            && matches!(ex.method.as_ref(), "POST" | "PUT" | "PATCH")
        {
            parts.push(format!("--data-raw {}", quote(b)));
        }
    }
    parts.join(" \\\n  ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::demo::exchange;

    #[test]
    fn quoting_escapes_single_quotes() {
        assert_eq!(quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn get_and_post() {
        let g = exchange(1, "GET", "a.com", "/p?q=1", Some(200), 5.0);
        assert_eq!(curl_command(&g, None), "curl \\\n  'http://a.com/p?q=1'");
        let p = exchange(2, "POST", "a.com", "/api", Some(201), 5.0);
        let req = HttpMessage {
            headers: vec![
                ("Host".into(), "a.com".into()),
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), "7".into()),
            ],
            body_preview: Some("{\"a\":1}".into()),
            ..Default::default()
        };
        let c = curl_command(&p, Some(&req));
        assert!(c.contains("-X 'POST'"));
        assert!(c.contains("-H 'Content-Type: application/json'"));
        assert!(!c.contains("Host:") && !c.contains("Content-Length"));
        assert!(c.ends_with("--data-raw '{\"a\":1}'"));
    }
}
