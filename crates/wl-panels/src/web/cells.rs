//! Pure display helpers: short content types, cipher names, certificate CN, latency text.

/// Short, scannable content-type label ("text/html; charset=utf-8" -> "html").
pub fn short_type(ct: Option<&str>) -> &'static str {
    let Some(ct) = ct else { return "-" };
    let ct = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let (major, sub) = ct.split_once('/').unwrap_or((ct.as_str(), ""));
    match (major, sub) {
        (_, s) if s.contains("json") => "json",
        (_, s) if s.contains("javascript") || s == "ecmascript" => "js",
        (_, s) if s.contains("xml") && major != "image" => "xml",
        ("text", "html") | (_, "xhtml+xml") => "html",
        ("text", "css") => "css",
        ("text", _) => "text",
        ("image", _) => "img",
        ("font", _) | (_, "font-woff" | "font-woff2" | "x-font-ttf") => "font",
        ("video" | "audio", _) => "media",
        (_, "x-www-form-urlencoded" | "form-data") => "form",
        (_, "octet-stream" | "zip" | "gzip" | "pdf") => "bin",
        _ => "other",
    }
}

/// "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" -> "AES-256-GCM", "TLS_CHACHA20_POLY1305_SHA256" -> "CHACHA20-POLY1305".
pub fn cipher_short(name: &str) -> String {
    let n = name.trim();
    let n = n.strip_prefix("TLS_").unwrap_or(n);
    let n = n.split_once("_WITH_").map_or(n, |(_, tail)| tail);
    let parts: Vec<&str> = n.split('_').collect();
    let keep = match parts.last() {
        Some(l) if l.starts_with("SHA") && parts.len() > 1 => &parts[..parts.len() - 1],
        _ => &parts[..],
    };
    keep.join("-")
}

/// Common name of a certificate subject ("CN=example.com, O=Ex" -> "example.com").
pub fn cert_cn(subject: &str) -> &str {
    subject
        .split(',')
        .map(str::trim)
        .find_map(|p| {
            p.strip_prefix("CN=")
                .or_else(|| p.strip_prefix("commonName="))
        })
        .unwrap_or(subject.trim())
}

/// "12 ms", "184 ms", "1.20 s".
pub fn latency(ms: f64) -> String {
    if ms < 1.0 {
        format!("{ms:.2} ms")
    } else if ms < 1000.0 {
        format!("{ms:.0} ms")
    } else {
        format!("{:.2} s", ms / 1000.0)
    }
}

pub use wl_kit::text::contains_ci as ci_contains;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types() {
        assert_eq!(short_type(Some("text/html; charset=utf-8")), "html");
        assert_eq!(short_type(Some("application/json")), "json");
        assert_eq!(short_type(Some("application/ld+json")), "json");
        assert_eq!(short_type(Some("application/javascript")), "js");
        assert_eq!(short_type(Some("text/css")), "css");
        assert_eq!(short_type(Some("image/svg+xml")), "img");
        assert_eq!(short_type(Some("font/woff2")), "font");
        assert_eq!(short_type(Some("application/octet-stream")), "bin");
        assert_eq!(short_type(None), "-");
    }

    #[test]
    fn ciphers_and_certs() {
        assert_eq!(cipher_short("TLS_AES_128_GCM_SHA256"), "AES-128-GCM");
        assert_eq!(
            cipher_short("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            "AES-256-GCM"
        );
        assert_eq!(
            cipher_short("TLS_CHACHA20_POLY1305_SHA256"),
            "CHACHA20-POLY1305"
        );
        assert_eq!(
            cert_cn("CN=*.wikipedia.org, O=WMF, C=US"),
            "*.wikipedia.org"
        );
        assert_eq!(cert_cn("O=Acme"), "O=Acme");
    }

    #[test]
    fn latency_text() {
        assert_eq!(latency(0.5), "0.50 ms");
        assert_eq!(latency(42.4), "42 ms");
        assert_eq!(latency(1234.0), "1.23 s");
    }
}
