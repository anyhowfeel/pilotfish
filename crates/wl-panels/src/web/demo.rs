//! Deterministic synthetic web traffic for `--demo-web`, screenshots and tests (no tshark).

use std::sync::Arc;

use wl_model::{CertInfo, HttpDetail, HttpExchange, HttpMessage, TlsSession};

/// One synthetic exchange (just the fields tests care about).
pub fn exchange(
    id: u64,
    method: &str,
    host: &str,
    uri: &str,
    status: Option<u16>,
    ms: f64,
) -> HttpExchange {
    HttpExchange {
        id,
        stream: Some(id as u32),
        req_frame: Some(id * 2),
        resp_frame: Some(id * 2 + 1),
        method: method.into(),
        host: host.into(),
        uri: uri.into(),
        version: "HTTP/1.1".into(),
        status,
        reason: status.map(|s| Arc::from(reason(s))),
        content_type: None,
        req_bytes: 180,
        resp_bytes: 1200,
        start_rel: id as f64 * 0.37,
        time_ms: Some(ms),
    }
}

/// One synthetic TLS session.
pub fn session(frame: u64, sni: &str) -> TlsSession {
    TlsSession {
        stream: Some(frame as u32),
        first_frame: frame,
        start_rel: frame as f64 * 0.5,
        server_name: sni.into(),
        version: "TLS 1.3".into(),
        cipher: Some("TLS_AES_128_GCM_SHA256".into()),
        alpn: Some("h2".into()),
        cert_subject: Some(format!("CN={sni}, O=Example Inc, C=US").into()),
        certs: demo_chain(sni),
        ja3: Some("e7d705a3286e19ea42f587b344ee6865".into()),
        ja4: Some("t13d1516h2_8daaf6152771_02713d6af862".into()),
        ja3s: Some("eb1d94daa7e0344597e756a1fb6e7054".into()),
        src: "192.168.1.20".into(),
        dst: "93.184.216.34".into(),
        bytes: 48_000 + frame * 1300,
    }
}

fn demo_chain(sni: &str) -> Vec<CertInfo> {
    let cert = |subject: String, issuer: &str, sans: Vec<String>, is_ca| CertInfo {
        subject,
        issuer: issuer.into(),
        not_before: 1_735_689_600,
        not_after: 2_051_222_400,
        sans,
        key: if is_ca { "RSA 4096 bit" } else { "EC P-256" }.into(),
        sig_alg: "sha256WithRSA".into(),
        serial: "0a1b2c3d4e5f".into(),
        is_ca,
    };
    vec![
        cert(
            format!("CN={sni}"),
            "CN=Example CA R3, O=Example Inc",
            vec![sni.into()],
            false,
        ),
        cert(
            "CN=Example CA R3, O=Example Inc".into(),
            "CN=Example Root",
            Vec::new(),
            true,
        ),
    ]
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        304 => "Not Modified",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "",
    }
}

const HOSTS: [&str; 6] = [
    "www.wikipedia.com",
    "api.example.org",
    "cdn.assets.net",
    "intranet.corp.local",
    "static.example.org",
    "shop.example.com",
];
const PATHS: [(&str, &str, &str); 8] = [
    ("GET", "/", "text/html; charset=utf-8"),
    ("GET", "/static/app.3f9c1a.js", "application/javascript"),
    ("GET", "/static/site.css", "text/css"),
    ("GET", "/img/logo.svg?v=2", "image/svg+xml"),
    ("POST", "/api/v1/orders", "application/json"),
    (
        "GET",
        "/api/v1/users/42?include=profile,settings",
        "application/json",
    ),
    ("PUT", "/api/v1/cart/items/7", "application/json"),
    ("DELETE", "/api/v1/sessions/current", "application/json"),
];
const STATUSES: [u16; 10] = [200, 200, 200, 304, 200, 201, 404, 200, 500, 301];

/// ~40 exchanges across hosts/methods/statuses plus 10 TLS sessions.
pub fn demo_data() -> (Vec<HttpExchange>, Vec<TlsSession>) {
    let ex = (0..40u64)
        .map(|i| {
            let (m, uri, ct) = PATHS[(i as usize * 3) % PATHS.len()];
            let mut e = exchange(
                i + 1,
                m,
                HOSTS[(i as usize * 5) % HOSTS.len()],
                uri,
                Some(STATUSES[(i as usize * 7) % STATUSES.len()]),
                8.0 + ((i * 53) % 37) as f64 * 9.5,
            );
            e.content_type = Some(ct.into());
            e.resp_bytes = 300 + (i * 7919) % 90_000;
            e.start_rel = 0.4 + i as f64 * 0.83;
            e.req_bytes = if m == "GET" { 210 } else { 640 };
            e
        })
        .collect();
    let snis = [
        "www.google.com",
        "fonts.gstatic.com",
        "api.github.com",
        "login.microsoftonline.com",
        "cdn.jsdelivr.net",
        "www.wikipedia.org",
        "update.mozilla.org",
        "i.ytimg.com",
        "telemetry.example.net",
        "static.cloudflareinsights.com",
    ];
    let tls = snis
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut t = session(100 + i as u64 * 11, s);
            t.start_rel = 0.9 + i as f64 * 3.3;
            t.alpn = Some(["h2", "h2", "http/1.1", "h3"][i % 4].into());
            if i % 3 == 1 {
                t.version = "TLS 1.2".into();
                t.cipher = Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into());
            }
            t
        })
        .collect();
    (ex, tls)
}

/// Synthetic request/response detail for an exchange.
pub fn demo_detail(e: &HttpExchange) -> HttpDetail {
    let h = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    let json = e
        .content_type
        .as_deref()
        .is_some_and(|c| c.contains("json"));
    let body = if json {
        r#"{"id":42,"name":"Ada","roles":["admin","dev"],"profile":{"email":"ada@example.org","verified":true}}"#
    } else {
        "<!doctype html><html><head><title>Example</title></head><body><h1>Hello</h1></body></html>"
    };
    let request = HttpMessage {
        start_line: format!("{} {} {}", e.method, e.uri, e.version),
        headers: vec![
            h("Host", &e.host),
            h(
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0",
            ),
            h("Accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
            h("Accept-Language", "en-US,en;q=0.5"),
            h("Accept-Encoding", "gzip, deflate"),
            h(
                "Cookie",
                "session=9f8e7d6c5b4a39281716; theme=dark; consent=1; _ga=GA1.2.1234567890.1700000000",
            ),
            h("Connection", "keep-alive"),
        ],
        body_preview: (e.method.as_ref() != "GET").then(|| r#"{"item":7,"qty":2}"#.to_owned()),
        body_len: if e.method.as_ref() == "GET" { 0 } else { 18 },
        body_image: None,
    };
    let response = HttpMessage {
        start_line: format!(
            "{} {} {}",
            e.version,
            e.status.unwrap_or(0),
            e.reason.as_deref().unwrap_or("")
        ),
        headers: vec![
            h("Server", "nginx/1.25.3"),
            h("Date", "Fri, 20 Nov 2026 13:55:42 GMT"),
            h(
                "Content-Type",
                e.content_type.as_deref().unwrap_or("text/plain"),
            ),
            h("Content-Length", &e.resp_bytes.to_string()),
            h("Cache-Control", "public, max-age=3600"),
            h(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            ),
        ],
        body_preview: Some(body.to_owned()),
        body_len: e.resp_bytes,
        body_image: None,
    };
    HttpDetail {
        request: Some(request),
        response: Some(response),
    }
}
