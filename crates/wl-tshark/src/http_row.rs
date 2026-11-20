//! One `tshark -T fields` line of the HTTP pass -> `HttpRec` (a single request or response).

use std::sync::Arc;

use crate::interner::Interner;
use crate::tsv_pass::{columns, opt};

/// Column order is part of the contract with `parse`. HTTP/2 columns are best effort.
pub const FIELDS: [&str; 22] = [
    "frame.number",
    "frame.time_relative",
    "tcp.stream",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.request.full_uri",
    "http.request.version",
    "http.response.version",
    "http.response.code",
    "http.response.code.desc",
    "http.content_type",
    "http.content_length",
    "http.request_in",
    "http.response_in",
    "http.time",
    "frame.len",
    "http2.streamid",
    "http2.headers.method",
    "http2.headers.path",
    "http2.headers.authority",
    "http2.headers.status",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Request,
    Response,
}

#[derive(Debug, Clone)]
pub struct HttpRec {
    pub kind: Kind,
    pub frame: u64,
    pub rel: f64,
    pub stream: Option<u32>,
    /// HTTP/2 stream identifier (pairs h2 requests with responses).
    pub h2_stream: Option<u32>,
    pub method: Arc<str>,
    pub host: Arc<str>,
    pub uri: Arc<str>,
    pub version: Arc<str>,
    pub status: Option<u16>,
    pub reason: Option<Arc<str>>,
    pub content_type: Option<Arc<str>>,
    pub content_len: u64,
    pub frame_len: u64,
    pub request_in: Option<u64>,
    pub time_ms: Option<f64>,
}

/// `http://host:80/a?b` -> ("host:80", "/a?b").
fn split_url(url: &str) -> (&str, &str) {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    }
}

fn num<T: std::str::FromStr>(s: &str) -> Option<T> {
    s.trim().parse().ok()
}

pub fn parse(line: &str, interner: &mut Interner) -> Option<HttpRec> {
    let f: [&str; FIELDS.len()] = columns(line);
    let method = opt(f[3]).or(opt(f[18]));
    let status: Option<u16> = num(f[9]).or_else(|| num(f[21]));
    let kind = match (method, status) {
        (Some(_), _) => Kind::Request,
        (None, Some(_)) => Kind::Response,
        _ => return None,
    };
    let (url_host, url_path) = split_url(f[6]);
    let host = opt(f[4]).or(opt(f[20])).unwrap_or(url_host);
    let uri = opt(f[5])
        .or(opt(f[19]))
        .unwrap_or(if f[6].is_empty() { "" } else { url_path });
    let version = match (opt(f[7]).or(opt(f[8])), opt(f[17])) {
        (Some(v), _) => v,
        (None, Some(_)) => "HTTP/2",
        _ => "",
    };
    Some(HttpRec {
        kind,
        frame: num(f[0])?,
        rel: num(f[1]).unwrap_or(0.0),
        stream: num(f[2]),
        h2_stream: num(f[17]),
        method: interner.intern(method.unwrap_or("")),
        host: interner.intern(host),
        uri: interner.intern(uri),
        version: interner.intern(version),
        status,
        reason: opt(f[10]).map(|s| interner.intern(s)),
        content_type: opt(f[11]).map(|s| interner.intern(s)),
        content_len: num(f[12]).unwrap_or(0),
        frame_len: num(f[16]).unwrap_or(0),
        request_in: num(f[13]),
        time_ms: num::<f64>(f[15]).map(|s| s * 1000.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(cols: &[(usize, &str)]) -> String {
        let mut v = vec![""; FIELDS.len()];
        for (i, s) in cols {
            v[*i] = s;
        }
        v.join("\t")
    }

    #[test]
    fn parses_request_and_response() {
        let mut i = Interner::default();
        let req = line(&[
            (0, "4"),
            (1, "0.5"),
            (2, "0"),
            (3, "GET"),
            (4, "h:80"),
            (5, "/a"),
            (7, "HTTP/1.1"),
            (16, "155"),
        ]);
        let r = parse(&req, &mut i).expect("req");
        assert_eq!((r.kind, &*r.method, &*r.uri), (Kind::Request, "GET", "/a"));
        let resp = line(&[
            (0, "8"),
            (2, "0"),
            (6, "http://h:80/a?q=1"),
            (8, "HTTP/1.0"),
            (9, "404"),
            (10, "Not Found"),
            (13, "4"),
            (15, "0.0030388"),
        ]);
        let r = parse(&resp, &mut i).expect("resp");
        assert_eq!(
            (r.kind, r.status, r.request_in),
            (Kind::Response, Some(404), Some(4))
        );
        assert_eq!((&*r.host, &*r.uri), ("h:80", "/a?q=1"));
        assert!((r.time_ms.unwrap_or(0.0) - 3.0388).abs() < 1e-6);
    }

    #[test]
    fn http2_columns_and_noise() {
        let mut i = Interner::default();
        let h2 = line(&[
            (0, "9"),
            (2, "3"),
            (17, "1"),
            (18, "GET"),
            (19, "/x"),
            (20, "a.test"),
        ]);
        let r = parse(&h2, &mut i).expect("h2");
        assert_eq!(
            (&*r.version, &*r.host, r.h2_stream),
            ("HTTP/2", "a.test", Some(1))
        );
        assert!(parse(&line(&[(0, "10"), (17, "0")]), &mut i).is_none());
    }

    #[test]
    fn splits_urls() {
        assert_eq!(split_url("https://a.b:8/x?y"), ("a.b:8", "/x?y"));
        assert_eq!(split_url("a.b"), ("a.b", "/"));
    }
}
