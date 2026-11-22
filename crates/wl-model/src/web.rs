//! Web traffic model: HTTP request/response exchanges and TLS sessions (what HTTPS exposes).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::CertInfo;

/// One HTTP request paired with its response (when seen). Built from tshark `http` fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpExchange {
    /// Stable id within a capture (request frame number, or response frame if unpaired).
    pub id: u64,
    /// `tcp.stream` the exchange belongs to.
    pub stream: Option<u32>,
    pub req_frame: Option<u64>,
    pub resp_frame: Option<u64>,
    /// "GET", "POST", ... (empty if only the response was captured).
    pub method: Arc<str>,
    pub host: Arc<str>,
    /// Path + query as sent on the wire.
    pub uri: Arc<str>,
    /// "HTTP/1.1", "HTTP/2", ...
    pub version: Arc<str>,
    pub status: Option<u16>,
    pub reason: Option<Arc<str>>,
    pub content_type: Option<Arc<str>>,
    pub req_bytes: u64,
    pub resp_bytes: u64,
    /// Seconds from the first packet of the capture to the request.
    pub start_rel: f64,
    /// Request -> response latency in milliseconds (`http.time`).
    pub time_ms: Option<f64>,
}

/// Coarse class of an HTTP status for colouring (1xx info, 2xx ok, 3xx redirect, 4xx/5xx error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    Info,
    Success,
    Redirect,
    ClientError,
    ServerError,
    Unknown,
}

impl HttpExchange {
    pub fn status_class(&self) -> StatusClass {
        match self.status {
            Some(100..=199) => StatusClass::Info,
            Some(200..=299) => StatusClass::Success,
            Some(300..=399) => StatusClass::Redirect,
            Some(400..=499) => StatusClass::ClientError,
            Some(500..=599) => StatusClass::ServerError,
            _ => StatusClass::Unknown,
        }
    }

    /// `http://host/uri` (scheme is not on the wire for plain HTTP; HTTPS never reaches here).
    pub fn full_url(&self) -> String {
        format!("http://{}{}", self.host, self.uri)
    }
}

/// One TLS connection: what stays visible without decryption (HTTPS metadata).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsSession {
    pub stream: Option<u32>,
    pub first_frame: u64,
    pub start_rel: f64,
    /// SNI from the ClientHello — the "host" of an HTTPS request.
    pub server_name: Arc<str>,
    /// Negotiated version label, e.g. "TLS 1.3".
    pub version: Arc<str>,
    pub cipher: Option<Arc<str>>,
    /// Negotiated ALPN protocol ("h2", "http/1.1", "h3"), if any.
    pub alpn: Option<Arc<str>>,
    pub cert_subject: Option<Arc<str>>,
    /// Certificate chain sent by the server, leaf first (empty when encrypted or not seen).
    pub certs: Vec<CertInfo>,
    /// Client / server TLS fingerprints (JA3 MD5, JA4, JA3S), when tshark computes them.
    pub ja3: Option<Arc<str>>,
    pub ja4: Option<Arc<str>>,
    pub ja3s: Option<Arc<str>>,
    pub src: Arc<str>,
    pub dst: Arc<str>,
    pub bytes: u64,
    /// Application named by an offline JA4DB fingerprint match.
    #[serde(default)]
    pub client: Option<Arc<str>>,
    /// Blocklist that lists this session's fingerprint, server name or server address.
    #[serde(default)]
    pub threat: Option<Arc<str>>,
}

/// Headers + start line of one HTTP message, for the detail view (display order preserved).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct HttpMessage {
    /// "GET /path HTTP/1.1" or "HTTP/1.1 200 OK" — without trailing CRLF.
    pub start_line: String,
    /// (name, value) pairs, values trimmed, no CRLF.
    pub headers: Vec<(String, String)>,
    /// First bytes of the body decoded as text when it looks like text (capped by the backend).
    pub body_preview: Option<String>,
    pub body_len: u64,
    /// Decoded body of a PNG / JPEG / GIF response, when small enough to display.
    pub body_image: Option<Vec<u8>>,
}

/// Full detail of an exchange: request and response messages.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct HttpDetail {
    pub request: Option<HttpMessage>,
    pub response: Option<HttpMessage>,
}
