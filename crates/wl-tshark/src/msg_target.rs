//! A TCP stream that may carry a Server-Sent Events response, found while grouping rows.

/// A TCP stream that carries (or may carry) a Server-Sent Events response.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SseTarget {
    pub stream: u32,
    pub id: u64,
    pub host: String,
    pub target: String,
    pub start_rel: f64,
    /// HTTP status of the response row, empty when only the request was dissected.
    pub status: String,
    pub client_port: Option<u16>,
    pub server_port: Option<u16>,
    /// A response row confirmed the content type.
    pub confirmed: bool,
    /// Decrypted TLS: the raw segments are ciphertext and cannot be decoded.
    pub tls: bool,
}

impl SseTarget {
    /// True when a segment sent from `port` is the server's half of the connection.
    pub fn is_server_port(&self, port: u16) -> bool {
        match (self.server_port, self.client_port) {
            (Some(s), _) => s == port,
            (None, Some(c)) => c != port,
            (None, None) => false,
        }
    }
}

pub fn port_of(addr: &str) -> Option<u16> {
    addr.rsplit(':').next()?.parse().ok()
}
