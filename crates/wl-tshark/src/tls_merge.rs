//! Handshake rows -> one `TlsSession` per connection. ClientHello gives SNI and the endpoints,
//! ServerHello version / cipher / ALPN, Certificate the subject (absent in TLS 1.3: encrypted).

use std::collections::HashMap;
use std::sync::Arc;

use wl_model::TlsSession;

use crate::interner::Interner;
use crate::tls_names::{cipher_label, version_label};
use crate::tsv_pass::{columns, opt};

pub const FIELDS: [&str; 18] = [
    "frame.number",
    "frame.time_relative",
    "tcp.stream",
    "udp.stream",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.ja3",
    "tls.handshake.ja4",
    "tls.handshake.ja3s",
    "frame.time_epoch",
];
const JA3: usize = 14;
const JA4: usize = 15;
const JA3S: usize = 16;
const EPOCH: usize = 17;
const CERT: usize = 18;
/// Leaf certificate subject alternative name (first DNS name) — the best cheap "subject".
pub const CERT_FIELD: &str = "x509ce.dNSName";

/// Identity of a connection: TCP streams and QUIC/UDP flows have independent numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamKey {
    Tcp(u32),
    Udp(u32),
}

pub fn stream_key(tcp: &str, udp: &str) -> Option<StreamKey> {
    match (tcp.trim().parse().ok(), udp.trim().parse().ok()) {
        (Some(t), _) => Some(StreamKey::Tcp(t)),
        (None, Some(u)) => Some(StreamKey::Udp(u)),
        _ => None,
    }
}

struct Entry {
    key: StreamKey,
    s: TlsSession,
    has_version: bool,
    has_client: bool,
}

#[derive(Default)]
pub struct Merger {
    entries: Vec<Entry>,
    index: HashMap<StreamKey, usize>,
    interner: Interner,
}

impl Merger {
    pub fn push_line(&mut self, line: &str) {
        let f: [&str; FIELDS.len() + 1] = columns(line);
        let (Some(frame), Some(key)) = (f[0].trim().parse::<u64>().ok(), stream_key(f[2], f[3]))
        else {
            return;
        };
        let rel = f[1].trim().parse().unwrap_or(0.0);
        let epoch = f[EPOCH]
            .trim()
            .parse::<f64>()
            .ok()
            .map(|e| e.floor() as i64);
        let idx = *self.index.entry(key).or_insert_with(|| {
            let e = self.interner.intern("");
            self.entries.push(Entry {
                key,
                s: TlsSession {
                    stream: match key {
                        StreamKey::Tcp(n) => Some(n),
                        StreamKey::Udp(_) => None,
                    },
                    first_frame: frame,
                    start_rel: rel,
                    start_epoch: epoch,
                    server_name: e.clone(),
                    version: e.clone(),
                    cipher: None,
                    alpn: None,
                    cert_subject: None,
                    certs: Vec::new(),
                    ja3: None,
                    ja4: None,
                    ja3s: None,
                    src: e.clone(),
                    dst: e,
                    bytes: 0,
                    client: None,
                    threat: None,
                },
                has_version: false,
                has_client: false,
            });
            self.entries.len() - 1
        });
        let first = f[8].split(',').next().unwrap_or("").trim();
        let src = opt(f[4]).or(opt(f[6]));
        let dst = opt(f[5]).or(opt(f[7]));
        let it = &mut self.interner;
        let en = &mut self.entries[idx];
        if frame < en.s.first_frame {
            en.s.first_frame = frame;
            en.s.start_rel = rel;
            en.s.start_epoch = epoch;
        }
        if first == "1" {
            if let Some(n) = opt(f[12]) {
                en.s.server_name = it.intern(n);
            }
            if !en.has_client {
                en.has_client = true;
                en.s.src = it.intern(src.unwrap_or(""));
                en.s.dst = it.intern(dst.unwrap_or(""));
            }
            if !en.has_version {
                // Offered, not negotiated: only shown until a ServerHello arrives.
                let v = opt(f[10]).or(opt(f[9])).unwrap_or("");
                en.s.version = it.intern(&version_label(v));
            }
        } else if first == "2" {
            let v = opt(f[10]).or(opt(f[9])).unwrap_or("");
            en.s.version = it.intern(&version_label(v));
            en.has_version = true;
            en.s.cipher = opt(f[11]).map(|c| it.intern(&cipher_label(c)));
            en.s.alpn = opt(f[13]).map(|a| it.intern(a));
            if !en.has_client {
                en.s.src = it.intern(dst.unwrap_or(""));
                en.s.dst = it.intern(src.unwrap_or(""));
            }
        }
        for (slot, col) in [
            (&mut en.s.ja3, JA3),
            (&mut en.s.ja4, JA4),
            (&mut en.s.ja3s, JA3S),
        ] {
            if let Some(v) = opt(f[col]) {
                slot.get_or_insert_with(|| it.intern(v));
            }
        }
        if let Some(c) = opt(f[CERT]) {
            en.s.cert_subject.get_or_insert_with(|| it.intern(c));
        }
    }

    /// Sessions ordered by first frame; `bytes` fills `TlsSession::bytes`.
    pub fn finish(self, bytes: &HashMap<StreamKey, u64>) -> Vec<TlsSession> {
        let mut v: Vec<TlsSession> = self
            .entries
            .into_iter()
            .map(|mut e| {
                e.s.bytes = bytes.get(&e.key).copied().unwrap_or(0);
                if e.s.version.is_empty() {
                    e.s.version = Arc::from("unknown");
                }
                e.s
            })
            .collect();
        v.sort_by_key(|s| s.first_frame);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(frame: u32, tcp: &str, cols: &[(usize, &str)]) -> String {
        let mut v = vec![""; FIELDS.len() + 1];
        let fs = frame.to_string();
        v[0] = &fs;
        v[2] = tcp;
        for (i, s) in cols {
            v[*i] = s;
        }
        v.join("\t")
    }

    #[test]
    fn merges_hello_pair_and_certificate() {
        let mut m = Merger::default();
        m.push_line(&row(
            4,
            "0",
            &[
                (4, "10.0.0.1"),
                (5, "10.0.0.2"),
                (8, "1"),
                (9, "0x0303"),
                (12, "a.test"),
                (JA3, "c3"),
                (JA4, "c4"),
            ],
        ));
        m.push_line(&row(
            6,
            "0",
            &[
                (4, "10.0.0.2"),
                (5, "10.0.0.1"),
                (8, "2,11"),
                (9, "0x0303"),
                (11, "0xc030"),
                (13, "h2"),
                (CERT, "a.test"),
                (JA3S, "s3"),
            ],
        ));
        m.push_line(&row(21, "1", &[(8, "1"), (12, "b.test")]));
        m.push_line(&row(
            23,
            "1",
            &[(8, "2"), (9, "0x0303"), (10, "0x0304"), (11, "0x1302")],
        ));
        let bytes = HashMap::from([(StreamKey::Tcp(0), 8407)]);
        let v = m.finish(&bytes);
        assert_eq!(v.len(), 2);
        let a = &v[0];
        assert_eq!(
            (&*a.server_name, &*a.version, a.bytes),
            ("a.test", "TLS 1.2", 8407)
        );
        assert_eq!(a.cipher.as_deref(), Some("ECDHE-RSA-AES256-GCM-SHA384"));
        assert_eq!(
            (a.alpn.as_deref(), a.cert_subject.as_deref()),
            (Some("h2"), Some("a.test"))
        );
        assert_eq!((&*a.src, &*a.dst), ("10.0.0.1", "10.0.0.2"));
        assert_eq!(
            (a.ja3.as_deref(), a.ja4.as_deref(), a.ja3s.as_deref()),
            (Some("c3"), Some("c4"), Some("s3"))
        );
        let b = &v[1];
        assert_eq!((&*b.version, b.cert_subject.as_deref()), ("TLS 1.3", None));
    }

    #[test]
    fn server_hello_first_swaps_endpoints_and_quic_has_no_tcp_stream() {
        let mut m = Merger::default();
        m.push_line(&row(
            2,
            "",
            &[
                (3, "7"),
                (4, "1.1.1.1"),
                (5, "2.2.2.2"),
                (8, "2"),
                (10, "0x0304"),
            ],
        ));
        let v = m.finish(&HashMap::new());
        assert_eq!(
            (v[0].stream, &*v[0].src, &*v[0].dst),
            (None, "2.2.2.2", "1.1.1.1")
        );
    }

    #[test]
    fn client_hello_only_has_offered_version() {
        let mut m = Merger::default();
        m.push_line(&row(1, "5", &[(8, "1"), (9, "0x0303"), (10, "0x0304")]));
        assert_eq!(&*m.finish(&HashMap::new())[0].version, "TLS 1.3");
    }
}
