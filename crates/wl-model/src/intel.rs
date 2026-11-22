//! Offline threat intelligence: blocklisted addresses and domains, and TLS client fingerprints
//! (JA3 / JA4) with the application they belong to. Built from local files, never fetched.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::TlsSession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub label: Arc<str>,
    pub malicious: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Indicator {
    Ip(IpAddr),
    Domain(String),
    Fingerprint(String),
}

#[derive(Debug, Clone, Default)]
pub struct ThreatIntel {
    ips: HashMap<IpAddr, Arc<str>>,
    domains: HashMap<String, Arc<str>>,
    fingerprints: HashMap<String, Fingerprint>,
}

impl ThreatIntel {
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.domains.is_empty() && self.fingerprints.is_empty()
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (self.ips.len(), self.domains.len(), self.fingerprints.len())
    }

    pub fn has_tls_indicators(&self) -> bool {
        !self.fingerprints.is_empty() || !self.domains.is_empty() || !self.ips.is_empty()
    }

    /// Adds every indicator of a plain-text or CSV blocklist, labelled with the list name.
    pub fn add_blocklist(&mut self, list: &str, text: &str) {
        let label: Arc<str> = Arc::from(list);
        for ind in text.lines().filter_map(parse_line) {
            match ind {
                Indicator::Ip(ip) => {
                    self.ips.entry(ip).or_insert_with(|| label.clone());
                }
                Indicator::Domain(d) => {
                    self.domains.entry(d).or_insert_with(|| label.clone());
                }
                Indicator::Fingerprint(f) => {
                    self.fingerprints.entry(f).or_insert_with(|| Fingerprint {
                        label: label.clone(),
                        malicious: true,
                    });
                }
            }
        }
    }

    /// Adds the fingerprints of a JA4DB export; returns how many were read.
    pub fn add_ja4db(&mut self, json: &str) -> Result<usize, String> {
        let entries = parse_ja4db(json)?;
        let n = entries.len();
        for (hash, fp) in entries {
            self.fingerprints.entry(hash).or_insert(fp);
        }
        Ok(n)
    }

    pub fn ip(&self, addr: &str) -> Option<&str> {
        self.ips.get(&addr.parse::<IpAddr>().ok()?).map(|l| &**l)
    }

    /// Exact name or any parent domain (`a.evil.com` matches a listed `evil.com`).
    pub fn domain(&self, name: &str) -> Option<&str> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = name.as_str();
        loop {
            if let Some(l) = self.domains.get(rest) {
                return Some(l);
            }
            rest = rest.split_once('.')?.1;
            if !rest.contains('.') {
                return None;
            }
        }
    }

    pub fn fingerprint(&self, hash: &str) -> Option<&Fingerprint> {
        self.fingerprints.get(&hash.to_ascii_lowercase())
    }

    /// First blocklist hit among the session's fingerprints, server name and server address.
    pub fn tls_threat(&self, t: &TlsSession) -> Option<Arc<str>> {
        let by_print = [&t.ja3, &t.ja4]
            .into_iter()
            .flatten()
            .filter_map(|h| self.fingerprint(h))
            .find(|f| f.malicious)
            .map(|f| f.label.clone());
        by_print
            .or_else(|| self.domain(&t.server_name).map(Arc::from))
            .or_else(|| self.ip(&t.dst).map(Arc::from))
    }

    /// Application a benign JA4DB fingerprint of the session belongs to.
    pub fn tls_client(&self, t: &TlsSession) -> Option<Arc<str>> {
        [&t.ja4, &t.ja3]
            .into_iter()
            .flatten()
            .filter_map(|h| self.fingerprint(h))
            .find(|f| !f.malicious)
            .map(|f| f.label.clone())
    }

    pub fn annotate_tls(&self, sessions: &mut [TlsSession]) {
        for t in sessions {
            t.threat = self.tls_threat(t);
            t.client = self.tls_client(t);
        }
    }
}

const SINK_ADDRS: [&str; 3] = ["0.0.0.0", "127.0.0.1", "::"];
const NAME_KEYS: [&str; 7] = [
    "application",
    "name",
    "client",
    "malware",
    "library",
    "device",
    "os",
];
const HASH_KEYS: [&str; 4] = ["ja4_fingerprint", "ja3_fingerprint", "ja4", "ja3"];

/// First indicator of a line: a comment-free CSV / hosts-file / one-per-line entry.
fn parse_line(line: &str) -> Option<Indicator> {
    let line = line.trim();
    if line.is_empty() || line.starts_with(['#', ';']) || line.starts_with("//") {
        return None;
    }
    line.split([',', '\t', ' ', ';', '"'])
        .filter(|t| !t.is_empty())
        .find_map(parse_token)
}

fn parse_token(token: &str) -> Option<Indicator> {
    let host = token
        .split_once("://")
        .map_or(token, |(_, rest)| rest)
        .split(['/', '?'])
        .next()
        .unwrap_or_default();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return (!SINK_ADDRS.contains(&host)).then_some(Indicator::Ip(ip));
    }
    let bare = host.rsplit_once(':').map_or(host, |(h, _)| h);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Some(Indicator::Ip(ip));
    }
    if is_fingerprint(bare) {
        return Some(Indicator::Fingerprint(bare.to_ascii_lowercase()));
    }
    is_domain(bare).then(|| Indicator::Domain(bare.trim_end_matches('.').to_ascii_lowercase()))
}

fn is_fingerprint(s: &str) -> bool {
    let hex = |p: &str, n: usize| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit());
    if hex(s, 32) {
        return true;
    }
    let mut parts = s.split('_');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), None)
            if a.len() == 10
                && a.starts_with(['t', 'q', 'd'])
                && a.bytes().all(|b| b.is_ascii_alphanumeric())
                && hex(b, 12)
                && hex(c, 12)
    )
}

fn is_domain(s: &str) -> bool {
    let s = s.trim_end_matches('.');
    let Some((_, tld)) = s.rsplit_once('.') else {
        return false;
    };
    s.len() <= 253
        && tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        && s.split('.').all(|l| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn parse_ja4db(json: &str) -> Result<Vec<(String, Fingerprint)>, String> {
    let root: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    match &root {
        serde_json::Value::Array(items) => items.iter().for_each(|i| push_entry(i, &mut out)),
        serde_json::Value::Object(map) => {
            for (hash, name) in map {
                if let Some(name) = name.as_str().filter(|n| !n.is_empty()) {
                    out.push((hash.to_ascii_lowercase(), benign(name)));
                }
            }
        }
        _ => return Err("expected a JSON array or object".to_owned()),
    }
    Ok(out)
}

fn push_entry(item: &serde_json::Value, out: &mut Vec<(String, Fingerprint)>) {
    let text = |key: &str| {
        item.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    };
    let Some(label) = NAME_KEYS.iter().find_map(|k| text(k)) else {
        return;
    };
    let malicious =
        item.get("malicious").and_then(|v| v.as_bool()) == Some(true) || text("malware").is_some();
    for hash in HASH_KEYS.iter().filter_map(|k| text(k)) {
        let fp = Fingerprint {
            label: Arc::from(label),
            malicious,
        };
        out.push((hash.to_ascii_lowercase(), fp));
    }
}

fn benign(label: &str) -> Fingerprint {
    Fingerprint {
        label: Arc::from(label),
        malicious: false,
    }
}

#[cfg(test)]
#[path = "intel_tests.rs"]
mod tests;
