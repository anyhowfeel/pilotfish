//! Offline threat intelligence: blocklisted addresses and domains, and TLS client fingerprints
//! (JA3 / JA4) with the application they belong to. Built from local files, never fetched.

use std::collections::{BTreeMap, HashMap};
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
    Range(IpAddr, u8),
    Domain(String),
    Fingerprint(String),
}

#[derive(Debug, Clone, Default)]
pub struct ThreatIntel {
    ips: HashMap<IpAddr, Arc<str>>,
    /// CIDR ranges by (is IPv6, prefix length), keyed by the masked network address.
    ranges: BTreeMap<(bool, u8), HashMap<u128, Arc<str>>>,
    domains: HashMap<String, Arc<str>>,
    fingerprints: HashMap<String, Fingerprint>,
}

impl ThreatIntel {
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
            && self.ranges.is_empty()
            && self.domains.is_empty()
            && self.fingerprints.is_empty()
    }

    /// Single addresses, CIDR ranges, domains and fingerprints.
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.ips.len(),
            self.ranges.values().map(HashMap::len).sum(),
            self.domains.len(),
            self.fingerprints.len(),
        )
    }

    pub fn has_tls_indicators(&self) -> bool {
        !self.is_empty()
    }

    /// Adds every indicator of a plain-text or CSV blocklist, labelled with the list name.
    pub fn add_blocklist(&mut self, list: &str, text: &str) {
        let label: Arc<str> = Arc::from(list);
        for ind in strip_bom(text).lines().filter_map(parse_line) {
            match ind {
                Indicator::Ip(ip) => {
                    self.ips.entry(ip).or_insert_with(|| label.clone());
                }
                Indicator::Range(net, prefix) => {
                    let (v6, bits) = ip_bits(net);
                    self.ranges
                        .entry((v6, prefix))
                        .or_default()
                        .entry(mask(bits, v6, prefix))
                        .or_insert_with(|| label.clone());
                }
                Indicator::Domain(d) => {
                    self.domains.entry(d).or_insert_with(|| label.clone());
                }
                Indicator::Fingerprint(f) => self.add_fingerprint(
                    f,
                    Fingerprint {
                        label: label.clone(),
                        malicious: true,
                    },
                ),
            }
        }
    }

    /// Adds the fingerprints of a JA4DB export (JSON array or object, or the official CSV);
    /// returns how many were read.
    pub fn add_ja4db(&mut self, text: &str) -> Result<usize, String> {
        let entries = parse_ja4db(strip_bom(text))?;
        let n = entries.len();
        for (hash, fp) in entries {
            self.add_fingerprint(hash, fp);
        }
        Ok(n)
    }

    /// A malicious entry always wins over a benign one, whatever the load order.
    fn add_fingerprint(&mut self, hash: String, fp: Fingerprint) {
        match self.fingerprints.get(&hash) {
            Some(known) if known.malicious || !fp.malicious => {}
            _ => {
                self.fingerprints.insert(hash, fp);
            }
        }
    }

    /// Whether `text` is a JA4DB CSV export rather than a blocklist.
    pub fn is_ja4db_csv(text: &str) -> bool {
        csv_records(strip_bom(text))
            .next()
            .is_some_and(|h| h.iter().any(|c| c.eq_ignore_ascii_case("ja4_fingerprint")))
    }

    pub fn ip(&self, addr: &str) -> Option<&str> {
        let ip = addr.parse::<IpAddr>().ok()?;
        if let Some(l) = self.ips.get(&ip) {
            return Some(l);
        }
        let (v6, bits) = ip_bits(ip);
        self.ranges
            .iter()
            .filter(|((is6, _), _)| *is6 == v6)
            .find_map(|((_, prefix), nets)| nets.get(&mask(bits, v6, *prefix)))
            .map(|l| &**l)
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

fn strip_bom(text: &str) -> &str {
    text.trim_start_matches('\u{feff}')
}

fn ip_bits(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(a) => (false, u128::from(u32::from(a))),
        IpAddr::V6(a) => (true, u128::from(a)),
    }
}

fn mask(bits: u128, v6: bool, prefix: u8) -> u128 {
    let host = (if v6 { 128 } else { 32 }) - u32::from(prefix);
    bits.checked_shr(host)
        .unwrap_or(0)
        .checked_shl(host)
        .unwrap_or(0)
}

/// Addresses that hosts files use as a sink or placeholder for a blocked name.
fn is_sink(ip: IpAddr) -> bool {
    let v6_reserved = matches!(ip, IpAddr::V6(a) if a.segments()[0] == 0xfe00);
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || v6_reserved
        || matches!(ip, IpAddr::V4(a) if a.is_broadcast())
}

fn address(ip: IpAddr) -> Option<Indicator> {
    (!is_sink(ip)).then_some(Indicator::Ip(ip))
}

/// `10.0.0.0/8` or `2001:db8::/32`; a /0 would match every address and is refused.
fn parse_cidr(token: &str) -> Option<Indicator> {
    let (net, prefix) = token.split_once('/')?;
    let net: IpAddr = net.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let max = if net.is_ipv4() { 32 } else { 128 };
    match prefix {
        0 => None,
        p if p == max => address(net),
        p if p < max => Some(Indicator::Range(net, p)),
        _ => None,
    }
}

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
    if let Some(range) = parse_cidr(token) {
        return Some(range);
    }
    let host = token
        .split_once("://")
        .map_or(token, |(_, rest)| rest)
        .split(['/', '?'])
        .next()
        .unwrap_or_default();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return address(ip);
    }
    let bare = host.rsplit_once(':').map_or(host, |(h, _)| h);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return address(ip);
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

fn parse_ja4db(text: &str) -> Result<Vec<(String, Fingerprint)>, String> {
    if text.trim().is_empty() {
        return Err("empty file".to_owned());
    }
    if ThreatIntel::is_ja4db_csv(text) {
        return Ok(parse_ja4db_csv(text));
    }
    let root: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => return Err(json_error(text, &e)),
    };
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

fn json_error(text: &str, e: &serde_json::Error) -> String {
    let first_line_is_json = text
        .lines()
        .next()
        .is_some_and(|l| serde_json::from_str::<serde_json::Value>(l).is_ok());
    if first_line_is_json {
        "JSON Lines is not supported: export the JA4DB as one JSON array or as CSV".to_owned()
    } else {
        e.to_string()
    }
}

fn parse_ja4db_csv(text: &str) -> Vec<(String, Fingerprint)> {
    let mut records = csv_records(text);
    let header: Vec<String> = records
        .next()
        .map(|h| h.iter().map(|c| c.trim().to_ascii_lowercase()).collect())
        .unwrap_or_default();
    let mut out = Vec::new();
    for row in records {
        let get = |key: &str| {
            let at = header.iter().position(|h| h == key)?;
            row.get(at).map(|v| v.trim()).filter(|v| !v.is_empty())
        };
        push_fields(&get, false, &mut out);
    }
    out
}

/// Rows of an RFC 4180 CSV: quoted fields may hold commas, doubled quotes and line breaks.
fn csv_records(text: &str) -> impl Iterator<Item = Vec<String>> + '_ {
    let mut chars = text.chars().peekable();
    std::iter::from_fn(move || {
        chars.peek()?;
        let (mut row, mut field, mut quoted) = (Vec::new(), String::new(), false);
        while let Some(c) = chars.next() {
            match c {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    field.push('"');
                    chars.next();
                }
                '"' => quoted = !quoted,
                ',' if !quoted => row.push(std::mem::take(&mut field)),
                '\n' if !quoted => break,
                '\r' if !quoted => {}
                c => field.push(c),
            }
        }
        row.push(field);
        Some(row)
    })
}

fn push_entry(item: &serde_json::Value, out: &mut Vec<(String, Fingerprint)>) {
    let get = |key: &str| {
        item.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    };
    let flagged = item.get("malicious").and_then(|v| v.as_bool()) == Some(true);
    push_fields(&get, flagged, out);
}

fn push_fields<'a>(
    get: &dyn Fn(&str) -> Option<&'a str>,
    flagged: bool,
    out: &mut Vec<(String, Fingerprint)>,
) {
    let Some(label) = NAME_KEYS.iter().find_map(|k| get(k)) else {
        return;
    };
    let malicious = flagged || get("malware").is_some();
    for hash in HASH_KEYS.iter().filter_map(|k| get(k)) {
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
