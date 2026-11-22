//! Security findings: cleartext credentials and matches against the offline threat lists.

use std::collections::{BTreeMap, BTreeSet};

use wl_kit::format;
use wl_model::{
    CredKind, Credential, DnsQuery, HostStat, InsightSeverity, SecurityData, ThreatIntel,
};

use super::health::{Cap, Findings, push_capped};

const MAX_CARDS: usize = 8;
const LOGINS: Cap = Cap {
    name: "cleartext logins",
    max: MAX_CARDS,
};
const ADDRESSES: Cap = Cap {
    name: "blocklisted addresses",
    max: MAX_CARDS,
};
const DOMAINS: Cap = Cap {
    name: "blocklisted domains",
    max: MAX_CARDS,
};
const FINGERPRINTS: Cap = Cap {
    name: "malicious TLS fingerprints",
    max: MAX_CARDS,
};
const MAX_SAMPLES: usize = 3;
const MAX_FRAMES: usize = 10;

pub struct Inputs<'a> {
    pub security: Option<&'a SecurityData>,
    pub intel: &'a ThreatIntel,
    pub hosts: &'a [HostStat],
    pub dns: &'a [DnsQuery],
    pub reveal_secrets: bool,
}

pub fn detect(inp: &Inputs, out: &mut Findings) {
    if let Some(sec) = inp.security {
        credentials(&sec.credentials, inp.reveal_secrets, out);
    }
    if !inp.intel.is_empty() {
        addresses(inp.intel, inp.hosts, out);
        domains(inp, out);
        fingerprints(inp, out);
    }
}

fn ip_filter(addr: &str) -> String {
    let field = if addr.contains(':') {
        "ipv6.addr"
    } else {
        "ip.addr"
    };
    format!("{field} == {addr}")
}

/// A login without a secret to steal (an empty password) is only a warning.
fn severity(kind: CredKind, filled: bool) -> InsightSeverity {
    if !filled {
        return InsightSeverity::Warning;
    }
    match kind {
        CredKind::HttpBasic | CredKind::Ftp | CredKind::Smtp | CredKind::Pop3 => {
            InsightSeverity::Critical
        }
        CredKind::HttpBearer | CredKind::ApiKey | CredKind::Ntlm => InsightSeverity::Warning,
    }
}

fn sample(c: &Credential, reveal: bool) -> String {
    let mut parts = Vec::new();
    if let Some(u) = &c.user {
        parts.push(format!("user {u}"));
    }
    if let Some(s) = &c.secret {
        let shown = if reveal {
            s.clone()
        } else {
            c.masked_secret().unwrap_or_default()
        };
        parts.push(format!("secret {shown}"));
    }
    if let Some(f) = &c.field {
        parts.push(format!("in {f}"));
    }
    let sample = parts.join(", ");
    match c.count {
        0 | 1 => sample,
        n => format!("{sample}, seen {n} times"),
    }
}

fn frames_filter(frames: &[u64]) -> String {
    let list: Vec<String> = frames.iter().take(MAX_FRAMES).map(u64::to_string).collect();
    format!("frame.number in {{{}}}", list.join(","))
}

fn credentials(all: &[Credential], reveal: bool, out: &mut Findings) {
    let mut groups: BTreeMap<(CredKind, bool, &str, &str), Vec<&Credential>> = BTreeMap::new();
    for c in all {
        let filled = c.secret.as_deref() != Some("");
        groups
            .entry((c.kind, filled, &c.src, &c.dst))
            .or_default()
            .push(c);
    }
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_by_key(|((kind, filled, ..), v)| {
        (severity(*kind, *filled), std::cmp::Reverse(v.len()))
    });
    for ((kind, filled, src, dst), found) in groups {
        let label = if filled {
            kind.label().to_owned()
        } else {
            format!("{} without password", kind.label())
        };
        let samples: Vec<String> = found
            .iter()
            .take(MAX_SAMPLES)
            .map(|c| sample(c, reveal))
            .collect();
        let more = found.len().saturating_sub(MAX_SAMPLES);
        let tail = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        let frames: Vec<u64> = found.iter().map(|c| c.frame).collect();
        push_capped(
            out,
            Some(LOGINS),
            severity(kind, filled),
            format!("Cleartext {label}: {src} to {dst}"),
            format!(
                "{src} sent {label} unencrypted to {dst} ({}{tail}). Anyone on the path can read it: use TLS, and change the secret if it is real.",
                samples.join("; "),
            ),
            Some(&frames_filter(&frames)),
            format!(
                "{} found",
                found.iter().map(|c| u64::from(c.count)).sum::<u64>()
            ),
        );
    }
}

fn addresses(intel: &ThreatIntel, hosts: &[HostStat], out: &mut Findings) {
    let mut hits: Vec<(&HostStat, &str)> = hosts
        .iter()
        .filter_map(|h| intel.ip(&h.addr).map(|l| (h, l)))
        .collect();
    hits.sort_by_key(|(h, _)| std::cmp::Reverse(h.packets_in + h.packets_out));
    for (h, list) in hits {
        push_capped(
            out,
            Some(ADDRESSES),
            InsightSeverity::Critical,
            format!("Blocklisted address: {} ({list})", h.addr),
            format!(
                "{} is on the {list} list and exchanged traffic in this capture.",
                h.addr
            ),
            Some(&ip_filter(&h.addr)),
            format!("{} packets", format::count(h.packets_in + h.packets_out)),
        );
    }
}

/// Domains from DNS queries and TLS server names, each reported once.
fn domains(inp: &Inputs, out: &mut Findings) {
    let tls = inp.security.map_or(&[][..], |s| &s.tls);
    let names: BTreeSet<&str> = inp
        .dns
        .iter()
        .map(|q| q.name.as_str())
        .chain(tls.iter().map(|t| &*t.server_name))
        .collect();
    let hits = names
        .into_iter()
        .filter_map(|n| inp.intel.domain(n).map(|l| (n, l)));
    for (name, list) in hits {
        push_capped(
            out,
            Some(DOMAINS),
            InsightSeverity::Critical,
            format!("Blocklisted domain: {name} ({list})"),
            format!("{name} is on the {list} list and was looked up or contacted in this capture."),
            Some(&format!(
                "dns.qry.name == \"{name}\" || tls.handshake.extensions_server_name == \"{name}\""
            )),
            "domain".to_owned(),
        );
    }
}

fn fingerprints(inp: &Inputs, out: &mut Findings) {
    let Some(sec) = inp.security else { return };
    let mut bad: BTreeMap<(&str, &str), (&str, usize)> = BTreeMap::new();
    let mut clients: BTreeMap<std::sync::Arc<str>, usize> = BTreeMap::new();
    for t in &sec.tls {
        for (field, hash) in [("ja3", &t.ja3), ("ja4", &t.ja4)] {
            let Some(fp) = hash.as_deref().and_then(|h| inp.intel.fingerprint(h)) else {
                continue;
            };
            if fp.malicious {
                let hash = hash.as_deref().unwrap_or_default();
                bad.entry((field, hash)).or_insert((&*fp.label, 0)).1 += 1;
            }
        }
        if let Some(c) = inp.intel.tls_client(t) {
            *clients.entry(c).or_default() += 1;
        }
    }
    for ((field, hash), (label, n)) in bad {
        push_capped(
            out,
            Some(FINGERPRINTS),
            InsightSeverity::Critical,
            format!("Malicious TLS client fingerprint: {label}"),
            format!(
                "{n} TLS handshakes use the {} fingerprint {hash}, listed as {label}.",
                field.to_uppercase()
            ),
            Some(&format!("tls.handshake.{field} == \"{hash}\"")),
            format!("{n} sessions"),
        );
    }
    if !clients.is_empty() {
        let mut ranked: Vec<_> = clients.into_iter().collect();
        ranked.sort_by_key(|(name, n)| (std::cmp::Reverse(*n), name.clone()));
        let names: Vec<String> = ranked
            .iter()
            .take(5)
            .map(|(c, n)| format!("{c} ({n})"))
            .collect();
        push_capped(
            out,
            None,
            InsightSeverity::Info,
            "TLS clients identified by JA4DB",
            format!(
                "Fingerprints of the TLS handshakes match known applications: {}.",
                names.join(", ")
            ),
            Some("tls.handshake.type == 1"),
            format!("{} clients", ranked.len()),
        );
    }
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;
