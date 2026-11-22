//! Names seen in the capture (DNS log, TLS SNI, HTTP Host) and the addresses they resolve to.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use wl_model::{DnsQuery, HttpExchange, TlsSession};

const MAX_NAMES: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    Http,
    Sni,
    Dns,
}

impl NameKind {
    pub fn tag(self) -> &'static str {
        match self {
            NameKind::Http => "http",
            NameKind::Sni => "sni",
            NameKind::Dns => "dns",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NameBook {
    http: Vec<String>,
    sni: Vec<String>,
    dns: Vec<String>,
    /// Address -> names that resolved to it, with the log they come from.
    by_addr: BTreeMap<String, Vec<(String, NameKind)>>,
}

/// Names ordered by how often they occur, then alphabetically.
fn ranked(counts: HashMap<String, u32>) -> Vec<String> {
    let mut v: Vec<(String, u32)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(MAX_NAMES);
    v.into_iter().map(|(n, _)| n).collect()
}

fn tally<'a>(names: impl Iterator<Item = &'a str>) -> HashMap<String, u32> {
    let mut counts = HashMap::new();
    for n in names.filter(|n| !n.is_empty()) {
        *counts.entry(n.to_owned()).or_default() += 1;
    }
    counts
}

impl NameBook {
    pub fn build(dns: &[DnsQuery], tls: &[TlsSession], http: &[HttpExchange]) -> Self {
        let mut book = NameBook {
            http: ranked(tally(http.iter().map(|e| &*e.host))),
            sni: ranked(tally(tls.iter().map(|t| &*t.server_name))),
            dns: ranked(tally(dns.iter().map(|q| q.name.as_str()))),
            by_addr: BTreeMap::new(),
        };
        for q in dns {
            for a in q.answers.iter().filter(|a| a.parse::<IpAddr>().is_ok()) {
                book.link(a, &q.name, NameKind::Dns);
            }
        }
        for t in tls {
            book.link(&t.dst, &t.server_name, NameKind::Sni);
        }
        book
    }

    fn link(&mut self, addr: &str, name: &str, kind: NameKind) {
        if name.is_empty() {
            return;
        }
        let names = self.by_addr.entry(addr.to_owned()).or_default();
        if !names.iter().any(|(n, _)| n == name) {
            names.push((name.to_owned(), kind));
        }
    }

    pub fn is_empty(&self) -> bool {
        self.http.is_empty() && self.sni.is_empty() && self.dns.is_empty()
    }

    pub fn pool(&self, kind: NameKind) -> &[String] {
        match kind {
            NameKind::Http => &self.http,
            NameKind::Sni => &self.sni,
            NameKind::Dns => &self.dns,
        }
    }

    pub fn addresses(&self) -> impl Iterator<Item = &String> {
        self.by_addr.keys()
    }

    pub fn names_of(&self, addr: &str) -> &[(String, NameKind)] {
        self.by_addr.get(addr).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, answers: &[&str]) -> DnsQuery {
        DnsQuery {
            frame: 1,
            response_frame: None,
            rel: 0.0,
            client: "10.0.0.1".into(),
            server: "10.0.0.53".into(),
            name: name.into(),
            qtype: "A".into(),
            rcode: None,
            answers: answers.iter().map(|a| (*a).to_owned()).collect(),
            rtt_ms: None,
            retransmission: false,
        }
    }

    #[test]
    fn answers_link_names_to_addresses_and_skip_cnames() {
        let dns = [
            query("a.test", &["alias.test", "1.1.1.1"]),
            query("a.test", &["1.1.1.1"]),
        ];
        let book = NameBook::build(&dns, &[], &[]);
        assert_eq!(
            book.names_of("1.1.1.1"),
            [("a.test".to_owned(), NameKind::Dns)]
        );
        assert!(book.names_of("alias.test").is_empty());
        assert_eq!(book.pool(NameKind::Dns), ["a.test"]);
    }

    #[test]
    fn pools_are_ordered_by_frequency() {
        let dns = [
            query("rare.test", &[]),
            query("busy.test", &[]),
            query("busy.test", &[]),
        ];
        let book = NameBook::build(&dns, &[], &[]);
        assert_eq!(book.pool(NameKind::Dns), ["busy.test", "rare.test"]);
    }
}
