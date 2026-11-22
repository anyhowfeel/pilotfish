//! Values seen in the capture, offered after a comparison operator: addresses and ports from
//! the statistics, host names from the DNS log, SNI and HTTP Host.

use std::collections::HashMap;
use std::sync::Arc;

use wl_kit::text::contains_ci;
use wl_model::StatsSnapshot;

use crate::features::autocomplete_names::{NameBook, NameKind};

const MAX_PORTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub text: String,
    /// Name an address resolves to (or the address behind a name), shown beside the value.
    pub detail: String,
    pub hint: &'static str,
    /// String values: the popup inserts them between double quotes.
    pub quoted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    V4,
    V6,
    Port,
    Name(NameKind),
}

fn source_of(field: &str) -> Option<Source> {
    match field {
        "ip.addr" | "ip.src" | "ip.dst" => Some(Source::V4),
        "ipv6.addr" | "ipv6.src" | "ipv6.dst" => Some(Source::V6),
        "http.host" => Some(Source::Name(NameKind::Http)),
        "tls.handshake.extensions_server_name" => Some(Source::Name(NameKind::Sni)),
        "dns.qry.name" => Some(Source::Name(NameKind::Dns)),
        f if f.ends_with(".port") || f.ends_with(".srcport") || f.ends_with(".dstport") => {
            Some(Source::Port)
        }
        _ => None,
    }
}

/// 0 when `value` starts with `prefix` (lowercase), 1 when it only contains it.
fn match_rank(value: &str, prefix: &str) -> Option<u8> {
    if value.to_ascii_lowercase().starts_with(prefix) {
        Some(0)
    } else {
        contains_ci(value, prefix).then_some(1)
    }
}

fn plain(text: &str, hint: &'static str) -> Suggestion {
    Suggestion {
        text: text.to_owned(),
        detail: String::new(),
        hint,
        quoted: false,
    }
}

/// Candidate values of the open capture, most active first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValueIndex {
    v4: Vec<Arc<str>>,
    v6: Vec<Arc<str>>,
    ports: Vec<String>,
    names: Arc<NameBook>,
}

impl ValueIndex {
    pub fn from_stats(s: &StatsSnapshot) -> Self {
        let (v6, v4): (Vec<_>, Vec<_>) = s
            .hosts
            .iter()
            .map(|h| h.addr.clone())
            .partition(|a| a.contains(':'));
        let mut by_port: HashMap<u16, u64> = HashMap::new();
        for c in &s.conversations {
            // The lower port is the service; the other end is usually an ephemeral client port.
            if let Some(p) = [c.key.a_port, c.key.b_port].into_iter().flatten().min() {
                *by_port.entry(p).or_default() += c.packets;
            }
        }
        let mut ports: Vec<(u16, u64)> = by_port.into_iter().collect();
        ports.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Self {
            v4,
            v6,
            ports: ports
                .into_iter()
                .take(MAX_PORTS)
                .map(|(p, _)| p.to_string())
                .collect(),
            names: Arc::default(),
        }
    }

    pub fn with_names(mut self, names: Arc<NameBook>) -> Self {
        self.names = names;
        self
    }

    /// True when values exist for `field`, so that the popup should stay quiet for other fields.
    pub fn knows(&self, field: &str) -> bool {
        source_of(field).is_some()
    }

    /// Up to `max` values of `field` matching `prefix`: starts-with before contains.
    pub fn suggest(&self, field: &str, prefix: &str, max: usize) -> Vec<Suggestion> {
        let p = prefix.to_ascii_lowercase();
        let mut ranked: Vec<(u8, Suggestion)> = match source_of(field) {
            Some(Source::V4) => self.addresses(&self.v4, false, &p),
            Some(Source::V6) => self.addresses(&self.v6, true, &p),
            Some(Source::Port) => self
                .ports
                .iter()
                .filter_map(|v| Some((match_rank(v, &p)?, plain(v, "port"))))
                .collect(),
            Some(Source::Name(kind)) => self.names(kind, &p),
            None => Vec::new(),
        };
        ranked.sort_by_key(|(rank, _)| *rank);
        ranked.into_iter().take(max).map(|(_, s)| s).collect()
    }

    fn names(&self, kind: NameKind, p: &str) -> Vec<(u8, Suggestion)> {
        self.names
            .pool(kind)
            .iter()
            .filter_map(|n| {
                let s = Suggestion {
                    quoted: true,
                    ..plain(n, kind.tag())
                };
                Some((match_rank(n, p)?, s))
            })
            .collect()
    }

    /// Hosts of the capture plus resolved addresses, ranked: address prefix, name prefix,
    /// address contains, name contains.
    fn addresses(&self, hosts: &[Arc<str>], v6: bool, p: &str) -> Vec<(u8, Suggestion)> {
        let resolved = self.names.addresses().filter(|a| a.contains(':') == v6);
        let mut seen: Vec<&str> = Vec::new();
        let mut out = Vec::new();
        for addr in hosts
            .iter()
            .map(|a| &**a)
            .chain(resolved.map(String::as_str))
        {
            if seen.contains(&addr) {
                continue;
            }
            seen.push(addr);
            if let Some((rank, s)) = self.address(addr, p) {
                out.push((rank, s));
            }
        }
        out
    }

    fn address(&self, addr: &str, p: &str) -> Option<(u8, Suggestion)> {
        let names = self.names.names_of(addr);
        let by_addr = match_rank(addr, p).map(|r| r * 2);
        let by_name = names
            .iter()
            .find_map(|(n, k)| Some((match_rank(n, p)? * 2 + 1, n, k.tag())));
        let first = names.first().map(|(n, _)| n.clone()).unwrap_or_default();
        let (rank, detail, tag) = match (by_addr, by_name) {
            (Some(a), Some((n, ..))) if a < n => (a, first, "host"),
            (Some(a), None) => (a, first, "host"),
            (_, Some((n, name, tag))) => (n, name.clone(), tag),
            (None, None) => return None,
        };
        Some((
            rank,
            Suggestion {
                detail,
                ..plain(addr, tag)
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::{ConversationStat, FlowKey, HostStat, Transport};

    fn host(a: &str) -> HostStat {
        HostStat {
            addr: a.into(),
            ..Default::default()
        }
    }

    fn conv(a_port: u16, b_port: u16, packets: u64) -> ConversationStat {
        ConversationStat {
            key: FlowKey {
                a: "10.0.0.1".into(),
                b: "10.0.0.2".into(),
                transport: Transport::Tcp,
                a_port: Some(a_port),
                b_port: Some(b_port),
            },
            packets,
            bytes: 0,
            first_rel: 0.0,
            last_rel: 0.0,
            protocol: "TCP".into(),
        }
    }

    fn index() -> ValueIndex {
        ValueIndex::from_stats(&StatsSnapshot {
            hosts: vec![
                host("10.0.0.9"),
                host("::1"),
                host("192.168.1.5"),
                host("10.0.1.7"),
            ],
            conversations: vec![
                conv(443, 50000, 10),
                conv(443, 50001, 5),
                conv(80, 50002, 20),
            ],
            ..Default::default()
        })
    }

    fn texts(v: Vec<Suggestion>) -> Vec<String> {
        v.into_iter().map(|s| s.text).collect()
    }

    #[test]
    fn hosts_are_split_by_family_and_matched_by_prefix_first() {
        let i = index();
        assert_eq!(
            texts(i.suggest("ip.addr", "10.", 8)),
            ["10.0.0.9", "10.0.1.7"]
        );
        assert_eq!(texts(i.suggest("ip.dst", "5", 8)), ["192.168.1.5"]);
        assert_eq!(texts(i.suggest("ipv6.src", "", 8)), ["::1"]);
    }

    #[test]
    fn ports_are_the_service_ports_ranked_by_activity() {
        let i = index();
        assert_eq!(texts(i.suggest("tcp.port", "", 3)), ["80", "443"]);
        assert_eq!(texts(i.suggest("udp.dstport", "80", 8)), ["80"]);
    }

    #[test]
    fn unknown_fields_have_no_values() {
        let i = index();
        assert!(!i.knows("http.user_agent"));
        assert!(i.suggest("http.user_agent", "", 8).is_empty());
    }

    fn names() -> Arc<NameBook> {
        let dns = |name: &str, answer: &str| wl_model::DnsQuery {
            frame: 1,
            response_frame: None,
            rel: 0.0,
            client: "10.0.0.1".into(),
            server: "10.0.0.53".into(),
            name: name.into(),
            qtype: "A".into(),
            rcode: None,
            answers: vec![answer.into()],
            rtt_ms: None,
            retransmission: false,
        };
        let queries = [
            dns("shop.example.com", "93.184.216.34"),
            dns("shop.example.com", "93.184.216.35"),
            dns("intranet.corp", "10.0.0.9"),
            dns("v6.example.com", "2001:db8::1"),
        ];
        Arc::new(NameBook::build(&queries, &[], &[]))
    }

    fn named() -> ValueIndex {
        index().with_names(names())
    }

    #[test]
    fn a_name_expands_to_the_addresses_it_resolved_to() {
        let got = named().suggest("ip.addr", "shop", 8);
        let ips: Vec<_> = got.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(ips, ["93.184.216.34", "93.184.216.35"]);
        assert!(
            got.iter()
                .all(|s| s.detail == "shop.example.com" && s.hint == "dns")
        );
        assert!(
            named()
                .suggest("ipv6.addr", "v6.", 8)
                .iter()
                .any(|s| s.text == "2001:db8::1")
        );
    }

    #[test]
    fn address_prefix_beats_name_prefix_beats_contains() {
        let i = named();
        let top = |p: &str| texts(i.suggest("ip.addr", p, 8));
        assert_eq!(top("10.0.0.9"), ["10.0.0.9"]);
        assert_eq!(top("93.")[0], "93.184.216.34");
        assert_eq!(top("corp"), ["10.0.0.9"]);
        assert_eq!(top("example")[0], "93.184.216.34");
        assert_eq!(
            i.suggest("ip.addr", "10.0.0.9", 1)[0].detail,
            "intranet.corp"
        );
    }

    #[test]
    fn host_fields_get_quoted_names_ranked_by_prefix() {
        let i = named();
        let got = i.suggest("dns.qry.name", "exa", 8);
        assert_eq!(texts(got.clone()), ["shop.example.com", "v6.example.com"]);
        assert!(got.iter().all(|s| s.quoted));
        let by_prefix = i.suggest("dns.qry.name", "v6", 8);
        assert_eq!(texts(by_prefix), ["v6.example.com"]);
        assert!(i.knows("http.host") && i.knows("tls.handshake.extensions_server_name"));
    }
}
