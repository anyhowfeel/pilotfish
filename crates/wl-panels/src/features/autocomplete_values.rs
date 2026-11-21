//! Values seen in the capture, offered after a comparison operator (addresses, ports).

use std::collections::HashMap;
use std::sync::Arc;

use wl_kit::text::contains_ci;
use wl_model::StatsSnapshot;

const MAX_PORTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub text: String,
    pub hint: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    V4,
    V6,
    Port,
}

fn source_of(field: &str) -> Option<Source> {
    match field {
        "ip.addr" | "ip.src" | "ip.dst" => Some(Source::V4),
        "ipv6.addr" | "ipv6.src" | "ipv6.dst" => Some(Source::V6),
        f if f.ends_with(".port") || f.ends_with(".srcport") || f.ends_with(".dstport") => {
            Some(Source::Port)
        }
        _ => None,
    }
}

/// Candidate values of the open capture, most active first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValueIndex {
    v4: Vec<Arc<str>>,
    v6: Vec<Arc<str>>,
    ports: Vec<String>,
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
        }
    }

    /// True when values exist for `field`, so that the popup should stay quiet for other fields.
    pub fn knows(&self, field: &str) -> bool {
        source_of(field).is_some()
    }

    /// Up to `max` values of `field` starting with `prefix`, then containing it.
    pub fn suggest(&self, field: &str, prefix: &str, max: usize) -> Vec<Suggestion> {
        let (pool, hint): (Vec<&str>, &'static str) = match source_of(field) {
            Some(Source::V4) => (self.v4.iter().map(|a| &**a).collect(), "host"),
            Some(Source::V6) => (self.v6.iter().map(|a| &**a).collect(), "host"),
            Some(Source::Port) => (self.ports.iter().map(String::as_str).collect(), "port"),
            None => return Vec::new(),
        };
        let p = prefix.to_ascii_lowercase();
        let starts = pool
            .iter()
            .filter(|v| v.to_ascii_lowercase().starts_with(&p));
        let inside = pool
            .iter()
            .filter(|v| !v.to_ascii_lowercase().starts_with(&p) && contains_ci(v, &p));
        starts
            .chain(inside)
            .take(max)
            .map(|v| Suggestion {
                text: (*v).to_owned(),
                hint,
            })
            .collect()
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
        assert!(!i.knows("http.host"));
        assert!(i.suggest("http.host", "", 8).is_empty());
    }
}
