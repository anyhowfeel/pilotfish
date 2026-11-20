//! Aggregation of conversations into "top services" (pure).

use std::collections::HashMap;

use wl_model::{ConversationStat, Transport};

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceStat {
    pub label: String,
    pub bytes: u64,
}

fn transport_name(t: Transport) -> &'static str {
    match t {
        Transport::Tcp => "TCP",
        Transport::Udp => "UDP",
        Transport::Icmp => "ICMP",
        Transport::Other => "other",
    }
}

/// The "server" port of a flow: the one with a known service name, else the lower one.
fn server_port(c: &ConversationStat) -> Option<u16> {
    let t = c.key.transport;
    let (a, b) = (c.key.a_port, c.key.b_port);
    let named = |p: Option<u16>| p.filter(|&p| wl_stats::service_name(p, t).is_some());
    named(b).or(named(a)).or(match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    })
}

pub fn top_services(convs: &[ConversationStat], n: usize) -> Vec<ServiceStat> {
    let mut agg: HashMap<(String, Option<u16>, Transport), u64> = HashMap::new();
    for c in convs {
        let port = server_port(c);
        let name = port.and_then(|p| wl_stats::service_name(p, c.key.transport));
        let key = match (port, name) {
            (Some(p), Some(s)) => (
                format!("{s} \u{00B7} {p}/{}", transport_name(c.key.transport)),
                Some(p),
                c.key.transport,
            ),
            (Some(p), None) => (
                format!("port {p}/{}", transport_name(c.key.transport)),
                Some(p),
                c.key.transport,
            ),
            (None, _) => (c.protocol.to_string(), None, c.key.transport),
        };
        *agg.entry(key).or_default() += c.bytes;
    }
    let mut v: Vec<ServiceStat> = agg
        .into_iter()
        .map(|(k, bytes)| ServiceStat { label: k.0, bytes })
        .collect();
    v.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.label.cmp(&b.label)));
    v.truncate(n);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::FlowKey;

    fn c(ap: u16, bp: u16, bytes: u64) -> ConversationStat {
        ConversationStat {
            key: FlowKey {
                a: "a".into(),
                b: "b".into(),
                transport: Transport::Tcp,
                a_port: Some(ap),
                b_port: Some(bp),
            },
            packets: 1,
            bytes,
            first_rel: 0.0,
            last_rel: 1.0,
            protocol: "TCP".into(),
        }
    }

    #[test]
    fn aggregates_by_server_port() {
        let v = top_services(
            &[c(50000, 443, 10), c(50001, 443, 20), c(40000, 40001, 5)],
            5,
        );
        assert_eq!(v.len(), 2);
        assert!(v[0].label.contains("443/TCP"));
        assert_eq!(v[0].bytes, 30);
        assert_eq!(v[1].label, "port 40000/TCP");
    }
}
