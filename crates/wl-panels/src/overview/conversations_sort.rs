//! Pure filter + sort of conversation rows (returns indices into the snapshot).

use std::cmp::Ordering;

use wl_model::ConversationStat;

use crate::overview::sort::SortState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowCol {
    Endpoints,
    Service,
    Protocol,
    Packets,
    Bytes,
    Duration,
}

pub fn duration(c: &ConversationStat) -> f64 {
    (c.last_rel - c.first_rel).max(0.0)
}

/// Service name of the flow (either side's port), via `wl_stats::service_name`.
pub fn service(c: &ConversationStat) -> Option<&'static str> {
    [c.key.b_port, c.key.a_port]
        .into_iter()
        .flatten()
        .find_map(|p| wl_stats::service_name(p, c.key.transport))
}

pub fn endpoints(c: &ConversationStat) -> String {
    format!(
        "{} <-> {}",
        end(&c.key.a, c.key.a_port),
        end(&c.key.b, c.key.b_port)
    )
}

fn end(addr: &str, port: Option<u16>) -> String {
    match port {
        Some(p) if addr.contains(':') => format!("[{addr}]:{p}"),
        Some(p) => format!("{addr}:{p}"),
        None => addr.to_string(),
    }
}

/// Display filter selecting exactly this flow.
pub fn flow_filter(c: &ConversationStat) -> String {
    let k = &c.key;
    let mut f = format!("ip.addr == {} && ip.addr == {}", k.a, k.b);
    if k.a.contains(':') {
        f = format!("ipv6.addr == {} && ipv6.addr == {}", k.a, k.b);
    }
    let proto = match k.transport {
        wl_model::Transport::Tcp => "tcp",
        wl_model::Transport::Udp => "udp",
        _ => return f,
    };
    if let (Some(a), Some(b)) = (k.a_port, k.b_port) {
        f.push_str(&format!(" && {proto}.port == {a} && {proto}.port == {b}"));
    }
    f
}

fn cmp(a: &ConversationStat, b: &ConversationStat, col: FlowCol) -> Ordering {
    match col {
        FlowCol::Endpoints => {
            (&a.key.a, a.key.a_port, &a.key.b).cmp(&(&b.key.a, b.key.a_port, &b.key.b))
        }
        FlowCol::Service => service(a).cmp(&service(b)),
        FlowCol::Protocol => a.protocol.cmp(&b.protocol),
        FlowCol::Packets => a.packets.cmp(&b.packets),
        FlowCol::Bytes => a.bytes.cmp(&b.bytes),
        FlowCol::Duration => duration(a).total_cmp(&duration(b)),
    }
}

fn matches(c: &ConversationStat, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let n = needle.to_lowercase();
    endpoints(c).to_lowercase().contains(&n)
        || c.protocol.to_lowercase().contains(&n)
        || service(c).is_some_and(|s| s.to_lowercase().contains(&n))
}

pub fn visible(convs: &[ConversationStat], filter: &str, sort: SortState<FlowCol>) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..convs.len())
        .filter(|&i| matches(&convs[i], filter))
        .collect();
    idx.sort_by(|&a, &b| {
        let o = cmp(&convs[a], &convs[b], sort.col).then_with(|| a.cmp(&b));
        if sort.desc { o.reverse() } else { o }
    });
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::{FlowKey, Transport};

    fn c(a: &str, ap: u16, b: &str, bp: u16, bytes: u64, proto: &str) -> ConversationStat {
        ConversationStat {
            key: FlowKey {
                a: a.into(),
                b: b.into(),
                transport: Transport::Tcp,
                a_port: Some(ap),
                b_port: Some(bp),
            },
            packets: 1,
            bytes,
            first_rel: 0.0,
            last_rel: bytes as f64,
            protocol: proto.into(),
        }
    }

    #[test]
    fn sort_filter_and_filter_string() {
        let v = [
            c("10.0.0.1", 5000, "1.1.1.1", 443, 10, "TLS"),
            c("10.0.0.1", 5001, "9.9.9.9", 80, 99, "HTTP"),
        ];
        let r = visible(&v, "", SortState::new(FlowCol::Bytes, true));
        assert_eq!(r, vec![1, 0]);
        assert_eq!(
            visible(&v, "tls", SortState::new(FlowCol::Bytes, true)),
            vec![0]
        );
        assert_eq!(
            flow_filter(&v[0]),
            "ip.addr == 10.0.0.1 && ip.addr == 1.1.1.1 && tcp.port == 5000 && tcp.port == 443"
        );
        assert_eq!(endpoints(&v[0]), "10.0.0.1:5000 <-> 1.1.1.1:443");
    }

    #[test]
    fn ipv6_endpoint_is_bracketed() {
        assert_eq!(end("::1", Some(80)), "[::1]:80");
    }
}
