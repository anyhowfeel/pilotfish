//! Flow graph contract: per-packet events of one conversation (sequence diagram) and the
//! selection that identifies a conversation. Plain data, no I/O.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{FlowKey, Transport};

/// Hard cap of events one flow pass returns (the result is flagged `truncated` beyond it).
pub const MAX_FLOW_EVENTS: usize = 50_000;

/// Bit set of TCP flags and tshark `tcp.analysis` findings of one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FlowFlags(pub u16);

impl FlowFlags {
    pub const SYN: FlowFlags = FlowFlags(1);
    pub const ACK: FlowFlags = FlowFlags(1 << 1);
    pub const FIN: FlowFlags = FlowFlags(1 << 2);
    pub const RST: FlowFlags = FlowFlags(1 << 3);
    pub const PSH: FlowFlags = FlowFlags(1 << 4);
    /// Retransmission, fast retransmission or spurious retransmission.
    pub const RETRANS: FlowFlags = FlowFlags(1 << 5);
    pub const DUP_ACK: FlowFlags = FlowFlags(1 << 6);
    pub const OUT_OF_ORDER: FlowFlags = FlowFlags(1 << 7);
    pub const ZERO_WINDOW: FlowFlags = FlowFlags(1 << 8);
    /// "Previous segment not captured" / lost segment.
    pub const LOST: FlowFlags = FlowFlags(1 << 9);

    pub const fn contains(self, other: FlowFlags) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: FlowFlags) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn with(self, other: FlowFlags) -> FlowFlags {
        FlowFlags(self.0 | other.0)
    }

    /// Any anomaly reported by the TCP analysis.
    pub const fn is_anomaly(self) -> bool {
        self.intersects(FlowFlags(
            Self::RETRANS.0 | Self::DUP_ACK.0 | Self::OUT_OF_ORDER.0 | Self::LOST.0,
        ))
    }
}

/// One packet of a flow graph: who sent it to whom and what it says.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowEvent {
    pub frame: u64,
    /// Seconds since the first packet of the capture.
    pub rel: f64,
    pub src: Arc<str>,
    pub dst: Arc<str>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Arc<str>,
    /// tshark Info column without the leading `sport -> dport` (the arrow shows it).
    pub label: Arc<str>,
    pub flags: FlowFlags,
    /// Relative TCP sequence / acknowledgement numbers.
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    /// TCP payload length.
    pub len: u32,
}

/// Result of a flow pass.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct FlowEvents {
    pub events: Vec<FlowEvent>,
    /// More packets matched than `MAX_FLOW_EVENTS`.
    pub truncated: bool,
}

/// Which conversation (or host set) a flow view shows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlowSel {
    /// `tcp.stream` index.
    Stream(u32),
    /// One conversation of the Conversations table.
    Conversation(FlowKey),
    /// Every packet exchanged between these (>= 2) hosts.
    Hosts(Vec<Arc<str>>),
}

fn addr_field(addr: &str, suffix: &str) -> String {
    let family = if addr.contains(':') { "ipv6" } else { "ip" };
    format!("{family}.{suffix}")
}

impl FlowSel {
    /// tshark display filter selecting the packets of this selection.
    pub fn filter(&self) -> String {
        match self {
            FlowSel::Stream(n) => format!("tcp.stream eq {n}"),
            FlowSel::Conversation(k) => {
                let f = addr_field(&k.a, "addr");
                let mut s = format!("{f} == {} && {f} == {}", k.a, k.b);
                let proto = match k.transport {
                    Transport::Tcp => "tcp",
                    Transport::Udp => "udp",
                    _ => return s,
                };
                if let (Some(a), Some(b)) = (k.a_port, k.b_port) {
                    s.push_str(&format!(" && {proto}.port == {a} && {proto}.port == {b}"));
                }
                s
            }
            FlowSel::Hosts(h) => {
                let (v6, v4): (Vec<&Arc<str>>, Vec<&Arc<str>>) =
                    h.iter().partition(|a| a.contains(':'));
                let clause = |set: &[&Arc<str>]| {
                    let list = set.iter().map(|a| &***a).collect::<Vec<_>>().join(", ");
                    let first = set.first().map_or("", |a| &***a);
                    let (s, d) = (addr_field(first, "src"), addr_field(first, "dst"));
                    format!("{s} in {{{list}}} && {d} in {{{list}}}")
                };
                let clauses: Vec<String> = [v4, v6]
                    .iter()
                    .filter(|set| !set.is_empty())
                    .map(|set| clause(set))
                    .collect();
                match clauses.as_slice() {
                    [one] => one.clone(),
                    many => many
                        .iter()
                        .map(|c| format!("({c})"))
                        .collect::<Vec<_>>()
                        .join(" || "),
                }
            }
        }
    }

    /// Short human title, e.g. `10.0.0.1:443 <-> 10.0.0.2:5000`.
    pub fn title(&self) -> String {
        match self {
            FlowSel::Stream(n) => format!("TCP stream {n}"),
            FlowSel::Conversation(k) => {
                format!("{} <-> {}", end(&k.a, k.a_port), end(&k.b, k.b_port))
            }
            FlowSel::Hosts(h) => format!("{} hosts", h.len()),
        }
    }

    /// Parses the screenshot flag: `<stream>` or `host,host[,host...]`.
    pub fn parse(spec: &str) -> Option<FlowSel> {
        if let Ok(n) = spec.trim().parse::<u32>() {
            return Some(FlowSel::Stream(n));
        }
        let hosts: Vec<Arc<str>> = spec
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Arc::from)
            .collect();
        (hosts.len() >= 2).then_some(FlowSel::Hosts(hosts))
    }
}

fn end(addr: &str, port: Option<u16>) -> String {
    match port {
        Some(p) if addr.contains(':') => format!("[{addr}]:{p}"),
        Some(p) => format!("{addr}:{p}"),
        None => addr.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(t: Transport, ports: Option<(u16, u16)>) -> FlowKey {
        FlowKey {
            a: "10.0.0.1".into(),
            b: "10.0.0.2".into(),
            transport: t,
            a_port: ports.map(|p| p.0),
            b_port: ports.map(|p| p.1),
        }
    }

    #[test]
    fn filters_per_selection() {
        assert_eq!(FlowSel::Stream(3).filter(), "tcp.stream eq 3");
        let c = FlowSel::Conversation(key(Transport::Tcp, Some((80, 5000))));
        assert_eq!(
            c.filter(),
            "ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp.port == 80 && tcp.port == 5000"
        );
        let icmp = FlowSel::Conversation(key(Transport::Icmp, None));
        assert_eq!(icmp.filter(), "ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2");
        let h = FlowSel::parse("10.0.0.1, 10.0.0.2,10.0.0.3").unwrap();
        assert_eq!(
            h.filter(),
            "ip.src in {10.0.0.1, 10.0.0.2, 10.0.0.3} && ip.dst in {10.0.0.1, 10.0.0.2, 10.0.0.3}"
        );
    }

    #[test]
    fn mixed_families_get_one_clause_each() {
        let h = FlowSel::parse("127.0.0.1,::1").unwrap();
        assert_eq!(
            h.filter(),
            "(ip.src in {127.0.0.1} && ip.dst in {127.0.0.1}) || (ipv6.src in {::1} && ipv6.dst in {::1})"
        );
    }

    #[test]
    fn ipv6_and_parse() {
        let mut k = key(Transport::Udp, Some((53, 4000)));
        k.a = "fe80::1".into();
        let f = FlowSel::Conversation(k).filter();
        assert!(f.starts_with("ipv6.addr == fe80::1"));
        assert_eq!(FlowSel::parse("7"), Some(FlowSel::Stream(7)));
        assert_eq!(FlowSel::parse("only-one"), None);
    }

    #[test]
    fn flags_combine() {
        let f = FlowFlags::SYN.with(FlowFlags::ACK);
        assert!(f.contains(FlowFlags::SYN) && f.contains(FlowFlags::ACK));
        assert!(!f.contains(FlowFlags::FIN) && !f.is_anomaly());
        assert!(FlowFlags::RETRANS.is_anomaly() && FlowFlags::LOST.is_anomaly());
    }
}
