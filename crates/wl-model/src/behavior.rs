//! Inputs of the behavioural checks (port scans, beaconing, odd DNS names): per-channel
//! summaries, small enough to keep for captures of any size.

use std::sync::Arc;

use crate::DnsQuery;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
            Proto::Icmp => "ICMP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// Connection attempts: TCP SYN, first packet of a UDP flow, ICMP echo request.
    NewFlows,
    /// Payload packets inside one TCP connection and direction.
    Stream,
}

/// Timing of repeated events from `src` to `dst:dport`.
#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    pub src: Arc<str>,
    pub dst: Arc<str>,
    pub proto: Proto,
    pub kind: ChannelKind,
    pub dport: u16,
    pub count: u32,
    /// Mean seconds between consecutive events (0 with fewer than two events).
    pub gap_mean: f64,
    /// Standard deviation of the gaps relative to their mean.
    pub gap_jitter: f64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct BehaviorData {
    pub channels: Vec<Channel>,
    pub dns: Vec<DnsQuery>,
}
