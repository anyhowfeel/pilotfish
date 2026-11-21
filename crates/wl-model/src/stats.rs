use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::FlowKey;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProtocolStat {
    pub name: Arc<str>,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct HostStat {
    pub addr: Arc<str>,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub is_private: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConversationStat {
    pub key: FlowKey,
    pub packets: u64,
    pub bytes: u64,
    pub first_rel: f64,
    pub last_rel: f64,
    /// Most frequent protocol seen in the flow.
    pub protocol: Arc<str>,
}

/// Host-to-host traffic (all ports/protocols merged), the edge of the topology graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostEdge {
    /// Endpoints ordered canonically (`a <= b`), same strings as `HostStat::addr`.
    pub a: Arc<str>,
    pub b: Arc<str>,
    pub packets: u64,
    pub bytes: u64,
    /// Bytes sent by `a` towards `b` (the rest, `bytes - a_to_b`, went b -> a).
    pub a_to_b: u64,
    pub first_rel: f64,
    pub last_rel: f64,
    /// Most frequent protocol on this edge (edge colour/label).
    pub protocol: Arc<str>,
    /// True when any packet of the pair used an encrypted protocol (TLS, QUIC, SSH, IPsec...).
    pub encrypted: bool,
}

/// One bucket of the throughput time series: `[t, t + dt)` seconds since the first packet.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct RatePoint {
    pub t: f64,
    pub dt: f64,
    pub packets: u32,
    pub bytes: u64,
}

impl RatePoint {
    pub fn bytes_per_sec(&self) -> f64 {
        self.bytes as f64 / self.dt.max(f64::EPSILON)
    }

    pub fn packets_per_sec(&self) -> f64 {
        f64::from(self.packets) / self.dt.max(f64::EPSILON)
    }
}

/// Merges buckets into wider ones of `step` seconds aligned on multiples of `step`; series that
/// are already at least that coarse are returned unchanged.
pub fn rebin(points: &[RatePoint], step: f64) -> Vec<RatePoint> {
    if step <= 0.0 || points.iter().all(|p| p.dt >= step) {
        return points.to_vec();
    }
    let mut out: Vec<RatePoint> = Vec::new();
    for p in points {
        let t = (p.t / step).floor() * step;
        match out.last_mut() {
            Some(last) if (last.t - t).abs() < step * 1e-9 => {
                last.packets = last.packets.saturating_add(p.packets);
                last.bytes += p.bytes;
            }
            _ => out.push(RatePoint {
                t,
                dt: step,
                packets: p.packets,
                bytes: p.bytes,
            }),
        }
    }
    out
}

/// Immutable view handed to the UI; produced by the stats engine, sorted desc by bytes.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub protocols: Vec<ProtocolStat>,
    pub hosts: Vec<HostStat>,
    pub conversations: Vec<ConversationStat>,
    /// Host-pair aggregates for the topology graph, heaviest first, capped by the engine.
    pub edges: Vec<HostEdge>,
    pub rate: Vec<RatePoint>,
}
