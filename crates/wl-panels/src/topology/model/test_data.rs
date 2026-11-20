//! Shared fixtures for topology tests.

use wl_model::{HostEdge, HostStat};

use super::*;

pub fn host(addr: &str, private: bool, bytes: u64) -> HostStat {
    HostStat {
        addr: addr.into(),
        bytes_out: bytes / 2,
        bytes_in: bytes - bytes / 2,
        packets_in: 3,
        packets_out: 2,
        is_private: private,
    }
}

pub fn edge(a: &str, b: &str, bytes: u64, proto: &str) -> HostEdge {
    HostEdge {
        a: a.into(),
        b: b.into(),
        packets: bytes / 100 + 1,
        bytes,
        a_to_b: bytes / 4,
        first_rel: 0.0,
        last_rel: 10.0,
        protocol: proto.into(),
        encrypted: wl_model::is_encrypted_protocol(proto),
    }
}

/// Gateway `.1` with three clients and two public hosts.
pub fn star() -> StatsSnapshot {
    StatsSnapshot {
        hosts: vec![
            host("72.30.35.9", false, 700_000),
            host("192.168.74.124", true, 710_000),
            host("192.168.74.1", true, 50_000),
            host("192.168.74.7", true, 20_000),
        ],
        edges: vec![
            edge("192.168.74.124", "72.30.35.9", 700_000, "TLS"),
            edge("192.168.74.1", "192.168.74.124", 40_000, "DNS"),
            edge("192.168.74.1", "192.168.74.7", 10_000, "TCP"),
            edge("192.168.74.1", "8.8.8.8", 1_000, "DNS"),
        ],
        ..Default::default()
    }
}
