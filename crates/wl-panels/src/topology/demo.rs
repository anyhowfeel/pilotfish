//! Deterministic synthetic traffic for screenshots, benchmarks and tests.

use std::sync::Arc;

use wl_model::{HostEdge, HostStat, StatsSnapshot};

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const PROTOCOLS: [&str; 7] = ["TLSv1.3", "TCP", "DNS", "QUIC", "HTTP", "ICMP", "UDP"];

fn addr(i: usize, private: bool) -> Arc<str> {
    if private {
        Arc::from(format!("192.168.74.{}", 10 + i))
    } else {
        Arc::from(format!(
            "{}.{}.{}.{}",
            34 + i % 90,
            20 + i * 7 % 200,
            3 + i * 13 % 250,
            1 + i % 250
        ))
    }
}

/// A LAN of clients around a gateway talking to many public hosts: `hosts` nodes, about `edges` links.
pub fn demo_snapshot(hosts: usize, edges: usize) -> StatsSnapshot {
    let mut rng = Lcg(0x5EED);
    let lan = (hosts / 4).max(2);
    let names: Vec<(Arc<str>, bool)> = (0..hosts)
        .map(|i| {
            if i < lan {
                (addr(i, true), true)
            } else {
                (addr(i, false), false)
            }
        })
        .collect();
    let mut list: Vec<HostEdge> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut add = |list: &mut Vec<HostEdge>, i: usize, j: usize, rng: &mut Lcg| {
        let (i, j) = (i.min(j), i.max(j));
        if i == j || !seen.insert((i, j)) {
            return;
        }
        let (a, b) = if names[i].0 <= names[j].0 {
            (i, j)
        } else {
            (j, i)
        };
        let bytes = 400 + (rng.next() % 90) * (1 << (rng.next() % 12));
        let proto = PROTOCOLS[rng.below(PROTOCOLS.len())];
        list.push(HostEdge {
            a: names[a].0.clone(),
            b: names[b].0.clone(),
            packets: bytes / 400 + 1,
            bytes,
            a_to_b: bytes * (rng.next() % 100) / 100,
            first_rel: 0.0,
            last_rel: (rng.next() % 600) as f64,
            protocol: proto.into(),
            encrypted: wl_model::is_encrypted_protocol(proto),
        });
    };
    for j in 1..lan {
        add(&mut list, 0, j, &mut rng);
    }
    for j in lan..hosts {
        let client = rng.below(lan);
        add(&mut list, client, j, &mut rng);
    }
    let mut guard = 0;
    while list.len() < edges && guard < edges * 20 {
        guard += 1;
        let (i, j) = (rng.below(lan), rng.below(hosts));
        add(&mut list, i, j, &mut rng);
    }
    list.sort_by_key(|e| std::cmp::Reverse(e.bytes));
    let host_stats = names
        .iter()
        .map(|(a, private)| {
            let sum: u64 = list
                .iter()
                .filter(|e| e.a == *a || e.b == *a)
                .map(|e| e.bytes)
                .sum();
            HostStat {
                addr: a.clone(),
                packets_in: sum / 900,
                packets_out: sum / 1100,
                bytes_in: sum / 2,
                bytes_out: sum - sum / 2,
                is_private: *private,
            }
        })
        .collect();
    StatsSnapshot {
        total_packets: list.iter().map(|e| e.packets).sum(),
        total_bytes: list.iter().map(|e| e.bytes).sum(),
        hosts: host_stats,
        edges: list,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_sized() {
        let a = demo_snapshot(40, 120);
        assert_eq!(a, demo_snapshot(40, 120));
        assert_eq!(a.hosts.len(), 40);
        assert!(a.edges.len() >= 100 && a.edges.windows(2).all(|w| w[0].bytes >= w[1].bytes));
        assert!(a.edges.iter().all(|e| e.a <= e.b));
    }
}
