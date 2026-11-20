//! Graph model derived from a `StatsSnapshot`: heaviest hosts as nodes, host pairs as links.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use wl_model::StatsSnapshot;

use super::scale::{LogScale, node_radius};

/// Most nodes ever laid out and drawn (heaviest by bytes); the rest is summarised.
pub const MAX_NODES: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Filters {
    pub hide_private_pairs: bool,
    /// Links below this normalised log intensity (`0..=1`) are hidden.
    pub min_intensity: f32,
}

impl Default for Filters {
    fn default() -> Self {
        Self {
            hide_private_pairs: false,
            min_intensity: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    pub addr: Arc<str>,
    pub name: Option<Arc<str>>,
    pub bytes: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub private: bool,
    pub degree: u32,
    pub hub: bool,
    pub radius: f32,
}

impl Node {
    /// Resolved name when known, otherwise the address.
    pub fn label(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.addr)
    }
}

#[derive(Debug, Clone)]
pub struct Link {
    pub a: usize,
    pub b: usize,
    pub bytes: u64,
    pub packets: u64,
    pub a_to_b: u64,
    pub first_rel: f64,
    pub last_rel: f64,
    pub protocol: Arc<str>,
    pub encrypted: bool,
    /// Normalised log intensity `0..=1`.
    pub t: f32,
}

#[derive(Debug, Clone, Default)]
pub struct Graph {
    /// Sorted by bytes, heaviest first (index = rank).
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
    /// Link indices per node.
    pub adj: Vec<Vec<u32>>,
    /// Hosts that did not fit under `MAX_NODES`.
    pub hidden: usize,
    pub scale: Option<LogScale>,
}

fn is_private_addr(addr: &str) -> bool {
    wl_stats::is_private(addr.parse::<IpAddr>().ok())
}

impl Graph {
    pub fn build(
        snap: &StatsSnapshot,
        f: &Filters,
        name_of: &dyn Fn(&str) -> Option<Arc<str>>,
    ) -> Graph {
        let min = snap.edges.iter().map(|e| e.bytes).min().unwrap_or(0);
        let max = snap.edges.iter().map(|e| e.bytes).max().unwrap_or(0);
        let scale = LogScale::new(min, max);
        let hosts: HashMap<&str, usize> = snap
            .hosts
            .iter()
            .enumerate()
            .map(|(i, h)| (&*h.addr, i))
            .collect();
        let private = |a: &str| {
            hosts
                .get(a)
                .map_or_else(|| is_private_addr(a), |&i| snap.hosts[i].is_private)
        };
        let kept: Vec<_> = snap
            .edges
            .iter()
            .filter(|e| scale.norm(e.bytes) >= f.min_intensity)
            .filter(|e| !(f.hide_private_pairs && private(&e.a) && private(&e.b)))
            .collect();
        let mut acc: HashMap<&Arc<str>, u64> = HashMap::new();
        for e in &kept {
            *acc.entry(&e.a).or_default() += e.bytes;
            *acc.entry(&e.b).or_default() += e.bytes;
        }
        let mut order: Vec<(&Arc<str>, u64)> = acc
            .into_iter()
            .map(|(a, edge_bytes)| {
                let b = hosts.get(&**a).map_or(edge_bytes, |&i| {
                    snap.hosts[i].bytes_in + snap.hosts[i].bytes_out
                });
                (a, b)
            })
            .collect();
        order.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(y.0)));
        let hidden = order.len().saturating_sub(MAX_NODES);
        order.truncate(MAX_NODES);
        let max_bytes = order.first().map_or(0, |o| o.1);
        let index: HashMap<&str, usize> =
            order.iter().enumerate().map(|(i, o)| (&**o.0, i)).collect();
        let mut nodes: Vec<Node> = order
            .iter()
            .map(|(addr, bytes)| {
                let h = hosts.get(&***addr).map(|&i| &snap.hosts[i]);
                Node {
                    addr: (*addr).clone(),
                    name: name_of(addr),
                    bytes: *bytes,
                    bytes_in: h.map_or(0, |h| h.bytes_in),
                    bytes_out: h.map_or(0, |h| h.bytes_out),
                    packets_in: h.map_or(0, |h| h.packets_in),
                    packets_out: h.map_or(0, |h| h.packets_out),
                    private: private(addr),
                    degree: 0,
                    hub: false,
                    radius: node_radius(*bytes, max_bytes),
                }
            })
            .collect();
        let mut links = Vec::with_capacity(kept.len());
        let mut adj = vec![Vec::new(); nodes.len()];
        for e in kept {
            let (Some(&a), Some(&b)) = (index.get(&*e.a), index.get(&*e.b)) else {
                continue;
            };
            adj[a].push(links.len() as u32);
            if a != b {
                adj[b].push(links.len() as u32);
            }
            links.push(Link {
                a,
                b,
                bytes: e.bytes,
                packets: e.packets,
                a_to_b: e.a_to_b,
                first_rel: e.first_rel,
                last_rel: e.last_rel,
                protocol: e.protocol.clone(),
                encrypted: e.encrypted,
                t: scale.norm(e.bytes),
            });
        }
        let max_deg = adj.iter().map(Vec::len).max().unwrap_or(0);
        for (n, a) in nodes.iter_mut().zip(&adj) {
            n.degree = a.len() as u32;
            n.hub = a.len() >= 3 && a.len() * 2 >= max_deg;
        }
        Graph {
            nodes,
            links,
            adj,
            hidden,
            scale: Some(scale),
        }
    }

    /// Index of the neighbour of `node` over `link`.
    pub fn other(&self, link: usize, node: usize) -> usize {
        let l = &self.links[link];
        if l.a == node { l.b } else { l.a }
    }

    pub fn find(&self, addr: &str) -> Option<usize> {
        self.nodes.iter().position(|n| &*n.addr == addr)
    }

    /// Peers of `node` as `(peer index, link index)`, heaviest link first.
    pub fn peers(&self, node: usize) -> Vec<(usize, usize)> {
        let mut v: Vec<_> = self.adj[node]
            .iter()
            .map(|&l| (self.other(l as usize, node), l as usize))
            .collect();
        v.sort_by(|x, y| self.links[y.1].bytes.cmp(&self.links[x.1].bytes));
        v
    }
}

#[cfg(test)]
pub(crate) mod test_data;
#[cfg(test)]
mod tests;
