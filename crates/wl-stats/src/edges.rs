//! Host-pair aggregation (all ports/protocols merged) feeding the topology graph.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

use wl_model::{HostEdge, PacketRow};

use crate::top::top_n_by;

/// Hard cap on tracked host pairs; later unseen pairs are ignored (totals still count them).
pub const MAX_EDGES: usize = 500_000;
/// Default number of edges returned by a snapshot.
pub const DEFAULT_SNAPSHOT_EDGES: usize = 400;

#[derive(Debug)]
struct Edge {
    packets: u64,
    bytes: u64,
    a_to_b: u64,
    first: f64,
    last: f64,
    /// First protocol seen, counted inline: pairs mostly see one, so no per-edge allocation.
    main: (Arc<str>, u64),
    /// Some protocol seen on this pair is encrypted (checked once per distinct protocol).
    encrypted: bool,
    /// Further protocols (empty `Vec` does not allocate).
    extra: Vec<(Arc<str>, u64)>,
}

impl Edge {
    fn new(row: &PacketRow) -> Self {
        Self {
            packets: 0,
            bytes: 0,
            a_to_b: 0,
            first: row.rel,
            last: row.rel,
            main: (row.protocol.clone(), 0),
            encrypted: wl_model::is_encrypted_protocol(&row.protocol),
            extra: Vec::new(),
        }
    }

    fn add(&mut self, row: &PacketRow, from_a: bool) {
        let len = u64::from(row.len);
        self.packets += 1;
        self.bytes += len;
        if from_a {
            self.a_to_b += len;
        }
        self.first = self.first.min(row.rel);
        self.last = self.last.max(row.rel);
        if *self.main.0 == *row.protocol {
            self.main.1 += 1;
        } else if let Some(p) = self.extra.iter_mut().find(|(p, _)| **p == *row.protocol) {
            p.1 += 1;
        } else {
            self.encrypted |= wl_model::is_encrypted_protocol(&row.protocol);
            self.extra.push((row.protocol.clone(), 1));
        }
    }

    /// Most frequent protocol (first seen wins ties).
    fn dominant(&self) -> &Arc<str> {
        let best = self
            .extra
            .iter()
            .fold(&self.main, |b, c| if c.1 > b.1 { c } else { b });
        &best.0
    }
}

/// Fast multiplicative hasher for the packed pair key and the interned address strings
/// (keys are trusted capture data, HashDoS resistance is not needed).
#[derive(Default)]
struct PairHasher(u64);

impl Hasher for PairHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for c in bytes.chunks(8) {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            self.write_u64(u64::from_le_bytes(w));
        }
    }
    fn write_u8(&mut self, v: u8) {
        self.write_u64(u64::from(v));
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = (self.0 ^ v)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .rotate_left(26);
    }
}

type PairMap = HashMap<u64, Edge, BuildHasherDefault<PairHasher>>;

fn pack(lo: u32, hi: u32) -> u64 {
    (u64::from(lo) << 32) | u64::from(hi)
}

/// Endpoints are interned to `u32` ids so the per-packet pair lookup hashes two integers
/// instead of two strings; `Arc` clones happen only the first time an address / pair is seen.
#[derive(Debug, Default)]
pub struct EdgeTable {
    ids: HashMap<Arc<str>, u32, BuildHasherDefault<PairHasher>>,
    names: Vec<Arc<str>>,
    edges: PairMap,
    /// Key of the previous packet's pair: bulk flows skip both string lookups.
    last: Option<u64>,
}

impl EdgeTable {
    fn id(&mut self, addr: &Arc<str>) -> u32 {
        if let Some(&i) = self.ids.get(&**addr) {
            return i;
        }
        let i = self.names.len() as u32;
        self.names.push(addr.clone());
        self.ids.insert(addr.clone(), i);
        i
    }

    pub fn add(&mut self, row: &PacketRow) {
        let from_a = *row.src <= *row.dst;
        let (lo, hi) = if from_a {
            (&row.src, &row.dst)
        } else {
            (&row.dst, &row.src)
        };
        let names = &self.names;
        let memo = self.last.filter(|k| {
            *names[(k >> 32) as usize] == **lo && *names[(k & 0xFFFF_FFFF) as usize] == **hi
        });
        let key = if let Some(k) = memo {
            k
        } else if self.edges.len() >= MAX_EDGES {
            // Full: only already-tracked pairs keep counting (no new ids either).
            let (Some(&l), Some(&h)) = (self.ids.get(&**lo), self.ids.get(&**hi)) else {
                return;
            };
            let k = pack(l, h);
            if !self.edges.contains_key(&k) {
                return;
            }
            k
        } else {
            pack(self.id(lo), self.id(hi))
        };
        if memo.is_none() {
            self.last = Some(key);
        }
        self.edges
            .entry(key)
            .or_insert_with(|| Edge::new(row))
            .add(row, from_a);
    }

    pub fn clear(&mut self) {
        self.ids.clear();
        self.names.clear();
        self.edges.clear();
        self.last = None;
    }

    /// The `n` heaviest pairs by bytes (ties broken by address for determinism).
    pub fn top(&self, n: usize) -> Vec<HostEdge> {
        let names = &self.names;
        let addr = |k: &u64| {
            (
                &names[(*k >> 32) as usize],
                &names[(*k & 0xFFFF_FFFF) as usize],
            )
        };
        top_n_by(self.edges.iter(), n, |x, y| {
            y.1.bytes
                .cmp(&x.1.bytes)
                .then_with(|| addr(x.0).cmp(&addr(y.0)))
        })
        .into_iter()
        .map(|(k, e)| {
            let (a, b) = addr(k);
            HostEdge {
                a: a.clone(),
                b: b.clone(),
                packets: e.packets,
                bytes: e.bytes,
                a_to_b: e.a_to_b,
                first_rel: e.first,
                last_rel: e.last,
                protocol: e.dominant().clone(),
                encrypted: e.encrypted,
            }
        })
        .collect()
    }
}
