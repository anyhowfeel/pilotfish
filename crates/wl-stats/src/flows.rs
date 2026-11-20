use std::collections::HashMap;
use std::sync::Arc;

use wl_model::{ConversationStat, FlowKey, PacketRow};

use crate::top::top_n_by;

#[derive(Debug)]
struct Flow {
    packets: u64,
    bytes: u64,
    first: f64,
    last: f64,
    /// Per-protocol packet counts (tiny: flows rarely see >3 protocols).
    protos: Vec<(Arc<str>, u64)>,
    dominant: usize,
}

impl Flow {
    fn new(row: &PacketRow) -> Self {
        Self {
            packets: 0,
            bytes: 0,
            first: row.rel,
            last: row.rel,
            protos: vec![(row.protocol.clone(), 0)],
            dominant: 0,
        }
    }

    fn add(&mut self, row: &PacketRow) {
        self.packets += 1;
        self.bytes += u64::from(row.len);
        self.first = self.first.min(row.rel);
        self.last = self.last.max(row.rel);
        let i = match self.protos.iter().position(|(p, _)| **p == *row.protocol) {
            Some(i) => i,
            None => {
                self.protos.push((row.protocol.clone(), 0));
                self.protos.len() - 1
            }
        };
        self.protos[i].1 += 1;
        if self.protos[i].1 > self.protos[self.dominant].1 {
            self.dominant = i;
        }
    }
}

/// Hard cap on tracked conversations; later unseen ones are ignored.
pub const MAX_FLOWS: usize = 500_000;

#[derive(Debug, Default)]
pub struct FlowTable(HashMap<FlowKey, Flow>);

impl FlowTable {
    pub fn add(&mut self, row: &PacketRow) {
        let key = row.flow_key();
        if self.0.len() >= MAX_FLOWS && !self.0.contains_key(&key) {
            return; // bounded memory under scans / floods
        }
        self.0.entry(key).or_insert_with(|| Flow::new(row)).add(row);
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn top(&self, n: usize) -> Vec<ConversationStat> {
        top_n_by(self.0.iter(), n, |a, b| {
            b.1.bytes.cmp(&a.1.bytes).then_with(|| a.0.cmp(b.0))
        })
        .into_iter()
        .map(|(k, f)| ConversationStat {
            key: k.clone(),
            packets: f.packets,
            bytes: f.bytes,
            first_rel: f.first,
            last_rel: f.last,
            protocol: f.protos[f.dominant].0.clone(),
        })
        .collect()
    }
}
