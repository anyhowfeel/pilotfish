use std::collections::HashMap;
use std::sync::Arc;

use wl_model::{PacketRow, ProtocolStat};

use crate::top::top_n_by;

#[derive(Debug, Default)]
pub struct ProtocolTable(HashMap<Arc<str>, (u64, u64)>);

impl ProtocolTable {
    pub fn add(&mut self, row: &PacketRow) {
        let e = match self.0.get_mut(&*row.protocol) {
            Some(e) => e,
            None => self.0.entry(row.protocol.clone()).or_default(),
        };
        e.0 += 1;
        e.1 += u64::from(row.len);
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Sorted desc by bytes (then packets, then name).
    pub fn top(&self, n: usize) -> Vec<ProtocolStat> {
        let items: Vec<ProtocolStat> = self
            .0
            .iter()
            .map(|(name, &(packets, bytes))| ProtocolStat {
                name: name.clone(),
                packets,
                bytes,
            })
            .collect();
        top_n_by(items, n, |a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then(b.packets.cmp(&a.packets))
                .then_with(|| a.name.cmp(&b.name))
        })
    }
}
