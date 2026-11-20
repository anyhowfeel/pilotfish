use wl_model::{PacketRow, StatsSnapshot};

use crate::edges::{DEFAULT_SNAPSHOT_EDGES, EdgeTable};
use crate::flows::FlowTable;
use crate::hosts::HostTable;
use crate::protocols::ProtocolTable;
use crate::series::TimeSeries;

/// Incremental statistics: O(1) per packet; snapshots cost O(items + n log n).
#[derive(Debug, Default)]
pub struct StatsEngine {
    packets: u64,
    bytes: u64,
    protocols: ProtocolTable,
    hosts: HostTable,
    flows: FlowTable,
    edges: EdgeTable,
    series: TimeSeries,
}

impl StatsEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(&mut self, row: &PacketRow) {
        self.packets += 1;
        self.bytes += u64::from(row.len);
        self.protocols.add(row);
        self.hosts.add(row);
        self.flows.add(row);
        self.edges.add(row);
        self.series.add(row.rel, u64::from(row.len));
    }

    pub fn ingest_batch(&mut self, rows: &[PacketRow]) {
        rows.iter().for_each(|r| self.ingest(r));
    }

    /// Hosts and conversations are limited to the `top_n` largest by bytes;
    /// protocols (few) and the rate series are returned in full.
    pub fn snapshot(&self, top_n: usize) -> StatsSnapshot {
        StatsSnapshot {
            total_packets: self.packets,
            total_bytes: self.bytes,
            protocols: self.protocols.top(usize::MAX),
            hosts: self.hosts.top(top_n),
            conversations: self.flows.top(top_n),
            edges: self.edges.top(DEFAULT_SNAPSHOT_EDGES),
            rate: self.series.points(),
        }
    }

    pub fn reset(&mut self) {
        self.packets = 0;
        self.bytes = 0;
        self.protocols.clear();
        self.hosts.clear();
        self.flows.clear();
        self.edges.clear();
        self.series.clear();
    }
}

#[cfg(test)]
mod bench;
#[cfg(test)]
mod tests;
