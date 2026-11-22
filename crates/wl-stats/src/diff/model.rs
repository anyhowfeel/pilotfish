use std::sync::Arc;

use wl_model::{DnsQuery, HttpExchange, StatsSnapshot, TlsSession};

/// Everything the diff reads from one capture.
#[derive(Debug, Clone, Default)]
pub struct CaptureData {
    pub stats: Arc<StatsSnapshot>,
    pub http: Vec<HttpExchange>,
    pub tls: Vec<TlsSession>,
    pub dns: Vec<DnsQuery>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Traffic {
    pub packets: u64,
    pub bytes: u64,
}

impl Traffic {
    pub fn of_totals(s: &StatsSnapshot) -> Self {
        Traffic {
            packets: s.total_packets,
            bytes: s.total_bytes,
        }
    }

    pub fn add(&mut self, packets: u64, bytes: u64) {
        self.packets += packets;
        self.bytes += bytes;
    }
}

/// Mean latency in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Micros(pub u64);

/// A value that can be compared across captures and ranked by how much it moved.
pub trait Metric: Copy {
    fn size(&self) -> u64;
    fn same(&self, other: &Self) -> bool;
}

impl Metric for Traffic {
    fn size(&self) -> u64 {
        self.bytes
    }

    fn same(&self, other: &Self) -> bool {
        self == other
    }
}

impl Metric for u64 {
    fn size(&self) -> u64 {
        *self
    }

    fn same(&self, other: &Self) -> bool {
        self == other
    }
}

impl Metric for Micros {
    fn size(&self) -> u64 {
        self.0
    }

    // Latency jitters between runs: only a 10% move is a difference.
    fn same(&self, other: &Self) -> bool {
        self.0.abs_diff(other.0) * 10 <= self.0.max(other.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Added,
    Removed,
    Changed,
}

/// One named item with its value in the first and in the second capture.
#[derive(Debug, Clone, PartialEq)]
pub struct Row<V> {
    pub label: String,
    pub before: Option<V>,
    pub after: Option<V>,
}

impl<V: Metric> Row<V> {
    pub fn presence(&self) -> Presence {
        match (&self.before, &self.after) {
            (None, _) => Presence::Added,
            (_, None) => Presence::Removed,
            _ => Presence::Changed,
        }
    }

    pub fn movement(&self) -> u64 {
        let size = |v: &Option<V>| v.map_or(0, |v| v.size());
        size(&self.before).abs_diff(size(&self.after))
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CaptureDiff {
    pub before: Traffic,
    pub after: Traffic,
    pub hosts: Vec<Row<Traffic>>,
    /// Conversations merged per service (endpoints and server port), so ephemeral client ports
    /// do not make every flow look new.
    pub services: Vec<Row<Traffic>>,
    pub latency: Vec<Row<Micros>>,
    pub http_hosts: Vec<Row<u64>>,
    pub statuses: Vec<Row<u64>>,
    pub tls_names: Vec<Row<u64>>,
    /// Requests that never got a response, counted per `METHOD host/uri`.
    pub unanswered: Vec<Row<u64>>,
    /// Status code per URL, only for URLs seen in both captures.
    pub url_statuses: Vec<Row<u64>>,
    /// DNS response code per query (0 = unanswered, else code + 1), only for queries in both.
    pub dns_rcodes: Vec<Row<u64>>,
    /// DNS answers of the queries seen in both captures.
    pub dns_answers: Vec<Row<u64>>,
}

impl CaptureDiff {
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
            && self.services.is_empty()
            && self.latency.is_empty()
            && self.http_hosts.is_empty()
            && self.statuses.is_empty()
            && self.tls_names.is_empty()
            && self.unanswered.is_empty()
            && self.url_statuses.is_empty()
            && self.dns_rcodes.is_empty()
            && self.dns_answers.is_empty()
    }
}
