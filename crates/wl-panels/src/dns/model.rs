//! Pure logic of the DNS log: filtering, sorting and the summary statistics.

use std::cmp::Ordering;
use std::collections::HashMap;

use wl_model::{DnsQuery, Rcode};

use crate::overview::SortState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortCol {
    Frame,
    Time,
    Client,
    Server,
    Name,
    Type,
    Rcode,
    Rtt,
}

/// Status classes shown as toggle chips.
pub const CLASS_LABELS: [&str; 4] = ["NOERROR", "NXDOMAIN", "Failure", "No response"];

/// Index into `Filter::classes` of a query.
pub fn class_of(q: &DnsQuery) -> usize {
    match q.rcode {
        Some(Rcode::NoError) => 0,
        Some(Rcode::NxDomain) => 1,
        Some(_) => 2,
        None => 3,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    pub query: String,
    pub classes: [bool; 4],
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            query: String::new(),
            classes: [true; 4],
        }
    }
}

fn matches(q: &DnsQuery, needle: &str) -> bool {
    let has = |s: &str| s.to_ascii_lowercase().contains(needle);
    has(&q.name)
        || has(&q.client)
        || has(&q.server)
        || has(&q.qtype)
        || q.answers.iter().any(|a| has(a))
        || q.rcode.is_some_and(|r| has(&r.label()))
}

fn rcode_key(q: &DnsQuery) -> u16 {
    match q.rcode {
        None => 999,
        Some(Rcode::Other(n)) => 100 + u16::from(n),
        Some(r) => [
            "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
        ]
        .iter()
        .position(|l| *l == r.label())
        .unwrap_or(0) as u16,
    }
}

fn cmp(a: &DnsQuery, b: &DnsQuery, col: SortCol) -> Ordering {
    match col {
        SortCol::Frame => a.frame.cmp(&b.frame),
        SortCol::Time => a.rel.total_cmp(&b.rel),
        SortCol::Client => a.client.cmp(&b.client),
        SortCol::Server => a.server.cmp(&b.server),
        SortCol::Name => a
            .name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase()),
        SortCol::Type => a.qtype.cmp(&b.qtype),
        SortCol::Rcode => rcode_key(a).cmp(&rcode_key(b)),
        // Unanswered rows sort as the slowest.
        SortCol::Rtt => a
            .rtt_ms
            .unwrap_or(f64::MAX)
            .total_cmp(&b.rtt_ms.unwrap_or(f64::MAX)),
    }
}

/// Indices of the rows to show, filtered then sorted (ties keep capture order).
pub fn build(all: &[DnsQuery], f: &Filter, sort: SortState<SortCol>) -> Vec<u32> {
    let needle = f.query.trim().to_ascii_lowercase();
    let mut idx: Vec<u32> = (0..all.len() as u32)
        .filter(|&i| {
            let q = &all[i as usize];
            f.classes[class_of(q)] && (needle.is_empty() || matches(q, &needle))
        })
        .collect();
    idx.sort_by(|&a, &b| {
        let o = cmp(&all[a as usize], &all[b as usize], sort.col);
        if sort.desc { o.reverse() } else { o }.then(a.cmp(&b))
    });
    idx
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsStats {
    pub total: usize,
    pub unique_names: usize,
    pub nxdomain: usize,
    pub failures: usize,
    pub no_response: usize,
    pub retransmissions: usize,
    pub avg_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub max_ms: Option<f64>,
    /// Most queried names, most frequent first (at most `TOP_N`).
    pub top: Vec<(String, usize)>,
}

pub const TOP_N: usize = 5;

impl DnsStats {
    /// Share of queries that came back NXDOMAIN, 0..=1 (of all queries).
    pub fn nx_share(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.nxdomain as f64 / self.total as f64
        }
    }
}

pub fn aggregate(all: &[DnsQuery]) -> DnsStats {
    let mut s = DnsStats {
        total: all.len(),
        ..Default::default()
    };
    let mut names: HashMap<&str, usize> = HashMap::new();
    let mut rtts: Vec<f64> = Vec::new();
    for q in all {
        *names.entry(q.name.as_str()).or_default() += 1;
        match class_of(q) {
            1 => s.nxdomain += 1,
            2 => s.failures += 1,
            3 => s.no_response += 1,
            _ => {}
        }
        s.retransmissions += usize::from(q.retransmission);
        rtts.extend(q.rtt_ms);
    }
    s.unique_names = names.len();
    if !rtts.is_empty() {
        rtts.sort_by(f64::total_cmp);
        s.avg_ms = Some(rtts.iter().sum::<f64>() / rtts.len() as f64);
        let rank = ((rtts.len() as f64) * 0.95).ceil() as usize;
        s.p95_ms = Some(rtts[rank.clamp(1, rtts.len()) - 1]);
        s.max_ms = rtts.last().copied();
    }
    let mut top: Vec<(String, usize)> = names
        .into_iter()
        .filter(|(n, _)| !n.is_empty())
        .map(|(n, c)| (n.to_owned(), c))
        .collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top.truncate(TOP_N);
    s.top = top;
    s
}

/// Compact latency text: "0.8 ms", "42 ms", "1.20 s".
pub fn ms_text(ms: f64) -> String {
    if ms < 10.0 {
        format!("{ms:.1} ms")
    } else if ms < 1000.0 {
        format!("{ms:.0} ms")
    } else {
        format!("{:.2} s", ms / 1000.0)
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
pub(super) mod tests;
