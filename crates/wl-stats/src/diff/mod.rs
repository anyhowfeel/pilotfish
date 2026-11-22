//! Comparison of two captures from their aggregates: hosts, services, latency and web names.

use std::collections::HashSet;

mod join;
mod model;
mod sections;
#[cfg(test)]
mod tests;

pub use model::{CaptureData, CaptureDiff, Metric, Micros, Presence, Row, Traffic};

impl CaptureDiff {
    pub fn compute(before: &CaptureData, after: &CaptureData) -> Self {
        let common: HashSet<String> = sections::dns_queries(before)
            .intersection(&sections::dns_queries(after))
            .cloned()
            .collect();
        let changed = |mut rows: Vec<Row<u64>>| {
            rows.retain(|r| r.presence() == Presence::Changed);
            rows
        };
        CaptureDiff {
            before: Traffic::of_totals(&before.stats),
            after: Traffic::of_totals(&after.stats),
            hosts: join::rows(sections::hosts(before), sections::hosts(after)),
            services: join::rows(sections::services(before), sections::services(after)),
            latency: join::rows(sections::latency(before), sections::latency(after)),
            http_hosts: join::rows(sections::http_hosts(before), sections::http_hosts(after)),
            statuses: join::rows(sections::statuses(before), sections::statuses(after)),
            tls_names: join::rows(sections::tls_names(before), sections::tls_names(after)),
            unanswered: join::rows(sections::unanswered(before), sections::unanswered(after)),
            url_statuses: changed(join::rows(
                sections::status_by_url(before),
                sections::status_by_url(after),
            )),
            dns_rcodes: changed(join::rows(
                sections::dns_rcodes(before),
                sections::dns_rcodes(after),
            )),
            dns_answers: join::rows(
                sections::dns_answers(before, &common),
                sections::dns_answers(after, &common),
            ),
        }
    }
}
