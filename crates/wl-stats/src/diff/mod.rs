//! Comparison of two captures from their aggregates: hosts, services, latency and web names.

mod join;
mod model;
mod sections;
#[cfg(test)]
mod tests;

pub use model::{CaptureData, CaptureDiff, Metric, Micros, Presence, Row, Traffic};

impl CaptureDiff {
    pub fn compute(before: &CaptureData, after: &CaptureData) -> Self {
        CaptureDiff {
            before: Traffic::of_totals(&before.stats),
            after: Traffic::of_totals(&after.stats),
            hosts: join::rows(sections::hosts(before), sections::hosts(after)),
            services: join::rows(sections::services(before), sections::services(after)),
            latency: join::rows(sections::latency(before), sections::latency(after)),
            http_hosts: join::rows(sections::http_hosts(before), sections::http_hosts(after)),
            statuses: join::rows(sections::statuses(before), sections::statuses(after)),
            tls_names: join::rows(sections::tls_names(before), sections::tls_names(after)),
        }
    }
}
