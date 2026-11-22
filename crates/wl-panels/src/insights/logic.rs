//! Pure insight logic: category inference, ordering, grouping, health state. No egui.
use wl_kit::widgets::Severity;
use wl_model::{HealthInsight, InsightSeverity};

use super::category::{Category, category_of};
use crate::features::health::HEALTHY_TITLE;

pub fn severity_of(s: InsightSeverity) -> Severity {
    match s {
        InsightSeverity::Critical => Severity::Critical,
        InsightSeverity::Warning => Severity::Warning,
        InsightSeverity::Info => Severity::Info,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    NeedsAttention,
    Problems,
}

impl HealthState {
    pub fn label(self) -> &'static str {
        match self {
            HealthState::Healthy => "Healthy",
            HealthState::NeedsAttention => "Needs attention",
            HealthState::Problems => "Problems found",
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            HealthState::Healthy => Severity::Ok,
            HealthState::NeedsAttention => Severity::Warning,
            HealthState::Problems => Severity::Critical,
        }
    }
}

/// Findings only: the all-clear card is not a finding.
pub fn findings(all: &[HealthInsight]) -> Vec<&HealthInsight> {
    let mut v: Vec<&HealthInsight> = all.iter().filter(|i| i.title != HEALTHY_TITLE).collect();
    v.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| impact(b).total_cmp(&impact(a)))
    });
    v
}

/// Leading number of the metric text ("1,204 errors" -> 1204, "98% of bytes" -> 98).
pub fn impact(i: &HealthInsight) -> f64 {
    let digits: String = i
        .metric
        .chars()
        .take_while(|c| c.is_ascii_digit() || matches!(c, ',' | '.' | ' '))
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    digits.parse().unwrap_or(0.0)
}

pub fn health_state(found: &[&HealthInsight]) -> HealthState {
    if found
        .iter()
        .any(|i| i.severity == InsightSeverity::Critical)
    {
        HealthState::Problems
    } else if found.iter().any(|i| i.severity == InsightSeverity::Warning) {
        HealthState::NeedsAttention
    } else {
        HealthState::Healthy
    }
}

pub fn count(found: &[&HealthInsight], sev: InsightSeverity) -> usize {
    found.iter().filter(|i| i.severity == sev).count()
}

/// Groups findings by category (fixed category order, empty groups dropped); order inside a
/// group is preserved (already severity then impact).
pub fn group<'a>(found: &[&'a HealthInsight]) -> Vec<(Category, Vec<&'a HealthInsight>)> {
    Category::ALL
        .into_iter()
        .filter_map(|c| {
            let items: Vec<_> = found
                .iter()
                .copied()
                .filter(|i| category_of(i) == c)
                .collect();
            (!items.is_empty()).then_some((c, items))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins(sev: InsightSeverity, title: &str, metric: &str, flt: Option<&str>) -> HealthInsight {
        HealthInsight {
            severity: sev,
            title: title.into(),
            explanation: String::new(),
            suggested_filter: flt.map(Into::into),
            metric: metric.into(),
        }
    }

    #[test]
    fn categorises_by_keywords() {
        let c = |t: &str, f: Option<&str>| category_of(&ins(InsightSeverity::Info, t, "", f));
        assert_eq!(c("DNS lookups are retrying", None), Category::Dns);
        assert_eq!(c("ICMP unreachable", None), Category::Icmp);
        assert_eq!(
            c("TCP packet loss", Some("tcp.analysis")),
            Category::TcpHealth
        );
        assert_eq!(
            c("Single dominant talker: 1.2.3.4", None),
            Category::TopTalkers
        );
        assert_eq!(c("Malformed frames", None), Category::Anomalies);
    }

    #[test]
    fn orders_by_severity_then_impact_and_hides_healthy_card() {
        let all = vec![
            ins(InsightSeverity::Warning, "a", "5 errors", Some("x")),
            ins(InsightSeverity::Critical, "b", "1 errors", Some("x")),
            ins(InsightSeverity::Warning, "c", "1,200 events", Some("x")),
            ins(InsightSeverity::Info, HEALTHY_TITLE, "10 pkts", None),
        ];
        let f = findings(&all);
        let titles: Vec<_> = f.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(titles, ["b", "c", "a"]);
    }

    #[test]
    fn health_state_follows_worst_severity() {
        let w = ins(InsightSeverity::Warning, "w", "", Some("f"));
        let c = ins(InsightSeverity::Critical, "c", "", Some("f"));
        let i = ins(InsightSeverity::Info, "i", "", Some("f"));
        assert_eq!(health_state(&[]), HealthState::Healthy);
        assert_eq!(health_state(&[&i]), HealthState::Healthy);
        assert_eq!(health_state(&[&i, &w]), HealthState::NeedsAttention);
        assert_eq!(health_state(&[&w, &c]), HealthState::Problems);
    }

    #[test]
    fn groups_use_fixed_order_and_drop_empty() {
        let a = ins(InsightSeverity::Warning, "ICMP errors", "20", Some("icmp"));
        let b = ins(InsightSeverity::Warning, "DNS failing", "9", Some("dns"));
        let g = group(&[&a, &b]);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].0, Category::Dns);
        assert_eq!(g[1].0, Category::Icmp);
    }

    #[test]
    fn impact_parses_leading_number() {
        let i = ins(InsightSeverity::Info, "t", "1,204 errors", None);
        assert_eq!(impact(&i), 1204.0);
        assert_eq!(impact(&ins(InsightSeverity::Info, "t", "n/a", None)), 0.0);
    }
}
