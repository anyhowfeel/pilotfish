//! Pure insight logic: category inference, ordering, grouping, health state. No egui.
use wl_kit::widgets::Severity;
use wl_model::{Analyses, HealthInsight, InsightSeverity, Wireshark};

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

/// What the Findings tab shows. Every finding comes from an analysis, so the page says the capture
/// is clean only when all of them ran and found nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    NeedsWireshark,
    NoCapture,
    /// No analysis was started for this capture, for example while a live capture runs.
    NotRun,
    Analysing,
    Failed,
    AllClear,
    Findings,
}

pub fn view(
    wireshark: Wireshark,
    total_packets: u64,
    findings: usize,
    analyses: &Analyses,
) -> View {
    if wireshark.is_missing() {
        View::NeedsWireshark
    } else if findings > 0 {
        View::Findings
    } else if total_packets == 0 {
        View::NoCapture
    } else if !analyses.failures().is_empty() {
        View::Failed
    } else if analyses.any_pending() {
        View::Analysing
    } else if analyses.complete() {
        View::AllClear
    } else {
        View::NotRun
    }
}

/// The word and dot of the summary strip. "Healthy" needs every analysis to have finished.
pub fn strip(state: HealthState, analyses: &Analyses) -> (&'static str, Severity) {
    if analyses.any_pending() {
        ("Analysing...", state.severity())
    } else if state != HealthState::Healthy {
        (state.label(), state.severity())
    } else if !analyses.failures().is_empty() {
        ("Analysis incomplete", Severity::Warning)
    } else if !analyses.complete() {
        ("Not analysed", Severity::Info)
    } else {
        (state.label(), state.severity())
    }
}

/// What went wrong, in one sentence that also says what to do.
pub fn failure_text(analyses: &Analyses) -> String {
    let parts: Vec<String> = analyses
        .failures()
        .into_iter()
        .map(|(what, reason)| format!("{what}: {}", reason.trim_end_matches('.')))
        .collect();
    format!("{}. Use Re-analyse to try again.", parts.join("; "))
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

    use wl_model::{Analysis, BehaviorData, ExpertReport, ProtocolHierarchy, SecurityData};

    fn finished() -> Analyses {
        Analyses {
            expert: Analysis::Ready(ExpertReport::default()),
            hierarchy: Analysis::Ready(ProtocolHierarchy::default()),
            behavior: Analysis::Ready(BehaviorData::default()),
            security: Analysis::Ready(SecurityData::default()),
        }
    }

    fn with(edit: impl Fn(&mut Analyses)) -> Analyses {
        let mut a = finished();
        edit(&mut a);
        a
    }

    #[test]
    fn no_wireshark_never_reads_as_all_clear() {
        for (packets, found) in [(0, 0), (1523, 0), (1523, 3)] {
            for analyses in [Analyses::default(), finished()] {
                assert_eq!(
                    view(Wireshark::Missing, packets, found, &analyses),
                    View::NeedsWireshark
                );
            }
        }
    }

    #[test]
    fn with_wireshark_the_states_follow_the_data() {
        let a = Wireshark::Available;
        assert_eq!(view(a, 0, 0, &finished()), View::NoCapture);
        assert_eq!(view(a, 1523, 0, &finished()), View::AllClear);
        assert_eq!(view(a, 1523, 3, &finished()), View::Findings);
    }

    #[test]
    fn the_all_clear_needs_every_analysis_to_have_finished() {
        let a = Wireshark::Available;
        type Edit = fn(&mut Analyses);
        let cases: [(Edit, View); 8] = [
            (|x| x.expert = Analysis::Pending, View::Analysing),
            (|x| x.hierarchy = Analysis::Pending, View::Analysing),
            (|x| x.behavior = Analysis::Pending, View::Analysing),
            (|x| x.security = Analysis::Pending, View::Analysing),
            (|x| x.expert = Analysis::Idle, View::NotRun),
            (|x| x.security = Analysis::Idle, View::NotRun),
            (|x| x.expert = Analysis::Failed("boom".into()), View::Failed),
            (
                |x| x.behavior = Analysis::Failed("boom".into()),
                View::Failed,
            ),
        ];
        for (edit, expected) in cases {
            assert_eq!(view(a, 1523, 0, &with(edit)), expected);
        }
    }

    #[test]
    fn a_failure_wins_over_an_analysis_still_running() {
        let analyses = with(|x| {
            x.expert = Analysis::Failed("boom".into());
            x.behavior = Analysis::Pending;
        });
        assert_eq!(view(Wireshark::Available, 10, 0, &analyses), View::Failed);
    }

    #[test]
    fn findings_are_shown_even_when_another_analysis_failed() {
        let analyses = with(|x| x.expert = Analysis::Failed("boom".into()));
        assert_eq!(view(Wireshark::Available, 10, 2, &analyses), View::Findings);
    }

    #[test]
    fn nothing_analysed_in_an_empty_capture_is_no_capture() {
        assert_eq!(
            view(Wireshark::Available, 0, 0, &Analyses::default()),
            View::NoCapture
        );
    }

    #[test]
    fn a_fresh_capture_is_not_run_until_something_starts_it() {
        let a = Wireshark::Available;
        assert_eq!(view(a, 10, 0, &Analyses::default()), View::NotRun);
        let mut started = Analyses::default();
        started.start();
        assert_eq!(view(a, 10, 0, &started), View::Analysing);
    }

    #[test]
    fn the_strip_says_healthy_only_after_every_analysis_ran() {
        let healthy = HealthState::Healthy;
        assert_eq!(strip(healthy, &finished()), ("Healthy", Severity::Ok));
        assert_eq!(
            strip(
                healthy,
                &with(|x| x.security = Analysis::Failed("x".into()))
            ),
            ("Analysis incomplete", Severity::Warning)
        );
        assert_eq!(
            strip(healthy, &with(|x| x.expert = Analysis::Idle)),
            ("Not analysed", Severity::Info)
        );
        assert_eq!(
            strip(healthy, &with(|x| x.behavior = Analysis::Pending)),
            ("Analysing...", Severity::Ok)
        );
    }

    #[test]
    fn real_findings_keep_their_state_in_the_strip_whatever_failed() {
        let analyses = with(|x| x.expert = Analysis::Failed("x".into()));
        assert_eq!(
            strip(HealthState::Problems, &analyses),
            ("Problems found", Severity::Critical)
        );
    }

    #[test]
    fn the_failure_text_names_each_failed_analysis_and_the_way_out() {
        let analyses = with(|x| {
            x.expert = Analysis::Failed("tshark exited with status 2.".into());
            x.security = Analysis::Failed("no such file".into());
        });
        assert_eq!(
            failure_text(&analyses),
            "Expert info: tshark exited with status 2; Credential scan: no such file. \
             Use Re-analyse to try again."
        );
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
