//! Unit tests for plain-language Network Health diagnostic synthesis.

use wl_model::{
    ExpertEntry, ExpertReport, ExpertSeverity, HostStat, InsightSeverity, StatsSnapshot,
};

use crate::features::health::{InsightContext, synthesize_insights};
use crate::test_util::plain;

fn entry(severity: ExpertSeverity, frequency: u64, protocol: &str, summary: &str) -> ExpertEntry {
    ExpertEntry {
        severity,
        frequency,
        group: "Proto".into(),
        protocol: protocol.into(),
        summary: summary.into(),
    }
}

#[test]
fn flags_retransmissions_dns_errors_and_dominant_talker() {
    let rep = ExpertReport {
        entries: vec![
            entry(ExpertSeverity::Error, 2, "HTTP", "Malformed Packet"),
            entry(ExpertSeverity::Warn, 5, "TCP", "TCP Retransmission"),
            entry(ExpertSeverity::Warn, 4, "mDNS", "DNS query retransmission"),
            entry(
                ExpertSeverity::Note,
                20,
                "ICMPv6",
                "Type indicates an error",
            ),
        ],
    };
    let stats = StatsSnapshot {
        total_packets: 100,
        total_bytes: 10_000,
        hosts: vec![HostStat {
            addr: "10.0.0.5".into(),
            bytes_in: 8_000,
            bytes_out: 1_000,
            ..Default::default()
        }],
        ..Default::default()
    };
    let insights = synthesize_insights(Some(&rep), None, None, &stats, &plain());
    assert!(
        insights
            .iter()
            .any(|i| i.severity == InsightSeverity::Critical)
    );
    assert!(insights.iter().any(|i| i.title.contains("retransmissions")));
    assert!(
        insights
            .iter()
            .filter_map(|i| i.suggested_filter.as_deref())
            .any(|f| f.contains("tcp.analysis.duplicate_ack"))
    );
    assert!(insights.iter().any(|i| i.title.contains("DNS")));
    assert!(insights.iter().any(|i| i.title.contains("ICMP")));
    assert!(insights.iter().any(|i| i.title.contains("10.0.0.5")));
}

#[test]
fn healthy_capture_produces_all_clear_card() {
    let stats = StatsSnapshot {
        total_packets: 50,
        total_bytes: 2048,
        ..Default::default()
    };
    let insights =
        synthesize_insights(Some(&ExpertReport::default()), None, None, &stats, &plain());
    assert_eq!(insights.len(), 1);
    assert!(insights[0].title.contains("healthy"));
}

fn retrans_stats() -> (ExpertReport, StatsSnapshot) {
    let rep = ExpertReport {
        entries: vec![entry(ExpertSeverity::Warn, 5, "TCP", "TCP Retransmission")],
    };
    let stats = StatsSnapshot {
        total_packets: 100,
        total_bytes: 10_000,
        ..Default::default()
    };
    (rep, stats)
}

#[test]
fn muted_findings_are_counted_and_never_reported_as_healthy() {
    let (rep, stats) = retrans_stats();
    let intel = wl_model::ThreatIntel::default();
    let titles = |rules: &crate::insights::InsightRules| {
        let cx = InsightContext {
            security: None,
            intel: &intel,
            rules,
            wireshark: Default::default(),
        };
        synthesize_insights(Some(&rep), None, None, &stats, &cx)
            .into_iter()
            .map(|f| f.title)
            .collect::<Vec<_>>()
    };
    let mut rules = crate::insights::InsightRules::default();
    assert!(titles(&rules)[0].contains("TCP packet loss"));
    rules.mute("packet loss");
    rules.mute("anomaly rate");
    let after = titles(&rules);
    assert_eq!(after, ["2 findings hidden by mutes"]);
}
