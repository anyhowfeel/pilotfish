//! Unit tests for plain-language Network Health diagnostic synthesis.

use wl_model::{
    ExpertEntry, ExpertReport, ExpertSeverity, HostStat, InsightSeverity, StatsSnapshot,
};

use crate::features::health::synthesize_insights;

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
    let insights = synthesize_insights(Some(&rep), None, None, &stats);
    assert!(
        insights
            .iter()
            .any(|i| i.severity == InsightSeverity::Critical)
    );
    assert!(insights.iter().any(|i| i.title.contains("retransmissions")));
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
    let insights = synthesize_insights(Some(&ExpertReport::default()), None, None, &stats);
    assert_eq!(insights.len(), 1);
    assert!(insights[0].title.contains("healthy"));
}
