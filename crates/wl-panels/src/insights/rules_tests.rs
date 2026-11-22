use wl_model::InsightSeverity;

use super::*;

fn finding(title: &str) -> HealthInsight {
    HealthInsight {
        severity: InsightSeverity::Warning,
        title: title.into(),
        explanation: String::new(),
        suggested_filter: None,
        metric: String::new(),
    }
}

#[test]
fn defaults_are_the_historic_constants() {
    let t = Thresholds::default();
    assert_eq!((t.scan_min_ports, t.sweep_min_hosts), (20, 20));
    assert_eq!((t.beacon_min_events, t.beacon_max_jitter_pct), (8, 10));
    assert_eq!((t.dns_long_name, t.dns_long_label), (60, 40));
}

#[test]
fn clamping_keeps_every_value_usable() {
    let t = Thresholds {
        scan_min_ports: 0,
        sweep_min_hosts: 9_999,
        sweep_max_tries_per_host: 0,
        beacon_min_events: 0,
        beacon_min_period_secs: 0,
        beacon_max_jitter_pct: 400,
        dns_long_name: 5,
        dns_long_label: 100,
    }
    .clamped();
    assert_eq!(t.scan_min_ports, 2);
    assert_eq!(t.sweep_min_hosts, 1_000);
    assert_eq!(t.sweep_max_tries_per_host, 1);
    assert_eq!(t.beacon_min_events, 4);
    assert_eq!(t.beacon_min_period_secs, 1);
    assert_eq!(t.beacon_max_jitter_pct, 50);
    assert_eq!(t.dns_long_label, 63);
    assert!(t.dns_long_name >= t.dns_long_label);
}

#[test]
fn old_prefs_without_rules_load_with_defaults() {
    let r: InsightRules = serde_json::from_str("{}").unwrap();
    assert_eq!(r, InsightRules::default());
    let r: InsightRules = serde_json::from_str(r#"{"thresholds":{"scan_min_ports":5}}"#).unwrap();
    assert_eq!(r.thresholds.scan_min_ports, 5);
    assert_eq!(r.thresholds.sweep_min_hosts, 20);
}

#[test]
fn rules_round_trip_through_json() {
    let mut r = InsightRules::default();
    r.mute("10.0.0.9");
    r.reveal_secrets = true;
    r.thresholds.scan_min_ports = 7;
    let back: InsightRules = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
}

#[test]
fn muted_patterns_hide_matching_titles_case_insensitively() {
    let mut r = InsightRules::default();
    assert!(r.mute("  TCP port scan "));
    assert!(!r.mute("TCP port scan"));
    assert!(!r.mute("   "));
    assert!(r.hides(&finding("tcp Port Scan: 10.0.0.9 probes 10.0.0.1")));
    assert!(!r.hides(&finding("Host ping sweep from 10.0.0.7")));
    assert!(!InsightRules::default().hides(&finding("anything")));
}

#[test]
fn clamping_drops_blank_patterns() {
    let r = InsightRules {
        muted: vec!["a".into(), " ".into(), String::new()],
        ..InsightRules::default()
    };
    assert_eq!(r.clamped().muted, ["a"]);
}

#[test]
fn right_click_offers_hosts_kind_and_title() {
    let f = finding("Regular connections: 10.0.0.5 to 8.8.8.8:443 (TCP)");
    let got: Vec<_> = mute_choices(&f).into_iter().map(|c| c.pattern).collect();
    assert_eq!(
        got,
        ["10.0.0.5", "8.8.8.8", "Regular connections", &f.title]
    );
}

#[test]
fn right_click_on_a_plain_title_only_offers_the_title() {
    let f = finding("Unusually long DNS names");
    let got = mute_choices(&f);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].label, "Mute this finding");
}

#[test]
fn ipv6_hosts_are_recognised() {
    let f = finding("Host ping sweep from 2001:db8::7");
    assert_eq!(mute_choices(&f)[0].pattern, "2001:db8::7");
}

#[test]
fn muting_a_host_hides_findings_that_name_it() {
    let mut r = InsightRules::default();
    let f = finding("Regular connections: 10.0.0.5 to 8.8.8.8:443 (TCP)");
    r.mute(&mute_choices(&f)[0].pattern);
    assert!(r.hides(&f));
    assert!(!r.hides(&finding(
        "Regular connections: 10.0.0.6 to 8.8.8.8:443 (TCP)"
    )));
}

#[test]
fn a_muted_address_does_not_hide_longer_addresses() {
    let mut r = InsightRules::default();
    r.mute("10.0.0.5");
    assert!(!r.hides(&finding("TCP port scan: 10.0.0.50 probes 10.0.0.1")));
    assert!(r.hides(&finding("TCP port scan: 10.0.0.9 probes 10.0.0.5")));
}
