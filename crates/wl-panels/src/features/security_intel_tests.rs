use super::*;

fn intel() -> ThreatIntel {
    let mut i = ThreatIntel::default();
    i.add_blocklist(
        "feodo",
        "198.51.100.7\nbad.example.net\ne7d705a3286e19ea42f587b344ee6865\n",
    );
    i.add_ja4db(
        r#"[{"application":"Chrome","ja4_fingerprint":"t13d1516h2_8daaf6152771_02713d6af862"}]"#,
    )
    .unwrap();
    i
}

#[test]
fn blocklisted_hosts_are_ranked_by_traffic() {
    let mut i = intel();
    i.add_blocklist("other", "203.0.113.5");
    let hosts = [
        host("203.0.113.5", 5),
        host("198.51.100.7", 90),
        host("8.8.8.8", 1000),
    ];
    let out = run(None, &i, &hosts, &[], false);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].title, "Blocklisted address: 198.51.100.7 (feodo)");
    assert_eq!(
        out[0].suggested_filter.as_deref(),
        Some("ip.addr == 198.51.100.7")
    );
    assert_eq!(out[0].severity, InsightSeverity::Critical);
}

#[test]
fn domains_from_dns_and_tls_are_reported_once() {
    let sec = SecurityData {
        credentials: Vec::new(),
        tls: vec![
            tls("c2.bad.example.net", "x", "y"),
            tls("good.example.com", "x", "y"),
        ],
    };
    let names = [dns("c2.bad.example.net"), dns("www.good.example.com")];
    let out = run(Some(&sec), &intel(), &[], &names, false);
    let domain: Vec<_> = out
        .iter()
        .filter(|f| f.title.starts_with("Blocklisted domain"))
        .collect();
    assert_eq!(domain.len(), 1);
    assert_eq!(
        domain[0].title,
        "Blocklisted domain: c2.bad.example.net (feodo)"
    );
}

#[test]
fn bad_fingerprints_and_known_clients() {
    let sec = SecurityData {
        credentials: Vec::new(),
        tls: vec![
            tls(
                "a.example.com",
                "e7d705a3286e19ea42f587b344ee6865",
                "t13d0000h2_000000000000_000000000000",
            ),
            tls(
                "b.example.com",
                "e7d705a3286e19ea42f587b344ee6865",
                "t13d1516h2_8daaf6152771_02713d6af862",
            ),
        ],
    };
    let out = run(Some(&sec), &intel(), &[], &[], false);
    let bad = out
        .iter()
        .find(|f| f.title.starts_with("Malicious TLS"))
        .unwrap();
    assert_eq!(bad.metric, "2 sessions");
    assert_eq!(
        bad.suggested_filter.as_deref(),
        Some("tls.handshake.ja3 == \"e7d705a3286e19ea42f587b344ee6865\"")
    );
    let known = out.iter().find(|f| f.title.contains("JA4DB")).unwrap();
    assert_eq!(known.severity, InsightSeverity::Info);
    assert!(known.explanation.contains("Chrome (1)"));
}

#[test]
fn empty_intel_and_no_scan_yield_nothing() {
    let hosts = [host("198.51.100.7", 5)];
    assert!(
        run(
            None,
            &ThreatIntel::default(),
            &hosts,
            &[dns("bad.example.net")],
            false
        )
        .is_empty()
    );
}

#[test]
fn synthesis_includes_security_cards_and_honours_mutes() {
    let sec = SecurityData {
        credentials: vec![cred(
            CredKind::HttpBasic,
            3,
            Some("alice"),
            Some("s3cretPass"),
        )],
        tls: Vec::new(),
    };
    let stats = StatsSnapshot {
        total_packets: 10,
        hosts: vec![host("198.51.100.7", 10)],
        ..Default::default()
    };
    let behavior = BehaviorData {
        channels: Vec::new(),
        dns: vec![dns("bad.example.net")],
    };
    let i = intel();
    let titles = |rules: &InsightRules| -> Vec<String> {
        let cx = InsightContext {
            security: Some(&sec),
            intel: &i,
            rules,
        };
        synthesize_insights(None, None, Some(&behavior), &stats, &cx)
            .into_iter()
            .map(|f| f.title)
            .collect()
    };
    let mut rules = InsightRules::default();
    let all = titles(&rules);
    assert_eq!(all.len(), 3, "{all:?}");
    rules.mute("10.0.0.80");
    rules.mute("Blocklisted domain");
    assert_eq!(
        titles(&rules),
        [
            "Blocklisted address: 198.51.100.7 (feodo)",
            "2 findings hidden by mutes"
        ]
    );
}
