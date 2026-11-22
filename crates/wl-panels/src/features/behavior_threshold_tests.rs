use super::*;

fn run_with(th: Thresholds, channels: Vec<Channel>, dns: Vec<DnsQuery>) -> Vec<HealthInsight> {
    let mut out = Vec::new();
    detect(&BehaviorData { channels, dns }, &th, &mut out);
    out
}

#[test]
fn lower_port_threshold_flags_smaller_scans() {
    let ports = many(8, |p| flow(Proto::Tcp, "10.0.0.1", p));
    assert!(run(ports.clone(), Vec::new()).is_empty());
    let th = Thresholds {
        scan_min_ports: 5,
        ..Thresholds::default()
    };
    assert_eq!(run_with(th, ports, Vec::new()).len(), 1);
}

#[test]
fn higher_host_threshold_silences_a_sweep() {
    let hosts = many(25, |h| flow(Proto::Tcp, &format!("10.0.1.{h}"), 22));
    let th = Thresholds {
        sweep_min_hosts: 40,
        ..Thresholds::default()
    };
    assert!(run_with(th, hosts, Vec::new()).is_empty());
}

#[test]
fn beacon_thresholds_apply_to_events_period_and_jitter() {
    let c = |count, mean, jitter| {
        chan(
            Proto::Tcp,
            ChannelKind::NewFlows,
            "8.8.8.8",
            443,
            count,
            mean,
            jitter,
        )
    };
    let flagged = |th: Thresholds, ch: Channel| run_with(th, vec![ch], Vec::new()).len();
    let base = Thresholds::default();
    assert_eq!(flagged(base.clone(), c(6, 30.0, 0.02)), 0);
    let few = Thresholds {
        beacon_min_events: 5,
        ..base.clone()
    };
    assert_eq!(flagged(few, c(6, 30.0, 0.02)), 1);
    let slow_only = Thresholds {
        beacon_min_period_secs: 60,
        ..base.clone()
    };
    assert_eq!(flagged(slow_only, c(10, 30.0, 0.02)), 0);
    let loose = Thresholds {
        beacon_max_jitter_pct: 40,
        ..base
    };
    assert_eq!(flagged(loose, c(10, 30.0, 0.3)), 1);
}

#[test]
fn dns_length_thresholds_are_applied_and_quoted() {
    let name = format!("{}.example.com", "a".repeat(25));
    assert!(run(Vec::new(), vec![dns(&name)]).is_empty());
    let th = Thresholds {
        dns_long_label: 20,
        dns_long_name: 30,
        ..Thresholds::default()
    };
    let out = run_with(th, Vec::new(), vec![dns(&name)]);
    assert_eq!(out.len(), 1);
    assert!(out[0].explanation.contains("30+ characters"));
    assert_eq!(
        out[0].suggested_filter.as_deref(),
        Some("dns.qry.name.len >= 30")
    );
}
