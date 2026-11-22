use wl_model::DnsQuery;

use super::*;

fn chan(
    proto: Proto,
    kind: ChannelKind,
    dst: &str,
    dport: u16,
    count: u32,
    mean: f64,
    jitter: f64,
) -> Channel {
    Channel {
        src: "10.0.0.9".into(),
        dst: dst.into(),
        proto,
        kind,
        dport,
        count,
        gap_mean: mean,
        gap_jitter: jitter,
    }
}

fn flow(proto: Proto, dst: &str, dport: u16) -> Channel {
    chan(proto, ChannelKind::NewFlows, dst, dport, 1, 0.0, 0.0)
}

fn dns(name: &str) -> DnsQuery {
    DnsQuery {
        frame: 1,
        response_frame: None,
        rel: 0.0,
        client: "10.0.0.1".into(),
        server: "10.0.0.2".into(),
        name: name.into(),
        qtype: "A".into(),
        rcode: None,
        answers: Vec::new(),
        rtt_ms: None,
        retransmission: false,
    }
}

fn run(channels: Vec<Channel>, dns: Vec<DnsQuery>) -> Vec<HealthInsight> {
    let mut out = Vec::new();
    detect(
        &BehaviorData { channels, dns },
        &Thresholds::default(),
        &mut out,
    );
    out
}

fn many(n: u16, f: impl Fn(u16) -> Channel) -> Vec<Channel> {
    (1..=n).map(f).collect()
}

#[test]
fn many_ports_on_one_host_is_a_port_scan_for_tcp_and_udp() {
    let tcp = run(many(25, |p| flow(Proto::Tcp, "10.0.0.1", p)), Vec::new());
    assert_eq!(tcp.len(), 1);
    assert!(tcp[0].title.starts_with("TCP port scan"));
    assert!(
        tcp[0]
            .suggested_filter
            .as_deref()
            .unwrap()
            .contains("ip.dst == 10.0.0.1")
    );
    let udp = run(many(25, |p| flow(Proto::Udp, "10.0.0.1", p)), Vec::new());
    assert!(udp[0].title.starts_with("UDP port scan"));
}

#[test]
fn many_hosts_on_one_port_is_a_sweep() {
    let out = run(
        many(25, |h| flow(Proto::Tcp, &format!("10.0.1.{h}"), 22)),
        Vec::new(),
    );
    assert_eq!(out.len(), 1);
    assert!(out[0].title.contains("sweep on port 22"));
}

#[test]
fn icmp_echo_to_many_hosts_is_a_ping_sweep() {
    let out = run(
        many(25, |h| flow(Proto::Icmp, &format!("10.0.1.{h}"), 0)),
        Vec::new(),
    );
    assert_eq!(out.len(), 1);
    assert!(out[0].title.contains("ping sweep"));
    assert!(
        out[0]
            .suggested_filter
            .as_deref()
            .unwrap()
            .contains("icmp.type == 8")
    );
}

#[test]
fn browsing_many_hosts_on_https_is_not_a_sweep() {
    assert!(
        run(
            many(60, |h| flow(Proto::Tcp, &format!("10.0.1.{h}"), 443)),
            Vec::new()
        )
        .is_empty()
    );
}

#[test]
fn hosts_contacted_many_times_are_not_a_sweep() {
    let busy = many(25, |h| {
        chan(
            Proto::Tcp,
            ChannelKind::NewFlows,
            &format!("10.0.1.{h}"),
            22,
            50,
            0.5,
            0.9,
        )
    });
    assert!(run(busy, Vec::new()).is_empty());
}

#[test]
fn steady_period_is_flagged_but_jittery_and_fast_ones_are_not() {
    let steady = chan(
        Proto::Tcp,
        ChannelKind::NewFlows,
        "8.8.8.8",
        443,
        10,
        30.0,
        0.02,
    );
    let jittery = chan(
        Proto::Tcp,
        ChannelKind::NewFlows,
        "1.1.1.1",
        443,
        10,
        30.0,
        0.8,
    );
    let fast = chan(
        Proto::Tcp,
        ChannelKind::NewFlows,
        "9.9.9.9",
        443,
        20,
        0.2,
        0.01,
    );
    let few = chan(
        Proto::Tcp,
        ChannelKind::NewFlows,
        "4.4.4.4",
        443,
        3,
        30.0,
        0.0,
    );
    let out = run(vec![steady, jittery, fast, few], Vec::new());
    assert_eq!(out.len(), 1, "{out:#?}");
    assert!(out[0].title.contains("8.8.8.8:443"));
}

#[test]
fn rhythm_inside_one_long_connection_is_flagged_with_its_own_wording() {
    let c = chan(
        Proto::Tcp,
        ChannelKind::Stream,
        "8.8.8.8",
        443,
        12,
        60.0,
        0.01,
    );
    let out = run(vec![c], Vec::new());
    assert!(
        out[0]
            .title
            .starts_with("Regular traffic in one connection")
    );
    assert!(
        out[0]
            .suggested_filter
            .as_deref()
            .unwrap()
            .contains("tcp.len > 0")
    );
}

#[test]
fn icmp_rhythm_is_ordinary_ping_not_a_beacon() {
    let c = chan(
        Proto::Icmp,
        ChannelKind::NewFlows,
        "8.8.8.8",
        0,
        30,
        1.0,
        0.0,
    );
    assert!(run(vec![c], Vec::new()).is_empty());
}

#[test]
fn long_dns_names_scale_with_count() {
    let long = format!("{}.example.com", "a".repeat(45));
    let one = run(Vec::new(), vec![dns(&long), dns("ok.test")]);
    assert_eq!(one[0].severity, InsightSeverity::Info);
    let more = run(Vec::new(), vec![dns(&long); 6]);
    assert_eq!(more[0].severity, InsightSeverity::Warning);
    assert!(run(Vec::new(), vec![dns("www.example.com")]).is_empty());
}

#[path = "behavior_threshold_tests.rs"]
mod thresholds;
