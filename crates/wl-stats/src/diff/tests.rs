use std::sync::Arc;

use wl_model::{
    ConversationStat, DnsQuery, FlowKey, HostStat, HttpExchange, StatsSnapshot, TlsSession,
    Transport,
};

use super::{CaptureData, CaptureDiff, Micros, Presence, Traffic};

fn host(addr: &str, bytes: u64) -> HostStat {
    HostStat {
        addr: addr.into(),
        packets_in: 1,
        packets_out: 1,
        bytes_in: bytes / 2,
        bytes_out: bytes - bytes / 2,
        is_private: true,
    }
}

fn conv(a: &str, a_port: u16, b: &str, b_port: u16, bytes: u64) -> ConversationStat {
    ConversationStat {
        key: FlowKey {
            a: a.into(),
            b: b.into(),
            transport: Transport::Tcp,
            a_port: Some(a_port),
            b_port: Some(b_port),
        },
        packets: 2,
        bytes,
        first_rel: 0.0,
        last_rel: 1.0,
        protocol: "TCP".into(),
        server_port: None,
    }
}

fn http(host: &str, status: u16, ms: f64) -> HttpExchange {
    HttpExchange {
        id: 1,
        stream: None,
        req_frame: None,
        resp_frame: None,
        method: "GET".into(),
        host: host.into(),
        uri: "/".into(),
        version: "HTTP/1.1".into(),
        status: Some(status),
        reason: None,
        content_type: None,
        req_bytes: 0,
        resp_bytes: 0,
        start_rel: 0.0,
        time_ms: Some(ms),
    }
}

fn tls(name: &str) -> TlsSession {
    TlsSession {
        stream: None,
        first_frame: 1,
        start_rel: 0.0,
        start_epoch: None,
        server_name: name.into(),
        version: "TLS 1.3".into(),
        cipher: None,
        alpn: None,
        cert_subject: None,
        ja3: None,
        ja4: None,
        ja3s: None,
        src: "10.0.0.1".into(),
        dst: "10.0.0.9".into(),
        bytes: 0,
        certs: Vec::new(),
        client: None,
        threat: None,
    }
}

fn dns(name: &str, rtt_ms: f64) -> DnsQuery {
    DnsQuery {
        frame: 1,
        response_frame: None,
        rel: 0.0,
        client: "10.0.0.1".into(),
        server: "10.0.0.53".into(),
        name: name.into(),
        qtype: "A".into(),
        rcode: None,
        answers: Vec::new(),
        rtt_ms: Some(rtt_ms),
        retransmission: false,
    }
}

fn data(hosts: Vec<HostStat>, convs: Vec<ConversationStat>) -> CaptureData {
    CaptureData {
        stats: Arc::new(StatsSnapshot {
            total_packets: 10,
            total_bytes: hosts.iter().map(|h| h.bytes_in + h.bytes_out).sum(),
            hosts,
            conversations: convs,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn identical_captures_have_no_difference() {
    let d = data(vec![host("10.0.0.1", 100)], vec![conv("a", 1, "b", 80, 50)]);
    assert!(CaptureDiff::compute(&d, &d).is_empty());
}

#[test]
fn hosts_are_added_removed_and_changed() {
    let before = data(vec![host("1.1.1.1", 100), host("2.2.2.2", 100)], vec![]);
    let after = data(vec![host("2.2.2.2", 400), host("3.3.3.3", 50)], vec![]);
    let diff = CaptureDiff::compute(&before, &after);
    let kinds: Vec<_> = diff
        .hosts
        .iter()
        .map(|r| (&*r.label, r.presence()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("2.2.2.2", Presence::Changed),
            ("1.1.1.1", Presence::Removed),
            ("3.3.3.3", Presence::Added),
        ]
    );
    assert_eq!(
        diff.hosts[0].after,
        Some(Traffic {
            packets: 2,
            bytes: 400
        })
    );
}

#[test]
fn services_ignore_the_ephemeral_client_port() {
    let before = data(vec![], vec![conv("10.0.0.1", 50001, "10.0.0.9", 443, 500)]);
    let after = data(vec![], vec![conv("10.0.0.1", 50777, "10.0.0.9", 443, 900)]);
    let diff = CaptureDiff::compute(&before, &after);
    assert_eq!(diff.services.len(), 1);
    assert_eq!(diff.services[0].presence(), Presence::Changed);
    assert!(diff.services[0].label.ends_with("TCP/443"));
}

#[test]
fn latency_tolerates_jitter_but_not_a_real_shift() {
    let mut before = CaptureData::default();
    let mut after = CaptureData::default();
    before.http = vec![http("steady", 200, 100.0), http("slow", 200, 100.0)];
    after.http = vec![http("steady", 200, 105.0), http("slow", 200, 300.0)];
    before.dns = vec![dns("a.test", 4.0)];
    let diff = CaptureDiff::compute(&before, &after);
    let rows: Vec<_> = diff
        .latency
        .iter()
        .map(|r| (&*r.label, r.presence()))
        .collect();
    assert_eq!(
        rows,
        [
            ("HTTP slow", Presence::Changed),
            ("DNS a.test", Presence::Removed)
        ]
    );
    assert_eq!(diff.latency[0].after, Some(Micros(300_000)));
}

#[test]
fn web_names_and_status_codes_are_compared() {
    let mut before = CaptureData::default();
    let mut after = CaptureData::default();
    before.http = vec![http("old.test", 200, 1.0), http("both.test", 200, 1.0)];
    after.http = vec![http("both.test", 404, 1.0), http("new.test", 200, 1.0)];
    before.tls = vec![tls("gone.test")];
    after.tls = vec![tls("fresh.test")];
    let diff = CaptureDiff::compute(&before, &after);
    let hosts: Vec<_> = diff
        .http_hosts
        .iter()
        .map(|r| (&*r.label, r.presence()))
        .collect();
    assert_eq!(
        hosts,
        [
            ("new.test", Presence::Added),
            ("old.test", Presence::Removed)
        ]
    );
    let statuses: Vec<_> = diff
        .statuses
        .iter()
        .map(|r| (&*r.label, r.presence()))
        .collect();
    assert_eq!(
        statuses,
        [("200", Presence::Changed), ("404", Presence::Added)]
    );
    assert_eq!(diff.tls_names.len(), 2);
}

#[test]
fn service_side_comes_from_the_handshake_not_the_port_order() {
    let mut c = conv("10.0.0.1", 40001, "10.0.0.9", 50051, 500);
    c.server_port = Some(50051);
    let before = data(vec![], vec![c.clone()]);
    c.key.a_port = Some(40002);
    let after = data(vec![], vec![c]);
    let diff = CaptureDiff::compute(&before, &after);
    assert!(diff.services.is_empty());
}

#[test]
fn unanswered_requests_status_swaps_and_dns_changes_are_listed() {
    let unanswered = |uri: &str| {
        let mut e = http("h.test", 200, 1.0);
        e.uri = uri.into();
        e.status = None;
        e.time_ms = None;
        e
    };
    let mut ok = http("h.test", 200, 1.0);
    ok.uri = "/a".into();
    let mut bad = ok.clone();
    bad.status = Some(500);
    let mut before = CaptureData::default();
    let mut after = CaptureData::default();
    before.http = vec![ok];
    after.http = vec![bad, unanswered("/b")];
    let mut q = dns("a.test", 1.0);
    q.rcode = Some(wl_model::Rcode::NoError);
    q.answers = vec!["1.1.1.1".into()];
    let mut q2 = q.clone();
    q2.rcode = Some(wl_model::Rcode::NxDomain);
    q2.answers = vec!["2.2.2.2".into()];
    before.dns = vec![q];
    after.dns = vec![q2];
    let diff = CaptureDiff::compute(&before, &after);
    let one = |rows: &[super::Row<u64>]| {
        assert_eq!(rows.len(), 1);
        (rows[0].label.clone(), rows[0].before, rows[0].after)
    };
    assert_eq!(one(&diff.unanswered).0, "GET h.test/b");
    assert_eq!(
        one(&diff.url_statuses),
        ("GET h.test/a".into(), Some(200), Some(500))
    );
    assert_eq!(one(&diff.dns_rcodes), ("a.test A".into(), Some(1), Some(4)));
    assert_eq!(diff.dns_answers.len(), 2);
}
