use super::*;

fn line(cols: &[(usize, &str)]) -> String {
    let mut v = vec![""; FIELDS.len()];
    for &(i, s) in cols {
        v[i] = s;
    }
    v.join("\t")
}

fn syn(t: &str, src: &str, dst: &str, port: &str) -> String {
    line(&[
        (0, t),
        (1, src),
        (3, dst),
        (5, "True"),
        (6, "False"),
        (8, port),
        (9, "0"),
    ])
}

fn find(v: &[Channel], kind: ChannelKind, port: u16) -> &Channel {
    v.iter()
        .find(|c| c.kind == kind && c.dport == port)
        .expect("channel")
}

#[test]
fn syns_group_by_target_and_measure_the_rhythm() {
    let mut r = Reducer::default();
    for i in 0..5 {
        r.push_line(&syn(&format!("{}", i * 10), "10.0.0.1", "10.0.0.2", "443"));
    }
    r.push_line(&syn("1", "10.0.0.1", "10.0.0.2", "22"));
    let v = r.finish();
    let c = find(&v, ChannelKind::NewFlows, 443);
    assert_eq!((c.count, c.gap_mean, c.gap_jitter), (5, 10.0, 0.0));
    assert_eq!(find(&v, ChannelKind::NewFlows, 22).count, 1);
}

#[test]
fn jitter_reflects_irregular_gaps() {
    let mut r = Reducer::default();
    for t in ["0", "1", "10", "11", "30"] {
        r.push_line(&syn(t, "a", "b", "80"));
    }
    let v = r.finish();
    assert!(find(&v, ChannelKind::NewFlows, 80).gap_jitter > 0.5);
}

#[test]
fn udp_counts_one_event_per_flow() {
    let mut r = Reducer::default();
    for (t, stream) in [("0", "1"), ("0.1", "1"), ("5", "2")] {
        r.push_line(&line(&[
            (0, t),
            (1, "10.0.0.1"),
            (3, "10.0.0.9"),
            (10, "53"),
            (11, stream),
        ]));
    }
    let v = r.finish();
    let c = find(&v, ChannelKind::NewFlows, 53);
    assert_eq!((c.proto, c.count), (Proto::Udp, 2));
}

#[test]
fn icmp_echo_counts_but_icmp_errors_embedding_tcp_do_not() {
    let mut r = Reducer::default();
    r.push_line(&line(&[(0, "1"), (1, "a"), (3, "b"), (12, "8")]));
    r.push_line(&line(&[
        (0, "2"),
        (1, "b"),
        (3, "a"),
        (12, "3"),
        (5, "True"),
        (6, "False"),
        (8, "80"),
        (9, "0"),
    ]));
    let v = r.finish();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].proto, Proto::Icmp);
}

#[test]
fn stream_payload_is_tracked_per_connection_and_short_ones_dropped() {
    let mut r = Reducer::default();
    for i in 0..6 {
        r.push_line(&line(&[
            (0, &format!("{}", i * 30)),
            (1, "a"),
            (3, "b"),
            (5, "False"),
            (6, "True"),
            (7, "40"),
            (8, "443"),
            (9, "7"),
        ]));
    }
    r.push_line(&line(&[
        (0, "1"),
        (1, "c"),
        (3, "d"),
        (7, "10"),
        (8, "80"),
        (9, "8"),
    ]));
    let v = r.finish();
    assert_eq!(v.len(), 1);
    assert_eq!(
        (v[0].kind, v[0].count, v[0].gap_mean),
        (ChannelKind::Stream, 6, 30.0)
    );
}
