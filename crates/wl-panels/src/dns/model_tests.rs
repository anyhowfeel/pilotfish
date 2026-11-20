//! Unit tests for the DNS model (own file: 250-line limit).
use super::*;

pub fn q(frame: u64, name: &str, rc: Option<Rcode>, rtt: Option<f64>) -> DnsQuery {
    DnsQuery {
        frame,
        response_frame: rc.map(|_| frame + 1),
        rel: frame as f64,
        client: "10.0.0.2".into(),
        server: "10.0.0.1".into(),
        name: name.into(),
        qtype: "A".into(),
        rcode: rc,
        answers: vec!["1.2.3.4".into()],
        rtt_ms: rtt,
        retransmission: false,
    }
}

fn sample() -> Vec<DnsQuery> {
    vec![
        q(1, "b.test", Some(Rcode::NoError), Some(10.0)),
        q(3, "a.test", Some(Rcode::NxDomain), Some(30.0)),
        q(5, "a.test", Some(Rcode::ServFail), Some(200.0)),
        q(7, "c.test", None, None),
    ]
}

#[test]
fn stats_cover_rtt_and_top_names() {
    let s = aggregate(&sample());
    assert_eq!((s.total, s.unique_names), (4, 3));
    assert_eq!((s.nxdomain, s.failures, s.no_response), (1, 1, 1));
    assert!((s.nx_share() - 0.25).abs() < 1e-9);
    assert!((s.avg_ms.unwrap_or(0.0) - 80.0).abs() < 1e-9);
    assert_eq!(s.p95_ms, Some(200.0));
    assert_eq!(s.top[0], ("a.test".to_owned(), 2));
    assert_eq!(aggregate(&[]), DnsStats::default());
}

#[test]
fn filter_by_text_and_class() {
    let all = sample();
    let mut f = Filter {
        query: "A.TEST".into(),
        ..Default::default()
    };
    assert_eq!(
        build(&all, &f, SortState::new(SortCol::Time, false)),
        [1, 2]
    );
    f.query = "nxdomain".into();
    assert_eq!(build(&all, &f, SortState::new(SortCol::Time, false)), [1]);
    f.query.clear();
    f.classes = [false, true, true, true];
    assert_eq!(
        build(&all, &f, SortState::new(SortCol::Time, false)),
        [1, 2, 3]
    );
}

#[test]
fn sorts_with_unanswered_last_when_ascending() {
    let all = sample();
    let f = Filter::default();
    let asc = build(&all, &f, SortState::new(SortCol::Rtt, false));
    assert_eq!(asc, [0, 1, 2, 3]);
    let desc = build(&all, &f, SortState::new(SortCol::Name, true));
    assert_eq!(desc, [3, 0, 1, 2]);
}

#[test]
fn latency_text() {
    assert_eq!(ms_text(0.84), "0.8 ms");
    assert_eq!(ms_text(42.4), "42 ms");
    assert_eq!(ms_text(1500.0), "1.50 s");
}
