//! Unit tests (kept in their own file to respect the 250-line limit).
use super::*;

fn line(cols: &[(usize, &str)]) -> String {
    let mut v = vec![""; FIELDS.len()];
    for (i, s) in cols {
        v[*i] = s;
    }
    v.join("\t")
}

#[test]
fn pairs_query_and_response() {
    let mut b = Builder::default();
    b.push(&line(&[
        (0, "1"),
        (1, "0.5"),
        (2, "10.0.0.2"),
        (4, "10.0.0.1"),
        (6, "False"),
        (8, "example.com"),
        (9, "1"),
    ]));
    b.push(&line(&[
        (0, "2"),
        (1, "0.52"),
        (2, "10.0.0.1"),
        (4, "10.0.0.2"),
        (6, "True"),
        (7, "0"),
        (8, "example.com"),
        (9, "1"),
        (10, "1"),
        (11, "0.020"),
        (13, "1.2.3.4,5.6.7.8"),
    ]));
    assert_eq!(b.out.len(), 1);
    let q = &b.out[0];
    assert_eq!((q.frame, q.response_frame), (1, Some(2)));
    assert_eq!(q.client, "10.0.0.2");
    assert_eq!(q.rcode, Some(Rcode::NoError));
    assert_eq!(q.answers, ["1.2.3.4", "5.6.7.8"]);
    assert!((q.rtt_ms.unwrap_or(0.0) - 20.0).abs() < 1e-9);
    assert_eq!(q.qtype, "A");
}

#[test]
fn retransmission_folds_and_unanswered_stays_open() {
    let mut b = Builder::default();
    b.push(&line(&[(0, "1"), (6, "False"), (8, "a.test"), (9, "28")]));
    b.push(&line(&[
        (0, "5"),
        (6, "False"),
        (8, "a.test"),
        (9, "28"),
        (17, "True"),
        (18, "1"),
    ]));
    b.push(&line(&[
        (0, "6"),
        (6, "True"),
        (7, "3"),
        (10, "5"),
        (11, "0.001"),
    ]));
    assert_eq!(b.out.len(), 1);
    assert!(b.out[0].retransmission);
    assert_eq!(b.out[0].rcode, Some(Rcode::NxDomain));
    assert_eq!(b.out[0].qtype, "AAAA");
    b.push(&line(&[(0, "9"), (6, "False"), (8, "b.test"), (9, "99")]));
    assert_eq!(b.out[1].rcode, None);
    assert_eq!(b.out[1].qtype, "99");
}

#[test]
fn orphan_response_gets_a_row() {
    let mut b = Builder::default();
    b.push(&line(&[
        (0, "7"),
        (1, "1.0"),
        (2, "10.0.0.1"),
        (4, "10.0.0.2"),
        (6, "True"),
        (7, "2"),
        (10, "3"),
        (11, "0.5"),
    ]));
    assert_eq!(b.out[0].client, "10.0.0.2");
    assert_eq!(b.out[0].rcode, Some(Rcode::ServFail));
    assert!((b.out[0].rel - 0.5).abs() < 1e-9);
}
