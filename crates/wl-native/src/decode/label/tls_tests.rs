use super::*;
use crate::test_util::{client_hello, handshake_message, server_hello, tls_record};

fn run(st: &mut Stream, dir: usize, payload: &[u8]) -> Option<Label> {
    label(payload, Some((st, dir)))
}

#[test]
fn client_hello_shows_the_server_name_and_the_hello_version() {
    let mut st = Stream::new(0);
    let hello = tls_record(
        22,
        0x0301,
        &client_hello(0x0303, "example.org", &[0x0304, 0x0303]),
    );
    let l = run(&mut st, 0, &hello).expect("tls");
    assert_eq!(
        (l.protocol, l.info.as_str()),
        ("TLSv1.2", "Client Hello (SNI=example.org)")
    );
    assert_eq!(st.tls, None);
}

#[test]
fn a_tls13_only_client_is_called_tls13() {
    let mut st = Stream::new(0);
    let hello = tls_record(22, 0x0301, &client_hello(0x0303, "h", &[0x0304]));
    assert_eq!(run(&mut st, 0, &hello).expect("tls").protocol, "TLSv1.3");
}

#[test]
fn server_hello_fixes_the_stream_version() {
    let mut st = Stream::new(0);
    let sh = tls_record(22, 0x0303, &server_hello(0x0303, Some(0x0304)));
    let l = run(&mut st, 1, &sh).expect("tls");
    assert_eq!((l.protocol, l.info.as_str()), ("TLSv1.3", "Server Hello"));
    assert_eq!(st.tls, Some(0x0304));
    let app = tls_record(23, 0x0303, &[0; 30]);
    assert_eq!(run(&mut st, 0, &app).expect("tls").protocol, "TLSv1.3");
}

#[test]
fn tls12_server_hello_without_the_extension_keeps_the_field() {
    let mut st = Stream::new(0);
    let sh = tls_record(22, 0x0303, &server_hello(0x0303, None));
    assert_eq!(run(&mut st, 1, &sh).expect("tls").protocol, "TLSv1.2");
    assert_eq!(st.tls, Some(0x0303));
}

#[test]
fn several_handshake_messages_in_one_record_are_listed() {
    let mut st = Stream::new(0);
    let mut body = server_hello(0x0303, None);
    body.extend(handshake_message(11, &[0; 5]));
    body.extend(handshake_message(12, &[]));
    body.extend(handshake_message(14, &[]));
    let l = run(&mut st, 1, &tls_record(22, 0x0303, &body)).expect("tls");
    assert_eq!(
        l.info,
        "Server Hello, Certificate, Server Key Exchange, Server Hello Done"
    );
}

#[test]
fn several_records_in_one_segment_are_listed_and_ccs_encrypts_what_follows() {
    let mut st = Stream::new(0);
    let mut seg = tls_record(22, 0x0303, &handshake_message(16, &[0; 10]));
    seg.extend(tls_record(20, 0x0303, &[1]));
    seg.extend(tls_record(22, 0x0303, &[0; 40]));
    let l = run(&mut st, 0, &seg).expect("tls");
    assert_eq!(
        l.info,
        "Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message"
    );
    let alert = tls_record(21, 0x0303, &[0; 26]);
    assert_eq!(
        run(&mut st, 0, &alert).expect("tls").info,
        "Encrypted Alert"
    );
    assert_eq!(run(&mut st, 1, &alert).expect("tls").info, "Alert");
}

#[test]
fn plain_alerts_name_level_and_description() {
    let mut st = Stream::new(0);
    let a = tls_record(21, 0x0303, &[2, 40]);
    assert_eq!(
        run(&mut st, 0, &a).expect("tls").info,
        "Alert (Level: Fatal, Description: Handshake Failure)"
    );
    let w = tls_record(21, 0x0303, &[1, 0]);
    assert_eq!(
        run(&mut st, 0, &w).expect("tls").info,
        "Alert (Level: Warning, Description: Close Notify)"
    );
}

#[test]
fn a_record_split_over_segments_is_tcp_until_its_last_segment() {
    let mut st = Stream::new(0);
    let rec = tls_record(23, 0x0303, &[7; 3000]);
    assert!(run(&mut st, 1, &rec[..1400]).is_none());
    assert_eq!(st.half[1].pending, 3005 - 1400);
    assert!(run(&mut st, 1, &rec[1400..2800]).is_none());
    let last = run(&mut st, 1, &rec[2800..]).expect("last segment");
    assert_eq!(
        (last.protocol, last.info.as_str()),
        ("TLSv1.2", "Application Data")
    );
    assert_eq!(st.half[1].pending, 0);
}

#[test]
fn the_last_segment_may_start_the_next_record() {
    let mut st = Stream::new(0);
    let rec = tls_record(23, 0x0303, &[7; 100]);
    assert!(run(&mut st, 0, &rec[..50]).is_none());
    let mut tail = rec[50..].to_vec();
    tail.extend(tls_record(23, 0x0303, &[1; 10]));
    assert_eq!(
        run(&mut st, 0, &tail).expect("tls").info,
        "Application Data, Application Data"
    );
}

#[test]
fn non_tls_payloads_are_not_labelled() {
    let mut st = Stream::new(0);
    for p in [
        &b"GET / HTTP/1.1"[..],
        &[0x17, 0x03, 0x05, 0, 1, 0][..],
        &[0x16, 0x03][..],
        &[][..],
        &[0x19, 3, 3, 0, 0][..],
    ] {
        assert!(run(&mut st, 0, p).is_none());
    }
}

#[test]
fn old_versions_have_their_names() {
    for (v, name) in [(0x0300, "SSLv3"), (0x0301, "TLSv1"), (0x0302, "TLSv1.1")] {
        let mut st = Stream::new(0);
        assert_eq!(
            run(&mut st, 0, &tls_record(23, v, &[0; 4]))
                .expect("tls")
                .protocol,
            name
        );
    }
}

#[test]
fn every_cut_of_a_hello_is_safe() {
    let hello = tls_record(22, 0x0301, &client_hello(0x0303, "example.org", &[0x0304]));
    for n in 0..hello.len() {
        let mut st = Stream::new(0);
        let _ = run(&mut st, 0, &hello[..n]);
    }
    let sh = tls_record(22, 0x0303, &server_hello(0x0303, Some(0x0304)));
    for n in 0..sh.len() {
        let mut st = Stream::new(0);
        let _ = run(&mut st, 1, &sh[..n]);
    }
}

#[test]
fn a_handshake_record_with_a_lying_length_is_handled() {
    let mut st = Stream::new(0);
    let l = run(
        &mut st,
        0,
        &tls_record(22, 0x0303, &[1, 0xff, 0xff, 0xff, 0, 0]),
    )
    .expect("tls");
    assert_eq!(l.info, "Client Hello");
}
