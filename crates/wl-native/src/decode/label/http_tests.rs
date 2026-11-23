use super::*;

fn msg(o: Outcome) -> Label {
    match o {
        Outcome::Message(l) => l,
        _ => panic!("not a whole message"),
    }
}

#[test]
fn requests_and_responses_are_recognised_by_their_first_line() {
    let mut st = Stream::new(0);
    for (payload, info) in [
        (
            &b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            "GET /a HTTP/1.1 ",
        ),
        (
            b"POST /f HTTP/1.1\r\nContent-Length: 2\r\n\r\nab",
            "POST /f HTTP/1.1 ",
        ),
        (b"HEAD / HTTP/1.0\r\n\r\n", "HEAD / HTTP/1.0 "),
        (
            b"HTTP/1.1 304 Not Modified\r\n\r\n",
            "HTTP/1.1 304 Not Modified ",
        ),
    ] {
        let l = msg(label(payload, &mut st, 0));
        assert_eq!((l.protocol, l.info.as_str()), ("HTTP", info));
    }
}

#[test]
fn other_text_is_not_http() {
    let mut st = Stream::new(0);
    for p in [
        &b"GETTING / HTTP/1.1\r\n"[..],
        b"GET /only-a-path\r\n\r\n",
        b"hello",
        b"",
        b"\xff\xfe",
    ] {
        assert!(matches!(label(p, &mut st, 0), Outcome::NotHttp), "{p:?}");
    }
}

#[test]
fn a_cut_request_line_is_still_a_request() {
    let mut st = Stream::new(0);
    assert!(matches!(
        label(b"GET /very/long/pa", &mut st, 0),
        Outcome::Message(_)
    ));
}

#[test]
fn a_body_longer_than_its_segment_is_followed_to_its_end() {
    let mut st = Stream::new(0);
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
    let mut first = head.to_vec();
    first.extend_from_slice(&[b'x'; 30]);
    let Outcome::Partial(info) = label(&first, &mut st, 1) else {
        panic!("not partial");
    };
    assert_eq!(info, "HTTP/1.1 200 OK ");
    assert!(matches!(label(&[0; 40], &mut st, 1), Outcome::Body));
    let l = msg(label(&[0; 30], &mut st, 1));
    assert_eq!(l.info, "HTTP/1.1 200 OK ");
    assert_eq!(st.half[1].pending, 0);
}

#[test]
fn headers_without_a_body_that_fits_are_whole() {
    let mut st = Stream::new(0);
    let m = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    assert!(matches!(label(m, &mut st, 0), Outcome::Message(_)));
    let m = b"HTTP/1.1 204 No Content\r\n\r\n";
    assert!(matches!(label(m, &mut st, 0), Outcome::Message(_)));
}

#[test]
fn chunked_bodies_end_at_the_zero_chunk() {
    let mut st = Stream::new(0);
    let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n";
    assert!(matches!(label(head, &mut st, 1), Outcome::Partial(_)));
    assert!(matches!(label(b"3\r\ndef\r\n", &mut st, 1), Outcome::Body));
    assert!(matches!(
        label(b"0\r\n\r\n", &mut st, 1),
        Outcome::Message(_)
    ));
    let whole = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n";
    assert!(matches!(label(whole, &mut st, 1), Outcome::Message(_)));
}

#[test]
fn a_response_without_a_length_runs_until_the_connection_closes() {
    let mut st = Stream::new(0);
    let head = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nabc";
    assert!(matches!(label(head, &mut st, 1), Outcome::Partial(_)));
    assert!(matches!(label(b"more", &mut st, 1), Outcome::Body));
    let l = close(&mut st).expect("closed");
    assert_eq!(l.info, "HTTP/1.0 200 OK ");
    assert!(close(&mut st).is_none());
}

#[test]
fn requests_without_a_length_are_whole() {
    let mut st = Stream::new(0);
    assert!(matches!(
        label(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", &mut st, 0),
        Outcome::Message(_)
    ));
}

#[test]
fn absurd_content_lengths_do_not_overflow() {
    let mut st = Stream::new(0);
    let m = b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n";
    assert!(matches!(
        label(m, &mut st, 0),
        Outcome::Message(_) | Outcome::Partial(_)
    ));
    let m = b"HTTP/1.1 200 OK\r\nContent-Length: 4294967290\r\n\r\n";
    let mut fresh = Stream::new(1);
    assert!(matches!(label(m, &mut fresh, 0), Outcome::Partial(_)));
    assert!(matches!(label(&[0; 100], &mut fresh, 0), Outcome::Body));
}
