//! The Web scans narrowed by a display filter, against the real fixtures. Skips when tshark is missing.

use std::path::PathBuf;

use wl_model::CaptureBackend;
use wl_tshark::TsharkBackend;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn an_http_scan_keeps_only_the_exchanges_the_filter_lets_through() {
    let Ok(b) = TsharkBackend::new() else { return };
    let file = fixture("web-http.pcapng");
    let all = b.http_exchanges(&file).expect("all exchanges");
    assert!(all.len() >= 2, "the fixture holds several exchanges");

    // No filter, or an empty one, is the whole capture.
    assert_eq!(
        b.http_exchanges_scoped(&file, None).expect("none").len(),
        all.len()
    );
    assert_eq!(
        b.http_exchanges_scoped(&file, Some("  "))
            .expect("blank")
            .len(),
        all.len()
    );

    // One request and its response: that exchange and no other.
    let one = &all[0];
    let (req, resp) = (
        one.req_frame.expect("a request"),
        one.resp_frame.expect("a response"),
    );
    let scope = format!("frame.number == {req} || frame.number == {resp}");
    let kept = b
        .http_exchanges_scoped(&file, Some(&scope))
        .expect("one exchange");
    assert_eq!(kept.len(), 1, "{kept:#?}");
    assert_eq!((&kept[0].uri, kept[0].req_frame), (&one.uri, one.req_frame));
    assert_eq!(
        kept[0].resp_frame, one.resp_frame,
        "frame numbers stay those of the whole capture"
    );

    // A filter that matches nothing leaves nothing.
    let none = b
        .http_exchanges_scoped(&file, Some("ip.addr == 203.0.113.99"))
        .expect("nothing");
    assert!(none.is_empty(), "{none:#?}");

    // A filter tshark rejects is an error, not a silently empty page.
    assert!(
        b.http_exchanges_scoped(&file, Some("this is not (a filter"))
            .is_err()
    );
}

#[test]
fn a_tls_scan_keeps_only_the_sessions_of_the_filtered_streams() {
    let Ok(b) = TsharkBackend::new() else { return };
    let file = fixture("web-tls.pcapng");
    let all = b.tls_sessions(&file).expect("all sessions");
    let Some(stream) = all.iter().find_map(|s| s.stream) else {
        return;
    };
    let kept = b
        .tls_sessions_scoped(&file, Some(&format!("tcp.stream == {stream}")))
        .expect("one stream");
    assert!(!kept.is_empty() && kept.len() < all.len() + 1);
    assert!(kept.iter().all(|s| s.stream == Some(stream)), "{kept:#?}");
    let none = b
        .tls_sessions_scoped(&file, Some("tcp.stream == 99999"))
        .expect("no stream");
    assert!(none.is_empty(), "{none:#?}");
}

#[test]
fn a_scoped_scan_does_not_leak_into_the_shared_results() {
    let Ok(b) = TsharkBackend::new() else { return };
    let file = fixture("web-http.pcapng");
    let before = b.http_exchanges(&file).expect("before").len();
    let _ = b.http_exchanges_scoped(&file, Some("ip.addr == 203.0.113.99"));
    assert_eq!(
        b.http_exchanges(&file).expect("after").len(),
        before,
        "the memo of the whole capture is untouched"
    );
}

#[test]
fn a_message_stream_scan_keeps_only_the_filtered_traffic() {
    let Ok(b) = TsharkBackend::new() else { return };
    let file = fixture("web-streams.pcap");
    let all = b.message_streams(&file).expect("all streams");
    if all.is_empty() {
        return;
    }
    let none = b
        .message_streams_scoped(&file, Some("ip.addr == 203.0.113.99"))
        .expect("nothing");
    assert!(none.is_empty(), "{none:#?}");
    let same = b.message_streams_scoped(&file, None).expect("everything");
    assert_eq!(same.len(), all.len());
}
