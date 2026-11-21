//! Real loopback traffic (python http.server-like, curl, openssl s_server) captured with dumpcap
//! and analysed through the `CaptureBackend` web methods. Skips when a tool is missing.
//! Set `WL_FIXTURE_OUT=<dir>` to keep the generated captures (used to refresh tests/fixtures).

mod web_support;

use std::path::{Path, PathBuf};

use wl_model::{CaptureBackend, ChannelKind, HttpExchange, Proto, StatusClass};
use wl_tshark::TsharkBackend;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn keep(src: &Path, name: &str) {
    if let Some(dir) = std::env::var_os("WL_FIXTURE_OUT") {
        let _ = std::fs::copy(src, Path::new(&dir).join(name));
    }
}

fn find<'a>(v: &'a [HttpExchange], uri: &str) -> &'a HttpExchange {
    v.iter().find(|e| &*e.uri == uri).unwrap_or_else(|| {
        panic!(
            "no exchange for {uri}: {:?}",
            v.iter().map(|e| &e.uri).collect::<Vec<_>>()
        )
    })
}

fn check_http(b: &TsharkBackend, pcap: &Path, port: u16) {
    let ex = b.http_exchanges(pcap).expect("http_exchanges");
    assert_eq!(ex.len(), 6, "{ex:#?}");
    let host = format!("127.0.0.1:{port}");
    assert!(
        ex.iter()
            .all(|e| *e.host == *host && &*e.version == "HTTP/1.1")
    );
    assert!(
        ex.iter()
            .all(|e| e.req_frame.is_some() && e.resp_frame > e.req_frame)
    );
    assert!(ex.iter().all(|e| e.time_ms.is_some_and(|t| t >= 0.0)));
    let (ok, post, miss) = (
        find(&ex, "/ok"),
        find(&ex, "/submit"),
        find(&ex, "/missing"),
    );
    assert_eq!((&*ok.method, ok.status), ("GET", Some(200)));
    assert_eq!((&*post.method, post.status), ("POST", Some(200)));
    assert_eq!(
        (miss.status, miss.status_class()),
        (Some(404), StatusClass::ClientError)
    );
    assert_eq!(ok.content_type.as_deref(), Some("text/plain"));
    assert_eq!(ok.reason.as_deref(), Some("OK"));
    let ka: Vec<_> = ["/ka1", "/ka2", "/ka3"]
        .iter()
        .map(|u| find(&ex, u))
        .collect();
    assert!(
        ka.iter().all(|e| e.stream == ka[0].stream),
        "keep-alive shares one TCP stream"
    );
    assert!(ka[0].id < ka[1].id && ka[1].id < ka[2].id);
    assert_ne!(ok.stream, ka[0].stream);
    // Detail: clean start lines, ordered headers without CR/LF, decoded bodies.
    let d = b.http_detail(pcap, ok).expect("detail");
    let (rq, rs) = (d.request.expect("request"), d.response.expect("response"));
    assert_eq!(rq.start_line, "GET /ok HTTP/1.1");
    assert_eq!(rs.start_line, "HTTP/1.1 200 OK");
    assert_eq!(rq.headers[0], ("Host".into(), host));
    let all = rq.headers.iter().chain(&rs.headers);
    assert!(
        all.clone()
            .all(|(n, v)| !n.contains(['\r', '\n']) && !v.contains(['\r', '\n']))
    );
    assert!(
        rs.headers
            .iter()
            .any(|(n, v)| n == "Content-Length" && v == "9")
    );
    assert_eq!(
        (rs.body_preview.as_deref(), rs.body_len),
        (Some("hello /ok"), 9)
    );
    let d = b.http_detail(pcap, post).expect("post detail");
    assert_eq!(b.http_detail(pcap, post).expect("cached"), d);
    let (rq, rs) = (d.request.expect("request"), d.response.expect("response"));
    assert_eq!(rq.body_preview.as_deref(), Some("a=1&b=2"));
    assert_eq!(rs.body_preview.as_deref(), Some("got a=1&b=2"));
    assert!(b.tls_sessions(pcap).expect("tls").is_empty());
}

#[test]
fn http_exchanges_and_detail_on_live_loopback_traffic() {
    let Ok(b) = TsharkBackend::new() else { return };
    b.set_tls_keylog(None);
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("http.pcapng");
    let Some(port) = web_support::http_scenario(&pcap) else {
        return eprintln!("skipped: python3/curl/dumpcap unavailable");
    };
    keep(&pcap, "web-http.pcapng");
    check_http(&b, &pcap, port);
}

#[test]
fn committed_http_fixture_parses() {
    let (Ok(b), pcap) = (TsharkBackend::new(), fixture("web-http.pcapng")) else {
        return;
    };
    let ex = b.http_exchanges(&pcap).expect("http_exchanges");
    assert_eq!(ex.len(), 6);
    assert!(
        ex.iter()
            .all(|e| e.status.is_some() && e.req_frame.is_some())
    );
}

#[test]
fn tls_sessions_and_keylog_decryption() {
    let Ok(b) = TsharkBackend::new() else { return };
    b.set_tls_keylog(None);
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("tls.pcapng");
    let Some(run) = web_support::tls_scenario(dir.path(), &pcap) else {
        return eprintln!("skipped: openssl/curl/dumpcap unavailable");
    };
    keep(&pcap, "web-tls.pcapng");
    keep(&run.keylog, "web-tls.keylog");
    let tls = b.tls_sessions(&pcap).expect("tls_sessions");
    assert_eq!(tls.len(), 2, "{tls:#?}");
    let t12 = tls
        .iter()
        .find(|s| &*s.server_name == "tls12.wirelens.test")
        .expect("1.2");
    let t13 = tls
        .iter()
        .find(|s| &*s.server_name == "tls13.wirelens.test")
        .expect("1.3");
    assert_eq!((&*t12.version, &*t13.version), ("TLS 1.2", "TLS 1.3"));
    assert!(t12.cipher.is_some() && t13.cipher.is_some());
    assert_eq!(t12.cert_subject.as_deref(), Some("wirelens.test"));
    assert!(
        t13.cert_subject.is_none(),
        "TLS 1.3 certificates are encrypted"
    );
    assert!(t12.bytes > 500 && t13.bytes > 500);
    assert_eq!((&*t12.src, &*t12.dst), ("127.0.0.1", "127.0.0.1"));
    assert!(t12.first_frame < t13.first_frame);
    assert!(
        b.http_exchanges(&pcap).expect("http").is_empty(),
        "opaque without keys"
    );

    b.set_tls_keylog(Some(run.keylog.clone()));
    let ex = b.http_exchanges(&pcap).expect("decrypted http");
    assert_eq!(ex.len(), 2, "{ex:#?}");
    let hosts: Vec<_> = ex.iter().map(|e| e.host.to_string()).collect();
    assert!(hosts.contains(&format!("tls12.wirelens.test:{}", run.tls12_port)));
    assert!(hosts.contains(&format!("tls13.wirelens.test:{}", run.tls13_port)));
    let d = b.http_detail(&pcap, &ex[0]).expect("detail");
    assert_eq!(d.request.expect("request").start_line, "GET / HTTP/1.1");
    let t13 = b.tls_sessions(&pcap).expect("tls with keys");
    assert!(
        t13.iter()
            .all(|s| s.cert_subject.as_deref() == Some("wirelens.test"))
    );
}

#[test]
fn tls_sessions_carry_fingerprints() {
    let Ok(b) = TsharkBackend::new() else { return };
    let tls = b
        .tls_sessions(&fixture("web-tls.pcapng"))
        .expect("tls_sessions");
    assert!(!tls.is_empty());
    for s in &tls {
        assert_eq!(s.ja3.as_deref().map(str::len), Some(32), "{s:?}");
        assert!(
            s.ja4.as_deref().is_some_and(|j| j.starts_with('t')),
            "{s:?}"
        );
        assert!(s.ja3s.is_some(), "{s:?}");
    }
}

#[test]
fn behavior_channels_summarise_syns_and_streams() {
    let Ok(b) = TsharkBackend::new() else { return };
    let ch = b
        .behavior_channels(&fixture("web-tls.pcapng"))
        .expect("behavior_channels");
    assert!(
        ch.iter()
            .any(|c| c.kind == ChannelKind::NewFlows && c.dport > 0)
    );
    assert!(ch.iter().all(|c| !c.src.is_empty() && c.count > 0));
}

#[test]
fn behavior_channels_expose_scan_beacon_and_sweep_shapes() {
    let Ok(b) = TsharkBackend::new() else { return };
    let ch = b
        .behavior_channels(&fixture("behavior.pcap"))
        .expect("behavior_channels");
    let from = |src: &str| {
        ch.iter()
            .filter(move |c| &*c.src == src)
            .collect::<Vec<_>>()
    };
    assert_eq!(from("10.0.0.9").len(), 40, "one channel per scanned port");
    let beacon = from("10.0.0.5");
    assert_eq!(
        (beacon.len(), beacon[0].count, beacon[0].gap_mean),
        (1, 10, 30.0)
    );
    assert!(beacon[0].gap_jitter < 1e-9);
    assert!(from("10.0.0.7").iter().all(|c| c.proto == Proto::Icmp));
    assert_eq!(from("10.0.0.7").len(), 25);
}
