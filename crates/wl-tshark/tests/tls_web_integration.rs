//! TLS key log embedding, certificates, message streams and packet comments against the
//! committed fixtures. Skips when tshark / editcap are missing.

use std::path::PathBuf;

use wl_model::{CaptureBackend, StreamKind};
use wl_tshark::TsharkBackend;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn backend() -> Option<TsharkBackend> {
    let b = TsharkBackend::new().ok()?;
    b.set_tls_keylog(None);
    b.can_embed_tls_keys().then_some(b)
}

#[test]
fn embedded_keys_decrypt_without_a_key_log() {
    let Some(b) = backend() else { return };
    let (pcap, keylog) = (fixture("web-tls.pcapng"), fixture("web-tls.keylog"));
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("with-keys.pcapng");

    assert!(b.embed_tls_keys(&pcap, &out).is_err(), "needs a key log");
    b.set_tls_keylog(Some(keylog));
    b.embed_tls_keys(&pcap, &out).expect("embed");
    b.set_tls_keylog(None);

    assert!(b.http_exchanges(&pcap).expect("plain").is_empty());
    assert_eq!(b.http_exchanges(&out).expect("embedded").len(), 2);
}

#[test]
fn embedding_never_overwrites_the_original() {
    let Some(b) = backend() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let copy = dir.path().join("orig.pcapng");
    std::fs::copy(fixture("web-tls.pcapng"), &copy).expect("copy");
    let before = std::fs::read(&copy).expect("read");
    b.set_tls_keylog(Some(fixture("web-tls.keylog")));
    assert!(b.embed_tls_keys(&copy, &copy).is_err());
    assert_eq!(std::fs::read(&copy).expect("read"), before);
}

#[test]
fn tls12_sessions_carry_the_parsed_certificate_chain() {
    let Ok(b) = TsharkBackend::new() else { return };
    b.set_tls_keylog(None);
    let tls = b.tls_sessions(&fixture("web-tls.pcapng")).expect("tls");
    let t12 = tls
        .iter()
        .find(|s| &*s.version == "TLS 1.2")
        .expect("TLS 1.2 session");
    let leaf = t12.certs.first().expect("leaf certificate");
    assert_eq!(leaf.subject, "CN=wirelens.test");
    assert!(leaf.is_self_signed());
    assert_eq!(leaf.sans, ["wirelens.test"]);
    assert_eq!(leaf.key, "RSA 2048 bit");
    assert_eq!(leaf.sig_alg, "sha256WithRSA");
    assert_eq!(wl_model::date_label(leaf.not_before), "2026-11-20");
    assert_eq!(wl_model::date_label(leaf.not_after), "2026-11-22");
    assert!(
        tls.iter()
            .filter(|s| &*s.version == "TLS 1.3")
            .all(|s| s.certs.is_empty()),
        "TLS 1.3 certificates are encrypted"
    );
    let now = leaf.not_before + 60;
    let found = wl_model::evaluate_chain(&t12.certs, &t12.server_name, now);
    let kinds: Vec<_> = found.iter().map(|f| f.warning).collect();
    assert_eq!(
        kinds,
        [
            wl_model::CertWarning::SelfSigned,
            wl_model::CertWarning::HostnameMismatch
        ],
        "SNI tls12.wirelens.test is not covered by the wirelens.test certificate"
    );
    let later = wl_model::evaluate_chain(&t12.certs, "wirelens.test", leaf.not_after + 1);
    assert!(
        later
            .iter()
            .any(|f| f.warning == wl_model::CertWarning::Expired)
    );
}

fn streams() -> Option<Vec<wl_model::MessageStream>> {
    let b = TsharkBackend::new().ok()?;
    b.set_tls_keylog(None);
    Some(
        b.message_streams(&fixture("web-streams.pcap"))
            .expect("message_streams"),
    )
}

fn view(s: &wl_model::MessageStream) -> Vec<(wl_model::MsgDir, &str, &str)> {
    s.messages
        .iter()
        .map(|m| (m.dir, m.label.as_str(), m.payload.as_str()))
        .collect()
}

#[test]
fn fixture_yields_one_stream_of_each_kind() {
    let Some(all) = streams() else { return };
    let kinds: Vec<_> = all.iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        [StreamKind::WebSocket, StreamKind::Sse, StreamKind::Grpc],
        "{all:#?}"
    );
}

#[test]
fn websocket_timeline_has_directions_opcodes_and_payloads() {
    use wl_model::MsgDir::{ToClient, ToServer};
    let Some(all) = streams() else { return };
    let ws = &all[0];
    assert_eq!((ws.host.as_str(), ws.target.as_str()), ("ws.test", "/chat"));
    assert_eq!(
        view(ws),
        [
            (ToServer, "text", "hello server"),
            (ToClient, "text", "{\"reply\":\"hello client\"}"),
            (ToServer, "ping", "70 69 6e 67"),
            (ToClient, "pong", "70 69 6e 67"),
            (ToClient, "binary", "01 02 03 04"),
            (ToServer, "close", "code 1000"),
            (ToClient, "close", "code 1000"),
        ]
    );
    assert_eq!(ws.status, "closed 1000");
}

#[test]
fn sse_events_are_split_with_names_ids_and_comments() {
    use wl_model::MsgDir::ToClient;
    let Some(all) = streams() else { return };
    let sse = &all[1];
    assert_eq!(
        (sse.host.as_str(), sse.target.as_str(), sse.status.as_str()),
        ("sse.test", "/events", "200")
    );
    assert_eq!(
        view(sse),
        [
            (ToClient, "message", "welcome"),
            (ToClient, "tick #1", "{\"n\":1}"),
            (ToClient, "tick #2", "{\"n\":2}"),
            (ToClient, "comment", "keep-alive"),
            (ToClient, "message", "line one line two"),
        ]
    );
    let frames: Vec<_> = sse.messages.iter().map(|m| m.frame).collect();
    assert!(
        frames.windows(2).all(|w| w[0] <= w[1]),
        "per-segment timing: {frames:?}"
    );
}

#[test]
fn grpc_call_shows_method_messages_and_status() {
    use wl_model::MsgDir::{ToClient, ToServer};
    let Some(all) = streams() else { return };
    let g = &all[2];
    assert_eq!(
        (g.host.as_str(), g.target.as_str(), g.status.as_str()),
        ("grpc.test:50051", "/helloworld.Greeter/SayHello", "0 OK")
    );
    assert_eq!(
        view(g),
        [
            (ToServer, "request", "/helloworld.Greeter/SayHello"),
            (ToServer, "message", "world"),
            (ToClient, "response", "HTTP 200"),
            (ToClient, "message", "Hello world"),
            (ToClient, "trailers", "grpc-status 0 OK OK"),
        ]
    );
}

fn bm(frame_no: u64, comment: &str) -> wl_model::PacketBookmark {
    wl_model::PacketBookmark {
        frame_no,
        comment: comment.into(),
    }
}

#[test]
fn comments_round_trip_through_a_new_pcapng() {
    let Some(b) = backend() else { return };
    let src = fixture("sample.pcapng");
    assert!(b.packet_comments(&src).expect("read").is_empty());
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("annotated.pcapng");
    let notes = [bm(3, "first: handshake"), bm(5, "two\nlines"), bm(8, "")];
    b.save_with_comments(&src, &notes, &out).expect("write");
    assert_eq!(
        b.packet_comments(&out).expect("read back"),
        [bm(3, "first: handshake"), bm(5, "two\nlines")]
    );
    assert!(b.packet_comments(&src).expect("untouched").is_empty());
}

#[test]
fn saving_replaces_existing_comments_and_refuses_the_original() {
    let Some(b) = backend() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let (one, two) = (dir.path().join("one.pcapng"), dir.path().join("two.pcapng"));
    b.save_with_comments(
        &fixture("sample.pcapng"),
        &[bm(2, "old"), bm(4, "stale")],
        &one,
    )
    .expect("first");
    b.save_with_comments(&one, &[bm(4, "new")], &two)
        .expect("second");
    assert_eq!(b.packet_comments(&two).expect("read"), [bm(4, "new")]);
    assert!(b.save_with_comments(&one, &[bm(1, "x")], &one).is_err());
    assert_eq!(b.packet_comments(&one).expect("intact").len(), 2);
}

#[test]
fn embedding_leaves_out_keys_of_other_sessions() {
    let Some(b) = backend() else { return };
    let pcap = fixture("web-tls.pcapng");
    let dir = tempfile::tempdir().expect("tempdir");
    let mut text = std::fs::read_to_string(fixture("web-tls.keylog")).expect("keylog");
    let bogus = format!("CLIENT_RANDOM {} {}", "ab".repeat(32), "cd".repeat(48));
    text.push_str(&format!("{bogus}\n"));
    let keylog = dir.path().join("extra.keylog");
    std::fs::write(&keylog, text).expect("write");
    let out = dir.path().join("with-keys.pcapng");

    b.set_tls_keylog(Some(keylog));
    b.embed_tls_keys(&pcap, &out).expect("embed");
    b.set_tls_keylog(None);

    let bytes = std::fs::read(&out).expect("read");
    assert!(!bytes.windows(bogus.len()).any(|w| w == bogus.as_bytes()));
    assert!(!bytes.windows(32).any(|w| w == "ab".repeat(16).as_bytes()));
    assert_eq!(b.http_exchanges(&out).expect("embedded").len(), 2);
}

#[test]
fn embedding_fails_when_no_key_belongs_to_the_capture() {
    let Some(b) = backend() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let keylog = dir.path().join("other.keylog");
    std::fs::write(
        &keylog,
        format!("CLIENT_RANDOM {} {}\n", "ab".repeat(32), "cd".repeat(48)),
    )
    .expect("write");
    b.set_tls_keylog(Some(keylog));
    let out = dir.path().join("out.pcapng");
    assert!(b.embed_tls_keys(&fixture("web-tls.pcapng"), &out).is_err());
    assert!(!out.exists());
}

#[test]
fn every_comment_of_a_packet_survives_a_save() {
    let Some(b) = backend() else { return };
    let src = fixture("comments-multi.pcapng");
    let read = b.packet_comments(&src).expect("read");
    assert_eq!(
        read,
        [
            bm(1, "first note\n\nsecond\nnote with\ttab"),
            bm(2, "only one"),
            bm(3, "back\\slash \"q\""),
        ]
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("copy.pcapng");
    b.save_with_comments(&src, &read, &out).expect("write");
    assert_eq!(b.packet_comments(&out).expect("read back"), read);
}
