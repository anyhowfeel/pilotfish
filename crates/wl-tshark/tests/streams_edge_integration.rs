//! Open SSE streams, fragmented WebSocket messages and cancelled gRPC calls against
//! tests/fixtures/streams-edge.pcap (gen_streams_edge.py). Skips when tshark is missing.

use std::path::PathBuf;

use wl_model::{CaptureBackend, MessageStream};
use wl_tshark::TsharkBackend;

fn streams() -> Option<Vec<MessageStream>> {
    let b = TsharkBackend::new().ok()?;
    b.set_tls_keylog(None);
    let file =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/streams-edge.pcap");
    Some(b.message_streams(&file).expect("message_streams"))
}

fn by_target<'a>(all: &'a [MessageStream], target: &str) -> &'a MessageStream {
    all.iter()
        .find(|s| s.target == target)
        .unwrap_or_else(|| panic!("no {target} in {all:#?}"))
}

fn payloads(s: &MessageStream) -> Vec<&str> {
    s.messages.iter().map(|m| m.payload.as_str()).collect()
}

#[test]
fn sse_streams_without_a_terminating_response_are_listed_as_open() {
    let Some(all) = streams() else { return };
    let open = by_target(&all, "/open");
    assert_eq!(open.status, "200 open");
    assert_eq!(payloads(open), ["first", "second"]);
    let plain = by_target(&all, "/plain");
    assert_eq!(plain.status, "200");
    assert_eq!(payloads(plain), ["one", "two"]);
}

#[test]
fn fragmented_websocket_message_is_one_message() {
    let Some(all) = streams() else { return };
    let ws = by_target(&all, "/frag");
    assert_eq!(payloads(ws), ["hello world", "ok"]);
    assert_eq!((ws.sent(), ws.received()), (1, 1));
}

#[test]
fn grpc_counts_messages_and_shows_cancellation() {
    let Some(all) = streams() else { return };
    let done = by_target(&all, "/svc.Chat/Talk");
    assert_eq!(done.status, "0 OK");
    assert_eq!((done.sent(), done.received()), (2, 2));
    let cancelled = by_target(&all, "/svc.Chat/Cancelled");
    assert_eq!(cancelled.status, "cancelled");
    assert_eq!((cancelled.sent(), cancelled.received()), (2, 2));
}
