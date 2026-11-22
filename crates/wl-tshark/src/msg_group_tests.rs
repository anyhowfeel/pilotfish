use super::*;
use crate::msg_rows::{GrpcMsg, H2Frame, Row, WsFrame};

const CLIENT: &str = "10.0.0.1:50000";
const SERVER: &str = "10.0.0.2:8080";

fn row(frame: u64, src: &str) -> Row {
    Row {
        frame,
        rel: frame as f64 / 10.0,
        stream: 0,
        src: src.into(),
        ..Row::default()
    }
}

fn upgrade(frame: u64) -> Row {
    Row {
        method: "GET".into(),
        host: "ws.test".into(),
        uri: "/chat".into(),
        upgrade: true,
        ..row(frame, CLIENT)
    }
}

fn ws(frame: u64, src: &str, opcode: u8, masked: bool, payload: &[u8]) -> Row {
    Row {
        ws: vec![WsFrame {
            opcode,
            masked,
            payload: payload.to_vec(),
            close_code: (opcode == 8).then_some(1000),
        }],
        ..row(frame, src)
    }
}

fn run(rows: &[Row]) -> (Vec<MessageStream>, Vec<SseTarget>) {
    let mut g = Grouper::default();
    rows.iter().for_each(|r| g.push(r));
    g.finish()
}

#[test]
fn websocket_frames_become_one_stream_with_directions() {
    let (streams, sse) = run(&[
        upgrade(4),
        ws(6, CLIENT, 1, true, b"hello"),
        ws(7, SERVER, 1, false, b"{\"a\":1}"),
        ws(8, SERVER, 2, false, &[1, 2, 3]),
        ws(9, CLIENT, 8, true, &[3, 232]),
    ]);
    assert!(sse.is_empty());
    let [s] = streams.as_slice() else {
        panic!("{streams:?}")
    };
    assert_eq!(
        (s.id, s.kind, s.host.as_str(), s.target.as_str()),
        (4, StreamKind::WebSocket, "ws.test", "/chat")
    );
    let view: Vec<_> = s
        .messages
        .iter()
        .map(|m| (m.dir, m.label.as_str(), m.payload.as_str()))
        .collect();
    assert_eq!(
        view,
        [
            (MsgDir::ToServer, "text", "hello"),
            (MsgDir::ToClient, "text", "{\"a\":1}"),
            (MsgDir::ToClient, "binary", "01 02 03"),
            (MsgDir::ToServer, "close", "code 1000"),
        ]
    );
    assert_eq!(s.status, "closed 1000");
    assert_eq!((s.sent(), s.received()), (2, 2));
}

#[test]
fn websocket_without_the_handshake_in_the_capture_still_groups() {
    let (streams, _) = run(&[ws(3, CLIENT, 1, true, b"x"), ws(4, SERVER, 1, false, b"y")]);
    assert_eq!(streams.len(), 1);
    assert_eq!((streams[0].id, streams[0].target.as_str()), (3, ""));
}

fn headers(frame: u64, src: &str, sid: u32, h: &[(&str, &str)]) -> Row {
    Row {
        h2: vec![H2Frame::Headers {
            stream_id: sid,
            headers: h
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }],
        ..row(frame, src)
    }
}

fn data(frame: u64, src: &str, sid: u32, payload: &[u8]) -> Row {
    Row {
        h2: vec![H2Frame::Data { stream_id: sid }],
        grpc: vec![GrpcMsg {
            len: payload.len() as u32,
            compressed: false,
            data: payload.to_vec(),
        }],
        ..row(frame, src)
    }
}

fn grpc_call() -> Vec<Row> {
    vec![
        headers(
            35,
            CLIENT,
            1,
            &[
                (":method", "POST"),
                (":path", "/helloworld.Greeter/SayHello"),
                (":authority", "grpc.test"),
                ("content-type", "application/grpc"),
            ],
        ),
        data(35, CLIENT, 1, b"\x0a\x05world"),
        headers(
            36,
            SERVER,
            1,
            &[(":status", "200"), ("content-type", "application/grpc")],
        ),
        data(36, SERVER, 1, b"\x0a\x0bHello world"),
        headers(
            36,
            SERVER,
            1,
            &[("grpc-status", "0"), ("grpc-message", "OK")],
        ),
    ]
}

#[test]
fn grpc_call_reports_method_messages_and_status() {
    let (streams, _) = run(&grpc_call());
    let [s] = streams.as_slice() else {
        panic!("{streams:?}")
    };
    assert_eq!(
        (s.kind, s.target.as_str(), s.host.as_str()),
        (
            StreamKind::Grpc,
            "/helloworld.Greeter/SayHello",
            "grpc.test"
        )
    );
    assert_eq!(s.status, "0 OK");
    let view: Vec<_> = s
        .messages
        .iter()
        .map(|m| (m.dir, m.label.as_str(), m.payload.as_str()))
        .collect();
    assert_eq!(
        view,
        [
            (MsgDir::ToServer, "request", "/helloworld.Greeter/SayHello"),
            (MsgDir::ToServer, "message", "world"),
            (MsgDir::ToClient, "response", "HTTP 200"),
            (MsgDir::ToClient, "message", "Hello world"),
            (MsgDir::ToClient, "trailers", "grpc-status 0 OK OK"),
        ]
    );
}

#[test]
fn error_status_and_interleaved_streams_stay_apart() {
    let mut rows = grpc_call();
    rows.push(headers(
        40,
        CLIENT,
        3,
        &[
            (":method", "POST"),
            (":path", "/svc/Fail"),
            ("content-type", "application/grpc+proto"),
        ],
    ));
    rows.push(headers(
        41,
        SERVER,
        3,
        &[
            (":status", "200"),
            ("grpc-status", "14"),
            ("grpc-message", "down"),
        ],
    ));
    let (mut streams, _) = run(&rows);
    streams.sort_by_key(|s| s.id);
    assert_eq!(streams.len(), 2);
    assert_eq!(streams[1].status, "14 UNAVAILABLE");
    assert_eq!(
        streams[1].messages.last().map(|m| m.payload.as_str()),
        Some("grpc-status 14 UNAVAILABLE down")
    );
    assert_eq!(streams[0].status, "0 OK");
}

#[test]
fn plain_http2_calls_are_not_grpc() {
    let (streams, _) = run(&[headers(
        1,
        CLIENT,
        1,
        &[
            (":method", "GET"),
            (":path", "/"),
            ("content-type", "text/html"),
        ],
    )]);
    assert!(streams.is_empty());
}

#[test]
fn event_stream_responses_are_collected_for_decoding() {
    let req = Row {
        method: "GET".into(),
        host: "sse.test".into(),
        uri: "/events".into(),
        ..row(19, CLIENT)
    };
    let resp = Row {
        code: Some(200),
        content_type: "text/event-stream".into(),
        ..row(20, SERVER)
    };
    let (streams, sse) = run(&[req, resp]);
    assert!(streams.is_empty());
    let [t] = sse.as_slice() else {
        panic!("{sse:?}")
    };
    assert_eq!(
        (
            t.id,
            t.target.as_str(),
            t.server.as_str(),
            t.status.as_str()
        ),
        (19, "/events", SERVER, "200")
    );
}
