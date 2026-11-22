//! Rows -> WebSocket and gRPC message streams, plus the SSE responses found on the way.

use std::collections::HashMap;

use wl_model::{MessageStream, MsgDir, StreamKind, StreamMessage, grpc_status_name};

use crate::msg_preview as preview;
use crate::msg_rows::{GrpcMsg, H2Frame, Row, WsFrame};

#[derive(Debug, Clone, PartialEq)]
pub struct SseTarget {
    pub stream: u32,
    pub id: u64,
    pub host: String,
    pub target: String,
    pub start_rel: f64,
    pub status: String,
    /// `address:port` of the server, to pick its half of the connection.
    pub server: String,
}

struct Request {
    frame: u64,
    rel: f64,
    host: String,
    uri: String,
    upgrade: bool,
}

struct Builder {
    stream: MessageStream,
    client: String,
}

impl Builder {
    fn dir_of(&self, src: &str) -> MsgDir {
        if src == self.client {
            MsgDir::ToServer
        } else {
            MsgDir::ToClient
        }
    }

    fn push(&mut self, row: &Row, dir: MsgDir, label: &str, payload: String, bytes: u64) {
        self.stream.messages.push(StreamMessage {
            frame: row.frame,
            rel: row.rel,
            dir,
            label: label.to_owned(),
            payload,
            bytes,
        });
    }
}

#[derive(Default)]
pub struct Grouper {
    requests: HashMap<u32, Request>,
    ws: HashMap<u32, Builder>,
    grpc: HashMap<(u32, u32), Builder>,
    sse: Vec<SseTarget>,
}

fn opcode_label(op: u8) -> String {
    match op {
        0 => "continuation".into(),
        1 => "text".into(),
        2 => "binary".into(),
        8 => "close".into(),
        9 => "ping".into(),
        10 => "pong".into(),
        n => format!("opcode {n}"),
    }
}

fn ws_payload(f: &WsFrame) -> String {
    match f.opcode {
        1 | 0 => preview::text(&f.payload),
        8 => {
            let reason = f.payload.get(2..).map(preview::text).unwrap_or_default();
            let code = f
                .close_code
                .map(|c| format!("code {c}"))
                .unwrap_or_default();
            format!("{code} {reason}").trim().to_owned()
        }
        _ => preview::hex(&f.payload),
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn grpc_status(headers: &[(String, String)]) -> Option<(String, String)> {
    let code = header(headers, "grpc-status")?;
    let name = code
        .parse()
        .map(grpc_status_name)
        .unwrap_or("UNKNOWN_STATUS");
    let msg = header(headers, "grpc-message").unwrap_or("");
    Some((
        format!("{code} {name}"),
        format!("grpc-status {code} {name} {msg}").trim().to_owned(),
    ))
}

/// Index of the DATA frame each gRPC message of a packet came from.
fn message_frames(frames: &[H2Frame], msgs: &[GrpcMsg]) -> Vec<usize> {
    let data: Vec<usize> = frames
        .iter()
        .enumerate()
        .filter(|(_, f)| matches!(f, H2Frame::Data { .. }))
        .map(|(i, _)| i)
        .collect();
    let zip = data.len() == msgs.len();
    (0..msgs.len())
        .filter_map(|i| data.get(if zip { i } else { 0 }).copied())
        .collect()
}

impl Grouper {
    pub fn push(&mut self, row: &Row) {
        if !row.method.is_empty() {
            self.requests.insert(
                row.stream,
                Request {
                    frame: row.frame,
                    rel: row.rel,
                    host: row.host.clone(),
                    uri: row.uri.clone(),
                    upgrade: row.upgrade,
                },
            );
        }
        if let Some(code) = row.code {
            self.response(row, code);
        }
        for f in &row.ws {
            self.websocket(row, f);
        }
        self.http2(row);
    }

    fn response(&mut self, row: &Row, code: u16) {
        if !row.content_type.contains("text/event-stream") {
            return;
        }
        let req = self.requests.get(&row.stream);
        self.sse.push(SseTarget {
            stream: row.stream,
            id: req.map_or(row.frame, |r| r.frame),
            host: req.map(|r| r.host.clone()).unwrap_or_default(),
            target: req.map(|r| r.uri.clone()).unwrap_or_default(),
            start_rel: req.map_or(row.rel, |r| r.rel),
            status: code.to_string(),
            server: row.src.clone(),
        });
    }

    fn websocket(&mut self, row: &Row, f: &WsFrame) {
        let req = self.requests.get(&row.stream).filter(|r| r.upgrade);
        let b = self.ws.entry(row.stream).or_insert_with(|| Builder {
            client: String::new(),
            stream: MessageStream {
                id: req.map_or(row.frame, |r| r.frame),
                stream: row.stream,
                kind: StreamKind::WebSocket,
                host: req.map(|r| r.host.clone()).unwrap_or_default(),
                target: req.map(|r| r.uri.clone()).unwrap_or_default(),
                start_rel: req.map_or(row.rel, |r| r.rel),
                status: String::new(),
                messages: Vec::new(),
            },
        });
        let dir = if f.masked {
            MsgDir::ToServer
        } else {
            MsgDir::ToClient
        };
        b.push(
            row,
            dir,
            &opcode_label(f.opcode),
            ws_payload(f),
            f.payload.len() as u64,
        );
        if f.opcode == 8 && b.stream.status.is_empty() {
            b.stream.status = f
                .close_code
                .map_or("closed".into(), |c| format!("closed {c}"));
        }
    }

    fn http2(&mut self, row: &Row) {
        let owners = message_frames(&row.h2, &row.grpc);
        for (fi, f) in row.h2.iter().enumerate() {
            match f {
                H2Frame::Headers { stream_id, headers } => {
                    self.h2_headers(row, *stream_id, headers)
                }
                H2Frame::Data { stream_id } => {
                    for (m, _) in row.grpc.iter().zip(&owners).filter(|(_, o)| **o == fi) {
                        self.h2_message(row, *stream_id, m);
                    }
                }
            }
        }
    }

    fn h2_message(&mut self, row: &Row, sid: u32, m: &GrpcMsg) {
        let Some(b) = self.grpc.get_mut(&(row.stream, sid)) else {
            return;
        };
        let label = if m.compressed {
            "message (compressed)"
        } else {
            "message"
        };
        let dir = b.dir_of(&row.src);
        b.push(
            row,
            dir,
            label,
            preview::protobuf(&m.data),
            u64::from(m.len),
        );
    }

    fn h2_headers(&mut self, row: &Row, sid: u32, headers: &[(String, String)]) {
        let key = (row.stream, sid);
        if let Some(path) = header(headers, ":path")
            && header(headers, "content-type").is_some_and(|c| c.starts_with("application/grpc"))
        {
            let mut b = Builder {
                client: row.src.clone(),
                stream: MessageStream {
                    id: row.frame,
                    stream: row.stream,
                    kind: StreamKind::Grpc,
                    host: header(headers, ":authority").unwrap_or_default().to_owned(),
                    target: path.to_owned(),
                    start_rel: row.rel,
                    status: String::new(),
                    messages: Vec::new(),
                },
            };
            b.push(row, MsgDir::ToServer, "request", path.to_owned(), 0);
            self.grpc.insert(key, b);
            return;
        }
        let Some(b) = self.grpc.get_mut(&key) else {
            return;
        };
        if let Some((status, text)) = grpc_status(headers) {
            b.stream.status = status;
            let dir = b.dir_of(&row.src);
            b.push(row, dir, "trailers", text, 0);
        } else if let Some(code) = header(headers, ":status") {
            let dir = b.dir_of(&row.src);
            b.push(row, dir, "response", format!("HTTP {code}"), 0);
        }
    }

    /// Finished WebSocket / gRPC streams and the SSE responses still to be decoded.
    pub fn finish(self) -> (Vec<MessageStream>, Vec<SseTarget>) {
        let streams = self
            .ws
            .into_values()
            .chain(self.grpc.into_values())
            .map(|b| b.stream)
            .collect();
        (streams, self.sse)
    }
}

#[cfg(test)]
#[path = "msg_group_tests.rs"]
mod tests;
