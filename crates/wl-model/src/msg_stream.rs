//! Long-lived message streams of web traffic: WebSocket, Server-Sent Events and gRPC.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamKind {
    WebSocket,
    Sse,
    Grpc,
}

impl StreamKind {
    pub fn label(self) -> &'static str {
        match self {
            StreamKind::WebSocket => "WebSocket",
            StreamKind::Sse => "SSE",
            StreamKind::Grpc => "gRPC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MsgDir {
    ToServer,
    ToClient,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamMessage {
    pub frame: u64,
    pub rel: f64,
    pub dir: MsgDir,
    /// WebSocket opcode, SSE event name, gRPC "message" / "trailers" ...
    pub label: String,
    /// Single-line preview of the payload.
    pub payload: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageStream {
    /// First frame of the stream: stable within a capture.
    pub id: u64,
    pub stream: u32,
    pub kind: StreamKind,
    pub host: String,
    /// Request path, or `/package.Service/Method` for gRPC.
    pub target: String,
    pub start_rel: f64,
    /// gRPC status, WebSocket close code or HTTP status; empty while open.
    pub status: String,
    pub messages: Vec<StreamMessage>,
}

impl MessageStream {
    pub fn sent(&self) -> usize {
        self.count(MsgDir::ToServer)
    }

    pub fn received(&self) -> usize {
        self.count(MsgDir::ToClient)
    }

    fn count(&self, dir: MsgDir) -> usize {
        self.messages.iter().filter(|m| m.dir == dir).count()
    }
}

/// gRPC status code names (`grpc-status` trailer).
pub fn grpc_status_name(code: u32) -> &'static str {
    const NAMES: [&str; 17] = [
        "OK",
        "CANCELLED",
        "UNKNOWN",
        "INVALID_ARGUMENT",
        "DEADLINE_EXCEEDED",
        "NOT_FOUND",
        "ALREADY_EXISTS",
        "PERMISSION_DENIED",
        "RESOURCE_EXHAUSTED",
        "FAILED_PRECONDITION",
        "ABORTED",
        "OUT_OF_RANGE",
        "UNIMPLEMENTED",
        "INTERNAL",
        "UNAVAILABLE",
        "DATA_LOSS",
        "UNAUTHENTICATED",
    ];
    NAMES
        .get(code as usize)
        .copied()
        .unwrap_or("UNKNOWN_STATUS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_names() {
        assert_eq!(grpc_status_name(0), "OK");
        assert_eq!(grpc_status_name(14), "UNAVAILABLE");
        assert_eq!(grpc_status_name(99), "UNKNOWN_STATUS");
    }

    #[test]
    fn counts_by_direction() {
        let m = |dir| StreamMessage {
            frame: 1,
            rel: 0.0,
            dir,
            label: String::new(),
            payload: String::new(),
            bytes: 0,
        };
        let s = MessageStream {
            id: 1,
            stream: 0,
            kind: StreamKind::Grpc,
            host: String::new(),
            target: String::new(),
            start_rel: 0.0,
            status: String::new(),
            messages: vec![
                m(MsgDir::ToServer),
                m(MsgDir::ToClient),
                m(MsgDir::ToClient),
            ],
        };
        assert_eq!((s.sent(), s.received()), (1, 2));
    }
}
