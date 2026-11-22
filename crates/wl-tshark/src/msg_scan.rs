//! `message_streams`: one pass for WebSocket / HTTP/2 / gRPC / SSE headers, then a raw-payload pass
//! over the SSE connections (their events never form a complete HTTP body while the stream lives).

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, MessageStream, MsgDir, StreamKind, StreamMessage};

use crate::msg_group::{Grouper, SseTarget};
use crate::msg_rows::{self, SEP};
use crate::sse::{SseDecoder, SseEvent};
use crate::tsv_pass::{Pass, columns, run_pass_all};

const FILTER: &str = "http || websocket || http2";
const PAYLOAD_FIELDS: [&str; 5] = [
    "frame.number",
    "frame.time_relative",
    "tcp.stream",
    "tcp.srcport",
    "tcp.payload",
];

fn separator_opts(opts: &[String]) -> Vec<String> {
    let mut all = opts.to_vec();
    all.extend(["-E".into(), format!("aggregator={SEP}")]);
    all
}

fn group(
    tools: &crate::process::Tools,
    file: &Path,
    opts: &[String],
) -> Result<Grouper, CaptureError> {
    let all = separator_opts(opts);
    let pass = Pass {
        file,
        filter: FILTER,
        fields: &msg_rows::FIELDS,
        opts: &all,
    };
    let mut g = Grouper::default();
    run_pass_all(tools, &pass, |line| {
        if let Some(row) = msg_rows::parse_line(line) {
            g.push(&row);
        }
        ControlFlow::Continue(())
    })?;
    Ok(g)
}

fn event_message(frame: u64, rel: f64, e: SseEvent) -> StreamMessage {
    let label = match (&e.event, &e.id, &e.comment) {
        (Some(ev), Some(id), _) => format!("{ev} #{id}"),
        (Some(ev), None, _) => ev.clone(),
        (None, Some(id), _) => format!("message #{id}"),
        (None, None, Some(_)) if e.data.is_empty() => "comment".into(),
        _ => "message".into(),
    };
    let payload = if e.data.is_empty() {
        e.comment.clone().unwrap_or_default()
    } else {
        e.data
    };
    StreamMessage {
        frame,
        rel,
        dir: MsgDir::ToClient,
        label,
        bytes: payload.len() as u64,
        payload: crate::msg_preview::text(payload.as_bytes()),
    }
}

/// Events per TCP stream, in arrival order; only the server's half of each connection is read.
fn sse_events(
    tools: &crate::process::Tools,
    file: &Path,
    targets: &[SseTarget],
    opts: &[String],
) -> Result<HashMap<u32, Vec<StreamMessage>>, CaptureError> {
    let streams: Vec<String> = targets.iter().map(|t| t.stream.to_string()).collect();
    let filter = format!("tcp.len > 0 && tcp.stream in {{{}}}", streams.join(" "));
    let mut all = opts.to_vec();
    all.extend(["-o".into(), "tcp.desegment_tcp_streams:FALSE".into()]);
    let pass = Pass {
        file,
        filter: &filter,
        fields: &PAYLOAD_FIELDS,
        opts: &all,
    };
    let ports: HashMap<u32, &str> = targets
        .iter()
        .map(|t| (t.stream, t.server.rsplit(':').next().unwrap_or("")))
        .collect();
    let mut decoders: HashMap<u32, SseDecoder> = HashMap::new();
    let mut out: HashMap<u32, Vec<StreamMessage>> = HashMap::new();
    crate::tsv_pass::run_pass(tools, &pass, |line| {
        let f: [&str; 5] = columns(line);
        let (Ok(frame), Ok(stream)) = (f[0].trim().parse(), f[2].trim().parse::<u32>()) else {
            return ControlFlow::Continue(());
        };
        if ports.get(&stream) != Some(&f[3].trim()) {
            return ControlFlow::Continue(());
        }
        let bytes = crate::cert_parse::hex_to_bytes(f[4]).unwrap_or_default();
        let rel = f[1].trim().parse().unwrap_or(0.0);
        for e in decoders.entry(stream).or_default().push(&bytes) {
            out.entry(stream)
                .or_default()
                .push(event_message(frame, rel, e));
        }
        ControlFlow::Continue(())
    })?;
    Ok(out)
}

fn sse_stream(t: SseTarget, messages: Vec<StreamMessage>) -> MessageStream {
    MessageStream {
        id: t.id,
        stream: t.stream,
        kind: StreamKind::Sse,
        host: t.host,
        target: t.target,
        start_rel: t.start_rel,
        status: t.status,
        messages,
    }
}

pub fn message_streams(
    tools: &crate::process::Tools,
    file: &Path,
    opts: &[String],
) -> Result<Vec<MessageStream>, CaptureError> {
    let (mut streams, targets) = group(tools, file, opts)?.finish();
    if !targets.is_empty() {
        let mut events = sse_events(tools, file, &targets, opts)?;
        streams.extend(targets.into_iter().map(|t| {
            sse_stream(
                t.clone(),
                events
                    .get_mut(&t.stream)
                    .map(std::mem::take)
                    .unwrap_or_default(),
            )
        }));
    }
    streams.sort_by_key(|s| s.id);
    Ok(streams)
}
