//! `message_streams`: one pass for WebSocket / HTTP/2 / gRPC / SSE headers, then a raw-payload pass
//! over the SSE connections (their events never form a complete HTTP body while the stream lives).

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, MessageStream, MsgDir, StreamKind, StreamMessage, is_control_label};

use crate::msg_group::Grouper;
use crate::msg_rows::{self, SEP};
use crate::msg_target::SseTarget;
use crate::sse::{SseDecoder, SseEvent};
use crate::tsv_pass::{Pass, columns, flag, run_pass_all};

const FILTER: &str = "http || websocket || http2";
const PAYLOAD_FIELDS: [&str; 6] = [
    "frame.number",
    "frame.time_relative",
    "tcp.stream",
    "tcp.srcport",
    "tcp.payload",
    "tcp.flags.fin",
];
/// Streams per payload pass: keeps the display filter far below the argument size limit.
const STREAMS_PER_PASS: usize = 256;

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
        bytes: payload.len() as u64,
        payload: crate::msg_preview::text(payload.as_bytes()),
        control: is_control_label(&label),
        label,
    }
}

fn pass_filter(part: &[&SseTarget]) -> String {
    let ids: Vec<String> = part.iter().map(|t| t.stream.to_string()).collect();
    format!(
        "tcp.stream in {{{}}} && (tcp.len > 0 || tcp.flags.fin == 1)",
        ids.join(",")
    )
}

/// What the server's half of one connection decoded to.
struct Decoded {
    decoder: SseDecoder,
    messages: Vec<StreamMessage>,
}

/// Events per TCP stream, in arrival order; only the server's half of each connection is read.
fn sse_events(
    tools: &crate::process::Tools,
    file: &Path,
    targets: &[&SseTarget],
    opts: &[String],
) -> Result<HashMap<u32, Decoded>, CaptureError> {
    let mut all = opts.to_vec();
    all.extend(["-o".into(), "tcp.desegment_tcp_streams:FALSE".into()]);
    let by_stream: HashMap<u32, &SseTarget> = targets.iter().map(|t| (t.stream, *t)).collect();
    let mut out: HashMap<u32, Decoded> = HashMap::new();
    for part in targets.chunks(STREAMS_PER_PASS) {
        let filter = pass_filter(part);
        let pass = Pass {
            file,
            filter: &filter,
            fields: &PAYLOAD_FIELDS,
            opts: &all,
        };
        crate::tsv_pass::run_pass(tools, &pass, |line| {
            let f: [&str; 6] = columns(line);
            let (Ok(frame), Ok(stream), Ok(port)) = (
                f[0].trim().parse(),
                f[2].trim().parse::<u32>(),
                f[3].trim().parse::<u16>(),
            ) else {
                return ControlFlow::Continue(());
            };
            if !by_stream
                .get(&stream)
                .is_some_and(|t| t.is_server_port(port))
            {
                return ControlFlow::Continue(());
            }
            let d = out.entry(stream).or_insert_with(|| Decoded {
                decoder: SseDecoder::default(),
                messages: Vec::new(),
            });
            let bytes = crate::cert_parse::hex_to_bytes(f[4]).unwrap_or_default();
            let rel = f[1].trim().parse().unwrap_or(0.0);
            d.messages.extend(
                d.decoder
                    .push(&bytes)
                    .into_iter()
                    .map(|e| event_message(frame, rel, e)),
            );
            if flag(f[5]) {
                d.decoder.server_closed();
            }
            ControlFlow::Continue(())
        })?;
    }
    Ok(out)
}

fn sse_stream(t: &SseTarget, decoded: Option<Decoded>) -> Option<MessageStream> {
    let seen = decoded
        .as_ref()
        .is_some_and(|d| d.decoder.is_event_stream());
    if !t.confirmed && !seen {
        return None;
    }
    let code = decoded
        .as_ref()
        .and_then(|d| d.decoder.status())
        .map_or_else(|| t.status.clone(), |c| c.to_string());
    let status = match &decoded {
        _ if t.tls => format!("{code} encrypted"),
        Some(d) if seen && d.decoder.is_open() => format!("{code} open"),
        _ => code,
    };
    Some(MessageStream {
        id: t.id,
        stream: t.stream,
        kind: StreamKind::Sse,
        host: t.host.clone(),
        target: t.target.clone(),
        start_rel: t.start_rel,
        status: status.trim().to_owned(),
        messages: decoded.map(|d| d.messages).unwrap_or_default(),
    })
}

pub fn message_streams(
    tools: &crate::process::Tools,
    file: &Path,
    opts: &[String],
) -> Result<Vec<MessageStream>, CaptureError> {
    let (mut streams, targets) = group(tools, file, opts)?.finish();
    let cleartext: Vec<&SseTarget> = targets.iter().filter(|t| !t.tls).collect();
    let mut decoded = if cleartext.is_empty() {
        HashMap::new()
    } else {
        sse_events(tools, file, &cleartext, opts)?
    };
    streams.extend(
        targets
            .iter()
            .filter_map(|t| sse_stream(t, decoded.remove(&t.stream))),
    );
    streams.sort_by_key(|s| s.id);
    Ok(streams)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_of_streams_split_into_short_filters() {
        let targets: Vec<SseTarget> = (4_000_000..4_005_000)
            .map(|stream| SseTarget {
                stream,
                ..SseTarget::default()
            })
            .collect();
        let refs: Vec<&SseTarget> = targets.iter().collect();
        let longest = refs
            .chunks(STREAMS_PER_PASS)
            .map(|c| pass_filter(c).len())
            .max()
            .unwrap_or(0);
        assert!(longest < 4096, "{longest}");
    }
}
