//! `http_detail`: dissects the request and response frames of one exchange (`-T json -J http`)
//! and caches the result (bounded LRU, same policy as frame details).

use std::path::Path;

use wl_model::{CaptureError, HttpDetail, HttpExchange, HttpMessage};

use crate::error::from_stderr;
use crate::frame::cache_key;
use crate::frame_cache::{LruCache, Weigh};
use crate::http_message::message;
use crate::json_ordered::{OneOrMany, Ordered, Packet};
use crate::process::{Tools, run};

pub type DetailCache = LruCache<HttpDetail>;

fn msg_weight(m: &HttpMessage) -> usize {
    m.start_line.len()
        + m.body_preview.as_ref().map_or(0, String::len)
        + m.headers
            .iter()
            .map(|(n, v)| 48 + n.len() + v.len())
            .sum::<usize>()
}

impl Weigh for HttpDetail {
    fn weight(&self) -> usize {
        256 + self.request.as_ref().map_or(0, msg_weight)
            + self.response.as_ref().map_or(0, msg_weight)
    }
}

/// The HTTP layer of each requested frame, in tshark output order.
fn layers(json: &[u8]) -> Result<Vec<(Ordered, bool)>, CaptureError> {
    if json.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let packets: Vec<Packet> = serde_json::from_slice(json)
        .map_err(|e| CaptureError::Other(format!("tshark json: {e}")))?;
    let mut out = Vec::new();
    for p in packets {
        match p.source.layers.http {
            Some(OneOrMany::One(o)) => out.push(o),
            Some(OneOrMany::Many(v)) => out.extend(v.into_iter().take(1)),
            None => {}
        }
    }
    Ok(out
        .into_iter()
        .map(|o| {
            let req = crate::http_message::is_request(&o);
            (o, req)
        })
        .collect())
}

pub fn http_detail(
    tools: &Tools,
    cache: &DetailCache,
    file: &Path,
    ex: &HttpExchange,
    opts: &[String],
) -> Result<HttpDetail, CaptureError> {
    let frames: Vec<u64> = [ex.req_frame, ex.resp_frame]
        .into_iter()
        .flatten()
        .collect();
    let Some(&last) = frames.iter().max() else {
        return Ok(HttpDetail::default());
    };
    let key = cache_key(file, ex.id)?;
    if let Some(hit) = cache.get(&key) {
        return Ok(hit);
    }
    let filter = frames
        .iter()
        .map(|f| format!("frame.number=={f}"))
        .collect::<Vec<_>>()
        .join(" || ");
    let mut args: Vec<String> = vec![
        "-n".into(),
        "-r".into(),
        file.to_string_lossy().into_owned(),
    ];
    args.extend(opts.iter().cloned());
    args.extend(["-c".into(), last.to_string(), "-Y".into(), filter]);
    args.extend(["-T".into(), "json".into(), "-J".into(), "http".into()]);
    let out = run(&tools.tshark, &args)?;
    if !out.status.success() {
        return Err(from_stderr(&String::from_utf8_lossy(&out.stderr)));
    }
    let mut detail = HttpDetail::default();
    for (layer, is_req) in layers(&out.stdout)? {
        let m = message(&layer);
        if is_req && detail.request.is_none() {
            detail.request = Some(m);
        } else if !is_req && detail.response.is_none() {
            detail.response = Some(m);
        }
    }
    cache.insert(key, detail.clone());
    Ok(detail)
}
