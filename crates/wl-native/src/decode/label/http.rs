//! HTTP/1.x messages recognised by the start of the payload. A body longer than its segment is
//! followed through `Content-Length`, because Wireshark labels the segments before the last one
//! TCP and only the last one HTTP.

use super::Label;
use crate::decode::streams::Stream;

const METHODS: [&[u8]; 8] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
];
const MAX_LINE: usize = 512;
/// `pending` values for bodies without a byte count.
const UNTIL_CLOSE: u32 = u32::MAX;
const UNTIL_LAST_CHUNK: u32 = u32::MAX - 1;

pub enum Outcome {
    /// The segment completes an HTTP message (or holds one whole).
    Message(Label),
    /// The segment starts a message whose body is still to come; TCP with this Info.
    Partial(String),
    /// The segment is part of a body that is still arriving.
    Body,
    NotHttp,
}

fn first_line(payload: &[u8]) -> &[u8] {
    let end = payload
        .iter()
        .take(MAX_LINE)
        .position(|b| *b == b'\r' || *b == b'\n')
        .unwrap_or(payload.len().min(MAX_LINE));
    &payload[..end]
}

fn is_message(payload: &[u8]) -> bool {
    let line = first_line(payload);
    let complete = line.len() < payload.len().min(MAX_LINE);
    payload.starts_with(b"HTTP/")
        || METHODS.iter().any(|m| line.starts_with(m))
            && (!complete || line.windows(5).any(|w| w == b"HTTP/"))
}

fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then_some(v.trim())
    })
}

fn line_info(payload: &[u8]) -> String {
    format!("{} ", String::from_utf8_lossy(first_line(payload)))
}

/// A response with no length and no chunking, unless its status forbids a body.
fn body_until_close(payload: &[u8]) -> bool {
    let status = first_line(payload).split(|b| *b == b' ').nth(1);
    payload.starts_with(b"HTTP/")
        && !matches!(status, Some([b'1', ..]) | Some(b"204") | Some(b"304"))
}

fn ends_chunked(body: &[u8]) -> bool {
    body.ends_with(b"0\r\n\r\n")
}

pub fn label(payload: &[u8], st: &mut Stream, dir: usize) -> Outcome {
    let pending = st.half[dir].pending;
    if pending > 0 && st.half[dir].pending_ct == 0 {
        let left = match pending {
            UNTIL_CLOSE => UNTIL_CLOSE,
            UNTIL_LAST_CHUNK if ends_chunked(payload) => 0,
            UNTIL_LAST_CHUNK => UNTIL_LAST_CHUNK,
            n => n.saturating_sub(u32::try_from(payload.len()).unwrap_or(u32::MAX)),
        };
        st.half[dir].pending = left;
        return if left > 0 { Outcome::Body } else { finish(st) };
    }
    if !is_message(payload) {
        return Outcome::NotHttp;
    }
    let info = line_info(payload);
    let Some(end) = payload.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Outcome::Message(Label::new("HTTP", info));
    };
    let (headers, body) = (
        String::from_utf8_lossy(&payload[..end]),
        &payload[end + 4..],
    );
    let chunked =
        header(&headers, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let length = header(&headers, "content-length").and_then(|v| v.parse::<usize>().ok());
    let pending = match length {
        _ if chunked => (!ends_chunked(body)).then_some(UNTIL_LAST_CHUNK),
        Some(total) if total > body.len() => {
            Some(u32::try_from(total - body.len()).unwrap_or(UNTIL_LAST_CHUNK - 1))
        }
        Some(_) => None,
        None => body_until_close(payload).then_some(UNTIL_CLOSE),
    };
    match pending {
        Some(n) => {
            st.half[dir].pending = n;
            st.half[dir].pending_ct = 0;
            st.http_line = Some(info.clone().into_boxed_str());
            Outcome::Partial(info)
        }
        None => Outcome::Message(Label::new("HTTP", info)),
    }
}

fn finish(st: &mut Stream) -> Outcome {
    let line = st.http_line.take().map(String::from).unwrap_or_default();
    Outcome::Message(Label::new("HTTP", line))
}

/// FIN or RST ends a body that runs until the connection closes.
pub fn close(st: &mut Stream) -> Option<Label> {
    let open = st
        .half
        .iter()
        .position(|h| h.pending == UNTIL_CLOSE && h.pending_ct == 0)?;
    st.half[open].pending = 0;
    match finish(st) {
        Outcome::Message(l) => Some(l),
        _ => None,
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
