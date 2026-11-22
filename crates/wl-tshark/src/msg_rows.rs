//! One tshark row of the message-stream pass -> a typed `Row` (WebSocket frames, HTTP/2 frames,
//! gRPC messages). Multi-valued fields arrive joined by `SEP`.

use crate::cert_parse::hex_to_bytes;
use crate::tsv_pass::{columns, flag};

pub const SEP: char = '\u{1f}';

pub const FIELDS: [&str; 28] = [
    "frame.number",
    "frame.time_relative",
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "http.request.method",
    "http.request.uri",
    "http.host",
    "http.response.code",
    "http.content_type",
    "http.upgrade",
    "websocket.opcode",
    "websocket.mask",
    "websocket.payload",
    "websocket.payload.close.status_code",
    "http2.streamid",
    "http2.type",
    "http2.header.count",
    "http2.header.name",
    "http2.header.value",
    "grpc.message_length",
    "grpc.compressed_flag",
    "grpc.message_data",
    "http.accept",
    "tls.record.content_type",
    "websocket.fin",
    "http2.rst_stream.error",
];

#[derive(Debug, Clone, PartialEq)]
pub struct WsFrame {
    pub opcode: u8,
    pub masked: bool,
    pub payload: Vec<u8>,
    pub close_code: Option<u16>,
    /// Last fragment of its message.
    pub fin: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum H2Frame {
    Headers {
        stream_id: u32,
        headers: Vec<(String, String)>,
    },
    Data {
        stream_id: u32,
    },
    Reset {
        stream_id: u32,
        error: u32,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct GrpcMsg {
    pub len: u32,
    pub compressed: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Row {
    pub frame: u64,
    pub rel: f64,
    pub stream: u32,
    /// `address:port` of the sender.
    pub src: String,
    pub method: String,
    pub uri: String,
    pub host: String,
    pub code: Option<u16>,
    pub content_type: String,
    pub upgrade: bool,
    /// The request accepts `text/event-stream`.
    pub accepts_sse: bool,
    /// Carried by TLS (decrypted): the raw segments are ciphertext.
    pub tls: bool,
    pub ws: Vec<WsFrame>,
    pub h2: Vec<H2Frame>,
    pub grpc: Vec<GrpcMsg>,
}

fn list(s: &str) -> Vec<&str> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(SEP).collect()
    }
}

fn nums<T: std::str::FromStr>(s: &str) -> Vec<T> {
    list(s)
        .into_iter()
        .filter_map(|v| v.trim().parse().ok())
        .collect()
}

/// Empty frames carry no payload value, so a short list only lines up when it has a single frame.
fn aligned<T: Clone + Default>(values: Vec<T>, frames: usize) -> Vec<T> {
    if values.len() == frames {
        values
    } else if frames == 1 {
        vec![values.into_iter().next().unwrap_or_default()]
    } else {
        vec![T::default(); frames]
    }
}

fn ws_frames(f: &[&str]) -> Vec<WsFrame> {
    let opcodes: Vec<u8> = nums(f[12]);
    let masks: Vec<bool> = list(f[13]).into_iter().map(flag).collect();
    let payloads: Vec<Vec<u8>> = list(f[14])
        .into_iter()
        .map(|h| hex_to_bytes(h).unwrap_or_default())
        .collect();
    let mut closes = nums::<u16>(f[15]).into_iter();
    let n = opcodes.len();
    let fins: Vec<bool> = list(f[26]).into_iter().map(flag).collect();
    let fins = if fins.len() == n { fins } else { vec![true; n] };
    let (masks, payloads) = (aligned(masks, n), aligned(payloads, n));
    opcodes
        .into_iter()
        .zip(masks)
        .zip(payloads)
        .zip(fins)
        .map(|(((opcode, masked), payload), fin)| WsFrame {
            opcode,
            masked,
            payload,
            close_code: if opcode == 8 { closes.next() } else { None },
            fin,
        })
        .collect()
}

fn h2_frames(f: &[&str]) -> Vec<H2Frame> {
    let ids: Vec<u32> = nums(f[16]);
    let types: Vec<u8> = nums(f[17]);
    let mut counts = nums::<usize>(f[18]).into_iter();
    let mut names = list(f[19]).into_iter();
    let mut values = list(f[20]).into_iter();
    let mut errors = nums::<u32>(f[27]).into_iter();
    ids.into_iter()
        .zip(types)
        .filter_map(|(stream_id, kind)| match kind {
            0 => Some(H2Frame::Data { stream_id }),
            1 => {
                let n = counts.next().unwrap_or(0);
                let headers = (&mut names)
                    .zip(&mut values)
                    .take(n)
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect();
                Some(H2Frame::Headers { stream_id, headers })
            }
            3 => Some(H2Frame::Reset {
                stream_id,
                error: errors.next().unwrap_or(0),
            }),
            _ => None,
        })
        .collect()
}

fn grpc_msgs(f: &[&str]) -> Vec<GrpcMsg> {
    let lens: Vec<u32> = nums(f[21]);
    let flags = aligned(nums::<u8>(f[22]), lens.len());
    let data: Vec<Vec<u8>> = list(f[23])
        .into_iter()
        .map(|h| hex_to_bytes(h).unwrap_or_default())
        .collect();
    let data = aligned(data, lens.len());
    lens.into_iter()
        .zip(flags)
        .zip(data)
        .map(|((len, flag), data)| GrpcMsg {
            len,
            compressed: flag != 0,
            data,
        })
        .collect()
}

pub fn parse_line(line: &str) -> Option<Row> {
    let f: [&str; FIELDS.len()] = columns(line);
    let addr = if f[3].is_empty() { f[4] } else { f[3] };
    Some(Row {
        frame: f[0].trim().parse().ok()?,
        rel: f[1].trim().parse().unwrap_or(0.0),
        stream: f[2].trim().parse().ok()?,
        src: format!("{}:{}", addr.split(SEP).next().unwrap_or(""), f[5].trim()),
        method: f[6].to_owned(),
        uri: f[7].to_owned(),
        host: f[8].to_owned(),
        code: f[9].trim().parse().ok(),
        content_type: f[10].to_owned(),
        upgrade: !f[11].is_empty(),
        accepts_sse: f[24].contains("text/event-stream"),
        tls: !f[25].is_empty(),
        ws: ws_frames(&f),
        h2: h2_frames(&f),
        grpc: grpc_msgs(&f),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(cols: &[(usize, &str)]) -> String {
        let mut v = vec![""; FIELDS.len()];
        v[0] = "5";
        v[2] = "1";
        v[3] = "10.0.0.1";
        v[5] = "5000";
        for (i, s) in cols {
            v[*i] = s;
        }
        v.join("\t")
    }

    #[test]
    fn websocket_frames_pair_opcode_mask_and_payload() {
        let r = parse_line(&line(&[(12, "1"), (13, "True"), (14, "6869")])).expect("row");
        assert_eq!(r.src, "10.0.0.1:5000");
        assert_eq!(
            r.ws,
            [WsFrame {
                opcode: 1,
                masked: true,
                payload: b"hi".to_vec(),
                close_code: None,
                fin: true
            }]
        );
    }

    #[test]
    fn empty_ping_payload_is_not_shifted_onto_the_next_frame() {
        let sep = SEP.to_string();
        let ops = format!("9{sep}1");
        let r = parse_line(&line(&[(12, &ops), (13, "False"), (14, "6869")])).expect("row");
        assert_eq!(r.ws.len(), 2);
        assert!(
            r.ws.iter().all(|w| w.payload.is_empty()),
            "ambiguous lists are dropped"
        );
        let one = parse_line(&line(&[(12, "9"), (13, "False")])).expect("row");
        assert!(one.ws[0].payload.is_empty());
    }

    #[test]
    fn close_code_goes_to_the_close_frame() {
        let r = parse_line(&line(&[
            (12, "8"),
            (13, "False"),
            (14, "03e8"),
            (15, "1000"),
        ]))
        .expect("row");
        assert_eq!(r.ws[0].close_code, Some(1000));
    }

    #[test]
    fn http2_headers_are_split_by_their_counts() {
        let s = SEP.to_string();
        let join = |v: &[&str]| v.join(&s);
        let r = parse_line(&line(&[
            (16, &join(&["1", "1", "1"])),
            (17, &join(&["1", "0", "1"])),
            (18, &join(&["2", "1"])),
            (19, &join(&[":status", "content-type", "grpc-status"])),
            (20, &join(&["200", "application/grpc", "0"])),
            (21, "7"),
            (22, "0"),
            (23, "0a05776f726c64"),
        ]))
        .expect("row");
        assert_eq!(r.h2.len(), 3);
        assert!(matches!(&r.h2[0], H2Frame::Headers { headers, .. } if headers.len() == 2));
        assert!(matches!(&r.h2[1], H2Frame::Data { stream_id: 1 }));
        assert!(
            matches!(&r.h2[2], H2Frame::Headers { headers, .. } if headers == &[("grpc-status".to_owned(), "0".to_owned())])
        );
        assert_eq!(r.grpc.len(), 1);
        assert_eq!(r.grpc[0].data, b"\x0a\x05world");
    }

    #[test]
    fn fragments_and_resets_are_parsed() {
        let s = SEP.to_string();
        let join = |v: &[&str]| v.join(&s);
        let r = parse_line(&line(&[
            (12, &join(&["1", "0"])),
            (13, &join(&["True", "True"])),
            (14, &join(&["6869", "6f6b"])),
            (26, &join(&["False", "True"])),
            (16, "1"),
            (17, "3"),
            (27, "8"),
            (24, "text/event-stream"),
            (25, "23"),
        ]))
        .expect("row");
        assert_eq!(
            r.ws.iter().map(|w| w.fin).collect::<Vec<_>>(),
            [false, true]
        );
        assert_eq!(
            r.h2,
            [H2Frame::Reset {
                stream_id: 1,
                error: 8
            }]
        );
        assert!(r.accepts_sse && r.tls);
    }

    #[test]
    fn rows_without_a_stream_are_dropped() {
        assert!(parse_line("5\t0.1\t").is_none());
    }
}
