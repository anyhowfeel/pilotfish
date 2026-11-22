//! WebSocket frame labels, previews and reassembly of fragmented messages.

use std::collections::HashMap;

use wl_model::{MsgDir, StreamMessage};

use crate::msg_preview as preview;
use crate::msg_rows::WsFrame;

/// Longest payload kept while reassembling; the byte count stays exact.
const MAX_REASSEMBLED: usize = 1 << 20;

pub fn opcode_label(op: u8) -> String {
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

pub fn ws_payload(f: &WsFrame) -> String {
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

/// A message whose final fragment has not arrived yet.
struct Partial {
    frame: u64,
    rel: f64,
    opcode: u8,
    payload: Vec<u8>,
    bytes: u64,
}

/// Joins the fragments of each direction (client frames are the masked ones) into messages.
#[derive(Default)]
pub struct Reassembly(HashMap<bool, Partial>);

fn dir_of(masked: bool) -> MsgDir {
    if masked {
        MsgDir::ToServer
    } else {
        MsgDir::ToClient
    }
}

fn message(p: Partial, masked: bool, suffix: &str) -> StreamMessage {
    let whole = WsFrame {
        opcode: p.opcode,
        masked,
        payload: p.payload,
        close_code: None,
        fin: true,
    };
    StreamMessage {
        frame: p.frame,
        rel: p.rel,
        dir: dir_of(masked),
        label: format!("{}{suffix}", opcode_label(p.opcode)),
        payload: ws_payload(&whole),
        bytes: p.bytes,
        control: false,
    }
}

impl Reassembly {
    /// Adds a text, binary or continuation frame; returns the message it completes.
    pub fn add(&mut self, frame: u64, rel: f64, f: &WsFrame) -> Option<StreamMessage> {
        let mut p = self.0.remove(&f.masked).unwrap_or(Partial {
            frame,
            rel,
            opcode: f.opcode,
            payload: Vec::new(),
            bytes: 0,
        });
        p.bytes += f.payload.len() as u64;
        let room = MAX_REASSEMBLED.saturating_sub(p.payload.len());
        p.payload
            .extend_from_slice(&f.payload[..f.payload.len().min(room)]);
        if f.fin {
            return Some(message(p, f.masked, ""));
        }
        self.0.insert(f.masked, p);
        None
    }

    /// Messages cut off by the end of the capture.
    pub fn drain(&mut self) -> Vec<StreamMessage> {
        std::mem::take(&mut self.0)
            .into_iter()
            .map(|(masked, p)| message(p, masked, " (incomplete)"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(opcode: u8, masked: bool, fin: bool, payload: &[u8]) -> WsFrame {
        WsFrame {
            opcode,
            masked,
            payload: payload.to_vec(),
            close_code: None,
            fin,
        }
    }

    #[test]
    fn fragments_join_into_one_message() {
        let mut r = Reassembly::default();
        assert!(r.add(1, 0.1, &frame(1, true, false, b"hel")).is_none());
        assert!(r.add(2, 0.2, &frame(0, true, false, b"lo ")).is_none());
        let reply = r.add(3, 0.25, &frame(1, false, true, b"ok"));
        assert_eq!(reply.map(|m| m.payload), Some("ok".to_owned()));
        let m = r
            .add(4, 0.3, &frame(0, true, true, b"world"))
            .expect("done");
        assert_eq!(
            (m.frame, m.label.as_str(), m.payload.as_str(), m.bytes),
            (1, "text", "hello world", 11)
        );
        assert_eq!(m.dir, MsgDir::ToServer);
        assert!(r.drain().is_empty());
    }

    #[test]
    fn unfinished_message_is_kept_and_flagged() {
        let mut r = Reassembly::default();
        r.add(1, 0.0, &frame(2, false, false, &[1, 2]));
        let [m] = r.drain().try_into().expect("one");
        assert_eq!(m.label, "binary (incomplete)");
    }
}
