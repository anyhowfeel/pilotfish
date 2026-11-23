//! Collecting the events of a `Session` in tests.

use std::net::Ipv4Addr;
use std::time::Duration;

use crossbeam_channel::RecvTimeoutError;
use wl_model::{CaptureEvent, PacketRow, Session};

use super::files::Frame;
use super::packets::udp4;

/// Everything a session sent, in order, until its channel closed.
#[derive(Debug, Default)]
pub struct Received {
    pub batches: Vec<Vec<PacketRow>>,
    /// `Finished` and `Failed` events, in arrival order.
    pub terminals: Vec<CaptureEvent>,
    /// Events that arrived after the first terminal one.
    pub after_terminal: usize,
}

impl Received {
    pub fn rows(&self) -> Vec<PacketRow> {
        self.batches.iter().flatten().cloned().collect()
    }
}

/// Reads until the sender is dropped; panics when nothing arrives for ten seconds.
pub fn collect(session: &Session) -> Received {
    let mut got = Received::default();
    loop {
        match session.events.recv_timeout(Duration::from_secs(10)) {
            Ok(ev) => {
                if !got.terminals.is_empty() {
                    got.after_terminal += 1;
                }
                match ev {
                    CaptureEvent::Rows(rows) => got.batches.push(rows),
                    other => got.terminals.push(other),
                }
            }
            Err(RecvTimeoutError::Disconnected) => return got,
            Err(RecvTimeoutError::Timeout) => panic!("the session sent nothing for 10 s"),
        }
    }
}

/// `n` small UDP frames, 1 ms apart, with ports that vary so every frame differs.
pub fn numbered_frames(n: usize) -> Vec<Frame> {
    let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    (0..n)
        .map(|i| {
            let port = 1000 + (i % 5000) as u16;
            Frame::new(
                1_700_000_000.0 + i as f64 * 0.001,
                udp4((a, port), (b, 53), &[i as u8; 4]),
            )
        })
        .collect()
}
