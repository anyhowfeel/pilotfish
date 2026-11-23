//! The worker thread: read, decode, filter, batch, send.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crossbeam_channel::{SendTimeoutError, Sender};
use wl_model::{CaptureError, CaptureEvent, PacketRow};

use super::{BATCH_ROWS, FLUSH_EVERY};
use crate::decode::Decoder;
use crate::filter::Filter;
use crate::reader::PacketSource;

/// Returns false when the receiver is gone or a stop was requested while the channel was full.
pub(super) fn send(tx: &Sender<CaptureEvent>, stop: &AtomicBool, mut ev: CaptureEvent) -> bool {
    loop {
        match tx.send_timeout(ev, FLUSH_EVERY) {
            Ok(()) => return true,
            Err(SendTimeoutError::Disconnected(_)) => return false,
            Err(SendTimeoutError::Timeout(back)) => {
                if stop.load(Ordering::SeqCst) {
                    return false;
                }
                ev = back;
            }
        }
    }
}

struct Batch<'a> {
    tx: &'a Sender<CaptureEvent>,
    stop: &'a AtomicBool,
    rows: Vec<PacketRow>,
    since: Instant,
}

impl Batch<'_> {
    fn is_due(&self) -> bool {
        self.rows.len() >= BATCH_ROWS
            || (!self.rows.is_empty() && self.since.elapsed() >= FLUSH_EVERY)
    }

    /// False when the session is over and the worker should end.
    fn flush(&mut self) -> bool {
        self.since = Instant::now();
        if self.rows.is_empty() {
            return true;
        }
        let full = std::mem::replace(&mut self.rows, Vec::with_capacity(BATCH_ROWS));
        send(self.tx, self.stop, CaptureEvent::Rows(full))
    }
}

pub fn run(
    mut source: Box<dyn PacketSource>,
    filter: Option<Filter>,
    tx: &Sender<CaptureEvent>,
    stop: &AtomicBool,
) {
    let mut batch = Batch {
        tx,
        stop,
        rows: Vec::with_capacity(BATCH_ROWS),
        since: Instant::now(),
    };
    let (mut decoder, mut data, mut first_epoch) = (Decoder::default(), Vec::new(), None);
    let last = loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match source.next_packet(&mut data) {
            Ok(Some(meta)) => {
                let first = *first_epoch.get_or_insert(meta.epoch);
                let decoded = decoder.decode(&meta, &data, first);
                if filter.as_ref().is_none_or(|f| f.matches(&decoded)) {
                    if batch.rows.is_empty() {
                        batch.since = Instant::now();
                    }
                    batch.rows.push(decoded.row);
                }
                if batch.is_due() && !batch.flush() {
                    return;
                }
            }
            Ok(None) => break CaptureEvent::Finished,
            Err(e) => break CaptureEvent::Failed(CaptureError::Other(e.to_string())),
        }
    };
    if batch.flush() {
        send(tx, stop, last);
    }
}
