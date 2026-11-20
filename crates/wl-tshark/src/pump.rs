//! Moves tshark's field output to the UI: reader thread (parse) + batching thread.

use std::io::{BufRead, BufReader};
use std::process::ChildStdout;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{RecvTimeoutError, SendTimeoutError, Sender, bounded};
use wl_model::{CaptureError, CaptureEvent, PacketRow};

use crate::interner::Interner;
use crate::row_parser::parse_line;

pub const BATCH_ROWS: usize = 500;
pub const FLUSH_EVERY: Duration = Duration::from_millis(50);

/// Called once tshark's stdout hit EOF; `true` when we stopped it. Returns the failure, if any.
pub type Finish = Box<dyn FnOnce(bool) -> Option<CaptureError> + Send>;

/// Returns false when the receiver is gone or we were asked to stop while blocked.
fn send(tx: &Sender<CaptureEvent>, stop: &AtomicBool, mut ev: CaptureEvent) -> bool {
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

fn send_row(rows: &Sender<PacketRow>, stop: &AtomicBool, mut row: PacketRow) -> bool {
    loop {
        match rows.send_timeout(row, FLUSH_EVERY) {
            Ok(()) => return true,
            Err(SendTimeoutError::Disconnected(_)) => return false,
            Err(SendTimeoutError::Timeout(back)) => {
                if stop.load(Ordering::SeqCst) {
                    return false;
                }
                row = back;
            }
        }
    }
}

fn read_rows(stdout: ChildStdout, rows: Sender<PacketRow>, stop: Arc<AtomicBool>) {
    let mut rdr = BufReader::with_capacity(256 * 1024, stdout);
    let (mut buf, mut interner) = (Vec::new(), Interner::default());
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        buf.clear();
        match rdr.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let line = String::from_utf8_lossy(&buf);
        if let Some(row) = parse_line(&line, &mut interner)
            && !send_row(&rows, &stop, row)
        {
            return;
        }
    }
}

fn batch_rows(
    rows: crossbeam_channel::Receiver<PacketRow>,
    tx: &Sender<CaptureEvent>,
    stop: &AtomicBool,
) {
    let mut batch: Vec<PacketRow> = Vec::with_capacity(BATCH_ROWS);
    let mut started = Instant::now();
    loop {
        let due = match rows.recv_timeout(FLUSH_EVERY) {
            Ok(r) => {
                if batch.is_empty() {
                    started = Instant::now();
                }
                batch.push(r);
                batch.len() >= BATCH_ROWS || started.elapsed() >= FLUSH_EVERY
            }
            Err(RecvTimeoutError::Timeout) => !batch.is_empty(),
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if due {
            let full = std::mem::replace(&mut batch, Vec::with_capacity(BATCH_ROWS));
            if !send(tx, stop, CaptureEvent::Rows(full)) {
                return;
            }
        }
    }
    if !batch.is_empty() {
        send(tx, stop, CaptureEvent::Rows(batch));
    }
}

pub fn spawn(
    stdout: ChildStdout,
    tx: Sender<CaptureEvent>,
    stop: Arc<AtomicBool>,
    finish: Finish,
) -> Vec<JoinHandle<()>> {
    let (row_tx, row_rx) = bounded::<PacketRow>(4096);
    let reader_stop = stop.clone();
    let reader = thread::spawn(move || read_rows(stdout, row_tx, reader_stop));
    let pump = thread::spawn(move || {
        batch_rows(row_rx, &tx, &stop);
        let err = finish(stop.load(Ordering::SeqCst));
        let last = err.map_or(CaptureEvent::Finished, CaptureEvent::Failed);
        send(&tx, &stop, last);
    });
    vec![reader, pump]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_unblocks_full_bounded_channel() {
        let (tx, _rx) = bounded::<CaptureEvent>(1);
        let stop = Arc::new(AtomicBool::new(false));
        assert!(send(&tx, &stop, CaptureEvent::Finished));
        let stop_bg = stop.clone();
        let tx_bg = tx.clone();
        let h = thread::spawn(move || send(&tx_bg, &stop_bg, CaptureEvent::Finished));
        thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::SeqCst);
        assert!(!h.join().unwrap());
    }
}
