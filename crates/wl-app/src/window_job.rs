//! Statistics limited to a time window, for the dashboard's "Window" scope.
//!
//! Approach: a second `CaptureBackend::start` over the backing file with the display filter
//! `frame.time_relative >= a && <= b`, folded into a fresh `StatsEngine` on a helper thread.
//! That reuses the exact row pipeline (so every number matches the "All" cards), keeps no copy of
//! the rows in memory and works for live captures; tshark only dissects the frames inside the
//! window, so the cost follows the window, not the capture. The latest request wins.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use wl_model::{CaptureBackend, CaptureEvent, CaptureSource, StatsSnapshot};
use wl_stats::StatsEngine;

/// Same cap as the main snapshot.
const TOP_N: usize = 200;

pub struct Window {
    pub from: u32,
    pub to: u32,
    pub stats: Arc<StatsSnapshot>,
}

pub struct WindowJob {
    backend: Arc<dyn CaptureBackend>,
    ctx: egui::Context,
    seq: Arc<AtomicU64>,
    tx: Sender<(u64, Window)>,
    rx: Receiver<(u64, Window)>,
    latest: Mutex<Option<Window>>,
}

/// The display filter selecting the capture seconds `[from, to)`, i.e. exactly the 1 s buckets the
/// throughput chart totals are made of.
pub fn window_filter(from: u32, to: u32) -> String {
    format!("frame.time_relative >= {from} && frame.time_relative < {to}")
}

impl WindowJob {
    pub fn new(backend: Arc<dyn CaptureBackend>, ctx: egui::Context) -> Self {
        let (tx, rx) = unbounded();
        Self {
            backend,
            ctx,
            seq: Arc::new(AtomicU64::new(0)),
            tx,
            rx,
            latest: Mutex::new(None),
        }
    }

    /// Starts (superseding any earlier request) the statistics of `[from, to]` seconds.
    pub fn request(&self, file: PathBuf, from: u32, to: u32) {
        let mine = self.seq.fetch_add(1, Ordering::AcqRel) + 1;
        let (backend, seq, tx, ctx) = (
            self.backend.clone(),
            self.seq.clone(),
            self.tx.clone(),
            self.ctx.clone(),
        );
        std::thread::spawn(move || {
            let stats = fold(&*backend, file, from, to, || {
                seq.load(Ordering::Acquire) != mine
            });
            if let Some(stats) = stats {
                let _ = tx.send((mine, Window { from, to, stats }));
                ctx.request_repaint();
            }
        });
    }

    /// The newest finished window, once.
    pub fn poll(&self) -> Option<Window> {
        let current = self.seq.load(Ordering::Acquire);
        let mut latest = self.latest.lock().unwrap_or_else(|e| e.into_inner());
        while let Ok((seq, w)) = self.rx.try_recv() {
            if seq == current {
                *latest = Some(w);
            }
        }
        latest.take()
    }
}

/// Reads the windowed rows into an engine; `None` when superseded or the capture failed.
fn fold(
    backend: &dyn CaptureBackend,
    file: PathBuf,
    from: u32,
    to: u32,
    superseded: impl Fn() -> bool,
) -> Option<Arc<StatsSnapshot>> {
    let mut session = backend
        .start(CaptureSource::File(file), Some(window_filter(from, to)))
        .ok()?;
    let mut engine = StatsEngine::new();
    let mut done = false;
    while !done && !superseded() {
        match session.events.recv() {
            Ok(CaptureEvent::Rows(rows)) => engine.ingest_batch(&rows),
            Ok(CaptureEvent::Finished) => done = true,
            Ok(CaptureEvent::Failed(_)) | Err(_) => break,
        }
    }
    (session.stop)();
    done.then(|| Arc::new(engine.snapshot(TOP_N)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_selects_the_half_open_second_range() {
        assert_eq!(
            window_filter(3, 13),
            "frame.time_relative >= 3 && frame.time_relative < 13"
        );
    }
}
