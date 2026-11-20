//! Bounded background workers (frame dissection, filter validation, pcap export) owned by `Controller`.
//! Detail and filter requests coalesce into single-slot mailboxes with monotonic generation IDs so
//! rapid clicks/keystrokes never spawn unbounded threads or apply stale results.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crossbeam_channel::{Receiver, Sender, bounded};
use wl_model::{CaptureBackend, CaptureError, FrameDetail};

/// Result of one background job.
pub enum BgEvent {
    Detail(u64, u64, Result<FrameDetail, CaptureError>),
    Filter(u64, String, Result<(), CaptureError>),
    Export(Result<PathBuf, CaptureError>),
}

/// 1-slot "latest wins" mailbox: O(1) memory, never blocks producers, wakes one worker.
pub(crate) struct LatestSlot<T> {
    state: Mutex<(Option<T>, bool)>,
    cv: Condvar,
}

impl<T> LatestSlot<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new((None, false)),
            cv: Condvar::new(),
        }
    }

    pub(crate) fn put(&self, item: T) {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !g.1 {
            g.0 = Some(item);
            self.cv.notify_one();
        }
    }

    pub(crate) fn clear(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).0 = None;
    }

    pub(crate) fn take(&self) -> Option<T> {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(item) = g.0.take() {
                return Some(item);
            }
            if g.1 {
                return None;
            }
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    pub(crate) fn close(&self) {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        *g = (None, true);
        self.cv.notify_all();
    }
}

type DetailReq = (u64, (PathBuf, u64));
type FilterReq = (u64, String);
type ExportReq = (PathBuf, Option<Vec<u64>>, PathBuf);

fn spawn_latest<T, F>(
    slot: Arc<LatestSlot<(u64, T)>>,
    seq_ctr: Arc<AtomicU64>,
    tx: Sender<BgEvent>,
    mut work: F,
) where
    T: Send + 'static,
    F: FnMut(u64, T) -> BgEvent + Send + 'static,
{
    thread::spawn(move || {
        while let Some((seq, item)) = slot.take() {
            if seq_ctr.load(Ordering::Acquire) != seq {
                continue;
            }
            let ev = work(seq, item);
            if seq_ctr.load(Ordering::Acquire) == seq && tx.send(ev).is_err() {
                break;
            }
        }
    });
}

pub struct BgJobs {
    rx: Receiver<BgEvent>,
    detail_slot: Arc<LatestSlot<(u64, (PathBuf, u64))>>,
    detail_gen: Arc<AtomicU64>,
    detail_wanted: Option<(u64, u64)>,
    detail: Option<FrameDetail>,
    filter_slot: Arc<LatestSlot<FilterReq>>,
    filter_gen: Arc<AtomicU64>,
    filter_result: Option<(String, Result<(), CaptureError>)>,
    export_tx: Sender<ExportReq>,
}

impl BgJobs {
    pub fn new(backend: Arc<dyn CaptureBackend>) -> Self {
        let (tx, rx) = bounded(64);
        let detail_slot = Arc::new(LatestSlot::<DetailReq>::new());
        let detail_gen = Arc::new(AtomicU64::new(0));
        let filter_slot = Arc::new(LatestSlot::<FilterReq>::new());
        let filter_gen = Arc::new(AtomicU64::new(0));
        let (export_tx, export_rx) = bounded::<ExportReq>(8);

        let b1 = backend.clone();
        spawn_latest(
            detail_slot.clone(),
            detail_gen.clone(),
            tx.clone(),
            move |seq, (f, n)| BgEvent::Detail(seq, n, b1.frame_detail(&f, n)),
        );
        let b2 = backend.clone();
        spawn_latest(
            filter_slot.clone(),
            filter_gen.clone(),
            tx.clone(),
            move |seq, f| {
                let r = b2.check_filter(&f);
                BgEvent::Filter(seq, f, r)
            },
        );
        thread::spawn(move || {
            while let Ok((file, frames, dest)) = export_rx.recv() {
                let r = backend
                    .export(&file, frames.as_deref(), &dest)
                    .map(|()| dest);
                if tx.send(BgEvent::Export(r)).is_err() {
                    break;
                }
            }
        });

        Self {
            rx,
            detail_slot,
            detail_gen,
            detail_wanted: None,
            detail: None,
            filter_slot,
            filter_gen,
            filter_result: None,
            export_tx,
        }
    }

    pub fn detail(&self) -> Option<&FrameDetail> {
        self.detail.as_ref()
    }

    pub fn take_filter_result(&mut self) -> Option<(String, Result<(), CaptureError>)> {
        self.filter_result.take()
    }

    pub fn clear_detail(&mut self) {
        self.detail_gen.fetch_add(1, Ordering::AcqRel);
        self.detail_slot.clear();
        self.detail = None;
        self.detail_wanted = None;
    }

    pub fn request_detail(&mut self, file: PathBuf, frame_no: u64) {
        let seq = self.detail_gen.fetch_add(1, Ordering::AcqRel) + 1;
        self.detail_wanted = Some((seq, frame_no));
        self.detail_slot.put((seq, (file, frame_no)));
    }

    pub fn validate_filter(&self, filter: String) {
        let seq = self.filter_gen.fetch_add(1, Ordering::AcqRel) + 1;
        self.filter_slot.put((seq, filter));
    }

    pub fn export(&self, file: PathBuf, frames: Option<Vec<u64>>, dest: PathBuf) {
        let _ = self.export_tx.try_send((file, frames, dest));
    }

    /// Drains finished jobs into internal state; returns `(changed, notice, error)`.
    pub fn drain(&mut self) -> (bool, Option<String>, Option<CaptureError>) {
        let (mut changed, mut notice, mut error) = (false, None, None);
        let cur_filter_seq = self.filter_gen.load(Ordering::Acquire);
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                BgEvent::Detail(seq, no, Ok(d)) if self.detail_wanted == Some((seq, no)) => {
                    self.detail = Some(d);
                    changed = true;
                }
                BgEvent::Detail(seq, no, Err(e)) if self.detail_wanted == Some((seq, no)) => {
                    error = Some(e);
                    changed = true;
                }
                BgEvent::Detail(..) => {}
                BgEvent::Filter(seq, f, r) if seq == cur_filter_seq => {
                    self.filter_result = Some((f, r));
                    changed = true;
                }
                BgEvent::Filter(..) => {}
                BgEvent::Export(Ok(p)) => {
                    notice = Some(format!("Saved {}", p.display()));
                    changed = true;
                }
                BgEvent::Export(Err(e)) => {
                    error = Some(e);
                    changed = true;
                }
            }
        }
        (changed, notice, error)
    }
}

impl Drop for BgJobs {
    fn drop(&mut self) {
        self.detail_gen.fetch_add(1, Ordering::AcqRel);
        self.filter_gen.fetch_add(1, Ordering::AcqRel);
        self.detail_slot.close();
        self.filter_slot.close();
    }
}
