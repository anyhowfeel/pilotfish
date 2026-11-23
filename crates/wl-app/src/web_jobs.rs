//! Background jobs of the Web page: the HTTP/TLS scan of the backing file and the detail of one
//! exchange. Both are "latest wins" single-slot mailboxes (no unbounded threads, stale results are
//! dropped by a generation counter). `WebState` adds the refresh policy (new capture, live ticks).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, unbounded};
use wl_model::{CaptureBackend, CaptureError, HttpDetail, HttpExchange, MessageStream, TlsSession};

use crate::bg::LatestSlot;

/// Live captures are re-scanned this often while the Web page is visible.
pub const LIVE_REFRESH: Duration = Duration::from_secs(3);

pub type WebData = (Vec<HttpExchange>, Vec<TlsSession>, Vec<MessageStream>);

enum Event {
    Web(u64, Result<WebData, CaptureError>),
    Detail(u64, Result<HttpDetail, CaptureError>),
}

/// One mailbox + generation counter + "queued" / "running" flags.
struct Lane<T> {
    slot: Arc<LatestSlot<(u64, T)>>,
    generation: Arc<AtomicU64>,
    queued: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
}

impl<T: Send + 'static> Lane<T> {
    fn spawn(tx: Sender<Event>, run: impl Fn(u64, T) -> Event + Send + 'static) -> Self {
        let lane = Lane {
            slot: Arc::new(LatestSlot::new()),
            generation: Arc::new(AtomicU64::new(0)),
            queued: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
        };
        let (slot, generation) = (lane.slot.clone(), lane.generation.clone());
        let (queued, running) = (lane.queued.clone(), lane.running.clone());
        thread::spawn(move || {
            while let Some((seq, item)) = slot.take() {
                running.store(true, Ordering::Release);
                queued.store(false, Ordering::Release);
                if generation.load(Ordering::Acquire) == seq {
                    let ev = run(seq, item);
                    if generation.load(Ordering::Acquire) == seq && tx.send(ev).is_err() {
                        break;
                    }
                }
                running.store(false, Ordering::Release);
            }
        });
        lane
    }

    fn submit(&self, item: T) {
        let seq = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.queued.store(true, Ordering::Release);
        self.slot.put((seq, item));
    }

    /// Drops queued work and makes any running job's result stale.
    fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.slot.clear();
        self.queued.store(false, Ordering::Release);
    }

    fn in_flight(&self) -> bool {
        self.queued.load(Ordering::Acquire) || self.running.load(Ordering::Acquire)
    }

    fn current(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

impl<T> Drop for Lane<T> {
    fn drop(&mut self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.slot.close();
    }
}

pub struct WebJobs {
    rx: Receiver<Event>,
    scan: Lane<(PathBuf, Option<String>)>,
    detail: Lane<(PathBuf, HttpExchange)>,
    scan_result: Mutex<Option<WebData>>,
    detail_result: Mutex<Option<HttpDetail>>,
}

impl WebJobs {
    pub fn new(backend: Arc<dyn CaptureBackend>) -> Self {
        let (tx, rx) = unbounded();
        let b = backend.clone();
        let scan = Lane::spawn(
            tx.clone(),
            move |seq, (file, scope): (PathBuf, Option<String>)| {
                // The scans are independent tshark passes: run them side by side. They keep only what the
                // display filter of the application lets through.
                let scope = scope.as_deref();
                let (h, t, m) = thread::scope(|s| {
                    let h = s.spawn(|| b.http_exchanges_scoped(&file, scope));
                    let m = s.spawn(|| b.message_streams_scoped(&file, scope));
                    let t = b.tls_sessions_scoped(&file, scope);
                    (
                        h.join().unwrap_or_else(|_| Err(panic_err())),
                        t,
                        m.join().unwrap_or_else(|_| Err(panic_err())),
                    )
                });
                // Message streams are an extra tab: their failure must not hide the exchanges.
                let m = m.unwrap_or_default();
                Event::Web(seq, h.and_then(|h| t.map(|t| (h, t, m))))
            },
        );
        let detail = Lane::spawn(tx, move |seq, (file, ex): (PathBuf, HttpExchange)| {
            Event::Detail(seq, backend.http_detail(&file, &ex))
        });
        Self {
            rx,
            scan,
            detail,
            scan_result: Mutex::new(None),
            detail_result: Mutex::new(None),
        }
    }

    pub fn request(&self, file: PathBuf, scope: Option<String>) {
        self.scan.submit((file, scope));
    }

    pub fn request_detail(&self, file: PathBuf, ex: HttpExchange) {
        self.detail.submit((file, ex));
    }

    pub fn in_flight(&self) -> bool {
        self.scan.in_flight()
    }

    pub fn is_busy(&self) -> bool {
        self.scan.in_flight() || self.detail.in_flight() || !self.rx.is_empty()
    }

    /// Forgets results and cancels work for the previous capture.
    pub fn invalidate(&self) {
        self.scan.invalidate();
        self.detail.invalidate();
        *lock(&self.scan_result) = None;
        *lock(&self.detail_result) = None;
    }

    /// Moves finished jobs into the result slots; returns the first error of the current jobs.
    pub fn drain(&self) -> Option<CaptureError> {
        let mut err = None;
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Event::Web(seq, r) if seq == self.scan.current() => match r {
                    Ok(d) => *lock(&self.scan_result) = Some(d),
                    Err(e) => err = Some(e),
                },
                Event::Detail(seq, r) if seq == self.detail.current() => match r {
                    Ok(d) => *lock(&self.detail_result) = Some(d),
                    Err(e) => err = Some(e),
                },
                _ => {}
            }
        }
        err
    }

    pub fn take_web(&self) -> Option<WebData> {
        lock(&self.scan_result).take()
    }

    pub fn take_detail(&self) -> Option<HttpDetail> {
        lock(&self.detail_result).take()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn panic_err() -> CaptureError {
    CaptureError::Other("web scan thread panicked".into())
}

/// Refresh policy on top of `WebJobs`.
pub struct WebState {
    pub jobs: WebJobs,
    active: bool,
    dirty: bool,
    last: Option<Instant>,
}

impl WebState {
    pub fn new(backend: Arc<dyn CaptureBackend>) -> Self {
        Self {
            jobs: WebJobs::new(backend),
            active: false,
            dirty: true,
            last: None,
        }
    }

    pub fn set_active(&mut self, active: bool, live: bool) {
        // A live capture moved on while the page was hidden: refresh when it is shown again.
        self.dirty |= active && !self.active && live;
        self.active = active;
    }

    pub fn on_new_capture(&mut self) {
        self.jobs.invalidate();
        self.dirty = true;
        self.last = None;
    }

    /// The capture just stopped: one last scan so the page ends up complete.
    pub fn on_stop(&mut self, was_live: bool) {
        self.dirty |= was_live;
    }

    pub fn request_now(&mut self, backing: Option<PathBuf>, scope: Option<String>, now: Instant) {
        if let Some(file) = backing {
            self.jobs.request(file, scope);
            self.dirty = false;
            self.last = Some(now);
        }
    }

    /// Called every poll: starts a scan when one is due. Cheap when nothing is.
    pub fn tick(
        &mut self,
        backing: Option<PathBuf>,
        scope: Option<String>,
        live: bool,
        now: Instant,
    ) {
        if !self.active || self.jobs.in_flight() || backing.is_none() {
            return;
        }
        let stale = live
            && self
                .last
                .is_none_or(|t| now.duration_since(t) >= LIVE_REFRESH);
        if self.dirty || stale {
            self.request_now(backing, scope, now);
        }
    }
}

#[cfg(test)]
#[path = "web_jobs_tests.rs"]
mod tests;
