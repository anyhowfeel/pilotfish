//! Background helpers of the Setup page, all off the UI thread:
//! a ~1 Hz interface traffic sampler (only while the page is visible) and capture-filter checks.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use wl_model::{CaptureBackend, CaptureError, Interface};
use wl_panels::overview::{ActivityMap, FilterStatus};
use wl_tshark::netinfo;

const TICK: Duration = Duration::from_millis(250);
const SAMPLE_EVERY: Duration = Duration::from_secs(1);

struct Shared {
    activity: Mutex<ActivityMap>,
    names: Mutex<Vec<String>>,
    visible: AtomicBool,
}

pub struct SetupIo {
    shared: Arc<Shared>,
    backend: Arc<dyn CaptureBackend>,
    ctx: egui::Context,
    tx: Sender<FilterStatus>,
    rx: Receiver<FilterStatus>,
    status: Option<FilterStatus>,
}

impl SetupIo {
    pub fn new(backend: Arc<dyn CaptureBackend>, ctx: egui::Context) -> Self {
        let shared = Arc::new(Shared {
            activity: Mutex::default(),
            names: Mutex::default(),
            visible: AtomicBool::new(false),
        });
        let (s, c) = (shared.clone(), ctx.clone());
        std::thread::spawn(move || sampler(&s, &c));
        let (tx, rx) = unbounded();
        SetupIo {
            shared,
            backend,
            ctx,
            tx,
            rx,
            status: None,
        }
    }

    /// Tell the sampler whether the Setup page is on screen (it idles otherwise).
    pub fn set_visible(&self, visible: bool) {
        self.shared.visible.store(visible, Ordering::Relaxed);
    }

    pub fn set_interfaces(&self, list: &[Interface]) {
        let names = list
            .iter()
            .filter(|i| i.sys.present)
            .map(|i| i.name.clone())
            .collect();
        *self.shared.names.lock().unwrap_or_else(|e| e.into_inner()) = names;
    }

    pub fn activity(&self) -> MutexGuard<'_, ActivityMap> {
        self.shared
            .activity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub fn status(&self) -> Option<&FilterStatus> {
        self.status.as_ref()
    }

    /// Validates `filter` on `interface` in the background; the answer shows up in `status()`.
    pub fn check_filter(&self, interface: String, filter: String) {
        let (b, tx, ctx) = (self.backend.clone(), self.tx.clone(), self.ctx.clone());
        std::thread::spawn(move || {
            let result = b
                .check_capture_filter(&interface, &filter)
                .map_err(|e| match e {
                    CaptureError::BadFilter(m) => m,
                    other => other.to_string(),
                });
            let _ = tx.send(FilterStatus {
                interface,
                filter,
                result,
            });
            ctx.request_repaint();
        });
    }

    /// Collects finished filter checks. Call once per frame.
    pub fn poll(&mut self) {
        while let Ok(s) = self.rx.try_recv() {
            self.status = Some(s);
        }
    }
}

fn sampler(shared: &Arc<Shared>, ctx: &egui::Context) {
    let mut prev: HashMap<String, (u64, Instant)> = HashMap::new();
    let mut last = Instant::now() - SAMPLE_EVERY;
    loop {
        std::thread::sleep(TICK);
        if Arc::strong_count(shared) == 1 {
            return; // the app is gone
        }
        if !shared.visible.load(Ordering::Relaxed) {
            prev.clear(); // counters keep running while hidden: restart the deltas on return
            continue;
        }
        if last.elapsed() < SAMPLE_EVERY {
            continue;
        }
        last = Instant::now();
        let names = shared
            .names
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut act = shared.activity.lock().unwrap_or_else(|e| e.into_inner());
        for n in names {
            let Some(bytes) = netinfo::byte_counters(&n) else {
                continue;
            };
            let now = Instant::now();
            if let Some((p, t)) = prev.insert(n.clone(), (bytes, now)) {
                let rate = netinfo::rate(p, bytes, now.duration_since(t).as_secs_f64());
                act.entry(n).or_default().push(rate);
            }
        }
        drop(act);
        ctx.request_repaint();
    }
}
