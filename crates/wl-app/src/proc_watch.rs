//! Background poller that keeps a `ProcessMap` fresh while a live capture runs.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use eframe::egui;
use wl_model::{FlowKey, ProcessInfo, ProcessMap};

use crate::proc_scan::scan;

const PERIOD: Duration = Duration::from_secs(2);
const PROC: &str = "/proc";

#[derive(Clone, Default)]
pub struct ProcWatch {
    map: Arc<RwLock<ProcessMap>>,
    active: Arc<AtomicBool>,
    updated: Arc<AtomicBool>,
}

impl ProcWatch {
    pub fn spawn(ctx: egui::Context) -> Self {
        let w = Self::default();
        if cfg!(target_os = "linux") {
            let bg = w.clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(PERIOD);
                    if bg.active.load(Ordering::Relaxed) {
                        bg.merge(scan(Path::new(PROC)));
                        ctx.request_repaint();
                    }
                }
            });
        }
        w
    }

    fn replace(&self, map: ProcessMap) {
        if let Ok(mut g) = self.map.write() {
            *g = map;
            self.updated.store(true, Ordering::Relaxed);
        }
    }

    fn merge(&self, scanned: ProcessMap) {
        if let Ok(mut g) = self.map.write() {
            *g = std::mem::take(&mut *g).refreshed(scanned);
            self.updated.store(true, Ordering::Relaxed);
        }
    }

    pub fn set_active(&self, on: bool) {
        self.active.store(on, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.replace(ProcessMap::default());
    }

    pub fn take_updated(&self) -> bool {
        self.updated.swap(false, Ordering::Relaxed)
    }

    pub fn has_any(&self) -> bool {
        self.map.read().is_ok_and(|m| !m.is_empty())
    }

    pub fn for_host(&self, addr: &str) -> Vec<ProcessInfo> {
        self.map
            .read()
            .map(|m| m.for_host(addr).to_vec())
            .unwrap_or_default()
    }

    pub fn for_flow(&self, key: &FlowKey) -> Option<ProcessInfo> {
        self.map.read().ok()?.for_flow(key).cloned()
    }
}
