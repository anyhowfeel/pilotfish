//! Capture Diff page glue: second-capture picker, background comparison, panel.
use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use wl_model::CaptureBackend;
use wl_panels::diff::{DiffAction, DiffData, DiffPanel, DiffState};
use wl_stats::CaptureDiff;

use crate::dialogs::pick_capture;
use crate::diff_scan::scan;

type Pair = (PathBuf, PathBuf);

pub struct DiffHub {
    backend: Arc<dyn CaptureBackend>,
    panel: DiffPanel,
    state: DiffState,
    other: Option<PathBuf>,
    started: Option<Pair>,
    picker: Option<Receiver<PathBuf>>,
    tx: Sender<(Pair, Result<CaptureDiff, String>)>,
    rx: Receiver<(Pair, Result<CaptureDiff, String>)>,
}

fn compare(backend: &dyn CaptureBackend, (a, b): &Pair) -> Result<CaptureDiff, String> {
    let (a, b) = std::thread::scope(|s| {
        let first = s.spawn(|| scan(backend, a));
        let second = scan(backend, b);
        (first.join(), second)
    });
    let first = a.map_err(|_| "the comparison panicked".to_owned())?;
    Ok(CaptureDiff::compute(
        &first.map_err(|e| e.to_string())?,
        &b.map_err(|e| e.to_string())?,
    ))
}

impl DiffHub {
    pub fn new(backend: Arc<dyn CaptureBackend>) -> Self {
        let (tx, rx) = unbounded();
        Self {
            backend,
            panel: DiffPanel::default(),
            state: DiffState::Idle,
            other: None,
            started: None,
            picker: None,
            tx,
            rx,
        }
    }

    pub fn set_other(&mut self, file: PathBuf) {
        self.other = Some(file);
    }

    fn start(&mut self, pair: Pair, ctx: &egui::Context) {
        self.state = DiffState::Loading;
        self.started = Some(pair.clone());
        let (backend, tx, ctx) = (self.backend.clone(), self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = compare(&*backend, &pair);
            let _ = tx.send((pair, result));
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        for (pair, result) in self.rx.try_iter() {
            if self.started.as_ref() != Some(&pair) {
                continue;
            }
            self.state = match result {
                Ok(d) => DiffState::Ready(Arc::new(d)),
                Err(e) => DiffState::Error(e),
            };
        }
        if let Some(p) = self.picker.as_ref().and_then(|r| r.try_recv().ok()) {
            self.other = Some(p);
            self.picker = None;
        }
    }

    /// `base` is the open capture's file and display name.
    pub fn ui(&mut self, ui: &mut egui::Ui, base: Option<(PathBuf, String)>) {
        self.poll();
        if let (Some((file, _)), Some(other)) = (&base, &self.other) {
            let pair = (file.clone(), other.clone());
            if self.started.as_ref() != Some(&pair) {
                self.start(pair, ui.ctx());
            }
        }
        let name = |p: &PathBuf| p.file_name().map(|n| n.to_string_lossy().into_owned());
        let other = self.other.as_ref().and_then(name);
        let data = DiffData {
            state: &self.state,
            base: base.as_ref().map_or("", |(_, n)| n),
            other: other.as_deref(),
        };
        for DiffAction::PickFile in self.panel.ui(ui, &data) {
            self.picker = Some(pick_capture(ui.ctx().clone()));
        }
    }
}
