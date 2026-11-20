//! Capture file properties dialog: `capinfos` summary on a helper thread, SHA256 computed lazily.

use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use wl_model::{CaptureBackend, CaptureProperties};
use wl_panels::properties::{PropertiesAction, PropertiesDialog};

/// Files up to this size get their hash computed right away (it reads the whole file).
const AUTO_HASH_MAX: u64 = 256 << 20;

enum Msg {
    Props(PathBuf, Result<Box<CaptureProperties>, String>),
    Hash(PathBuf, Result<String, String>),
}

pub struct PropsHub {
    backend: Arc<dyn CaptureBackend>,
    ctx: egui::Context,
    pub dialog: PropertiesDialog,
    file: Option<PathBuf>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl PropsHub {
    pub fn new(backend: Arc<dyn CaptureBackend>, ctx: egui::Context) -> Self {
        let (tx, rx) = unbounded();
        Self {
            backend,
            ctx,
            dialog: PropertiesDialog::default(),
            file: None,
            tx,
            rx,
        }
    }

    /// Opens the dialog for `file` and starts reading its properties.
    pub fn open(&mut self, file: PathBuf) {
        self.dialog.begin();
        self.file = Some(file.clone());
        let (backend, tx, ctx) = (self.backend.clone(), self.tx.clone(), self.ctx.clone());
        std::thread::spawn(move || {
            let r = backend
                .capture_properties(&file)
                .map(Box::new)
                .map_err(|e| e.to_string());
            let _ = tx.send(Msg::Props(file, r));
            ctx.request_repaint();
        });
    }

    fn start_hash(&mut self) {
        let Some(file) = self.file.clone() else {
            return;
        };
        self.dialog.set_hash_computing();
        let (backend, tx, ctx) = (self.backend.clone(), self.tx.clone(), self.ctx.clone());
        std::thread::spawn(move || {
            let r = backend.file_sha256(&file).map_err(|e| e.to_string());
            let _ = tx.send(Msg::Hash(file, r));
            ctx.request_repaint();
        });
    }

    /// Stores finished jobs; true when the dialog changed.
    pub fn pump(&mut self) -> bool {
        let mut changed = false;
        while let Ok(m) = self.rx.try_recv() {
            changed = true;
            match m {
                Msg::Props(f, r) if Some(&f) == self.file.as_ref() => {
                    let small = r.as_ref().is_ok_and(|p| p.file_size <= AUTO_HASH_MAX);
                    self.dialog.set_properties(r.map(|p| *p));
                    if small {
                        self.start_hash();
                    }
                }
                Msg::Hash(f, r) if Some(&f) == self.file.as_ref() => self.dialog.set_hash(r),
                _ => {}
            }
        }
        if changed {
            // The window sizes itself from the previous frame's content: one more frame settles it.
            self.ctx.request_repaint();
        }
        changed
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        if let Some(PropertiesAction::ComputeHash) = self.dialog.ui(ctx) {
            self.start_hash();
        }
    }
}
