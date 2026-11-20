//! Off-thread `CaptureBackend::frame_fields` requests (Find Packet, custom columns).
//! One short-lived thread per request; the panel matches results to requests by id.

use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use wl_model::{CaptureBackend, FrameFields};

pub type FieldsResult = (u64, Result<Vec<FrameFields>, String>);

pub struct FieldJobs {
    backend: Arc<dyn CaptureBackend>,
    tx: Sender<FieldsResult>,
    rx: Receiver<FieldsResult>,
}

impl FieldJobs {
    pub fn new(backend: Arc<dyn CaptureBackend>) -> Self {
        let (tx, rx) = unbounded();
        Self { backend, tx, rx }
    }

    pub fn request(
        &self,
        file: PathBuf,
        id: u64,
        filter: String,
        fields: Vec<String>,
        ctx: egui::Context,
    ) {
        let (backend, tx) = (self.backend.clone(), self.tx.clone());
        std::thread::spawn(move || {
            let r = backend
                .frame_fields(&file, &filter, &fields)
                .map_err(|e| e.to_string());
            let _ = tx.send((id, r));
            ctx.request_repaint();
        });
    }

    pub fn poll(&self) -> Vec<FieldsResult> {
        self.rx.try_iter().collect()
    }
}
