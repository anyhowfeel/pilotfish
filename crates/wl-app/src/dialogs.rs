//! Non-blocking native file dialogs (open / export) run on background threads.
use std::path::PathBuf;

use crossbeam_channel::{Receiver, unbounded};
use eframe::egui;

pub struct FileDialogs {
    open_rx: Receiver<PathBuf>,
    export_rx: Receiver<PathBuf>,
    export_frames: Vec<u64>,
}

impl Default for FileDialogs {
    fn default() -> Self {
        Self {
            open_rx: unbounded().1,
            export_rx: unbounded().1,
            export_frames: Vec::new(),
        }
    }
}

/// Opens the native "choose a capture" dialog on a thread; the chosen path arrives on the receiver.
pub fn pick_capture(ctx: egui::Context) -> Receiver<PathBuf> {
    let (tx, rx) = unbounded();
    std::thread::spawn(move || {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("Captures", &["pcap", "pcapng", "cap"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            let _ = tx.send(p);
            ctx.request_repaint();
        }
    });
    rx
}

impl FileDialogs {
    pub fn ask_open(&mut self, ctx: egui::Context) {
        self.open_rx = pick_capture(ctx);
    }

    pub fn ask_export(&mut self, frames: Vec<u64>, ctx: egui::Context) {
        let (tx, rx) = unbounded();
        self.export_rx = rx;
        self.export_frames = frames;
        std::thread::spawn(move || {
            if let Some(p) = rfd::FileDialog::new()
                .set_file_name("capture.pcapng")
                .add_filter("pcapng", &["pcapng", "pcap"])
                .save_file()
            {
                let _ = tx.send(p);
                ctx.request_repaint();
            }
        });
    }

    pub fn poll_open(&self) -> Option<PathBuf> {
        self.open_rx.try_recv().ok()
    }

    pub fn poll_export(&mut self) -> Option<(Option<Vec<u64>>, PathBuf)> {
        let dest = self.export_rx.try_recv().ok()?;
        let frames = std::mem::take(&mut self.export_frames);
        Some((Some(frames).filter(|f| !f.is_empty()), dest))
    }
}
