//! TLS key log management: choosing the file (dialog or drop), applying it to the backend and
//! reloading the capture, and saving a copy of the capture with the keys embedded.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use wl_model::CaptureSource;
use wl_panels::web::KeysInfo;
use wl_tshark::TsharkBackend;

use crate::app::App;
use crate::dispatch::Command;

enum Msg {
    Picked(PathBuf),
    Embedded(Result<String, String>),
}

pub struct KeysLink {
    tshark: Option<Arc<TsharkBackend>>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl KeysLink {
    pub fn new(tshark: Option<Arc<TsharkBackend>>) -> Self {
        let (tx, rx) = unbounded();
        Self { tshark, tx, rx }
    }

    pub fn info(&self) -> KeysInfo {
        let Some(b) = &self.tshark else {
            return KeysInfo::default();
        };
        KeysInfo {
            file: b.tls_keylog().map(|p| display_name(&p)),
            can_embed: b.can_embed_tls_keys(),
        }
    }

    pub fn pick(&self, ctx: &egui::Context) {
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            if let Some(p) = rfd::FileDialog::new()
                .add_filter("TLS key log", &["log", "keys", "keylog", "txt"])
                .add_filter("All files", &["*"])
                .pick_file()
            {
                let _ = tx.send(Msg::Picked(p));
                ctx.request_repaint();
            }
        });
    }

    pub fn embed(&self, source: PathBuf, ctx: &egui::Context) {
        let Some(b) = self.tshark.clone() else { return };
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let Some(dest) = rfd::FileDialog::new()
                .set_file_name(embed_name(&source))
                .add_filter("pcapng", &["pcapng"])
                .save_file()
            else {
                return;
            };
            let done = b
                .embed_tls_keys(&source, &dest)
                .map(|()| format!("Saved a capture with the TLS keys to {}", dest.display()))
                .map_err(|e| e.to_string());
            let _ = tx.send(Msg::Embedded(done));
            ctx.request_repaint();
        });
    }
}

fn display_name(p: &Path) -> String {
    p.file_name().map_or_else(
        || p.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

fn embed_name(source: &Path) -> String {
    let stem = source.file_stem().map_or_else(
        || "capture".to_owned(),
        |s| s.to_string_lossy().into_owned(),
    );
    format!("{stem}-keys.pcapng")
}

impl App {
    /// Applies a key log (or clears it) and re-dissects what is on screen.
    pub(crate) fn set_keylog(&mut self, path: Option<PathBuf>, ctx: &egui::Context) {
        let Some(b) = &self.keys.tshark else { return };
        b.set_tls_keylog(path);
        match self.ctrl.source().cloned() {
            Some(CaptureSource::File(p)) => self.execute(Command::OpenFile(p), ctx),
            _ => self.web_link.clear(),
        }
    }

    /// A dropped file is a key log when it looks like one, otherwise a capture to open.
    pub(crate) fn dropped_file(&mut self, p: PathBuf, ctx: &egui::Context) {
        if wl_tshark::keylog::is_keylog_file(&p) {
            self.set_keylog(Some(p), ctx);
        } else {
            self.execute(Command::OpenFile(p), ctx);
        }
    }

    pub(crate) fn keys_action(&mut self, a: wl_panels::web::WebAction, ctx: &egui::Context) {
        use wl_panels::web::WebAction as A;
        match a {
            A::PickKeylog => self.keys.pick(ctx),
            A::ClearKeylog => self.set_keylog(None, ctx),
            A::EmbedKeys => match self.ctrl.backing() {
                Some(file) => self.keys.embed(file, ctx),
                None => self.hub.error = Some("Open a capture first.".into()),
            },
            _ => {}
        }
    }

    pub(crate) fn pump_keys(&mut self, ctx: &egui::Context) {
        while let Ok(m) = self.keys.rx.try_recv() {
            match m {
                Msg::Picked(p) => self.set_keylog(Some(p), ctx),
                Msg::Embedded(Ok(s)) => self.hub.notice = Some(s),
                Msg::Embedded(Err(e)) => self.hub.error = Some(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_copy_gets_its_own_name() {
        assert_eq!(embed_name(Path::new("/x/a.b.pcap")), "a.b-keys.pcapng");
        assert_eq!(display_name(Path::new("/x/keys.log")), "keys.log");
    }
}
