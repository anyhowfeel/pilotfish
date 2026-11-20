//! Background jobs of the "extras" features: Export Objects, Decode As, DNS query log.
//! Every job runs on its own short-lived thread and answers through one channel; results of a
//! previous capture or rule set are dropped by a generation counter.

mod glue;
mod preview;

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use wl_model::{CaptureBackend, DecodeAs, DnsQuery, ExportObject, ObjectSet};
use wl_panels::decode_as::DecodeAsDialog;
use wl_panels::web::PreviewData;
use wl_tshark::objects_save;

pub(crate) enum Msg {
    Objects(String, Result<Arc<ObjectSet>, String>),
    Preview(PreviewData),
    Dns(Result<Arc<Vec<DnsQuery>>, String>),
    Protocols(String, Result<Vec<String>, String>),
    Done(Result<String, String>),
}

pub struct Extras {
    backend: Arc<dyn CaptureBackend>,
    ctx: egui::Context,
    tx: Sender<(u64, Msg)>,
    rx: Receiver<(u64, Msg)>,
    generation: u64,
    pub decode: DecodeAsDialog,
    pub rules: Vec<DecodeAs>,
}

impl Extras {
    /// `rules` (from the preferences / command line) are active from the first dissection on.
    pub fn new(backend: Arc<dyn CaptureBackend>, ctx: egui::Context, rules: Vec<DecodeAs>) -> Self {
        backend.set_decode_as(rules.clone());
        let (tx, rx) = unbounded();
        Self {
            backend,
            ctx,
            tx,
            rx,
            generation: 0,
            decode: DecodeAsDialog::default(),
            rules,
        }
    }

    /// A new capture (or new rules) makes pending results stale.
    pub fn reset(&mut self) {
        self.generation += 1;
    }

    /// Replaces the Decode As rules in the backend; later dissections use them.
    pub fn set_rules(&mut self, rules: Vec<DecodeAs>) {
        self.backend.set_decode_as(rules.clone());
        self.rules = rules;
        self.reset();
    }

    pub(crate) fn poll(&mut self) -> Vec<Msg> {
        let gen_now = self.generation;
        self.rx
            .try_iter()
            .filter(|(g, m)| *g == gen_now || matches!(m, Msg::Done(_) | Msg::Protocols(..)))
            .map(|(_, m)| m)
            .collect()
    }

    fn spawn(&self, job: impl FnOnce(&dyn CaptureBackend) -> Msg + Send + 'static) {
        let (b, tx, ctx, g) = (
            self.backend.clone(),
            self.tx.clone(),
            self.ctx.clone(),
            self.generation,
        );
        thread::spawn(move || {
            let _ = tx.send((g, job(b.as_ref())));
            ctx.request_repaint();
        });
    }

    pub fn load_objects(&self, file: PathBuf, protocol: String) {
        self.spawn(move |b| {
            let r = b
                .export_objects(&file, &protocol)
                .map(Arc::new)
                .map_err(|e| e.to_string());
            Msg::Objects(protocol, r)
        });
    }

    pub fn load_preview(&self, set: Arc<ObjectSet>, id: u32) {
        self.spawn(move |_| match set.objects.get(id as usize) {
            Some(o) => Msg::Preview(preview::build(&set, o)),
            None => Msg::Done(Err("object no longer available".into())),
        });
    }

    pub fn load_dns(&self, file: PathBuf) {
        self.spawn(move |b| {
            Msg::Dns(
                b.dns_queries(&file)
                    .map(Arc::new)
                    .map_err(|e| e.to_string()),
            )
        });
    }

    pub fn load_protocols(&self, field: String) {
        self.spawn(move |b| {
            let r = b.decode_protocols(&field).map_err(|e| e.to_string());
            Msg::Protocols(field, r)
        });
    }

    /// Asks where to save one object, then copies it there.
    pub fn save_one(&self, set: Arc<ObjectSet>, o: ExportObject) {
        self.spawn(move |_| {
            let dest = rfd::FileDialog::new()
                .set_file_name(&o.save_name)
                .save_file();
            Msg::Done(match dest {
                None => return Msg::Done(Ok(String::new())),
                Some(d) => objects_save::save_as(&set, &o, &d)
                    .map(|()| format!("Saved {}", d.display()))
                    .map_err(|e| format!("Could not save {}: {e}", o.save_name)),
            })
        });
    }

    /// Asks for a folder, then copies every object into it under its sanitised name.
    pub fn save_all(&self, set: Arc<ObjectSet>) {
        self.spawn(move |_| {
            let Some(dir) = rfd::FileDialog::new().pick_folder() else {
                return Msg::Done(Ok(String::new()));
            };
            Msg::Done(
                objects_save::save_all(&set, &dir)
                    .map(|n| format!("Saved {n} files to {}", dir.display()))
                    .map_err(|e| format!("Could not save files: {e}")),
            )
        });
    }
}
