//! Offline threat lists read from one local folder: JA4DB `.json` exports and plain-text / CSV
//! blocklists. Nothing is ever downloaded; the user drops files in the folder.
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use wl_kit::format;
use wl_model::ThreatIntel;
use wl_panels::settings::IntelInfo;

const MAX_FILE: u64 = 256 * 1024 * 1024;

pub type IntelHandle = Arc<RwLock<Arc<ThreatIntel>>>;

#[derive(Default)]
struct Loaded {
    intel: ThreatIntel,
    errors: Vec<String>,
}

enum Msg {
    Loaded(Loaded),
    Picked(PathBuf),
}

pub struct IntelStore {
    dir: PathBuf,
    shared: IntelHandle,
    loaded: Loaded,
    loading: bool,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl Default for IntelStore {
    fn default() -> Self {
        Self::in_dir(primary_dir())
    }
}

fn primary_dir() -> PathBuf {
    std::env::var_os("WIRELENS_INTEL_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::data_dir().map(|d| d.join("wirelens").join("intel")))
        .unwrap_or_default()
}

impl IntelStore {
    pub fn in_dir(dir: PathBuf) -> Self {
        let (tx, rx) = unbounded();
        Self {
            dir,
            shared: IntelHandle::default(),
            loaded: Loaded::default(),
            loading: false,
            tx,
            rx,
        }
    }

    pub fn handle(&self) -> IntelHandle {
        self.shared.clone()
    }

    pub fn current(&self) -> Arc<ThreatIntel> {
        self.shared.read().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn reload(&mut self, ctx: &egui::Context) {
        self.loading = true;
        let (dir, tx, ctx) = (self.dir.clone(), self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(Msg::Loaded(load_dir(&dir)));
            ctx.request_repaint();
        });
    }

    pub fn pick_file(&self, ctx: &egui::Context) {
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                let _ = tx.send(Msg::Picked(p));
                ctx.request_repaint();
            }
        });
    }

    pub fn open_folder(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .and_then(|()| {
                std::process::Command::new("xdg-open")
                    .arg(&self.dir)
                    .spawn()
                    .map(drop)
            })
            .map_err(|e| format!("Could not open {}: {e}", self.dir.display()))
    }

    /// Applies finished loads and picked files; true when the lists changed.
    pub fn poll(&mut self, ctx: &egui::Context) -> bool {
        let mut changed = false;
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Loaded(l) => {
                    if let Ok(mut g) = self.shared.write() {
                        *g = Arc::new(l.intel.clone());
                    }
                    self.loaded = l;
                    self.loading = false;
                    changed = true;
                }
                Msg::Picked(src) => match add_file(&src, &self.dir) {
                    Ok(()) => self.reload(ctx),
                    Err(e) => self.loaded.errors = vec![e],
                },
            }
        }
        changed
    }

    pub fn info(&self) -> IntelInfo {
        IntelInfo {
            dir: self.dir.display().to_string(),
            summary: summary(&self.loaded.intel),
            loading: self.loading,
            errors: self.loaded.errors.clone(),
        }
    }
}

fn summary(intel: &ThreatIntel) -> String {
    let (ips, domains, prints) = intel.counts();
    if intel.is_empty() {
        return "No lists found".to_owned();
    }
    let item = |n: usize, one: &str, many: &str| {
        format!(
            "{} {}",
            format::count(n as u64),
            if n == 1 { one } else { many }
        )
    };
    [
        item(ips, "address", "addresses"),
        item(domains, "domain", "domains"),
        item(prints, "fingerprint", "fingerprints"),
    ]
    .join(", ")
}

/// Reads every regular file of `dir`: `.json` as a JA4DB export, anything else as a blocklist
/// named after the file.
fn load_dir(dir: &Path) -> Loaded {
    let mut out = Loaded::default();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut files: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && !is_hidden(p))
        .collect();
    files.sort();
    for path in files {
        if let Err(e) = load_file(&path, &mut out.intel) {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            out.errors.push(format!("{name}: {e}"));
        }
    }
    out
}

fn is_hidden(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with('.'))
}

fn load_file(path: &Path, intel: &mut ThreatIntel) -> Result<(), String> {
    let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if size > MAX_FILE {
        return Err("larger than 256 MiB".to_owned());
    }
    let text = std::fs::read_to_string(path).map_err(|_| "not a text file".to_owned())?;
    if path
        .extension()
        .is_some_and(|x| x.eq_ignore_ascii_case("json"))
    {
        return intel.add_ja4db(&text).map(drop);
    }
    let list = path.file_stem().unwrap_or_default().to_string_lossy();
    intel.add_blocklist(&list, &text);
    Ok(())
}

fn add_file(src: &Path, dir: &Path) -> Result<(), String> {
    let name = src.file_name().ok_or("no file name")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::copy(src, dir.join(name))
        .map(drop)
        .map_err(|e| format!("Could not copy {}: {e}", src.display()))
}

#[cfg(test)]
#[path = "intel_store_tests.rs"]
mod tests;
