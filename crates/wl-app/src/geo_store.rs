//! Location databases managed from Settings: downloads proposed by wirelens and files added by
//! the user, all kept in one folder that `GeoDb` reads first.
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use maxminddb::Reader;
use wl_kit::format;
use wl_panels::settings::{GeoDbInfo, GeoDbRow, GeoDbState};

use crate::geo::GeoDb;

/// A database wirelens can download. DB-IP publishes a new "Lite" file every month.
pub struct Source {
    pub id: &'static str,
    pub title: &'static str,
    pub detail: &'static str,
    /// File name without the month and extension, e.g. `dbip-country-lite`.
    pub file: &'static str,
}

pub const SOURCES: [Source; 2] = [
    Source {
        id: "dbip-country",
        title: "DB-IP Country Lite",
        detail: "Country of public addresses. About 4 MB. CC BY 4.0, db-ip.com.",
        file: "dbip-country-lite",
    },
    Source {
        id: "dbip-asn",
        title: "DB-IP ASN Lite",
        detail: "Network operator (AS number and name). About 5 MB. CC BY 4.0, db-ip.com.",
        file: "dbip-asn-lite",
    },
];

const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_DOWNLOAD: u64 = 400 * 1024 * 1024;

enum Msg {
    Downloaded(&'static str, Result<(), String>),
    Picked(PathBuf),
}

pub struct GeoStore {
    dir: PathBuf,
    busy: HashSet<&'static str>,
    failed: HashMap<&'static str, String>,
    error: Option<String>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl Default for GeoStore {
    fn default() -> Self {
        Self::in_dir(GeoDb::primary_dir())
    }
}

impl GeoStore {
    pub fn in_dir(dir: PathBuf) -> Self {
        let (tx, rx) = unbounded();
        Self {
            dir,
            busy: HashSet::new(),
            failed: HashMap::new(),
            error: None,
            tx,
            rx,
        }
    }

    fn path_of(&self, file: &str) -> PathBuf {
        self.dir.join(format!("{file}.mmdb"))
    }

    fn size_of(path: &Path) -> Option<String> {
        std::fs::metadata(path).ok().map(|m| format::bytes(m.len()))
    }

    fn source_row(&self, s: &Source) -> GeoDbRow {
        let state = if self.busy.contains(s.id) {
            GeoDbState::Downloading
        } else if let Some(e) = self.failed.get(s.id) {
            GeoDbState::Failed(e.clone())
        } else {
            Self::size_of(&self.path_of(s.file)).map_or(GeoDbState::Missing, GeoDbState::Ready)
        };
        GeoDbRow {
            id: s.id.to_owned(),
            title: s.title.to_owned(),
            detail: s.detail.to_owned(),
            state,
            custom: false,
        }
    }

    /// `.mmdb` files of the folder that are not one of the proposed downloads.
    fn custom_files(&self) -> Vec<PathBuf> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut v: Vec<PathBuf> = rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "mmdb"))
            .filter(|p| {
                let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                !SOURCES.iter().any(|s| s.file == stem)
            })
            .collect();
        v.sort();
        v
    }

    pub fn info(&self) -> GeoDbInfo {
        let mut rows: Vec<GeoDbRow> = SOURCES.iter().map(|s| self.source_row(s)).collect();
        for p in self.custom_files() {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_owned();
            rows.push(GeoDbRow {
                id: name.clone(),
                title: name,
                detail: "Added by you.".to_owned(),
                state: Self::size_of(&p).map_or(GeoDbState::Missing, GeoDbState::Ready),
                custom: true,
            });
        }
        GeoDbInfo {
            dir: tilde(&self.dir),
            rows,
            error: self.error.clone(),
        }
    }

    pub fn download(&mut self, id: &str, ctx: &egui::Context) {
        let Some(src) = SOURCES.iter().find(|s| s.id == id) else {
            return;
        };
        if !self.busy.insert(src.id) {
            return;
        }
        self.failed.remove(src.id);
        let (dir, tx, ctx, file, sid) = (
            self.dir.clone(),
            self.tx.clone(),
            ctx.clone(),
            src.file,
            src.id,
        );
        std::thread::spawn(move || {
            let _ = tx.send(Msg::Downloaded(sid, fetch(file, &dir)));
            ctx.request_repaint();
        });
    }

    /// Opens a file dialog; the chosen database is validated and copied by `poll`.
    pub fn pick_file(&self, ctx: &egui::Context) {
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            if let Some(p) = rfd::FileDialog::new()
                .add_filter("MaxMind databases", &["mmdb"])
                .pick_file()
            {
                let _ = tx.send(Msg::Picked(p));
                ctx.request_repaint();
            }
        });
    }

    pub fn remove(&mut self, id: &str) {
        let valid = !id.contains(['/', '\\']) && id.ends_with(".mmdb") && id != ".mmdb";
        self.error = match valid.then(|| std::fs::remove_file(self.dir.join(id))) {
            Some(Ok(())) => None,
            Some(Err(e)) => Some(format!("Could not remove {id}: {e}")),
            None => Some(format!("Not a database file: {id}")),
        };
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

    /// Applies finished downloads and picked files; true when the set of databases changed.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        while let Ok(msg) = self.rx.try_recv() {
            changed = true;
            match msg {
                Msg::Downloaded(id, result) => {
                    self.busy.remove(id);
                    match result {
                        Ok(()) => self.error = None,
                        Err(e) => {
                            self.failed.insert(id, e);
                        }
                    }
                }
                Msg::Picked(path) => self.error = add_file(&path, &self.dir).err(),
            }
        }
        changed
    }
}

/// `path` for display, with the home folder written as `~`.
fn tilde(path: &Path) -> String {
    match dirs::home_dir().and_then(|h| path.strip_prefix(h).ok().map(Path::to_path_buf)) {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// `(year, month)` of the current month and of the one before it.
fn latest_months(year: i32, month: u32) -> [(i32, u32); 2] {
    let prev = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    [(year, month), prev]
}

fn url_for(file: &str, (year, month): (i32, u32)) -> String {
    format!("https://download.db-ip.com/free/{file}-{year}-{month:02}.mmdb.gz")
}

fn fetch(file: &str, dir: &Path) -> Result<(), String> {
    use chrono::Datelike;
    let today = chrono::Local::now();
    let mut last = String::from("no download available");
    for month in latest_months(today.year(), today.month()) {
        match download_gz(&url_for(file, month), dir, file) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn download_gz(url: &str, dir: &Path, file: &str) -> Result<(), String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let response = agent
        .get(url)
        .header("User-Agent", "wirelens")
        .call()
        .map_err(|e| format!("{e}"))?;
    let body = response
        .into_body()
        .into_with_config()
        .limit(MAX_DOWNLOAD)
        .reader();
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let part = dir.join(format!("{file}.mmdb.part"));
    let written = (|| -> io::Result<()> {
        let mut out = std::fs::File::create(&part)?;
        io::copy(&mut flate2::read::GzDecoder::new(body), &mut out)?;
        Ok(())
    })();
    let result = written
        .map_err(|e| e.to_string())
        .and_then(|()| validate(&part))
        .and_then(|()| {
            std::fs::rename(&part, dir.join(format!("{file}.mmdb"))).map_err(|e| e.to_string())
        });
    if result.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    result
}

fn validate(path: &Path) -> Result<(), String> {
    Reader::open_readfile(path)
        .map(drop)
        .map_err(|_| "not a valid MaxMind database".to_owned())
}

/// Copies a database chosen by the user into the managed folder after checking it opens.
fn add_file(src: &Path, dir: &Path) -> Result<(), String> {
    validate(src).map_err(|e| format!("{}: {e}", src.display()))?;
    let name = src.file_name().ok_or("no file name")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::copy(src, dir.join(name))
        .map(drop)
        .map_err(|e| format!("Could not copy {}: {e}", src.display()))
}

#[cfg(test)]
#[path = "geo_store_tests.rs"]
mod tests;
