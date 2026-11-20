//! Persisted preferences (ui scale, theme mode, recent files) in the user config dir.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wl_panels::settings::{Settings, ThemeChoice};

const MAX_RECENT: usize = 8;
/// Version 2 moved `ui_scale` / `light_mode` into `settings`.
const VERSION: u32 = 2;

fn legacy_version() -> u32 {
    0
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Files written before versioning have no field: treat them as version 0.
    #[serde(default = "legacy_version")]
    pub version: u32,
    pub settings: Settings,
    pub recent: Vec<PathBuf>,
    /// Favourite capture files, shown above the recent ones.
    pub pinned: Vec<PathBuf>,
    /// Packet count of capture files opened before (canonical path -> packets).
    pub packet_counts: HashMap<PathBuf, u64>,
    pub filter_history: Vec<String>,
    pub layout: Option<wl_panels::packets::Layout>,
    /// Packet-list columns (order, visibility, custom fields) and time display format.
    pub table: wl_panels::packets::TablePrefs,
    /// "Decode As" rules, applied to every dissection.
    pub decode_as: Vec<wl_model::DecodeAs>,
    /// Pre-v2 fields, read once by `migrate` and never written back.
    #[serde(skip_serializing_if = "Option::is_none")]
    ui_scale: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    light_mode: Option<bool>,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            version: VERSION,
            settings: Settings::default(),
            recent: Vec::new(),
            pinned: Vec::new(),
            packet_counts: HashMap::new(),
            filter_history: Vec::new(),
            layout: None,
            table: Default::default(),
            decode_as: Vec::new(),
            ui_scale: None,
            light_mode: None,
        }
    }
}

impl Prefs {
    /// Upgrades an older file in place and clamps every setting.
    pub fn migrate(mut self) -> Prefs {
        if self.version < 2 {
            if let Some(s) = self.ui_scale {
                self.settings.ui_scale = s;
            }
            if let Some(light) = self.light_mode {
                self.settings.theme = if light {
                    ThemeChoice::Light
                } else {
                    ThemeChoice::Dark
                };
            }
        }
        self.version = VERSION;
        self.ui_scale = None;
        self.light_mode = None;
        self.settings = self.settings.clamped();
        self
    }

    pub fn path() -> Option<PathBuf> {
        // WIRELENS_CONFIG_DIR redirects the file (screenshots / tests must not touch real prefs).
        let dir = std::env::var_os("WIRELENS_CONFIG_DIR")
            .map(PathBuf::from)
            .or_else(|| dirs::config_dir().map(|d| d.join("wirelens")))?;
        Some(dir.join("prefs.json"))
    }

    pub fn load() -> Prefs {
        Self::path()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<Prefs>(&b).ok())
            .unwrap_or_default()
            .migrate()
            .tidy()
    }

    pub fn save(&self) {
        let Some(path) = Self::path() else { return };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_vec_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Canonicalises recent and pinned paths, drops duplicates and files that no longer exist.
    pub fn tidy(mut self) -> Prefs {
        let clean = |list: &[PathBuf]| {
            let mut out: Vec<PathBuf> = Vec::new();
            for p in list {
                if let Ok(c) = std::fs::canonicalize(p)
                    && c.is_file()
                    && !out.contains(&c)
                {
                    out.push(c);
                }
            }
            out
        };
        self.recent = clean(&self.recent);
        self.pinned = clean(&self.pinned);
        self.recent.truncate(MAX_RECENT);
        self.prune_counts();
        self
    }

    fn prune_counts(&mut self) {
        let keep: Vec<PathBuf> = self.recent.iter().chain(&self.pinned).cloned().collect();
        self.packet_counts.retain(|k, _| keep.contains(k));
    }

    pub fn clear_recent(&mut self) {
        self.recent.clear();
        self.prune_counts();
    }

    pub fn toggle_pin(&mut self, file: &Path) {
        if let Some(i) = self.pinned.iter().position(|p| p == file) {
            self.pinned.remove(i);
        } else {
            self.pinned.push(file.to_path_buf());
        }
        self.prune_counts();
    }

    /// Remembers how many packets `file` holds (shown in the recent list).
    /// Returns true when the stored value changed.
    pub fn record_packets(&mut self, file: &Path, packets: u64) -> bool {
        let file = std::fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
        let changed = self.packet_counts.insert(file, packets) != Some(packets);
        self.prune_counts();
        changed
    }

    /// Moves `file` to the front of the recent list (deduplicated, bounded).
    pub fn push_recent(&mut self, file: PathBuf) {
        let file = std::fs::canonicalize(&file).unwrap_or(file);
        self.recent.retain(|f| f != &file);
        self.recent.insert(0, file);
        self.recent.truncate(MAX_RECENT);
        self.prune_counts();
    }
}

#[cfg(test)]
#[path = "prefs_tests.rs"]
mod tests;
