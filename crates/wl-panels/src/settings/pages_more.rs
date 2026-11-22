//! Names, Performance, Shortcuts and About category bodies.
use wl_kit::egui::Ui;
use wl_kit::widgets::{info_row, number_row, settings_card, shortcut_row, toggle_row};

use super::model::Settings;

/// Read-only facts shown on the About page (collected by the app).
#[derive(Clone, Debug, Default)]
pub struct AboutInfo {
    pub version: String,
    pub tshark: String,
    pub dumpcap: String,
    pub config_dir: String,
}

pub fn names(ui: &mut Ui, s: &mut Settings) {
    settings_card(ui, "Resolution", |ui| {
        toggle_row(
            ui,
            true,
            "Resolve DNS names",
            "Reverse lookups for hosts, in the background.",
            &mut s.resolve_dns,
        );
    });
}

pub fn performance(ui: &mut Ui, s: &mut Settings) {
    settings_card(ui, "Responsiveness", |ui| {
        number_row(
            ui,
            true,
            "Statistics refresh",
            "Dashboard updates per second.",
            &mut s.stats_hz,
            1..=30,
            " Hz",
        );
    });
}

pub fn shortcuts(ui: &mut Ui) {
    settings_card(ui, "Global", |ui| {
        let rows = [
            ("Command palette", "Ctrl K"),
            ("Settings", "Ctrl ,"),
            ("Zoom in / out / reset", "Ctrl +  /  Ctrl -  /  Ctrl 0"),
            ("Bookmark packet", "Ctrl B"),
            ("Close dialog or banner", "Esc"),
        ];
        for (i, (what, keys)) in rows.into_iter().enumerate() {
            shortcut_row(ui, i == 0, what, keys);
        }
    });
}

pub fn about(ui: &mut Ui, info: &AboutInfo) -> AboutAction {
    let mut act = AboutAction::None;
    settings_card(ui, "pilotfish", |ui| {
        let build = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        info_row(ui, true, "Version", &format!("{} ({build})", info.version));
        info_row(
            ui,
            false,
            "Platform",
            &format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        );
        info_row(ui, false, "tshark", &info.tshark);
        info_row(ui, false, "dumpcap", &info.dumpcap);
        info_row(ui, false, "Config folder", &info.config_dir);
    });
    settings_card(ui, "Maintenance", |ui| {
        wl_kit::widgets::settings_row(ui, true, "Open config folder", "", |ui| {
            if ui.button("Open").clicked() {
                act = AboutAction::OpenConfigDir;
            }
        });
        wl_kit::widgets::settings_row(
            ui,
            false,
            "Reset all settings",
            "Restores every default in this dialog.",
            |ui| {
                if ui.button("Reset all").clicked() {
                    act = AboutAction::ResetAll;
                }
            },
        );
    });
    act
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AboutAction {
    None,
    OpenConfigDir,
    ResetAll,
}
