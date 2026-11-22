//! Threat lists card of the "Locations" page: the folder the offline lists are read from.
use wl_kit::egui::{RichText, Ui};
use wl_kit::theme::Palette;
use wl_kit::widgets::{info_row, settings_card, settings_row};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct IntelInfo {
    pub dir: String,
    /// What the loaded files contain, e.g. "12 addresses, 3 domains, 400 fingerprints".
    pub summary: String,
    pub loading: bool,
    /// Files that could not be read.
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntelAction {
    AddFile,
    OpenFolder,
    Reload,
}

pub fn card(ui: &mut Ui, info: &IntelInfo) -> Option<IntelAction> {
    let mut act = None;
    settings_card(ui, "Threat lists", |ui| {
        let status = if info.loading {
            "Reading\u{2026}"
        } else {
            &info.summary
        };
        info_row(ui, true, "Loaded", status);
        for e in &info.errors {
            ui.label(RichText::new(e).small().color(Palette::danger()));
        }
        settings_row(
            ui,
            false,
            "Add a list",
            "A JA4DB .json export, or a text / CSV blocklist of addresses, domains and JA3 / JA4 fingerprints (abuse.ch formats work). Nothing is downloaded.",
            |ui| {
                if ui.button("Add file\u{2026}").clicked() {
                    act = Some(IntelAction::AddFile);
                }
            },
        );
        info_row(ui, false, "Folder", &info.dir);
        settings_row(ui, false, "Folder and files", "", |ui| {
            if ui.button("Reload").clicked() {
                act = Some(IntelAction::Reload);
            }
            if ui.button("Open").clicked() {
                act = Some(IntelAction::OpenFolder);
            }
        });
    });
    act
}
