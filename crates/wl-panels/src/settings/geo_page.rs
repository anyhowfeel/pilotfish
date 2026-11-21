//! "Locations" settings page: the databases that give hosts a country and a network.
use wl_kit::egui::{Align, Button, Layout, RichText, Ui};
use wl_kit::theme::Palette;
use wl_kit::widgets::{info_row, settings_card, settings_row};

/// What the app knows about one database, shown as a row.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum GeoDbState {
    #[default]
    Missing,
    Downloading,
    /// Installed; the text is its size.
    Ready(String),
    Failed(String),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoDbRow {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub state: GeoDbState,
    /// Files added by the user can be deleted; the proposed ones are replaced by a download.
    pub custom: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoDbInfo {
    pub dir: String,
    pub rows: Vec<GeoDbRow>,
    /// Last problem with a file the user added or removed.
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoAction {
    Download(String),
    Remove(String),
    AddFile,
    OpenFolder,
}

fn status_text(state: &GeoDbState) -> String {
    match state {
        GeoDbState::Missing => "Not installed".to_owned(),
        GeoDbState::Downloading => "Downloading\u{2026}".to_owned(),
        GeoDbState::Ready(size) => format!("Installed \u{b7} {size}"),
        GeoDbState::Failed(_) => "Download failed".to_owned(),
    }
}

fn button(ui: &mut Ui, state: &GeoDbState, custom: bool, id: &str) -> Option<GeoAction> {
    let download = || Some(GeoAction::Download(id.to_owned()));
    match state {
        GeoDbState::Downloading => {
            ui.add_enabled(false, Button::new("Downloading\u{2026}"));
            None
        }
        GeoDbState::Ready(_) if custom => ui
            .button("Remove")
            .clicked()
            .then(|| GeoAction::Remove(id.to_owned())),
        GeoDbState::Ready(_) => ui.button("Update").clicked().then(download).flatten(),
        GeoDbState::Missing | GeoDbState::Failed(_) => {
            ui.button("Download").clicked().then(download).flatten()
        }
    }
}

fn database_row(ui: &mut Ui, first: bool, row: &GeoDbRow) -> Option<GeoAction> {
    let mut act = None;
    settings_row(ui, first, &row.title, &row.detail, |ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            act = button(ui, &row.state, row.custom, &row.id);
            let color = match row.state {
                GeoDbState::Failed(_) => Palette::danger(),
                _ => Palette::muted(),
            };
            ui.label(RichText::new(status_text(&row.state)).small().color(color));
        });
    });
    if let GeoDbState::Failed(e) = &row.state {
        ui.label(RichText::new(e).small().color(Palette::danger()));
    }
    act
}

pub fn page(ui: &mut Ui, info: &GeoDbInfo) -> Option<GeoAction> {
    let mut act = None;
    settings_card(ui, "Databases", |ui| {
        for (i, row) in info.rows.iter().enumerate() {
            if let Some(a) = database_row(ui, i == 0, row) {
                act = Some(a);
            }
        }
    });
    settings_card(ui, "Your own files", |ui| {
        settings_row(
            ui,
            true,
            "Add a database",
            "A MaxMind-format .mmdb file (GeoLite2, DB-IP...), country or ASN.",
            |ui| {
                if ui.button("Add file\u{2026}").clicked() {
                    act = Some(GeoAction::AddFile);
                }
            },
        );
        if let Some(e) = &info.error {
            ui.label(RichText::new(e).small().color(Palette::danger()));
        }
        info_row(ui, false, "Folder", &info.dir);
        settings_row(ui, false, "Open folder", "", |ui| {
            if ui.button("Open").clicked() {
                act = Some(GeoAction::OpenFolder);
            }
        });
    });
    act
}
