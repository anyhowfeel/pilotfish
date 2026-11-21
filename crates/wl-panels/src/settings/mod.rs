//! Modal settings dialog: pinned header/footer, category rail, scrollable body, live preview.
//! The dialog only edits a `Settings` draft and returns `SettingsAction`s; the app persists.
mod category;
#[cfg(test)]
mod dialog_tests;
mod geo_page;
mod layout;
mod model;
mod pages;
mod pages_more;
mod shell;

pub use category::Category;
pub use geo_page::{GeoAction, GeoDbInfo, GeoDbRow, GeoDbState};
pub use layout::{Geometry, geometry};
pub use model::{Density, PillLook, Settings, ThemeChoice, TimeFormat};
pub use pages_more::AboutInfo;

use wl_kit::egui::{self, Key};

use pages_more::AboutAction;

#[derive(Clone, Debug, PartialEq)]
pub enum SettingsAction {
    /// Draft changed: apply theme/scale immediately (not yet saved).
    Preview(Settings),
    /// Save + close.
    Apply(Settings),
    /// Close and revert to the settings that were active when the dialog opened.
    Cancel(Settings),
    OpenConfigDir,
    /// A button of the Locations page (download, remove, add a file, open the folder).
    Geo(GeoAction),
}

#[derive(Default)]
pub struct SettingsDialog {
    open: bool,
    draft: Settings,
    original: Settings,
    sent: Settings,
    cat: Category,
    about: AboutInfo,
    geo: GeoDbInfo,
}

impl SettingsDialog {
    pub fn open(&mut self, current: Settings, about: AboutInfo, cat: Option<Category>) {
        self.draft = current.clone();
        self.original = current.clone();
        self.sent = current;
        self.about = about;
        if let Some(c) = cat {
            self.cat = c;
        }
        self.open = true;
    }

    /// Refresh the About facts (tool probe may finish after the dialog opened).
    pub fn set_about(&mut self, about: AboutInfo) {
        self.about = about;
    }

    /// Refreshes the database list of the Locations page (downloads finish while it is open).
    pub fn set_geo(&mut self, geo: GeoDbInfo) {
        self.geo = geo;
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    fn close(&mut self) {
        self.open = false;
    }

    pub fn ui(&mut self, ctx: &egui::Context) -> Option<SettingsAction> {
        if !self.open {
            return None;
        }
        let dragging = ctx.input(|i| i.pointer.any_down());
        // Ctrl +/-/0 changed the live scale behind the dialog: show it on the slider too.
        let live = wl_kit::scale::ui_scale(ctx);
        if !dragging && (live - self.sent.ui_scale).abs() > 1e-3 {
            self.draft.ui_scale = live;
            self.sent.ui_scale = live;
        }
        let geo = geometry(ctx.content_rect());
        let mut out = shell::show(
            ctx,
            &geo,
            &mut self.draft,
            &mut self.cat,
            &self.about,
            &self.geo,
        );
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            out.cancel = true;
        }
        if out.cancel {
            self.close();
            return Some(SettingsAction::Cancel(self.original.clone()));
        }
        if out.apply {
            self.close();
            return Some(SettingsAction::Apply(self.draft.clone().clamped()));
        }
        if out.reset {
            self.draft = Settings::default();
        }
        if let Some(a) = out.geo.take() {
            return Some(SettingsAction::Geo(a));
        }
        match out.about {
            AboutAction::OpenConfigDir => return Some(SettingsAction::OpenConfigDir),
            AboutAction::ResetAll => self.draft = Settings::default(),
            AboutAction::None => {}
        }
        // A scale change re-lays out the whole window, including the slider being dragged:
        // hold it back until the pointer is released.
        let mut preview = self.draft.clone().clamped();
        if dragging {
            preview.ui_scale = self.sent.ui_scale;
        }
        if preview != self.sent {
            self.sent = preview.clone();
            return Some(SettingsAction::Preview(preview));
        }
        None
    }
}
