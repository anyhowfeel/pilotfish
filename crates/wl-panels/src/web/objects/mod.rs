//! "Files" tab of the Web page (File > Export Objects): files carried in the capture for HTTP,
//! SMB, TFTP, IMF or DICOM, with a preview of small text/image objects and save one / save all.
//! Extraction and saving run in the app; the panel only asks (`ObjectsAction`) and shows.

#[cfg(test)]
mod layout_tests;
mod model;
mod preview;
mod table;
mod toolbar;

use std::sync::Arc;

use wl_kit::egui::{Align, Layout, Ui, vec2};
use wl_kit::theme::spacing;
use wl_kit::widgets::empty_state;
use wl_model::ExportObject;
use wl_model::ObjectSet;

use crate::overview::SortState;
use model::{PROTOCOLS, SortCol, build};
use preview::PreviewCache;

pub use model::{PREVIEW_IMAGE_MAX, PREVIEW_TEXT_BYTES, PreviewKind, preview_kind};
pub use preview::{Preview, PreviewData};

/// Dock height bounds of the preview card.
const DOCK_MIN: f32 = 150.0;
const DOCK_MAX: f32 = 280.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectsAction {
    /// Extract the objects of this protocol (answer with `set_result`).
    Load(String),
    /// Decode the preview of this object (answer with `set_preview`).
    Preview(u32),
    /// Save this object (the app asks for the destination).
    Save(u32),
    SaveAll,
    ShowInPackets(u64),
}

#[derive(Debug, Clone, Default)]
pub enum ObjectsState {
    #[default]
    Idle,
    Loading,
    Ready(Arc<ObjectSet>),
    Error(String),
}

pub struct ObjectsPanel {
    proto: usize,
    state: ObjectsState,
    requested: Option<usize>,
    query: String,
    sort: SortState<SortCol>,
    selected: Option<u32>,
    preview: PreviewCache,
    preview_asked: Option<u32>,
    /// Row to select once the objects are loaded (screenshots).
    pending_select: Option<u32>,
    order: Vec<u32>,
    dirty: bool,
}

impl Default for ObjectsPanel {
    fn default() -> Self {
        Self {
            proto: 0,
            state: ObjectsState::Idle,
            requested: None,
            query: String::new(),
            sort: SortState::new(SortCol::Packet, false),
            selected: None,
            preview: PreviewCache::default(),
            preview_asked: None,
            pending_select: None,
            order: Vec::new(),
            dirty: true,
        }
    }
}

impl ObjectsPanel {
    /// Protocol currently shown (tshark name).
    pub fn protocol(&self) -> &'static str {
        PROTOCOLS[self.proto].0
    }

    /// Switches to `name` (`http`, `smb` ...); unknown names are ignored.
    pub fn select_protocol(&mut self, name: &str) {
        if let Some(i) = PROTOCOLS.iter().position(|(n, _)| *n == name) {
            self.proto = i;
        }
    }

    pub fn set_result(&mut self, protocol: &str, r: Result<Arc<ObjectSet>, String>) {
        if protocol != self.protocol() {
            return;
        }
        self.selected = self.pending_select.take();
        self.preview.clear();
        self.preview_asked = None;
        self.state = match r {
            Ok(set) => ObjectsState::Ready(set),
            Err(e) => ObjectsState::Error(e),
        };
        self.dirty = true;
    }

    /// Selects object `id` as soon as the list is loaded.
    pub fn preselect(&mut self, id: u32) {
        self.pending_select = Some(id);
    }

    pub fn set_preview(&mut self, p: PreviewData) {
        if self.selected == Some(p.id) {
            self.preview.data = Some(p);
        }
    }

    /// The objects of a loaded set, for the app (save actions).
    pub fn set(&self) -> Option<&Arc<ObjectSet>> {
        match &self.state {
            ObjectsState::Ready(s) => Some(s),
            _ => None,
        }
    }

    pub fn selected_object(&self) -> Option<&ExportObject> {
        let id = self.selected?;
        self.set()?.objects.get(id as usize)
    }

    /// Forgets the data of the previous capture; the next visit extracts again.
    pub fn invalidate(&mut self) {
        self.state = ObjectsState::Idle;
        self.requested = None;
        self.selected = None;
        self.preview.clear();
        self.preview_asked = None;
        self.dirty = true;
    }

    pub fn ui(&mut self, ui: &mut Ui) -> Vec<ObjectsAction> {
        let mut out = Vec::new();
        if self.requested != Some(self.proto) {
            self.requested = Some(self.proto);
            self.state = ObjectsState::Loading;
            self.selected = None;
            self.preview.clear();
            out.push(ObjectsAction::Load(self.protocol().to_owned()));
        }
        self.toolbar(ui, &mut out);
        ui.add_space(spacing::SM);
        let set = match self.state.clone() {
            ObjectsState::Idle | ObjectsState::Loading => {
                empty_state(
                    ui,
                    "...",
                    "Extracting files",
                    "Reading the objects carried in the capture.",
                );
                return out;
            }
            ObjectsState::Error(e) => {
                empty_state(ui, "!", "Could not extract files", &e);
                return out;
            }
            ObjectsState::Ready(s) => s,
        };
        if set.truncated {
            toolbar::warning(
                ui,
                "Extraction stopped at the size limit: the list is incomplete.",
            );
            ui.add_space(spacing::SM);
        }
        if set.objects.is_empty() {
            empty_state(
                ui,
                "0",
                &format!("No {} files", PROTOCOLS[self.proto].1),
                "This capture carries no files for this protocol. Try another one above.",
            );
            return out;
        }
        if self.dirty {
            self.order = build(&set.objects, &self.query, self.sort);
            self.dirty = false;
        }
        self.body(ui, &set, &mut out);
        out
    }

    fn body(&mut self, ui: &mut Ui, set: &ObjectSet, out: &mut Vec<ObjectsAction>) {
        let w = ui.available_width();
        let sel = self.selected_object().cloned();
        let dock = sel
            .as_ref()
            .map(|_| (ui.available_height() * 0.4).clamp(DOCK_MIN, DOCK_MAX));
        let gap = if dock.is_some() { spacing::SM } else { 0.0 };
        let table_h = (ui.available_height() - dock.unwrap_or(0.0) - gap).max(80.0);
        let res = ui
            .allocate_ui_with_layout(vec2(w, table_h), Layout::top_down(Align::Min), |ui| {
                let t = table::TableIn {
                    all: &set.objects,
                    rows: &self.order,
                    sort: self.sort,
                    selected: self.selected,
                };
                table::table(ui, &t)
            })
            .inner;
        if let Some(c) = res.sort {
            self.sort.toggle(c);
            self.dirty = true;
        }
        if let Some(id) = res.picked
            && self.selected != Some(id)
        {
            self.selected = Some(id);
            self.preview.clear();
            self.preview_asked = None;
        }
        if let Some(o) = sel {
            ui.add_space(gap);
            if self.preview_asked != Some(o.id) {
                self.preview_asked = Some(o.id);
                if preview_kind(&o) != model::PreviewKind::None {
                    out.push(ObjectsAction::Preview(o.id));
                }
            }
            preview::show(ui, &o, &mut self.preview);
        }
    }
}
