//! "Web" page: HTTP exchanges and TLS sessions as a master table with a detail pane.
//! Master/detail: summary + filters on top, sortable table, resizable detail docked at the
//! bottom (right on wide windows) with request/response cards, timing and TLS info.

mod actions;
mod body;
mod card;
mod cells;
mod cert_card;
mod columns;
mod curl;
mod demo;
mod detail;
mod detail_header;
mod dock;
mod headers;
mod html_text;
mod keys_bar;
#[cfg(test)]
mod layout_tests;
mod message_card;
mod model;
mod nav;
mod objects;
mod stats;
mod streams;
mod summary;
mod table;
mod table_cells;
mod timing;

pub use actions::{KeysInfo, WebAction, WebData, WebStatus};
pub use demo::{demo_data, demo_detail, demo_streams};
pub use objects::{
    ObjectsAction, ObjectsPanel, ObjectsState, PREVIEW_IMAGE_MAX, PREVIEW_TEXT_BYTES, Preview,
    PreviewData, PreviewKind, preview_kind,
};

use wl_kit::egui::{Key, Ui};
use wl_kit::theme::spacing;
use wl_kit::widgets::{empty_state, segmented_w};

use crate::needs::needs_wireshark;
use crate::overview::SortState;
use detail::Shown;
/// Page heights below this hide the KPI strip while a row is selected.
const COMPACT_H: f32 = 520.0;

use model::{Data, Filter, RowRef, Sel, SortCol, build, sel_of};
use stats::{WebStats, aggregate};

/// Tabs of the Web page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Exchanges,
    Streams,
    Files,
}

pub struct WebPanel {
    tab: Tab,
    objects: ObjectsPanel,
    streams: streams::StreamsPanel,
    filter: Filter,
    sort: SortState<SortCol>,
    selected: Option<Sel>,
    /// Selection a detail request was already sent for.
    requested: Option<Sel>,
    order: Vec<RowRef>,
    key: Option<(u64, Filter, SortState<SortCol>)>,
    stats: WebStats,
    shown: Shown,
    shown_for: Option<Sel>,
    scroll_to: Option<usize>,
    /// Share of the height (bottom dock) / width (right dock) taken by the table.
    pending_scroll: bool,
    frac_v: f32,
    frac_h: f32,
}

impl Default for WebPanel {
    fn default() -> Self {
        Self {
            tab: Tab::default(),
            objects: ObjectsPanel::default(),
            streams: streams::StreamsPanel::default(),
            filter: Filter::default(),
            sort: SortState::new(SortCol::Time, false),
            selected: None,
            requested: None,
            order: Vec::new(),
            key: None,
            stats: WebStats::default(),
            shown: Shown::default(),
            shown_for: None,
            scroll_to: None,
            pending_scroll: false,
            frac_v: 0.5,
            frac_h: 0.58,
        }
    }
}

impl WebPanel {
    /// The Files tab (the app feeds it with results and previews).
    pub fn objects_mut(&mut self) -> &mut ObjectsPanel {
        &mut self.objects
    }

    /// Switches to the Files tab, optionally on another protocol (`smb`, `tftp` ...).
    pub fn show_files(&mut self, protocol: Option<&str>) {
        self.tab = Tab::Files;
        if let Some(p) = protocol {
            self.objects.select_protocol(p);
        }
    }

    /// Pre-selects a row (`http:<id>` or `tls:<first frame>`), for screenshots.
    pub fn preselect(&mut self, spec: &str) {
        self.selected = match spec.split_once(':') {
            Some(("http", n)) => n.parse().ok().map(Sel::Http),
            Some(("tls", n)) => n.parse().ok().map(Sel::Tls),
            Some(("stream", n)) => {
                self.tab = Tab::Streams;
                if let Ok(id) = n.parse() {
                    self.streams.select(id);
                }
                None
            }
            Some(("files", n)) => {
                self.tab = Tab::Files;
                if let Ok(id) = n.parse() {
                    self.objects.preselect(id);
                }
                None
            }
            _ => None,
        };
        self.pending_scroll = self.selected.is_some();
    }

    pub fn ui(&mut self, ui: &mut Ui, d: &WebData) -> Vec<WebAction> {
        // Exchanges, streams, files and key logs are all read by tshark.
        if d.wireshark.is_missing() {
            needs_wireshark(ui, "Web analysis");
            return Vec::new();
        }
        let tabs = [
            (Tab::Exchanges, "Exchanges"),
            (Tab::Streams, "Streams"),
            (Tab::Files, "Files"),
        ];
        let mut out = Vec::new();
        ui.horizontal_wrapped(|ui| {
            segmented_w(ui, &mut self.tab, &tabs, 300.0);
            keys_bar::keys_bar(ui, d.keys, &mut out);
        });
        ui.add_space(spacing::SM);
        if self.tab == Tab::Files {
            out.extend(self.objects.ui(ui).into_iter().map(WebAction::Objects));
            return out;
        }
        if self.tab == Tab::Streams {
            out.extend(self.streams.ui(ui, d.streams));
            return out;
        }
        out.extend(self.exchanges_ui(ui, d));
        out
    }

    fn exchanges_ui(&mut self, ui: &mut Ui, d: &WebData) -> Vec<WebAction> {
        let mut out = Vec::new();
        match d.status {
            WebStatus::Loading => {
                empty_state(
                    ui,
                    "...",
                    "Reading web traffic",
                    "Collecting HTTP exchanges and TLS sessions from the capture.",
                );
                return out;
            }
            WebStatus::Error(e) => {
                empty_state(ui, "!", "Could not read web traffic", e);
                return out;
            }
            WebStatus::Ready => {}
        }
        if d.exchanges.is_empty() && d.tls.is_empty() {
            empty_state(
                ui,
                "www",
                "No web traffic",
                "Open a capture or start one: HTTP requests and HTTPS sessions will be listed here.",
            );
            return out;
        }
        self.refresh(d);
        if self.pending_scroll {
            self.pending_scroll = false;
            self.scroll_to = self.selected.and_then(|s| {
                let data = Data {
                    ex: d.exchanges,
                    tls: d.tls,
                };
                self.order.iter().position(|r| sel_of(&data, *r) == s)
            });
        }
        let data = Data {
            ex: d.exchanges,
            tls: d.tls,
        };
        self.keyboard(ui, data, &mut out);
        // Short windows: the KPI strip yields its room to the table + detail while a row is open.
        if !(ui.available_height() < COMPACT_H && self.selected.is_some()) {
            summary::summary_strip(ui, &self.stats);
            ui.add_space(spacing::SM);
        }
        let total = d.exchanges.len() + d.tls.len();
        if summary::toolbar(ui, &mut self.filter, self.order.len(), total) {
            self.key = None;
        }
        ui.add_space(spacing::SM);
        self.sync_detail(d, &mut out);
        self.body(ui, d, data, &mut out);
        out
    }
}

fn frame_of(d: &Data, s: Sel) -> Option<u64> {
    match s {
        Sel::Http(id) => {
            d.ex.iter()
                .find(|e| e.id == id)
                .and_then(|e| e.req_frame.or(e.resp_frame))
        }
        Sel::Tls(f) => Some(f),
    }
}
