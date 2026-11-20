//! Master/detail layout: table above (or left of) the detail pane, separated by the shared
//! draggable splitter. The detail is anchored to the bottom (right on wide windows).

use wl_kit::egui::Ui;
use wl_kit::theme::spacing;

use super::WebPanel;
use super::actions::{WebAction, WebData};
use super::detail::{self, Shown};
use super::model::{Data, Sel};
use super::table::{TableIn, TableOut, master_table};
use crate::packets::split;

/// At or above this width the detail docks to the right instead of the bottom.
const RIGHT_DOCK_W: f32 = 1240.0;
/// Height of the bottom detail pane while nothing is selected (just a hint).
const EMPTY_H: f32 = 80.0;

fn detail_ui(
    ui: &mut Ui,
    sel: Option<Sel>,
    shown: &Shown,
    max_ms: f64,
    d: &WebData,
    out: &mut Vec<WebAction>,
) {
    ui.add_space(spacing::SM);
    match sel {
        Some(Sel::Http(id)) => match d.exchanges.iter().find(|e| e.id == id) {
            Some(e) => detail::http_detail(ui, e, d.detail, shown, max_ms, out),
            None => detail::placeholder(ui, "Select a request to inspect it"),
        },
        Some(Sel::Tls(f)) => match d.tls.iter().find(|t| t.first_frame == f) {
            Some(t) => detail::tls_detail(ui, t, out),
            None => detail::placeholder(ui, "Select a request to inspect it"),
        },
        None => detail::placeholder(ui, "Select a request or HTTPS session to inspect it"),
    }
}

impl WebPanel {
    /// Draws the table and the detail pane; applies sort / selection results.
    pub(super) fn body(&mut self, ui: &mut Ui, d: &WebData, data: Data, out: &mut Vec<WebAction>) {
        let (sel, max_ms) = (self.selected, self.stats.max_ms);
        let t = TableIn {
            data,
            rows: &self.order,
            sort: self.sort,
            selected: sel,
            max_ms,
            scroll_to: self.scroll_to.take(),
        };
        let mut res = TableOut::default();
        let top = |ui: &mut Ui| res = master_table(ui, &t);
        let shown = &self.shown;
        let bottom = |ui: &mut Ui| detail_ui(ui, sel, shown, max_ms, d, out);
        if ui.available_width() >= RIGHT_DOCK_W {
            split::horizontal(ui, &mut self.frac_h, top, bottom);
        } else if sel.is_none() {
            let mut hint = 1.0 - EMPTY_H / ui.available_height().max(EMPTY_H * 2.0);
            split::vertical(ui, &mut hint, top, bottom);
        } else {
            split::vertical(ui, &mut self.frac_v, top, bottom);
        }
        if let Some(c) = res.sort {
            self.sort.toggle(c);
        }
        if let Some(i) = res.picked {
            self.select(i, data);
            self.scroll_to = None;
        }
    }
}
