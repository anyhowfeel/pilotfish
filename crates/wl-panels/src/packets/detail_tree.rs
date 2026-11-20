//! Collapsible dissection tree. Selecting a node exposes its byte range for the hex view.

use std::collections::HashSet;

use eframe::egui::{self, CursorIcon, Key, Rect, Sense, Shape, Stroke, Ui, Vec2, pos2, vec2};
use wl_model::{DetailNode, FrameDetail};

use crate::packets::kit::{Palette, row_h, spacing};
use crate::packets::tree_model::{self as model, FlatRow};
use crate::packets::{detail_row, http_row, tree_menu};
use wl_kit::widgets::toast;

const INDENT: f32 = 14.0;
/// Widest key column before keys are elided (values stay aligned).
const KEY_COL_MAX: f32 = 220.0;

#[derive(Default)]
pub struct DetailTree {
    frame_no: Option<u64>,
    open: HashSet<usize>,
    query: String,
    selected: Option<usize>,
    range: Option<(usize, usize)>,
    cache: Vec<FlatRow>,
    /// Shared key-column width per visible row (aligned `Key: value`).
    keyw: Vec<f32>,
    dirty: bool,
    column_req: Option<String>,
}

fn arrow(ui: &Ui, rect: Rect, open: bool, color: egui::Color32) {
    let c = rect.center();
    let pts = if open {
        vec![
            pos2(c.x - 3.5, c.y - 2.0),
            pos2(c.x + 3.5, c.y - 2.0),
            pos2(c.x, c.y + 3.0),
        ]
    } else {
        vec![
            pos2(c.x - 2.0, c.y - 3.5),
            pos2(c.x - 2.0, c.y + 3.5),
            pos2(c.x + 3.0, c.y),
        ]
    };
    ui.painter()
        .add(Shape::convex_polygon(pts, color, Stroke::NONE));
}

impl DetailTree {
    /// Byte range of the selected node (as given by `DetailNode::range`).
    pub fn selected_range(&self) -> Option<(usize, usize)> {
        self.range
    }

    pub fn clear_selection(&mut self) {
        self.selected = None;
        self.range = None;
    }

    fn sync(&mut self, ui: &Ui, detail: Option<&FrameDetail>) {
        let no = detail.map(|d| d.frame_no);
        if no != self.frame_no {
            self.frame_no = no;
            self.open = detail
                .map(|d| model::default_open(&d.layers))
                .unwrap_or_default();
            self.clear_selection();
            self.dirty = true;
        }
        if self.dirty {
            self.cache = detail
                .map(|d| model::flatten(&d.layers, &self.open, &self.query))
                .unwrap_or_default();
            let items: Vec<_> = self
                .cache
                .iter()
                .map(|r| {
                    (
                        r.depth,
                        (r.depth > 0)
                            .then(|| detail_row::key_width(ui, &r.label))
                            .flatten(),
                    )
                })
                .collect();
            self.keyw = http_row::sibling_key_widths(&items, KEY_COL_MAX);
            self.dirty = false;
        }
    }

    fn toolbar(&mut self, ui: &mut Ui, layers: &[DetailNode]) {
        ui.horizontal(|ui| {
            let search_w = (ui.available_width() - 184.0).clamp(72.0, 180.0);
            let r = ui.add(
                wl_kit::widgets::text_field(&mut self.query)
                    .hint_text("Search tree")
                    .desired_width(search_w),
            );
            if r.has_focus() && !self.query.is_empty() && ui.input(|i| i.key_pressed(Key::Escape)) {
                self.query.clear();
                self.dirty = true;
            } else {
                self.dirty |= r.changed();
            }
            if ui
                .button("Expand all")
                .on_hover_cursor(CursorIcon::PointingHand)
                .clicked()
            {
                self.open = model::all_open(layers);
                self.dirty = true;
            }
            if ui
                .button("Collapse all")
                .on_hover_cursor(CursorIcon::PointingHand)
                .clicked()
            {
                self.open.clear();
                self.query.clear();
                self.dirty = true;
            }
        });
        ui.add_space(spacing::XS);
    }

    fn row(
        &mut self,
        ui: &mut Ui,
        i: usize,
        layers: &[DetailNode],
        current_filter: &str,
        out_filter: &mut Option<String>,
    ) {
        let r = self.cache[i].clone();
        let (rect, resp) =
            ui.allocate_exact_size(vec2(ui.available_width(), row_h()), Sense::click());
        let selected = self.selected == Some(r.idx);
        let v = ui.visuals();
        if selected {
            ui.painter().rect_filled(rect, 3.0, v.selection.bg_fill);
            let bar = Rect::from_min_max(rect.left_top(), pos2(rect.left() + 2.5, rect.bottom()));
            ui.painter().rect_filled(bar, 0.0, Palette::accent());
        } else if r.matches {
            ui.painter()
                .rect_filled(rect, 3.0, wl_kit::theme::tint(Palette::warn(), 45));
        } else if resp.hovered() {
            ui.painter()
                .rect_filled(rect, 3.0, v.widgets.hovered.weak_bg_fill);
        }
        let x = rect.left() + 6.0 + f32::from(r.depth) * INDENT;
        let box_rect = Rect::from_center_size(pos2(x + 6.0, rect.center().y), Vec2::splat(12.0));
        if r.has_children {
            arrow(ui, box_rect, r.open, Palette::muted());
        }
        let text_x = x + 16.0;
        let key_w = self.keyw.get(i).copied().unwrap_or(0.0);
        let hit = detail_row::paint_label(ui, rect, text_x, &r.label, key_w, r.depth);
        if resp.clicked() {
            self.selected = Some(r.idx);
            self.range = r.range;
            let px = resp.interact_pointer_pos().map_or(f32::MAX, |p| p.x);
            if let Some(h) = hit.as_ref().filter(|h| px >= h.left) {
                ui.ctx().copy_text(h.text.to_owned());
                toast::push(ui.ctx(), "Value copied");
            }
            if r.has_children && (px < text_x || resp.double_clicked()) {
                self.toggle(r.idx);
            }
        }
        resp.on_hover_text(&r.label).context_menu(|ui| {
            let parent = self.cache[..i]
                .iter()
                .rev()
                .find(|p| p.depth == 0)
                .map(|p| p.label.as_str());
            let path = || model::path_of(layers, r.idx).unwrap_or_default();
            let mut menu = tree_menu::Out::default();
            tree_menu::show(ui, &r, parent, current_filter, &path, &mut menu);
            if menu.filter.is_some() {
                *out_filter = menu.filter;
            }
            if menu.column.is_some() {
                self.column_req = menu.column;
            }
        });
    }

    /// Field chosen with "Apply as Column" since the last call.
    pub fn take_column_request(&mut self) -> Option<String> {
        self.column_req.take()
    }

    fn toggle(&mut self, idx: usize) {
        if !self.open.remove(&idx) {
            self.open.insert(idx);
        }
        self.dirty = true;
    }

    pub fn ui(
        &mut self,
        ui: &mut Ui,
        detail: Option<&FrameDetail>,
        current_filter: &str,
    ) -> Option<String> {
        let layers: &[DetailNode] = detail.map_or(&[], |d| &d.layers);
        self.toolbar(ui, layers);
        self.sync(ui, detail);
        if detail.is_none() {
            ui.centered_and_justified(|ui| {
                ui.label(
                    egui::RichText::new("Select a packet to inspect it").color(Palette::muted()),
                );
            });
            return None;
        }
        let n = self.cache.len();
        let mut out_filter = None;
        ui.spacing_mut().item_spacing.y = 0.0;
        egui::ScrollArea::vertical()
            .id_salt("detail_tree_scroll")
            .auto_shrink([false, false])
            .show_rows(ui, row_h(), n, |ui, range| {
                for i in range {
                    self.row(ui, i, layers, current_filter, &mut out_filter);
                }
            });
        self.sync(ui, detail);
        out_filter
    }
}
