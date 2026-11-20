//! Virtualized packet list (egui_extras table) over `TableState`.

use eframe::egui::{Align, ScrollArea, Ui, vec2};
use wl_model::PacketRow;

use crate::packets::actions::PacketsAction;
use crate::packets::column_set::ColumnSet;
use crate::packets::columns::ColKey;
use crate::packets::columns_menu;
use crate::packets::context_menu;
use crate::packets::custom_cols::{CustomCols, FieldStatus};
use crate::packets::kit::{row_h, spacing};
use crate::packets::quick_filter::{Census, QuickChip};
use crate::packets::table_cells::{CellCtx, build_table, cell, col_title, header_cell};
use crate::packets::table_state::TableState;
use crate::packets::time_format::{TimeCtx, TimeFormat};

const MIN_TABLE_W: f32 = 660.0;

#[derive(Default)]
pub struct PacketTable {
    pub state: TableState,
    pub(super) follow: bool,
    pub(super) follow_armed: bool,
    pub(super) left_bottom: bool,
    pub(super) scroll_to_selected: bool,
    pub(super) focused: bool,
    pub(super) quick_text: String,
    pub(super) census: Census,
    pub(super) census_frozen: bool,
    pub(super) columns: ColumnSet,
    pub(super) time_fmt: TimeFormat,
    /// Frame marked as `T=0` (number, epoch).
    pub(super) time_ref: Option<(u64, f64)>,
    pub(super) custom: CustomCols,
    pub(super) new_field: String,
    /// Screenshot helpers (`--packets-demo`).
    pub(super) open_columns_now: bool,
    pub(super) ref_pending: Option<u64>,
}

impl PacketTable {
    /// Re-sorts all rows (appended rows stay unsorted while a capture is streaming).
    pub fn resort(&mut self) {
        self.state.resort();
    }

    pub fn push_rows(&mut self, rows: Vec<PacketRow>) {
        if !self.census_frozen {
            rows.iter().for_each(|r| self.census.add(&r.protocol));
        }
        self.state.push_rows(rows);
    }

    /// Protocol chips of the whole capture (kept while a display filter narrows the list).
    pub fn quick_chips(&mut self) -> &[QuickChip] {
        self.census.chips()
    }

    /// Like `clear`, but a non-empty display filter keeps the unfiltered protocol census.
    pub fn clear_for_filter(&mut self, filtered: bool) {
        if !filtered {
            self.census.clear();
        }
        self.clear_rows();
        self.census_frozen = filtered;
    }

    pub fn clear(&mut self) {
        self.census.clear();
        self.census_frozen = false;
        self.time_ref = None;
        self.custom.clear();
        self.clear_rows();
    }

    fn clear_rows(&mut self) {
        self.state.clear();
        self.scroll_to_selected = false;
        self.left_bottom = false;
    }

    pub fn ui(&mut self, ui: &mut Ui) -> Vec<PacketsAction> {
        let mut out = Vec::new();
        if let Some(no) = self.ref_pending
            && let Some(r) = self.state.row_by_no(no)
        {
            self.time_ref = Some((r.no, r.epoch));
            self.ref_pending = None;
        }
        self.toolbar(ui, &mut out);
        ui.add_space(spacing::XS);
        let avail = ui.available_rect_before_wrap();
        if ui.input(|i| i.pointer.primary_pressed()) {
            let pos = ui.input(|i| i.pointer.interact_pos());
            self.focused = pos.is_some_and(|p| avail.contains(p));
        }
        let page = ((avail.height() / row_h()) as usize)
            .saturating_sub(1)
            .max(1);
        let keyed = self.handle_keys(ui, page);
        let pointer_in = ui.rect_contains_pointer(avail);
        let dy = ui.input(|i| i.smooth_scroll_delta.y);
        let (scrolled_up, scrolled_down) = (pointer_in && dy > 0.0, pointer_in && dy < 0.0);
        if scrolled_up {
            self.follow = false;
        }
        let n = self.state.visible();
        let (mut clicked, mut sort_click, mut saw_last) = (None, None, false);
        let (sort, sel) = (self.state.sort(), self.state.selected_pos());
        let follow = self.follow;
        let scroll_sel = std::mem::take(&mut self.scroll_to_selected);
        let now = ui.input(|i| i.time);
        let fields = self.columns.visible_fields();
        self.custom
            .request(&fields, self.state.total(), now, &mut out);
        let cols = self.columns.visible();
        let fmt = self.time_fmt;
        let state = &self.state;
        let custom = &self.custom;
        let (columns, time_fmt, time_ref, new_field) = (
            &mut self.columns,
            &mut self.time_fmt,
            &mut self.time_ref,
            &mut self.new_field,
        );
        let reference = *time_ref;
        let (table_w, table_h) = (
            avail.width().max(MIN_TABLE_W),
            avail.height().max(row_h() * 2.0),
        );
        ui.style_mut().interaction.selectable_labels = false;

        ScrollArea::horizontal()
            .id_salt("pkt_table_hscroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.allocate_ui(vec2(table_w, table_h), |ui| {
                    let mut tb = build_table(ui, table_h, &cols, fmt);
                    if follow && n > 0 {
                        tb = tb.scroll_to_row(n - 1, Some(Align::BOTTOM));
                    } else if scroll_sel && let Some(p) = sel {
                        tb = tb.scroll_to_row(p, Some(Align::Center));
                    } else if let (Some(_), Some(p)) = (keyed, sel) {
                        tb = tb.scroll_to_row(p, None);
                    }
                    tb.header(row_h() + 4.0, |mut h| {
                        for c in &cols {
                            h.col(|ui| {
                                let mut resp = header_cell(ui, c, col_title(c, fmt), sort);
                                if let ColKey::Field(f) = c {
                                    resp = resp.on_hover_text(match custom.status(f) {
                                        FieldStatus::Ready => f.clone(),
                                        FieldStatus::Loading => format!("{f}: loading\u{2026}"),
                                        FieldStatus::Failed(e) => format!("{f}: {e}"),
                                    });
                                }
                                if let (true, ColKey::Std(s)) = (resp.clicked(), c) {
                                    sort_click = Some(*s);
                                }
                                resp.context_menu(|ui| {
                                    columns_menu::show(ui, columns, time_fmt, new_field, time_ref)
                                });
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(row_h(), n, |mut row| {
                            let pos = row.index();
                            saw_last |= pos + 1 == n;
                            let Some(r) = state.row_at(pos) else { return };
                            row.set_selected(sel == Some(pos));
                            let cx = CellCtx {
                                time: TimeCtx {
                                    format: fmt,
                                    reference,
                                    prev_captured: (fmt == TimeFormat::DeltaPrevious)
                                        .then(|| state.row_by_no(r.no.saturating_sub(1)))
                                        .flatten()
                                        .map(|p| p.epoch),
                                    prev_displayed: (fmt.needs_displayed_prev() && pos > 0)
                                        .then(|| state.row_at(pos - 1))
                                        .flatten()
                                        .map(|p| p.epoch),
                                },
                                custom,
                            };
                            for c in &cols {
                                cell(&mut row, c, r, &cx);
                            }
                            let resp = row.response();
                            if resp.clicked() || resp.secondary_clicked() {
                                clicked = Some(pos);
                            }
                            resp.context_menu(|ui| context_menu::show(ui, r, &mut out, time_ref));
                        });
                    });
                });
            });
        if clicked.is_none() {
            self.update_follow_from_scroll(scrolled_up, scrolled_down, saw_last, n > 0);
        } else {
            self.follow = false;
            self.left_bottom = false;
        }
        if let Some(c) = sort_click {
            self.state.cycle_sort(c);
        }
        if let Some(no) = clicked.and_then(|p| self.state.select_pos(p)).or(keyed) {
            out.push(PacketsAction::Select(no));
        }
        out
    }
}
