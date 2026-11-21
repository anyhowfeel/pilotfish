//! `PacketsView`: filter bar + packet table + detail/hex split.

use eframe::egui::{self, Ui};
use wl_model::{FrameDetail, PacketRow};

use crate::packets::actions::PacketsAction;
use crate::packets::custom_cols;
use crate::packets::demo::Demo;
use crate::packets::detail_tree::DetailTree;
use crate::packets::filter_bar::{FilterBar, FilterStatus};
use crate::packets::find_bar;
use crate::packets::find_state::FindState;
use crate::packets::hex_view::HexView;
use crate::packets::kit::spacing;
use crate::packets::split::{self, Layout};
use crate::packets::table::PacketTable;

/// Minimum vertical height before the detail+hex pane auto-collapses so the table stays usable.
const MIN_SPLIT_H: f32 = 300.0;
const MIN_TABLE_H: f32 = 160.0;

#[derive(Default)]
pub struct PacketsView {
    pub filter_bar: FilterBar,
    pub table: PacketTable,
    tree: DetailTree,
    hex: HexView,
    layout: Layout,
    demo: Demo,
    find: FindState,
    demo_find_run: bool,
}

impl PacketsView {
    pub fn push_rows(&mut self, rows: Vec<PacketRow>) {
        self.table.push_rows(rows);
    }

    pub fn clear(&mut self) {
        self.find.invalidate();
        self.table.clear();
    }

    /// Clears the list for a (re)applied display filter, keeping the capture's protocol chips.
    pub fn clear_for_filter(&mut self, filtered: bool) {
        self.table.clear_for_filter(filtered);
    }

    /// Backend answer to a `PacketsAction::RunFields` request; may select a match.
    pub fn on_fields(
        &mut self,
        id: u64,
        res: &Result<Vec<wl_model::FrameFields>, String>,
    ) -> Vec<PacketsAction> {
        let mut out = Vec::new();
        if custom_cols::is_custom_id(id) {
            self.table.on_custom_result(id, res);
        } else {
            self.find.on_result(id, res, &mut self.table, &mut out);
        }
        out
    }

    /// Re-sorts all rows; call when a capture ends so appended rows join the sort order.
    pub fn resort(&mut self) {
        self.table.resort();
    }

    pub fn set_follow(&mut self, follow: bool) {
        self.table.set_follow(follow);
    }

    pub fn select_frame(&mut self, no: u64) -> bool {
        self.table.select_frame(no)
    }

    pub fn set_filter_status(&mut self, result: Result<(), String>) {
        self.filter_bar.set_status(result);
    }

    pub fn filter_status(&self) -> &FilterStatus {
        self.filter_bar.status()
    }

    pub fn filter_history(&self) -> Vec<String> {
        self.filter_bar.history()
    }

    pub fn set_filter_history(&mut self, items: Vec<String>) {
        self.filter_bar.set_history(items);
    }

    pub fn set_filter_values(&mut self, values: std::sync::Arc<crate::features::ValueIndex>) {
        self.filter_bar.set_values(values);
    }

    pub fn set_filter_catalog(&mut self, catalog: std::sync::Arc<crate::features::FieldCatalog>) {
        self.filter_bar.set_catalog(catalog);
    }

    /// Screenshot helper (`--packets-demo`): pre-sets filter text / open menus / find query.
    pub fn apply_demo(&mut self, spec: &str) {
        self.demo = Demo::parse(spec);
        if let Some(t) = self.demo.text.clone() {
            self.filter_bar.set_text(&t);
        }
        for f in std::mem::take(&mut self.demo.columns) {
            self.table.add_field_column(&f);
        }
        self.table.apply_demo(self.demo.time, self.demo.time_ref);
        if let Some(q) = self.demo.find_query() {
            self.find.query = q;
            self.find.open();
            self.demo_find_run = true;
        }
    }

    pub fn table_prefs(&self) -> crate::packets::TablePrefs {
        self.table.table_prefs()
    }

    pub fn set_table_prefs(&mut self, p: crate::packets::TablePrefs) {
        self.table.set_table_prefs(p);
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    pub fn set_layout(&mut self, layout: Layout) {
        self.layout = layout.sanitized();
    }

    pub fn ui(&mut self, ui: &mut Ui, detail: Option<&FrameDetail>) -> Vec<PacketsAction> {
        let now = ui.input(|i| i.time);
        let open_quick = self.demo.take_menu("quick", now);
        if self.demo.menu_pending() {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
        if self.demo.take_menu("columns", now) {
            self.table.open_columns_menu();
        }
        let mut out = self.filter_bar.ui(ui, self.table.quick_chips(), open_quick);
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::F)) {
            self.find.open();
        }
        find_bar::ui(ui, &mut self.find, &mut self.table, &mut out);
        if self.demo_find_run && self.table.state.total() > 0 {
            self.demo_find_run = false;
            self.find.step(true, &mut self.table, &mut out);
        }
        ui.add_space(spacing::SM);
        let current_filter = self.filter_bar.text().to_owned();
        let Self {
            table,
            tree,
            hex,
            layout,
            ..
        } = self;
        let mut table_out = Vec::new();
        let mut tree_filter = None;
        let avail_h = ui.available_height();
        if avail_h < MIN_SPLIT_H && detail.is_none() {
            table_out = table.ui(ui);
        } else {
            let mut bottom = layout.detail_frac;
            let mut top = layout.table_frac;
            let min_frac = (MIN_TABLE_H / avail_h.max(1.0)).clamp(0.15, 0.72);
            let mut eff_top = top.max(min_frac);
            split::vertical(
                ui,
                &mut eff_top,
                |ui| table_out = table.ui(ui),
                |ui| {
                    ui.add_space(spacing::XS);
                    let sel = std::cell::Cell::new(tree.selected_range());
                    split::horizontal(
                        ui,
                        &mut bottom,
                        |ui| {
                            tree_filter = tree.ui(ui, detail, &current_filter);
                            sel.set(tree.selected_range());
                        },
                        |ui| hex.ui(ui, detail, sel.get()),
                    );
                },
            );
            if (eff_top - top.max(min_frac)).abs() > f32::EPSILON {
                top = eff_top;
            }
            *layout = Layout {
                table_frac: top,
                detail_frac: bottom,
            };
        }
        if let Some(field) = tree.take_column_request() {
            table.add_field_column(&field);
        }
        if let Some(expr) = tree_filter {
            table_out.push(PacketsAction::ApplyFilter(expr));
        }
        for a in &table_out {
            if let PacketsAction::ApplyFilter(f) = a {
                self.filter_bar.set_text(f);
            }
        }
        out.extend(table_out);
        out
    }
}
