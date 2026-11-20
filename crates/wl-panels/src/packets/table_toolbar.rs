//! Packet-table toolbar (search, follow, clear, Columns menu) and column/time preferences.

use eframe::egui::{
    self, Align, CursorIcon, Key, Layout, Popup, PopupCloseBehavior, RectAlign, RichText,
    SetOpenCommand, Ui,
};
use wl_kit::widgets::{menu_chip, pill_toggle};

use crate::packets::actions::PacketsAction;
use crate::packets::column_set::TablePrefs;
use crate::packets::columns_menu;
use crate::packets::kit::Palette;
use crate::packets::table::PacketTable;
use crate::packets::time_format::TimeFormat;

const COLUMNS_BTN_W: f32 = 96.0;

impl PacketTable {
    pub fn table_prefs(&self) -> TablePrefs {
        TablePrefs {
            columns: self.columns.clone(),
            time: self.time_fmt,
        }
    }

    pub fn set_table_prefs(&mut self, p: TablePrefs) {
        self.columns = p.columns.sanitized();
        self.time_fmt = p.time;
    }

    pub fn apply_demo(&mut self, time: Option<TimeFormat>, ref_frame: Option<u64>) {
        if let Some(t) = time {
            self.time_fmt = t;
        }
        self.ref_pending = ref_frame;
    }

    /// Opens the Columns menu on the next frame (screenshots).
    pub fn open_columns_menu(&mut self) {
        self.open_columns_now = true;
    }

    /// "Apply as Column": shows tshark field `field` as a new column.
    pub fn add_field_column(&mut self, field: &str) {
        self.columns.add_field(field);
    }

    /// Backend answer for a custom column pass; false if `id` is not ours.
    pub fn on_custom_result(
        &mut self,
        id: u64,
        res: &Result<Vec<wl_model::FrameFields>, String>,
    ) -> bool {
        self.custom.on_result(id, res)
    }

    fn columns_button(&mut self, ui: &mut Ui) {
        let custom = !self.columns.is_default() || self.time_fmt != TimeFormat::default();
        let btn = menu_chip(ui, "Columns", custom);
        // Opens leftwards: the button sits at the right end of the toolbar.
        let mut popup = Popup::menu(&btn).align(RectAlign::BOTTOM_END);
        if std::mem::take(&mut self.open_columns_now) {
            popup = popup.open_memory(SetOpenCommand::Bool(true));
        }
        popup
            .close_behavior(PopupCloseBehavior::CloseOnClickOutside)
            .show(|ui| self.columns_menu(ui));
    }

    pub(crate) fn columns_menu(&mut self, ui: &mut Ui) {
        columns_menu::show(
            ui,
            &mut self.columns,
            &mut self.time_fmt,
            &mut self.new_field,
            &mut self.time_ref,
        );
    }

    pub(super) fn toolbar(&mut self, ui: &mut Ui, out: &mut Vec<PacketsAction>) {
        let (t, v) = (self.state.total(), self.state.visible());
        let count_txt = if t == v {
            format!("{t} packets")
        } else {
            format!("{v} of {t} packets")
        };
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let lbl = RichText::new(&count_txt)
                    .color(Palette::muted())
                    .monospace();
                ui.add(egui::Label::new(lbl).truncate());
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    let search_w =
                        (ui.available_width() - 156.0 - COLUMNS_BTN_W).clamp(72.0, 260.0);
                    let edit = wl_kit::widgets::text_field(&mut self.quick_text)
                        .hint_text("Quick search\u{2026}")
                        .desired_width(search_w);
                    let resp = ui.add(edit);
                    if resp.has_focus()
                        && !self.quick_text.is_empty()
                        && ui.input(|i| i.key_pressed(Key::Escape))
                    {
                        self.quick_text.clear();
                        self.state.set_quick("");
                    } else if resp.changed() {
                        self.state.set_quick(&self.quick_text);
                    }
                    let mut f = self.follow;
                    let tip = "Auto-scroll to newest packets";
                    if pill_toggle(ui, &mut f, "Follow")
                        .on_hover_text(tip)
                        .changed()
                    {
                        self.set_follow(f);
                    }
                    let clr = ui.button("Clear").on_hover_cursor(CursorIcon::PointingHand);
                    if clr.on_hover_text("Clear packet list").clicked() {
                        out.push(PacketsAction::ClearAll);
                    }
                    self.columns_button(ui);
                });
            });
        });
    }
}
