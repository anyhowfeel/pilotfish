//! Find Packet bar (Ctrl+F): query field, mode/scope selectors, case toggle, Prev/Next, status.

use eframe::egui::{self, Align, ComboBox, Key, Layout, RichText, Ui};
use wl_kit::widgets::{close_button, text_field, toggle_chip_h};

use crate::packets::actions::PacketsAction;
use crate::packets::find_query::{FindMode, FindScope};
use crate::packets::find_state::{FindState, Status};
use crate::packets::kit::{Palette, danger, spacing};
use crate::packets::table::PacketTable;

/// Single-row layout needs at least this much width; below it the controls wrap to a 2nd row.
const WIDE: f32 = 760.0;
const MODE_W: f32 = 118.0;
const SCOPE_W: f32 = 124.0;
const CASE_W: f32 = 30.0;
const STATUS_W: f32 = 104.0;

pub fn ui(ui: &mut Ui, st: &mut FindState, table: &mut PacketTable, out: &mut Vec<PacketsAction>) {
    if !st.open {
        return;
    }
    let mut step: Option<bool> = None;
    let mut changed = false;
    let wide = ui.available_width() >= WIDE;
    ui.add_space(spacing::XS);
    if wide {
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                nav(ui, st, &mut step);
                status(ui, &st.status, STATUS_W);
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    let ctl = MODE_W + SCOPE_W + CASE_W + 3.0 * ui.spacing().item_spacing.x;
                    let w = (ui.available_width() - ctl).max(80.0);
                    changed |= field(ui, st, w, &mut step);
                    changed |= selectors(ui, st);
                });
            });
        });
    } else {
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                nav(ui, st, &mut step);
                let w = ui.available_width();
                changed |= field(ui, st, w, &mut step);
            });
        });
        ui.add_space(spacing::XS);
        ui.horizontal(|ui| {
            changed |= selectors(ui, st);
            status(ui, &st.status, ui.available_width());
        });
    }
    if changed {
        st.invalidate();
    }
    if let Some(fwd) = step {
        st.step(fwd, table, out);
    }
    ui.add_space(spacing::XS);
}

/// Right-anchored: close, Next, Prev (drawn right to left).
fn nav(ui: &mut Ui, st: &mut FindState, step: &mut Option<bool>) {
    if close_button(ui).on_hover_text("Close (Esc)").clicked() {
        st.close();
    }
    if ui
        .button("Next")
        .on_hover_text("Next match (Enter)")
        .clicked()
    {
        *step = Some(true);
    }
    if ui
        .button("Previous")
        .on_hover_text("Previous match (Shift+Enter)")
        .clicked()
    {
        *step = Some(false);
    }
}

fn field(ui: &mut Ui, st: &mut FindState, width: f32, step: &mut Option<bool>) -> bool {
    let hint = match st.query.mode {
        FindMode::Filter => "Display filter, e.g. tcp.flags.reset == 1",
        FindMode::Text => "Find packet\u{2026}",
        FindMode::Hex => "Hex bytes, e.g. de ad be ef",
        FindMode::Regex => "Regular expression",
    };
    let edit = ui.add(
        text_field(&mut st.query.text)
            .hint_text(hint)
            .font(egui::TextStyle::Monospace)
            .desired_width(width),
    );
    if std::mem::take(&mut st.focus) {
        edit.request_focus();
    }
    if edit.has_focus() && ui.input(|i| i.key_pressed(Key::Escape)) {
        st.close();
    }
    if edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
        *step = Some(!ui.input(|i| i.modifiers.shift));
        edit.request_focus();
    }
    edit.changed()
}

fn selectors(ui: &mut Ui, st: &mut FindState) -> bool {
    let q = &mut st.query;
    let before = q.clone();
    ComboBox::from_id_salt("find_mode")
        .width(MODE_W - 20.0)
        .selected_text(q.mode.label())
        .show_ui(ui, |ui| {
            for m in FindMode::ALL {
                ui.selectable_value(&mut q.mode, m, m.label());
            }
        });
    ui.add_enabled_ui(q.mode.uses_scope(), |ui| {
        ComboBox::from_id_salt("find_scope")
            .width(SCOPE_W - 20.0)
            .selected_text(if q.mode.uses_scope() {
                q.scope.label()
            } else {
                "Whole frame"
            })
            .show_ui(ui, |ui| {
                for s in FindScope::ALL {
                    ui.selectable_value(&mut q.scope, s, s.label());
                }
            });
    });
    if toggle_chip_h(
        ui,
        q.case_sensitive,
        "Aa",
        None,
        ui.spacing().interact_size.y,
    )
    .on_hover_text("Match case")
    .clicked()
    {
        q.case_sensitive = !q.case_sensitive;
    }
    *q != before
}

fn status(ui: &mut Ui, s: &Status, width: f32) {
    let (text, color) = match s {
        Status::Idle => (String::new(), Palette::muted()),
        Status::Searching => ("Searching\u{2026}".to_owned(), Palette::muted()),
        Status::NotFound => ("No matches".to_owned(), danger()),
        Status::Error(e) => (e.clone(), danger()),
        Status::Found {
            index,
            total,
            capped,
        } => (
            format!("{index} of {total}{}", if *capped { "+" } else { "" }),
            Palette::muted(),
        ),
    };
    let label = RichText::new(&text).small().color(color);
    ui.allocate_ui_with_layout(
        egui::vec2(width.max(0.0), ui.spacing().interact_size.y),
        Layout::right_to_left(Align::Center),
        |ui| {
            ui.add(egui::Label::new(label).truncate())
                .on_hover_text(&text);
        },
    );
}
