//! Cells shared by the hosts and conversations tables.

use wl_kit::egui::{
    self, Align, CornerRadius, Key, Layout, RichText, Sense, Stroke, Ui, pos2, vec2,
};
use wl_kit::table::{CELL_PAD, sort_arrow};
use wl_kit::theme::{Palette, spacing, tint};
use wl_kit::widgets::close_button;

use super::sort::SortState;

/// Clickable sortable header cell with painted sort triangle; returns true when clicked.
pub fn sort_header<C: Copy + PartialEq>(
    ui: &mut Ui,
    text: &str,
    col: C,
    sort: &SortState<C>,
    right: bool,
) -> bool {
    let rect = ui.max_rect();
    let resp = ui.interact(rect, ui.scope_id().with(("sort", text)), Sense::click());
    // Subtle bottom rule under every header cell for crisp separation from row 0.
    ui.painter().line_segment(
        [
            pos2(rect.left(), rect.bottom()),
            pos2(rect.right(), rect.bottom()),
        ],
        Stroke::new(1.0, Palette::border()),
    );
    let active = sort.col == col;
    let color = if resp.hovered() || active {
        Palette::text()
    } else {
        Palette::muted()
    };
    let asc = !sort.desc;
    let rt = RichText::new(text).small().strong().color(color);
    if right {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add_space(CELL_PAD);
            if active {
                sort_arrow(ui, asc, Palette::accent());
            }
            ui.add(egui::Label::new(rt).truncate().selectable(false));
        });
    } else {
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            ui.add_space(CELL_PAD);
            ui.add(egui::Label::new(rt).truncate().selectable(false));
            if active {
                sort_arrow(ui, asc, Palette::accent());
            }
        });
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// Horizontal share bar (`frac` in 0..=1) vertically centered in the cell.
pub fn share_bar(ui: &mut Ui, frac: f32) {
    ui.add_space(CELL_PAD);
    let w = (ui.available_width() - spacing::SM).max(8.0);
    let (rect, resp) = ui.allocate_exact_size(vec2(w, 8.0), Sense::hover());
    let r = CornerRadius::same(4);
    ui.painter().rect_filled(rect, r, Palette::surface_hi());
    let mut fill = rect;
    fill.set_width((rect.width() * frac.clamp(0.0, 1.0)).max(if frac > 0.0 { 2.0 } else { 0.0 }));
    ui.painter()
        .rect_filled(fill, r, tint(Palette::accent(), 220));
    resp.on_hover_text(format!("{:.1}%", frac * 100.0));
}

/// Case-insensitive text edit with a hint, fixed width, Escape-to-clear, and clear icon button.
pub fn filter_box(ui: &mut Ui, text: &mut String, hint: &str, width: f32) -> bool {
    let w = width.min((ui.available_width() - 140.0).max(120.0));
    let edit = ui.add(
        wl_kit::widgets::text_field(text)
            .hint_text(hint)
            .desired_width(w),
    );
    let mut changed = edit.changed();
    if edit.has_focus() && !text.is_empty() && ui.input(|i| i.key_pressed(Key::Escape)) {
        text.clear();
        changed = true;
    }
    if !text.is_empty() && close_button(ui).clicked() {
        text.clear();
        changed = true;
    }
    changed
}
