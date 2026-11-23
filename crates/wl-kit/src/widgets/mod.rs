//! Pixel-aligned building blocks: pills, badges, cards, headers, toggles, elided labels.

pub mod chip;
pub mod http_pill;
pub mod icon_button;
pub mod lock;
pub mod mini_button;
pub mod modal;
pub mod pill;
pub mod pill_label;
pub mod pill_look;
pub mod rows;
pub mod rows_input;
pub mod segmented;
pub use segmented::{segmented, segmented_w};
pub mod severity;
pub mod text;
pub mod text_field;
pub mod toast;
pub mod toggle_chip;

use eframe::egui::{
    self, Align, Align2, CornerRadius, CursorIcon, FontId, Layout, Response, RichText, Sense,
    Stroke, StrokeKind, Ui, pos2, vec2,
};

use crate::theme::{Palette, RADIUS, mono, spacing};

pub use chip::{chip, chip_copy, chip_dot, chip_tip};
pub use http_pill::{
    METHOD_PILL_W, STATUS_PILL_W, class_of, method_color, method_pill, method_pill_at,
    status_color, status_pill, status_pill_at,
};
pub use icon_button::{Glyph, icon_button};
pub use lock::{is_encrypted_protocol, lock_icon, paint_lock};
pub use mini_button::{MINI_BUTTON, MiniGlyph, mini_button};
pub use modal::modal_scrim;
pub use pill::{
    PILL_HEIGHT, PROTOCOL_COL_W, PROTOCOL_PILL_W, PillStyle, badge, paint_pill, pill, pill_at,
    pill_width, protocol_pill, protocol_pill_centered,
};
pub use pill_label::abbreviate_protocol;
pub use pill_look::{Look as PillLookKind, set_look as set_pill_look};
pub use rows::{CONTROL_W, ROW_MIN_H, settings_card, settings_row, slider_row, switch, toggle_row};
pub use rows_input::{choice_row, info_row, number_row, shortcut_row, text_row};
pub use severity::{Severity, accent_card, severity_dot};
pub use text::{fit_middle, middle_ellipsis, paint_elided, paint_middle, text_width};
pub use text_field::text_field;
pub use toggle_chip::{
    TOGGLE_CHIP_H, menu_chip, menu_chip_width, toggle_chip, toggle_chip_h, toggle_chip_width,
};

fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(Palette::surface())
        .stroke(Stroke::new(1.0, Palette::border()))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::same(spacing::MD as i8))
}

/// Metric card: muted title, large monospace value, optional muted sub line. Fills available width.
pub fn stat_card(ui: &mut Ui, title: &str, value: &str, sub: Option<&str>) {
    stat_card_h(ui, title, value, sub, None);
}

/// `stat_card` stretched to exactly `height` (outer, incl. border) so grid cells have no dead gap.
pub fn stat_card_h(ui: &mut Ui, title: &str, value: &str, sub: Option<&str>, height: Option<f32>) {
    card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        if let Some(h) = height {
            ui.set_min_height(h - 2.0 * (spacing::MD + 1.0));
        }
        ui.spacing_mut().item_spacing.y = spacing::XS;
        ui.add(egui::Label::new(RichText::new(title).small().color(Palette::muted())).truncate());
        let val_resp =
            ui.add(egui::Label::new(mono(value).size(21.0).color(Palette::text())).truncate());
        if val_resp.hovered() {
            val_resp.on_hover_text(value);
        }
        let sub = sub.unwrap_or("");
        // Always reserve the line so cards in a row keep equal heights.
        let sub_resp = ui.add(
            egui::Label::new(
                RichText::new(if sub.is_empty() { " " } else { sub })
                    .small()
                    .color(Palette::muted()),
            )
            .truncate(),
        );
        if !sub.is_empty() && sub_resp.hovered() {
            sub_resp.on_hover_text(sub);
        }
    });
}

/// Section title with a subtle underline rule.
pub fn section_header(ui: &mut Ui, text: &str) {
    ui.add_space(spacing::XS);
    ui.add(egui::Label::new(RichText::new(text).strong().size(15.0)).truncate());
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0.0, Palette::border());
    ui.add_space(spacing::XS);
}

/// Centered placeholder with a circular vector badge, title and wrapped hint.
pub fn empty_state(ui: &mut Ui, icon: &str, title: &str, hint: &str) {
    let w = ui.available_width();
    let h = ui.available_height().max(140.0);
    let compact = h < 180.0;
    let block_h = if compact { 88.0 } else { 126.0 };
    ui.allocate_ui_with_layout(
        vec2(w, h),
        Layout::top_down(Align::Center).with_main_justify(false),
        |ui| {
            ui.add_space(((h - block_h) / 2.0).max(spacing::SM));
            let d = if compact { 32.0 } else { 44.0 };
            let (badge_rect, _) = ui.allocate_exact_size(vec2(d, d), Sense::hover());
            let p = ui.painter();
            p.circle_filled(badge_rect.center(), d / 2.0, Palette::surface());
            p.circle_stroke(
                badge_rect.center(),
                d / 2.0,
                Stroke::new(1.0, Palette::border()),
            );
            p.text(
                badge_rect.center(),
                Align2::CENTER_CENTER,
                icon,
                FontId::proportional(if compact { 16.0 } else { 20.0 }),
                Palette::muted(),
            );
            ui.add_space(spacing::SM);
            ui.label(
                RichText::new(title)
                    .strong()
                    .size(15.0)
                    .color(Palette::text()),
            );
            ui.add_space(spacing::XS * 0.5);
            ui.allocate_ui(vec2(w.min(360.0), 48.0), |ui| {
                ui.vertical_centered(|ui| {
                    ui.add(egui::Label::new(RichText::new(hint).color(Palette::muted())).wrap());
                });
            });
        },
    );
}

/// Painted vector close (`X`) button — never relies on missing Unicode glyphs.
pub fn close_button(ui: &mut Ui) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(22.0, 22.0), Sense::click());
    let p = ui.painter();
    if resp.hovered() {
        p.rect_filled(rect, CornerRadius::same(6), Palette::surface_hi());
    }
    let c = rect.center();
    let d = 4.0;
    let color = if resp.hovered() {
        Palette::text()
    } else {
        Palette::muted()
    };
    let stroke = Stroke::new(1.6, color);
    p.line_segment([pos2(c.x - d, c.y - d), pos2(c.x + d, c.y + d)], stroke);
    p.line_segment([pos2(c.x + d, c.y - d), pos2(c.x - d, c.y + d)], stroke);
    resp.on_hover_cursor(CursorIcon::PointingHand)
        .on_hover_text("Dismiss (Esc)")
}

/// Pill-shaped toggle button (on = accent tint). Returns a response that is `changed()` on click.
pub fn pill_toggle(ui: &mut Ui, on: &mut bool, text: &str) -> Response {
    let font = FontId::proportional(12.5);
    let w = text::text_width(ui, text, font.clone()) + 2.0 * spacing::MD;
    let (rect, mut resp) = ui.allocate_exact_size(vec2(w, 26.0), Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let (fill, stroke, fg) = if *on {
        (Palette::selection_bg(), Palette::accent(), Palette::text())
    } else if resp.hovered() {
        (Palette::surface_hi(), Palette::border(), Palette::text())
    } else {
        (Palette::surface(), Palette::border(), Palette::muted())
    };
    let r = CornerRadius::same(13);
    ui.painter().rect_filled(rect, r, fill);
    ui.painter()
        .rect_stroke(rect, r, Stroke::new(1.0, stroke), StrokeKind::Inside);
    ui.painter()
        .text(rect.center(), Align2::CENTER_CENTER, text, font, fg);
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// Single-line label occupying exactly `width`, elided with "…" and a hover tooltip when cut.
pub fn elided_label(ui: &mut Ui, text: &str, width: f32) -> Response {
    let h = ui.text_style_height(&egui::TextStyle::Body).max(18.0);
    let (rect, resp) = ui.allocate_exact_size(vec2(width.max(0.0), h), Sense::hover());
    let font = egui::TextStyle::Body.resolve(ui.style());
    let cut = text::paint_in(
        &ui.painter().with_clip_rect(rect),
        rect,
        text,
        font,
        ui.visuals().text_color(),
        Align::Min,
    );
    if cut { resp.on_hover_text(text) } else { resp }
}

/// Fixed-height, full-width row whose children are vertically centered.
pub fn centered_row<R>(ui: &mut Ui, height: f32, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    let w = ui.available_width();
    ui.allocate_ui_with_layout(
        vec2(w, height),
        Layout::left_to_right(Align::Center),
        add_contents,
    )
    .inner
}
