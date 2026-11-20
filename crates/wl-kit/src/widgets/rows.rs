//! Reusable form rows: grouped card, label+description left / control right, switch, segmented,
//! slider. Every row has the same minimum height and a vertically centred control column.
use eframe::egui::{
    self, Align, CornerRadius, CursorIcon, Frame, Layout, Margin, Rect, Response, RichText, Sense,
    Stroke, StrokeKind, Ui, UiBuilder, pos2, vec2,
};

use crate::theme::{Palette, RADIUS, spacing};

/// Minimum height of every form row.
pub const ROW_MIN_H: f32 = 48.0;
/// Width of the control column in a form row.
pub const CONTROL_W: f32 = 240.0;
/// Below this row width the control wraps under the label.
const STACK_BELOW: f32 = 440.0;

/// Titled group of rows inside one bordered surface; rows are separated by hairlines.
pub fn settings_card(ui: &mut Ui, title: &str, rows: impl FnOnce(&mut Ui)) {
    if !title.is_empty() {
        ui.add_space(spacing::XS);
        ui.label(
            RichText::new(title)
                .strong()
                .size(13.0)
                .color(Palette::muted()),
        );
    }
    Frame::new()
        .fill(Palette::surface())
        .stroke(Stroke::new(1.0, Palette::border()))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::symmetric(spacing::MD as i8, 0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            rows(ui);
        });
    ui.add_space(spacing::MD);
}

/// One row: strong label with muted wrapped description on the left, `control` on the right.
/// Draws a hairline above itself unless it is `first`.
pub fn settings_row<R>(
    ui: &mut Ui,
    first: bool,
    label: &str,
    desc: &str,
    control: impl FnOnce(&mut Ui) -> R,
) -> R {
    if !first {
        let (line, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
        ui.painter().rect_filled(line, 0.0, Palette::border());
    }
    let full = ui.available_width();
    let stack = full < STACK_BELOW;
    let ctl_w = if stack {
        full
    } else {
        CONTROL_W.min(full * 0.5)
    };
    let text_w = if stack {
        full
    } else {
        (full - ctl_w - spacing::LG).max(80.0)
    };
    let origin = ui.cursor().min;
    let pad = spacing::SM;
    let label_g = ui.painter().layout_no_wrap(
        label.to_owned(),
        egui::TextStyle::Body.resolve(ui.style()),
        Palette::text(),
    );
    let desc_g = (!desc.is_empty()).then(|| {
        ui.painter().layout(
            desc.to_owned(),
            egui::TextStyle::Small.resolve(ui.style()),
            Palette::muted(),
            text_w,
        )
    });
    let gap = 2.0;
    let text_h = label_g.size().y + desc_g.as_ref().map_or(0.0, |g| g.size().y + gap);
    let text_row_h = (text_h + 2.0 * pad).max(ROW_MIN_H);
    let (row_h, ctl_rect) = if stack {
        let r = Rect::from_min_size(
            origin + vec2(0.0, text_row_h - pad),
            vec2(ctl_w, ROW_MIN_H - pad),
        );
        (text_row_h + ROW_MIN_H - pad, r)
    } else {
        let r = Rect::from_min_size(origin + vec2(full - ctl_w, 0.0), vec2(ctl_w, text_row_h));
        (text_row_h, r)
    };
    let text_h_box = if stack { text_row_h } else { row_h };
    let mut y = origin.y + (text_h_box - text_h) / 2.0;
    let p = ui.painter().clone();
    let lh = label_g.size().y;
    p.galley(pos2(origin.x, y), label_g, Palette::text());
    y += lh + gap;
    if let Some(g) = desc_g {
        p.galley(pos2(origin.x, y), g, Palette::muted());
    }
    let mut right = ui.new_child(
        UiBuilder::new()
            .max_rect(ctl_rect)
            .layout(Layout::right_to_left(Align::Center)),
    );
    let out = control(&mut right);
    ui.allocate_exact_size(vec2(full, row_h), Sense::hover());
    out
}

/// iOS-style switch (painted, 36x20).
pub fn switch(ui: &mut Ui, on: &mut bool) -> Response {
    let (rect, mut resp) = ui.allocate_exact_size(vec2(36.0, 20.0), Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let (fill, knob) = if *on {
        (Palette::accent(), Palette::on_accent())
    } else {
        (Palette::surface_hi(), Palette::muted())
    };
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(10), fill);
    p.rect_stroke(
        rect,
        CornerRadius::same(10),
        Stroke::new(1.0, if *on { fill } else { Palette::border() }),
        StrokeKind::Inside,
    );
    let x = if *on {
        rect.right() - 10.0
    } else {
        rect.left() + 10.0
    };
    p.circle_filled(pos2(x, rect.center().y), 7.0, knob);
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// Label/description row with a switch on the right.
pub fn toggle_row(ui: &mut Ui, first: bool, label: &str, desc: &str, on: &mut bool) -> bool {
    settings_row(ui, first, label, desc, |ui| switch(ui, on).changed())
}

/// Label row with a slider (`range`, optional suffix) plus numeric readout.
pub fn slider_row(
    ui: &mut Ui,
    first: bool,
    label: &str,
    desc: &str,
    value: &mut f32,
    range: std::ops::RangeInclusive<f32>,
    suffix: &str,
) -> bool {
    settings_row(ui, first, label, desc, |ui| {
        let s = egui::Slider::new(value, range)
            .suffix(suffix)
            .trailing_fill(true);
        ui.spacing_mut().slider_width = CONTROL_W - 104.0;
        let w = &mut ui.visuals_mut().widgets;
        w.inactive.bg_fill = Palette::border();
        w.hovered.bg_fill = Palette::border();
        w.active.bg_fill = Palette::border();
        ui.add(s).changed()
    })
}
