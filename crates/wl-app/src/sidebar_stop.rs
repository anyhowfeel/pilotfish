//! "Stop capture" action pinned above the sidebar footer while a capture is running.

use wl_kit::egui::{self, Align2, FontId, Rect, Sense, Stroke, StrokeKind, pos2, vec2};
use wl_kit::theme::{Palette, RADIUS, spacing, tint};

/// What is currently running (drives the label).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Running {
    Live,
    Loading,
}

impl Running {
    fn label(self) -> &'static str {
        match self {
            Running::Live => "Stop capture",
            Running::Loading => "Stop loading",
        }
    }
}

/// Danger-tinted full-width button: stop square + label (icon only on the compact rail).
pub fn stop_button(
    ui: &mut egui::Ui,
    running: Running,
    labels: bool,
    row_h: f32,
    icon_w: f32,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), row_h), Sense::click());
    let danger = Palette::danger();
    let fill = tint(danger, if resp.hovered() { 56 } else { 32 });
    let p = ui.painter();
    p.rect_filled(rect, RADIUS, fill);
    p.rect_stroke(
        rect,
        RADIUS,
        Stroke::new(1.0, tint(danger, 120)),
        StrokeKind::Inside,
    );
    let icon_x = if labels {
        rect.left() + spacing::MD + icon_w / 2.0
    } else {
        rect.center().x
    };
    let square = Rect::from_center_size(pos2(icon_x, rect.center().y), vec2(10.0, 10.0));
    p.rect_filled(square, 2.0, danger);
    if labels {
        let x = rect.left() + spacing::MD + icon_w + spacing::SM;
        let clip = Rect::from_min_max(pos2(x, rect.top()), rect.right_bottom());
        p.with_clip_rect(clip).text(
            pos2(x, rect.center().y),
            Align2::LEFT_CENTER,
            running.label(),
            FontId::proportional(14.5),
            Palette::text(),
        );
    }
    resp.on_hover_text(running.label())
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// "Clear filter" action shown while a display filter is applied: neutral outlined button with
/// a painted cross; the tooltip shows the filter it will remove.
pub fn clear_filter_button(
    ui: &mut egui::Ui,
    filter: &str,
    labels: bool,
    row_h: f32,
    icon_w: f32,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), row_h), Sense::click());
    let p = ui.painter();
    let fill = if resp.hovered() {
        Palette::surface_hi()
    } else {
        Palette::surface()
    };
    p.rect_filled(rect, RADIUS, fill);
    p.rect_stroke(
        rect,
        RADIUS,
        Stroke::new(1.0, Palette::border()),
        StrokeKind::Inside,
    );
    let icon_x = if labels {
        rect.left() + spacing::MD + icon_w / 2.0
    } else {
        rect.center().x
    };
    let c = pos2(icon_x, rect.center().y);
    let s = Stroke::new(1.6, Palette::accent());
    p.line_segment([c + vec2(-4.5, -4.5), c + vec2(4.5, 4.5)], s);
    p.line_segment([c + vec2(-4.5, 4.5), c + vec2(4.5, -4.5)], s);
    if labels {
        let x = rect.left() + spacing::MD + icon_w + spacing::SM;
        let clip = Rect::from_min_max(pos2(x, rect.top()), rect.right_bottom());
        p.with_clip_rect(clip).text(
            pos2(x, rect.center().y),
            Align2::LEFT_CENTER,
            "Clear filter",
            FontId::proportional(14.5),
            Palette::text(),
        );
    }
    resp.on_hover_text(format!("Remove  {filter}"))
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}
