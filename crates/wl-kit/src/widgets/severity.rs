//! Severity vocabulary shared by findings/insights: colour tokens, dot, accent-bar card.
use eframe::egui::{self, Color32, CornerRadius, Frame, Margin, Rect, Sense, Stroke, Ui, vec2};

use crate::theme::{Palette, RADIUS, spacing};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    Warning,
    Info,
    Ok,
}

impl Severity {
    pub fn color(self) -> Color32 {
        match self {
            Severity::Critical => Palette::danger(),
            Severity::Warning => Palette::warn(),
            Severity::Info => Palette::accent(),
            Severity::Ok => Palette::ok(),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::Warning => "Warning",
            Severity::Info => "Info",
            Severity::Ok => "Healthy",
        }
    }
}

/// Filled circle of `d` points, allocated inline.
pub fn severity_dot(ui: &mut Ui, sev: Severity, d: f32) {
    let (r, _) = ui.allocate_exact_size(vec2(d, d), Sense::hover());
    ui.painter().circle_filled(r.center(), d / 2.0, sev.color());
}

/// Neutral surface card with a 4 px severity bar on its left edge (no coloured border/fill).
/// `selected` raises the surface one level (keyboard focus).
pub fn accent_card<R>(
    ui: &mut Ui,
    sev: Severity,
    selected: bool,
    add: impl FnOnce(&mut Ui) -> R,
) -> egui::InnerResponse<R> {
    let bar_w = 4.0;
    let out = Frame::new()
        .fill(if selected {
            Palette::surface_hi()
        } else {
            Palette::surface()
        })
        .stroke(Stroke::new(1.0, Palette::border()))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin {
            left: (spacing::MD + bar_w) as i8,
            right: spacing::MD as i8,
            top: spacing::MD as i8,
            bottom: spacing::MD as i8,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        });
    let r = out.response.rect;
    let bar = Rect::from_min_max(r.min, egui::pos2(r.min.x + bar_w, r.max.y));
    let rad = CornerRadius {
        nw: RADIUS,
        sw: RADIUS,
        ne: 0,
        se: 0,
    };
    ui.painter().rect_filled(bar, rad, sev.color());
    out
}
