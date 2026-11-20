//! Transient bottom-centre toast (e.g. "Zoom 125%"). Never a permanent widget.
use eframe::egui::{self, Align2, Area, Frame, Id, Margin, Order, RichText, Stroke, vec2};

use crate::theme::{Palette, RADIUS, spacing};

const LIFETIME: f64 = 1.4;

fn slot() -> Id {
    Id::NULL.with("wl_kit_toast")
}

/// Shows `msg` for a brief moment (replaces any toast currently visible).
pub fn push(ctx: &egui::Context, msg: impl Into<String>) {
    let until = ctx.input(|i| i.time) + LIFETIME;
    let msg = msg.into();
    ctx.data_mut(|d| d.insert_temp(slot(), (msg, until.to_bits())));
    ctx.request_repaint();
}

/// Paints the active toast, if any. Call once per frame at the end of the UI.
pub fn draw(ctx: &egui::Context) {
    let Some((msg, bits)) = ctx.data(|d| d.get_temp::<(String, u64)>(slot())) else {
        return;
    };
    if ctx.input(|i| i.time) >= f64::from_bits(bits) {
        ctx.data_mut(|d| d.remove_temp::<(String, u64)>(slot()));
        return;
    }
    Area::new(slot().with("area"))
        .order(Order::Tooltip)
        .anchor(Align2::CENTER_BOTTOM, vec2(0.0, -spacing::XL * 2.0))
        .interactable(false)
        .show(ctx, |ui| {
            Frame::new()
                .fill(Palette::surface_hi())
                .stroke(Stroke::new(1.0, Palette::border()))
                .corner_radius(RADIUS)
                .inner_margin(Margin::symmetric(spacing::LG as i8, spacing::SM as i8))
                .show(ui, |ui| {
                    ui.label(RichText::new(msg).color(Palette::text()));
                });
        });
    ctx.request_repaint_after(std::time::Duration::from_millis(100));
}
