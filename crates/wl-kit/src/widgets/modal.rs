//! Shared modal scrim: dims the whole window behind a dialog; returns true when clicked.
use eframe::egui::{self, Area, Color32, Id, Order, Sense};

/// Paints a full-window translucent scrim at `order` and reports a click on it
/// (click-outside-to-close). Call right before showing the dialog so it stacks beneath it.
pub fn modal_scrim(ctx: &egui::Context, salt: &str, order: Order) -> bool {
    let screen = ctx.content_rect();
    Area::new(Id::NULL.with(("wl_modal_scrim", salt)))
        .order(order)
        .fixed_pos(screen.min)
        .show(ctx, |ui| {
            let (r, resp) = ui.allocate_exact_size(screen.size(), Sense::click());
            ui.painter()
                .rect_filled(r, 0.0, Color32::from_black_alpha(140));
            resp.clicked()
        })
        .inner
}
