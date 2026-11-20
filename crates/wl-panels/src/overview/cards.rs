//! Card chrome: a painted rounded rect with a clipped child ui, so content can never leak out.

use wl_kit::egui::{Align, CornerRadius, Layout, Rect, Stroke, StrokeKind, Ui, UiBuilder};
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::section_header;

/// Paint a card in `rect`, run `add` inside its padded, clipped area. Returns the used content rect.
pub fn card(ui: &mut Ui, rect: Rect, title: &str, add: impl FnOnce(&mut Ui)) -> Rect {
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(RADIUS), Palette::surface());
    p.rect_stroke(
        rect,
        CornerRadius::same(RADIUS),
        Stroke::new(1.0, Palette::border()),
        StrokeKind::Inside,
    );
    let inner = rect.shrink(spacing::LG);
    let mut child = ui.new_child(
        UiBuilder::new()
            .max_rect(inner)
            .layout(Layout::top_down(Align::Min)),
    );
    child.set_clip_rect(inner.intersect(ui.clip_rect()));
    section_header(&mut child, title);
    add(&mut child);
    child.min_rect()
}

/// Height left for content inside a card of `rect` after padding and the header.
pub fn content_height(rect: Rect) -> f32 {
    (rect.height() - 2.0 * spacing::LG - 54.0).max(40.0)
}
