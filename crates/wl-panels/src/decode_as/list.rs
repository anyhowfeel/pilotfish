//! Searchable, virtualised protocol list of the Decode As dialog.

use wl_kit::egui::{
    Align2, CornerRadius, CursorIcon, FontId, ScrollArea, Sense, Stroke, StrokeKind, Ui, pos2, vec2,
};
use wl_kit::theme::{Palette, RADIUS, spacing};

pub const ROW_H: f32 = 28.0;
const VISIBLE_ROWS: f32 = 5.0;

/// Protocols whose name contains `query` (case-insensitive); prefix matches first.
pub fn matching<'a>(all: &'a [String], query: &str) -> Vec<&'a str> {
    let q = query.trim().to_ascii_lowercase();
    let mut hits: Vec<(bool, &str)> = all
        .iter()
        .filter_map(|p| {
            let l = p.to_ascii_lowercase();
            l.contains(&q).then_some((!l.starts_with(&q), p.as_str()))
        })
        .collect();
    hits.sort();
    hits.into_iter().map(|(_, p)| p).collect()
}

/// Framed list; `selected` follows clicks.
pub fn protocol_list(
    ui: &mut Ui,
    all: Option<&[String]>,
    query: &str,
    selected: &mut Option<String>,
) {
    let w = ui.available_width();
    let (frame, _) = ui.allocate_exact_size(vec2(w, ROW_H * VISIBLE_ROWS), Sense::hover());
    let radius = CornerRadius::same(RADIUS);
    ui.painter().rect_filled(frame, radius, Palette::bg());
    ui.painter().rect_stroke(
        frame,
        radius,
        Stroke::new(1.0, Palette::border()),
        StrokeKind::Inside,
    );
    let mut inner = ui.new_child(
        wl_kit::egui::UiBuilder::new()
            .max_rect(frame.shrink(1.0))
            .layout(*ui.layout()),
    );
    let Some(all) = all else {
        message(&mut inner, "Loading protocols\u{2026}");
        return;
    };
    let hits = matching(all, query);
    if hits.is_empty() {
        message(&mut inner, "No protocol matches");
        return;
    }
    ScrollArea::vertical()
        .id_salt("wl_decode_protocols")
        .auto_shrink([false, false])
        .show_rows(&mut inner, ROW_H, hits.len(), |ui, range| {
            for p in &hits[range] {
                row(ui, p, selected);
            }
        });
}

fn message(ui: &mut Ui, text: &str) {
    let r = ui.max_rect();
    ui.painter().text(
        r.center(),
        Align2::CENTER_CENTER,
        text,
        FontId::proportional(13.0),
        Palette::muted(),
    );
}

fn row(ui: &mut Ui, name: &str, selected: &mut Option<String>) {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::click());
    let on = selected.as_deref() == Some(name);
    if on {
        ui.painter().rect_filled(
            rect.shrink2(vec2(2.0, 1.0)),
            CornerRadius::same(5),
            Palette::selection_bg(),
        );
    } else if resp.hovered() {
        ui.painter().rect_filled(
            rect.shrink2(vec2(2.0, 1.0)),
            CornerRadius::same(5),
            Palette::surface_hi(),
        );
    }
    ui.painter().text(
        pos2(rect.left() + spacing::MD, rect.center().y),
        Align2::LEFT_CENTER,
        name,
        FontId::monospace(13.0),
        if on {
            Palette::text()
        } else {
            Palette::muted()
        },
    );
    if resp.on_hover_cursor(CursorIcon::PointingHand).clicked() {
        *selected = Some(name.to_owned());
    }
}
