//! Painted padlock glyph (font-independent; no emoji).

use eframe::egui::{
    Color32, CornerRadius, Painter, Pos2, Rect, Response, Sense, Shape, Stroke, Ui, pos2, vec2,
};

/// Paints a closed padlock centred on `c`, `size` points tall.
pub use wl_model::is_encrypted_protocol;

pub fn paint_lock(p: &Painter, c: Pos2, size: f32, color: Color32) {
    let s = size;
    let body = Rect::from_center_size(pos2(c.x, c.y + s * 0.17), vec2(s * 0.74, s * 0.5));
    p.rect_filled(body, CornerRadius::same((s * 0.1).round() as u8), color);
    let r = s * 0.22;
    let top = body.top();
    let mut pts = vec![pos2(c.x - r, top)];
    pts.push(pos2(c.x - r, top - s * 0.1));
    for i in 0..=8 {
        let a = std::f32::consts::PI * (1.0 - i as f32 / 8.0);
        pts.push(pos2(c.x + r * a.cos(), top - s * 0.1 - r * a.sin()));
    }
    pts.push(pos2(c.x + r, top));
    p.add(Shape::line(pts, Stroke::new((s * 0.14).max(1.2), color)));
}

/// Lock glyph allocated in the flow of `ui` (square of `size`).
pub fn lock_icon(ui: &mut Ui, size: f32, color: Color32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    paint_lock(ui.painter(), rect.center(), size * 0.9, color);
    resp
}
