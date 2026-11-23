//! Square icon button with vector-painted glyphs (font independent, pixel centred).

use eframe::egui::{
    Color32, CornerRadius, CursorIcon, Painter, Pos2, Rect, Response, Sense, Shape, Stroke,
    StrokeKind, Ui, pos2, vec2,
};

use crate::theme::Palette;

pub const ICON_BUTTON: f32 = 28.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glyph {
    Plus,
    Minus,
    /// Four corner brackets: "fit to view".
    Fit,
    /// Circular arrow: "reset the view".
    Reset,
    /// Diagonal cross: remove / close.
    Cross,
    /// Open eye: visible.
    Eye,
    /// Eye with a slash: hidden.
    EyeOff,
}

/// Lens-shaped eye outline (upper and lower arc) with a pupil.
fn paint_eye(p: &Painter, m: Pos2, u: f32, s: Stroke) {
    let arc = |sign: f32| -> Vec<Pos2> {
        (0..=14)
            .map(|i| {
                let x = -1.0 + 2.0 * (i as f32 / 14.0);
                pos2(m.x + x * u, m.y + sign * 0.62 * u * (1.0 - x * x))
            })
            .collect()
    };
    p.add(Shape::line(arc(-1.0), s));
    p.add(Shape::line(arc(1.0), s));
    p.circle_filled(m, u * 0.26, s.color);
}

/// Paints `glyph` centred in `r` (a ~14 px square).
pub fn paint_glyph(p: &Painter, glyph: Glyph, r: Rect, c: Color32) {
    let (m, u) = (r.center(), r.width() / 2.0);
    let s = Stroke::new(1.6, c);
    match glyph {
        Glyph::Plus | Glyph::Minus => {
            p.line_segment([pos2(m.x - u, m.y), pos2(m.x + u, m.y)], s);
            if glyph == Glyph::Plus {
                p.line_segment([pos2(m.x, m.y - u), pos2(m.x, m.y + u)], s);
            }
        }
        Glyph::Fit => {
            let k = u * 0.55;
            for (sx, sy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                let corner = pos2(m.x + sx * u, m.y + sy * u);
                p.line_segment([corner, pos2(corner.x - sx * k, corner.y)], s);
                p.line_segment([corner, pos2(corner.x, corner.y - sy * k)], s);
            }
        }
        Glyph::Reset => {
            let r = u * 0.85;
            let arc: Vec<Pos2> = (0..=18)
                .map(|i| {
                    let a = (45.0 + 270.0 * (i as f32 / 18.0)).to_radians();
                    pos2(m.x + r * a.cos(), m.y - r * a.sin())
                })
                .collect();
            p.add(Shape::line(arc.clone(), s));
            let (end, before) = (arc[arc.len() - 1], arc[arc.len() - 2]);
            let d = (end - before).normalized();
            let n = vec2(-d.y, d.x);
            let k = u * 0.6;
            p.line_segment([end, end - d * k + n * k * 0.7], s);
            p.line_segment([end, end - d * k - n * k * 0.7], s);
        }
        Glyph::Cross => {
            let d = u * 0.8;
            p.line_segment([pos2(m.x - d, m.y - d), pos2(m.x + d, m.y + d)], s);
            p.line_segment([pos2(m.x + d, m.y - d), pos2(m.x - d, m.y + d)], s);
        }
        Glyph::Eye => paint_eye(p, m, u, s),
        Glyph::EyeOff => {
            paint_eye(p, m, u, Stroke::new(1.6, c.gamma_multiply(0.55)));
            p.line_segment(
                [pos2(m.x - u, m.y + u * 0.9), pos2(m.x + u, m.y - u * 0.9)],
                s,
            );
        }
    }
}

/// 28 px square button showing `glyph`, with a hover tooltip.
pub fn icon_button(ui: &mut Ui, tip: &str, glyph: Glyph) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(ICON_BUTTON, ICON_BUTTON), Sense::click());
    let hot = resp.hovered();
    let radius = CornerRadius::same(7);
    let p = ui.painter();
    p.rect_filled(
        rect,
        radius,
        if hot {
            Palette::surface_hi()
        } else {
            Palette::surface()
        },
    );
    p.rect_stroke(
        rect,
        radius,
        Stroke::new(1.0, Palette::border()),
        StrokeKind::Inside,
    );
    let fg = if hot {
        Palette::text()
    } else {
        Palette::muted()
    };
    paint_glyph(
        p,
        glyph,
        Rect::from_center_size(rect.center(), vec2(14.0, 14.0)),
        fg,
    );
    resp.on_hover_cursor(CursorIcon::PointingHand)
        .on_hover_text(tip)
}
