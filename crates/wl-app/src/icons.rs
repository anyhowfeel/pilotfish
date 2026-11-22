//! Vector nav & chrome icons (font-independent, pixel centered).
use std::f32::consts::TAU;

use wl_kit::egui::{Color32, Painter, Pos2, Rect, Stroke, StrokeKind, pos2, vec2};

use crate::page::Page;

/// Draws the icon of `page` inside `r` (a square ~18 px).
pub fn paint(p: &Painter, page: Page, r: Rect, c: Color32) {
    let s = Stroke::new(1.6, c);
    let m = r.center();
    let u = r.width() / 2.0;
    match page {
        Page::Setup => {
            p.circle_stroke(m, u * 0.85, s);
            p.circle_filled(m, u * 0.38, c);
        }
        Page::Overview => {
            let q = u * 0.82;
            for (dx, dy, k) in [
                (-1.0, -1.0, 1.0),
                (1.0, -1.0, 0.55),
                (-1.0, 1.0, 0.55),
                (1.0, 1.0, 1.0),
            ] {
                let cell = Rect::from_center_size(
                    m + vec2(dx * q * 0.55, dy * q * 0.55),
                    vec2(q * 0.9, q * 0.9),
                );
                p.rect_filled(cell, 2.0, c.gamma_multiply(k));
            }
        }
        Page::Graphs => {
            // Axes with a rising polyline.
            let (o, top, right) = (
                pos2(m.x - u * 0.85, m.y + u * 0.8),
                pos2(m.x - u * 0.85, m.y - u * 0.85),
                pos2(m.x + u * 0.9, m.y + u * 0.8),
            );
            p.line_segment([top, o], s);
            p.line_segment([o, right], s);
            let pts = [
                pos2(m.x - u * 0.55, m.y + u * 0.35),
                pos2(m.x - u * 0.1, m.y - u * 0.2),
                pos2(m.x + u * 0.25, m.y + u * 0.15),
                pos2(m.x + u * 0.8, m.y - u * 0.6),
            ];
            for w in pts.windows(2) {
                p.line_segment([w[0], w[1]], s);
            }
        }
        Page::Packets => {
            for dy in [-0.6, 0.0, 0.6] {
                let y = m.y + dy * u;
                p.line_segment([pos2(m.x - u * 0.9, y), pos2(m.x + u * 0.9, y)], s);
            }
        }
        Page::Hosts => {
            let scr = Rect::from_center_size(m - vec2(0.0, u * 0.15), vec2(u * 1.8, u * 1.2));
            p.rect_stroke(scr, 2.0, s, StrokeKind::Inside);
            p.line_segment([pos2(m.x, scr.bottom()), pos2(m.x, m.y + u * 0.8)], s);
            p.line_segment(
                [
                    pos2(m.x - u * 0.5, m.y + u * 0.8),
                    pos2(m.x + u * 0.5, m.y + u * 0.8),
                ],
                s,
            );
        }
        Page::Map => {
            let hub = pos2(m.x - u * 0.1, m.y + u * 0.05);
            let leaves = [
                pos2(m.x - u * 0.75, m.y - u * 0.65),
                pos2(m.x + u * 0.8, m.y - u * 0.5),
                pos2(m.x + u * 0.55, m.y + u * 0.8),
                pos2(m.x - u * 0.7, m.y + u * 0.7),
            ];
            for l in leaves {
                p.line_segment([hub, l], Stroke::new(1.3, c));
                p.circle_filled(l, u * 0.2, c);
            }
            p.circle_filled(hub, u * 0.34, c);
        }
        Page::Conversations => {
            arrow(
                p,
                pos2(m.x - u * 0.85, m.y - u * 0.4),
                pos2(m.x + u * 0.85, m.y - u * 0.4),
                s,
            );
            arrow(
                p,
                pos2(m.x + u * 0.85, m.y + u * 0.4),
                pos2(m.x - u * 0.85, m.y + u * 0.4),
                s,
            );
        }
        Page::Flows => {
            // Sequence diagram: two lifelines with a request and a reply arrow between them.
            for x in [-0.8, 0.8] {
                p.line_segment(
                    [
                        pos2(m.x + x * u, m.y - u * 0.9),
                        pos2(m.x + x * u, m.y + u * 0.9),
                    ],
                    Stroke::new(1.3, c),
                );
            }
            arrow(
                p,
                pos2(m.x - u * 0.8, m.y - u * 0.35),
                pos2(m.x + u * 0.8, m.y - u * 0.35),
                s,
            );
            arrow(
                p,
                pos2(m.x + u * 0.8, m.y + u * 0.4),
                pos2(m.x - u * 0.8, m.y + u * 0.4),
                s,
            );
        }
        Page::Web => {
            // Globe: circle, meridian ellipse (two arcs) and equator.
            p.circle_stroke(m, u * 0.9, s);
            p.line_segment([pos2(m.x - u * 0.9, m.y), pos2(m.x + u * 0.9, m.y)], s);
            let arc = |k: f32| {
                (0..=12)
                    .map(|i| {
                        let a = std::f32::consts::PI * (i as f32 / 12.0 - 0.5);
                        pos2(m.x + k * u * 0.45 * a.cos(), m.y + u * 0.9 * a.sin())
                    })
                    .collect::<Vec<_>>()
            };
            p.add(wl_kit::egui::Shape::line(arc(1.0), s));
            p.add(wl_kit::egui::Shape::line(arc(-1.0), s));
        }
        Page::Diff => {
            for dx in [-0.35, 0.35] {
                let sq = Rect::from_center_size(m + vec2(dx * u, dx * u), vec2(u * 1.25, u * 1.25));
                p.rect_stroke(sq, 2.0, s, StrokeKind::Inside);
            }
        }
        Page::Insights => {
            let pts = [
                pos2(m.x - u * 0.9, m.y + u * 0.1),
                pos2(m.x - u * 0.4, m.y + u * 0.1),
                pos2(m.x - u * 0.15, m.y - u * 0.65),
                pos2(m.x + u * 0.2, m.y + u * 0.65),
                pos2(m.x + u * 0.45, m.y + u * 0.1),
                pos2(m.x + u * 0.9, m.y + u * 0.1),
            ];
            for w in pts.windows(2) {
                p.line_segment([w[0], w[1]], s);
            }
        }
    }
}

/// Draws a gear (settings) icon inside `r`: ring, hub and eight teeth.
pub fn paint_gear(p: &Painter, r: Rect, c: Color32) {
    let m = r.center();
    let u = r.width() / 2.0;
    p.circle_stroke(m, u * 0.55, Stroke::new(1.6, c));
    p.circle_stroke(m, u * 0.2, Stroke::new(1.3, c));
    for i in 0..8 {
        let a = (i as f32) * TAU / 8.0;
        let dir = vec2(a.cos(), a.sin());
        let seg = [m + dir * (u * 0.62), m + dir * (u * 0.98)];
        p.line_segment(seg, Stroke::new(2.2, c));
    }
}

fn arrow(p: &Painter, from: Pos2, to: Pos2, s: Stroke) {
    let d = (to - from).normalized();
    let n = vec2(-d.y, d.x);
    p.line_segment([from, to], s);
    p.line_segment([to, to - d * 4.5 + n * 3.5], s);
    p.line_segment([to, to - d * 4.5 - n * 3.5], s);
}
