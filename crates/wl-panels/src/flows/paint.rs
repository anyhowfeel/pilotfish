//! Painting of the flow graph: sticky host header, lifelines and one arrow per event.
//! Everything is painted straight into the painter (no widgets per row) so cost is O(visible).

use wl_kit::egui::{
    Align, Color32, CornerRadius, FontId, Painter, Pos2, Rect, Shape, Stroke, StrokeKind, pos2,
    vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, protocol_color, spacing, tint};
use wl_kit::widgets::text::{elided_galley, paint_in};
use wl_model::{FlowEvent, FlowFlags};

use super::geom::{Cols, HEAD_H, ROW_H};
use super::lanes::Lanes;
use super::marks::Mark;

const ARROW_Y: f32 = 25.0;
const HEAD_LEN: f32 = 6.0;

pub fn label_font() -> FontId {
    FontId::proportional(12.5)
}

pub fn mono_font() -> FontId {
    FontId::monospace(11.5)
}

/// Colour of a mark (handshake / teardown / problems); `None` for ordinary packets.
pub fn mark_color(m: Mark) -> Option<Color32> {
    match m {
        Mark::None => None,
        Mark::Handshake => Some(Palette::ok()),
        Mark::Teardown => Some(Palette::info()),
        Mark::Reset | Mark::Retransmission => Some(Palette::danger()),
        Mark::Anomaly => Some(Palette::warn()),
    }
}

fn arrow_color(e: &FlowEvent, m: Mark) -> Color32 {
    mark_color(m).unwrap_or_else(|| protocol_color(&e.protocol))
}

/// Sticky header: one box per host centred on its lifeline (name, optional port below).
pub fn header(p: &Painter, top_left: Pos2, cols: &Cols, lanes: &Lanes) {
    for (i, h) in lanes.hosts.iter().enumerate() {
        let w = cols.lane_w - spacing::SM;
        let r = Rect::from_center_size(
            pos2(top_left.x + cols.lane_x(i), top_left.y + HEAD_H / 2.0),
            vec2(w, HEAD_H - spacing::XS),
        );
        let radius = CornerRadius::same(wl_kit::theme::RADIUS);
        p.rect_filled(r, radius, Palette::surface());
        p.rect_stroke(
            r,
            radius,
            Stroke::new(1.0, Palette::border()),
            StrokeKind::Inside,
        );
        let inner = r.shrink2(vec2(spacing::SM, 0.0));
        let name = elided_galley(p, &h.addr, label_font(), Palette::text(), inner.width());
        let port = h.port.map(|v| {
            elided_galley(
                p,
                &format!(":{v}"),
                mono_font(),
                Palette::muted(),
                inner.width(),
            )
        });
        let ph = port.as_ref().map_or(0.0, |g| g.size().y);
        let top = r.center().y - (name.size().y + ph) / 2.0;
        p.galley(
            pos2(inner.center().x - name.size().x / 2.0, top.round()),
            name.clone(),
            Palette::text(),
        );
        if let Some(g) = port {
            let x = inner.center().x - g.size().x / 2.0;
            p.galley(pos2(x, (top + name.size().y).round()), g, Palette::muted());
        }
    }
}

/// Vertical lifelines spanning `y0..y1`.
pub fn lifelines(p: &Painter, x0: f32, y0: f32, y1: f32, cols: &Cols, n: usize) {
    for i in 0..n {
        let x = (x0 + cols.lane_x(i)).round() + 0.5;
        p.line_segment(
            [pos2(x, y0), pos2(x, y1)],
            Stroke::new(1.0, Palette::border()),
        );
    }
}

#[derive(Clone, Copy, Default)]
pub struct RowState {
    pub selected: bool,
    pub hovered: bool,
}

fn arrow(p: &Painter, from: Pos2, to: Pos2, c: Color32, dashed: bool) {
    let w = Stroke::new(1.6, c);
    let dir = if to.x >= from.x { 1.0 } else { -1.0 };
    let tip = pos2(to.x - dir * 1.0, to.y);
    let base = tip.x - dir * HEAD_LEN;
    if dashed {
        p.extend(Shape::dashed_line(&[from, pos2(base, to.y)], w, 5.0, 3.0));
    } else {
        p.line_segment([from, pos2(base, to.y)], w);
    }
    p.add(Shape::convex_polygon(
        vec![tip, pos2(base, to.y - 3.5), pos2(base, to.y + 3.5)],
        c,
        Stroke::NONE,
    ));
    p.circle_filled(from, 2.5, c);
}

/// "Seq 270  Ack 5658  Len 75" annotation of a TCP packet.
pub fn note(e: &FlowEvent) -> String {
    match (e.seq, e.ack) {
        (Some(s), Some(a)) if e.flags.contains(FlowFlags::ACK) => {
            format!("Seq {s}  Ack {a}  Len {}", e.len)
        }
        (Some(s), _) => format!("Seq {s}  Len {}", e.len),
        _ => e.protocol.to_string(),
    }
}

/// One event row whose top-left corner is `at` and whose width is `cols.width`.
pub fn row(
    p: &Painter,
    at: Pos2,
    cols: &Cols,
    e: &FlowEvent,
    (f, t): (usize, usize),
    m: Mark,
    st: RowState,
) {
    let rect = Rect::from_min_size(at, vec2(cols.width, ROW_H));
    let color = arrow_color(e, m);
    if st.selected {
        p.rect_filled(rect, 0.0, Palette::selection_bg());
        p.rect_filled(
            Rect::from_min_size(at, vec2(3.0, ROW_H)),
            0.0,
            Palette::accent(),
        );
    } else if mark_color(m).is_some() {
        p.rect_filled(rect, 0.0, tint(color, 24));
    } else if st.hovered {
        p.rect_filled(rect, 0.0, Palette::surface_hi());
    }
    let cell =
        |(l, r): (f32, f32)| Rect::from_min_max(pos2(at.x + l, at.y), pos2(at.x + r, at.y + ROW_H));
    let mono = mono_font();
    paint_in(
        p,
        cell(cols.frame),
        &format!("#{}", e.frame),
        mono.clone(),
        Palette::muted(),
        Align::Max,
    );
    paint_in(
        p,
        cell(cols.time),
        &format::time_rel(e.rel),
        mono.clone(),
        Palette::text(),
        Align::Max,
    );
    if let Some(n) = cols.note {
        paint_in(p, cell(n), &note(e), mono, Palette::muted(), Align::Min);
    }
    let y = at.y + ARROW_Y;
    let (xs, xd) = (at.x + cols.lane_x(f), at.x + cols.lane_x(t));
    if f != t {
        arrow(p, pos2(xs, y), pos2(xd, y), color, e.flags.is_anomaly());
    }
    label(p, at.y, (xs.min(xd), xs.max(xd)), e);
}

/// Protocol tag (non-TCP) + label centred above the arrow, elided to the arrow's span.
fn label(p: &Painter, top: f32, (x0, x1): (f32, f32), e: &FlowEvent) {
    let span = if x1 - x0 < 1.0 {
        160.0
    } else {
        x1 - x0 - 2.0 * spacing::SM
    };
    let mid = (x0 + x1) / 2.0;
    let tag_color = protocol_color(&e.protocol);
    let tag = (!matches!(&*e.protocol, "TCP" | ""))
        .then(|| elided_galley(p, &e.protocol, label_font(), tag_color, span / 2.0));
    let gap = if tag.is_some() {
        spacing::XS + 2.0
    } else {
        0.0
    };
    let tag_w = tag.as_ref().map_or(0.0, |g| g.size().x + gap);
    let max = (span - tag_w).max(8.0);
    let g = elided_galley(p, &e.label, label_font(), Palette::text(), max);
    let y = (top + 4.0).round();
    let mut x = (mid - (tag_w + g.size().x) / 2.0).round();
    if let Some(t) = tag {
        let w = t.size().x;
        p.galley(pos2(x, y), t, tag_color);
        x += w + gap;
    }
    p.galley(pos2(x, y), g, Palette::text());
}
