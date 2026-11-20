//! One selectable interface card: status dot, name, tag + detail line, live rate with sparkline
//! and a selection checkbox. Everything is painted into fixed rects, so rows line up exactly.

use wl_kit::egui::{
    Align, Color32, CornerRadius, CursorIcon, FontId, Pos2, Rect, Response, Sense, Stroke,
    StrokeKind, TextStyle, Ui, pos2, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::{PILL_HEIGHT, PillStyle, paint_elided, pill_at};
use wl_model::Interface;

use super::activity::{Activity, normalized};
use super::iface_class::{Class, Group};

pub const CARD_H: f32 = 64.0;
const CHECK: f32 = 18.0;
const ACT_W: f32 = 88.0;
const SPARK_H: f32 = 18.0;
const LINE_GAP: f32 = 3.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardEvent {
    None,
    /// Card body clicked: select only this interface (Ctrl toggles instead).
    Select,
    /// Checkbox clicked: add or remove from the multi-selection.
    Toggle,
}

pub struct CardData<'a> {
    pub iface: &'a Interface,
    pub class: Class,
    pub activity: Option<&'a Activity>,
    pub selected: bool,
}

/// Second line of text: description (or state) plus the link speed when known.
pub fn detail_text(i: &Interface) -> String {
    let base = i
        .description
        .clone()
        .unwrap_or_else(|| (if i.is_up { "up" } else { "down" }).to_string());
    // Virtual devices report a nominal speed that means nothing to the user.
    match i.sys.speed_mbps.filter(|_| i.sys.physical) {
        Some(m) if m >= 1000 => format!("{base} \u{b7} {} Gb/s", m / 1000),
        Some(m) => format!("{base} \u{b7} {m} Mb/s"),
        None => base,
    }
}

pub fn interface_card(ui: &mut Ui, rect: Rect, d: &CardData<'_>) -> (Response, CardEvent) {
    let id = ui.scope_id().with(("iface", &d.iface.name));
    let resp = ui.interact(rect, id, Sense::click());
    let inner = rect.shrink2(vec2(spacing::MD, spacing::XS));
    let check = Rect::from_center_size(
        pos2(inner.right() - CHECK / 2.0, rect.center().y),
        vec2(CHECK, CHECK),
    );
    let check_resp = ui.interact(check.expand(5.0), id.with("check"), Sense::click());
    paint_frame(ui, rect, d.selected, resp.hovered() || check_resp.hovered());
    paint_check(ui, check, d.selected, check_resp.hovered());

    let dot_r = 4.5;
    let color = if d.iface.is_up {
        Palette::ok()
    } else {
        Palette::muted()
    };
    let dot = pos2(inner.left() + dot_r, rect.center().y);
    ui.painter().circle_filled(dot, dot_r, color);

    let text_left = dot.x + dot_r + spacing::SM + 2.0;
    let act = Rect::from_min_max(
        pos2(check.left() - spacing::MD - ACT_W, inner.top()),
        pos2(check.left() - spacing::MD, inner.bottom()),
    );
    let text_right = (act.left() - spacing::MD).max(text_left);
    paint_text(ui, d, text_left, text_right, rect.center().y);
    paint_activity(ui, d, act);

    let tip = format!(
        "{} ({}) \u{b7} {}{}",
        d.iface.name,
        if d.iface.is_up { "up" } else { "down" },
        d.class.tag,
        if d.iface.sys.default_route {
            " \u{b7} default route"
        } else {
            ""
        }
    );
    let event = if check_resp.clicked() {
        CardEvent::Toggle
    } else if resp.clicked() {
        CardEvent::Select
    } else {
        CardEvent::None
    };
    let resp = resp
        .on_hover_text(tip)
        .on_hover_cursor(CursorIcon::PointingHand);
    (resp, event)
}

fn paint_frame(ui: &Ui, rect: Rect, selected: bool, hovered: bool) {
    let (fill, stroke) = match (selected, hovered) {
        (true, _) => (Palette::selection_bg(), Stroke::new(1.5, Palette::accent())),
        (false, true) => (Palette::surface_hi(), Stroke::new(1.0, Palette::accent())),
        _ => (Palette::surface(), Stroke::new(1.0, Palette::border())),
    };
    let r = CornerRadius::same(RADIUS);
    ui.painter().rect_filled(rect, r, fill);
    ui.painter()
        .rect_stroke(rect, r, stroke, StrokeKind::Inside);
}

fn paint_check(ui: &Ui, r: Rect, on: bool, hot: bool) {
    let round = CornerRadius::same(5);
    let p = ui.painter();
    if on {
        p.rect_filled(r, round, Palette::accent());
        let s = Stroke::new(1.8, Palette::on_accent());
        let c = r.center();
        let pts = [
            pos2(c.x - 4.0, c.y + 0.5),
            pos2(c.x - 1.2, c.y + 3.5),
            pos2(c.x + 4.5, c.y - 3.0),
        ];
        p.line_segment([pts[0], pts[1]], s);
        p.line_segment([pts[1], pts[2]], s);
    } else {
        let border = if hot {
            Palette::accent()
        } else {
            Palette::border()
        };
        p.rect_filled(r, round, Palette::bg());
        p.rect_stroke(r, round, Stroke::new(1.0, border), StrokeKind::Inside);
    }
}

fn paint_text(ui: &Ui, d: &CardData<'_>, left: f32, right: f32, cy: f32) {
    let name_h = ui.text_style_height(&TextStyle::Body);
    let stack = name_h + LINE_GAP + PILL_HEIGHT;
    let top = (cy - stack / 2.0).round();
    let w = (right - left).max(1.0);
    let name_rect = Rect::from_min_size(pos2(left, top), vec2(w, name_h));
    let body = TextStyle::Body.resolve(ui.style());
    paint_elided(
        &ui.painter().with_clip_rect(name_rect),
        name_rect,
        &d.iface.name,
        FontId::new(body.size, body.family),
        Palette::text(),
        Align::Min,
    );
    let row_cy = top + name_h + LINE_GAP + PILL_HEIGHT / 2.0;
    let tag_color = if d.class.group == Group::Network {
        Palette::accent()
    } else {
        Palette::muted()
    };
    let tag = pill_at(ui, left, row_cy, d.class.tag, tag_color, PillStyle::badge());
    let mut x = tag.right() + spacing::SM;
    if d.iface.sys.default_route {
        let p = pill_at(ui, x, row_cy, "default", Palette::ok(), PillStyle::badge());
        x = p.right() + spacing::SM;
    }
    if x < right {
        let r = Rect::from_min_max(
            pos2(x, row_cy - PILL_HEIGHT / 2.0),
            pos2(right, row_cy + PILL_HEIGHT / 2.0),
        );
        let small = TextStyle::Small.resolve(ui.style());
        paint_elided(
            &ui.painter().with_clip_rect(r),
            r,
            &detail_text(d.iface),
            small,
            Palette::muted(),
            Align::Min,
        );
    }
}

fn paint_activity(ui: &Ui, d: &CardData<'_>, area: Rect) {
    let cy = area.center().y;
    let text_h = 16.0;
    let total = text_h + LINE_GAP + SPARK_H;
    let top = (cy - total / 2.0).round();
    let label = Rect::from_min_size(pos2(area.left(), top), vec2(area.width(), text_h));
    let spark = Rect::from_min_size(
        pos2(area.left(), top + text_h + LINE_GAP),
        vec2(area.width(), SPARK_H),
    );
    let (text, live) = match d.activity {
        Some(a) if d.iface.is_up => (format::rate(a.rate), a.rate >= 1.0),
        _ => ("\u{2013}".to_string(), false),
    };
    let ink = if live {
        Palette::text()
    } else {
        Palette::muted()
    };
    let font = FontId::monospace(11.5);
    paint_elided(ui.painter(), label, &text, font, ink, Align::Max);
    sparkline(ui, spark, d.activity.map_or(&[][..], |a| &a.history), live);
}

fn sparkline(ui: &Ui, r: Rect, history: &[f32], live: bool) {
    let base = r.bottom() - 0.5;
    ui.painter().line_segment(
        [pos2(r.left(), base), pos2(r.right(), base)],
        Stroke::new(1.0, Palette::border()),
    );
    let n = normalized(history);
    if n.len() < 2 {
        return;
    }
    let step = r.width() / (crate::overview::activity::HISTORY - 1) as f32;
    let x0 = r.right() - step * (n.len() - 1) as f32;
    let pts: Vec<Pos2> = n
        .iter()
        .enumerate()
        .map(|(i, v)| pos2(x0 + step * i as f32, base - 1.0 - v * (r.height() - 3.0)))
        .collect();
    let c: Color32 = if live {
        Palette::accent()
    } else {
        Palette::muted()
    };
    ui.painter()
        .add(wl_kit::egui::Shape::line(pts, Stroke::new(1.4, c)));
}
