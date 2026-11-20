//! Paints one detail-tree label: HTTP start line with pills, `Key: value` on an aligned key
//! column, or plain text. Shared by every tree row so the generic and HTTP cases stay DRY.

use eframe::egui::{Align, FontId, Rect, TextStyle, Ui, pos2};
use wl_kit::widgets::{method_pill_at, paint_elided, status_pill_at, text_width};

use crate::packets::http_row::{self as http, Start};
use crate::packets::kit::{Palette, spacing};

/// Where the copyable value of a row starts, and its text.
pub struct ValueHit<'a> {
    pub left: f32,
    pub text: &'a str,
}

fn font(ui: &Ui) -> FontId {
    TextStyle::Body.resolve(ui.style())
}

/// Width of the key part of `label` (0 when it is not a `Key: value` row).
pub fn key_width(ui: &Ui, label: &str) -> Option<f32> {
    let (k, _) = http::split_kv(label)?;
    Some(text_width(ui, k, font(ui)))
}

/// Paints `label` starting at `x`; `key_w` is the shared key column width of its sibling group.
pub fn paint_label<'a>(
    ui: &Ui,
    rect: Rect,
    x: f32,
    label: &'a str,
    key_w: f32,
    depth: u16,
) -> Option<ValueHit<'a>> {
    let p = ui.painter().with_clip_rect(rect.intersect(ui.clip_rect()));
    let f = font(ui);
    let right = rect.right() - spacing::SM;
    let cy = rect.center().y;
    let span =
        |from: f32, to: f32| Rect::from_min_max(pos2(from, rect.top()), pos2(to, rect.bottom()));
    match http::parse_start(label) {
        Some(Start::Request {
            method,
            uri,
            version,
        }) => {
            let pill = method_pill_at(ui, x, cy, method);
            let ux = pill.right() + spacing::SM;
            let vw = text_width(ui, version, f.clone());
            let uri_w =
                text_width(ui, uri, f.clone()).min((right - ux - vw - spacing::SM).max(0.0));
            paint_elided(
                &p,
                span(ux, ux + uri_w),
                uri,
                f.clone(),
                Palette::text(),
                Align::Min,
            );
            let vx = ux + uri_w + spacing::SM;
            paint_elided(
                &p,
                span(vx, right),
                version,
                f,
                Palette::muted(),
                Align::Min,
            );
            return Some(ValueHit {
                left: ux,
                text: uri,
            });
        }
        Some(Start::Response {
            version,
            code,
            reason,
        }) => {
            let vw = text_width(ui, version, f.clone());
            paint_elided(
                &p,
                span(x, x + vw),
                version,
                f,
                Palette::muted(),
                Align::Min,
            );
            let txt = if reason.is_empty() {
                code.to_string()
            } else {
                format!("{code} {reason}")
            };
            status_pill_at(ui, x + vw + spacing::SM, cy, code, &txt);
            return None;
        }
        None => {}
    }
    if depth > 0
        && let Some((k, v)) = http::split_kv(label)
    {
        let kw = key_w;
        paint_elided(
            &p,
            span(x, x + kw),
            k,
            f.clone(),
            Palette::muted(),
            Align::Min,
        );
        let vx = x + kw + spacing::MD;
        paint_elided(&p, span(vx, right), v, f, Palette::text(), Align::Min);
        return Some(ValueHit { left: vx, text: v });
    }
    paint_elided(&p, span(x, right), label, f, Palette::text(), Align::Min);
    None
}
