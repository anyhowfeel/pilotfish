use eframe::egui::{
    Align, Align2, Color32, CornerRadius, FontId, Layout, Rect, Sense, Ui, UiBuilder, pos2, vec2,
};

use super::layout::{fraction, segment_widths};
use crate::theme::{Mode, Palette, mode, protocol_color, row_h, spacing, tint};
use crate::widgets::pill::{PILL_HEIGHT, protocol_pill};
use crate::widgets::text;

const GAP: f32 = 2.0;

fn bar_alphas() -> (u8, u8) {
    match mode() {
        Mode::Dark => (18, 56),
        Mode::Light => (16, 36),
    }
}

/// Horizontal stacked bar (+ wrapped legend). Items: (name, value, color).
pub fn proportion_bar(ui: &mut Ui, items: &[(String, f64, Color32)], height: f32) {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(w, height), Sense::hover());
    let total: f64 = items.iter().map(|i| i.1.max(0.0)).sum();
    let p = ui.painter();
    let r = CornerRadius::same(((height / 2.0).min(6.0)) as u8);
    p.rect_filled(rect, r, Palette::surface_hi());
    if total > 0.0 {
        let vals: Vec<f64> = items.iter().map(|i| i.1).collect();
        let widths = segment_widths(&vals, w, GAP, 3.0);
        let font = FontId::proportional(11.5);
        let mut x = rect.left();
        let mut hover = None;
        for (i, (item, sw)) in items.iter().zip(&widths).enumerate() {
            if *sw <= 0.0 {
                continue;
            }
            let seg = Rect::from_min_size(pos2(x, rect.top()), vec2(*sw, height));
            p.rect_filled(seg, CornerRadius::same(3), item.2);
            let label = format!("{:.0}%", item.1 / total * 100.0);
            if text::text_width(ui, &label, font.clone()) + 8.0 <= *sw {
                p.text(
                    seg.center(),
                    Align2::CENTER_CENTER,
                    label,
                    font.clone(),
                    Palette::on_color(item.2),
                );
            }
            if resp
                .hover_pos()
                .is_some_and(|hp| hp.x >= seg.left() && hp.x < seg.right() + GAP)
            {
                hover = Some(i);
            }
            x += sw + GAP;
        }
        if let Some(i) = hover {
            let it = &items[i];
            resp.on_hover_text(format!("{}: {:.1}%", it.0, it.1 / total * 100.0));
        }
    }
    ui.add_space(spacing::XS);
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(spacing::SM, spacing::XS);
        for (name, v, c) in items.iter().filter(|i| i.1 > 0.0) {
            let pct = if total > 0.0 { v / total * 100.0 } else { 0.0 };
            let pct_str = if pct < 1.0 {
                "<1%".to_owned()
            } else {
                format!("{pct:.0}%")
            };
            let label = format!("{name} {pct_str}");
            let font = FontId::proportional(11.5);
            let tw = text::text_width(ui, &label, font.clone());
            let (rect, _) =
                ui.allocate_exact_size(vec2(8.0 + 5.0 + tw + 10.0, PILL_HEIGHT), Sense::hover());
            let r = CornerRadius::same((PILL_HEIGHT / 2.0) as u8);
            let p = ui.painter();
            p.rect_filled(rect, r, tint(*c, 22));
            p.circle_filled(pos2(rect.left() + 8.0, rect.center().y), 3.0, *c);
            p.text(
                pos2(rect.left() + 15.0, rect.center().y),
                Align2::LEFT_CENTER,
                label,
                font,
                Palette::muted(),
            );
        }
    });
}

/// Ranked list: each row is a tinted bar (relative to the max value) with the label on the left
/// (elided) and the value text right-aligned in monospace. Rows are expected sorted by caller.
pub fn ranked_bars(ui: &mut Ui, rows: &[(String, f64, String)], color: Color32) {
    let max = rows.iter().map(|r| r.1).fold(0.0, f64::max);
    let font = FontId::proportional(13.0);
    let vfont = FontId::monospace(12.5);
    let w = ui.available_width();
    let prev = ui.spacing().item_spacing.y;
    ui.spacing_mut().item_spacing.y = 3.0;
    let (bg_a, bar_a) = bar_alphas();
    let vw = rows
        .iter()
        .map(|r| text::text_width(ui, &r.2, vfont.clone()))
        .fold(0.0, f32::max);
    for (label, v, vt) in rows {
        let (rect, resp) = ui.allocate_exact_size(vec2(w, row_h()), Sense::hover());
        let p = ui.painter().with_clip_rect(rect);
        let r = CornerRadius::same(5);
        p.rect_filled(rect, r, tint(color, bg_a));
        let bar = Rect::from_min_size(
            rect.min,
            vec2((rect.width() * fraction(*v, max)).max(2.0), row_h()),
        );
        p.rect_filled(bar, r, tint(color, bar_a));
        let inner = rect.shrink2(vec2(spacing::SM, 0.0));
        let val_rect = Rect::from_min_max(pos2(inner.right() - vw, inner.top()), inner.max);
        let lab_rect = Rect::from_min_max(
            inner.min,
            pos2(
                (val_rect.left() - spacing::MD).max(inner.left()),
                inner.bottom(),
            ),
        );
        let cut = text::paint_in(
            &p,
            lab_rect,
            label,
            font.clone(),
            Palette::text(),
            Align::Min,
        );
        text::paint_in(
            &p,
            val_rect,
            vt,
            vfont.clone(),
            Palette::muted(),
            Align::Max,
        );
        if cut {
            resp.on_hover_text(label);
        }
    }
    ui.spacing_mut().item_spacing.y = prev;
}

/// Ranked protocol list: each row pairs a signature `protocol_pill` on the left with a
/// protocol-tinted progress bar and right-aligned monospace value.
pub fn protocol_ranked_bars(ui: &mut Ui, rows: &[(String, f64, String)]) {
    let max = rows.iter().map(|r| r.1).fold(0.0, f64::max);
    let vfont = FontId::monospace(12.5);
    let w = ui.available_width();
    let prev = ui.spacing().item_spacing.y;
    ui.spacing_mut().item_spacing.y = 3.0;
    let (bg_a, bar_a) = bar_alphas();
    let vw = rows
        .iter()
        .map(|r| text::text_width(ui, &r.2, vfont.clone()))
        .fold(0.0, f32::max);
    for (proto, v, vt) in rows {
        let color = protocol_color(proto);
        let (rect, _) = ui.allocate_exact_size(vec2(w, row_h()), Sense::hover());
        let p = ui.painter().with_clip_rect(rect);
        let r = CornerRadius::same(5);
        p.rect_filled(rect, r, tint(color, bg_a));
        let bar = Rect::from_min_size(
            rect.min,
            vec2((rect.width() * fraction(*v, max)).max(2.0), row_h()),
        );
        p.rect_filled(bar, r, tint(color, bar_a));
        let inner = rect.shrink2(vec2(spacing::XS + 2.0, 0.0));
        let val_rect = Rect::from_min_max(pos2(inner.right() - vw - 2.0, inner.top()), inner.max);
        let pill_max = (val_rect.left() - spacing::SM - inner.left()).max(36.0);
        let pill_rect = Rect::from_min_size(
            pos2(inner.left(), rect.center().y - PILL_HEIGHT / 2.0),
            vec2(pill_max, PILL_HEIGHT),
        );
        let mut child = ui.new_child(
            UiBuilder::new()
                .max_rect(pill_rect)
                .layout(Layout::left_to_right(Align::Center)),
        );
        child.set_clip_rect(pill_rect.intersect(ui.clip_rect()));
        protocol_pill(&mut child, proto, 68.0_f32.min(pill_max));
        text::paint_in(
            &p,
            val_rect,
            vt,
            vfont.clone(),
            Palette::muted(),
            Align::Max,
        );
    }
    ui.spacing_mut().item_spacing.y = prev;
}
