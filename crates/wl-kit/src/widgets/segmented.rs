//! Segmented control: options sized to their labels, selected one filled.
use eframe::egui::{
    Align, CornerRadius, CursorIcon, FontId, Rect, Sense, Stroke, StrokeKind, Ui, vec2,
};

use crate::theme::Palette;
use crate::widgets::text;

const CONTROL_W: f32 = 240.0;

/// Segmented control: equal-width options, selected one tinted. Returns true when changed.
pub fn segmented<T: PartialEq + Copy>(ui: &mut Ui, value: &mut T, options: &[(T, &str)]) -> bool {
    let w = ui.available_width().min(CONTROL_W);
    segmented_w(ui, value, options, w)
}

/// Segment widths: each label gets the same padding on both sides (so gaps between labels are
/// even), the spare width is shared equally; falls back to equal widths when labels do not fit.
fn segment_widths<T>(ui: &Ui, options: &[(T, &str)], w: f32) -> Vec<f32> {
    let n = options.len().max(1) as f32;
    let font = FontId::proportional(12.5);
    let natural: Vec<f32> = options
        .iter()
        .map(|(_, t)| text::text_width(ui, t, font.clone()) + 2.0 * SEG_PAD)
        .collect();
    let sum: f32 = natural.iter().sum();
    if sum > w {
        return vec![w / n; options.len()];
    }
    let extra = (w - sum) / n;
    natural.iter().map(|x| x + extra).collect()
}

const SEG_PAD: f32 = 14.0;

/// `segmented` with an explicit total width.
pub fn segmented_w<T: PartialEq + Copy>(
    ui: &mut Ui,
    value: &mut T,
    options: &[(T, &str)],
    w: f32,
) -> bool {
    let widths = segment_widths(ui, options, w);
    let total: f32 = widths.iter().sum();
    // The id comes from this control's own allocation: `scope_id()` is shared by every control
    // of the parent ui, so two segmented controls used to steal each other's clicks.
    let (rect, base) = ui.allocate_exact_size(vec2(total, 28.0), Sense::hover());
    let mut changed = false;
    ui.painter()
        .rect_filled(rect, CornerRadius::same(7), Palette::bg());
    ui.painter().rect_stroke(
        rect,
        CornerRadius::same(7),
        Stroke::new(1.0, Palette::border()),
        StrokeKind::Inside,
    );
    let mut x = 0.0;
    for (i, (v, name)) in options.iter().enumerate() {
        let r = Rect::from_min_size(rect.min + vec2(x, 0.0), vec2(widths[i], rect.height()))
            .shrink(2.0);
        x += widths[i];
        let resp = ui.interact(r, base.id.with(("seg", i)), Sense::click());
        let sel = *v == *value;
        if sel {
            ui.painter()
                .rect_filled(r, CornerRadius::same(5), Palette::selection_bg());
        } else if resp.hovered() {
            ui.painter()
                .rect_filled(r, CornerRadius::same(5), Palette::surface_hi());
        }
        let font = FontId::proportional(12.5);
        let color = if sel {
            Palette::text()
        } else {
            Palette::muted()
        };
        let _ = text::paint_in(
            &ui.painter().with_clip_rect(r),
            r,
            name,
            font,
            color,
            Align::Center,
        );
        if resp.on_hover_cursor(CursorIcon::PointingHand).clicked() && !sel {
            *value = *v;
            changed = true;
        }
    }
    changed
}
