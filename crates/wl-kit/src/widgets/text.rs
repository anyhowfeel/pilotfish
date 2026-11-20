//! Painted text helpers: single-line, elided, vertically centered in a rect.

use eframe::egui::{
    Align, Color32, FontId, Painter, Pos2, Rect, Ui, pos2,
    text::{LayoutJob, TextFormat, TextWrapping},
};
use std::sync::Arc;

use eframe::egui::Galley;

pub fn elided_galley(
    p: &Painter,
    text: &str,
    font: FontId,
    color: Color32,
    max_w: f32,
) -> Arc<Galley> {
    let mut job = LayoutJob::single_section(text.to_owned(), TextFormat::simple(font, color));
    job.wrap = TextWrapping {
        max_width: max_w.max(1.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    p.layout_job(job)
}

/// Paint `text` inside `rect`, centered vertically, horizontally left/center/right aligned, elided to fit.
/// Returns true if the text had to be elided.
pub fn paint_in(
    p: &Painter,
    rect: Rect,
    text: &str,
    font: FontId,
    color: Color32,
    h: Align,
) -> bool {
    let g = elided_galley(p, text, font, color, rect.width());
    let size = g.size();
    let x = match h {
        Align::Max => rect.right() - size.x,
        Align::Center => rect.center().x - size.x / 2.0,
        Align::Min => rect.left(),
    };
    let pos: Pos2 = pos2(x, (rect.center().y - size.y / 2.0).round());
    let elided = g.rows.len() > 1 || g.elided;
    p.galley(pos, g, color);
    elided
}

/// Public alias of `paint_in`: elided single-line text centred vertically in `rect`.
pub fn paint_elided(
    p: &Painter,
    rect: Rect,
    text: &str,
    font: FontId,
    color: Color32,
    h: Align,
) -> bool {
    paint_in(p, rect, text, font, color, h)
}

pub fn text_width(ui: &Ui, text: &str, font: FontId) -> f32 {
    ui.painter()
        .layout_no_wrap(text.to_owned(), font, Color32::WHITE)
        .size()
        .x
}

/// `s` shortened to at most `max` chars with the middle replaced by `…` (head gets the extra char).
pub fn middle_ellipsis(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let (head, tail) = (keep.div_ceil(2), keep / 2);
    let mut out: String = chars[..head].iter().collect();
    out.push('\u{2026}');
    out.extend(&chars[chars.len() - tail..]);
    out
}

/// The longest middle-elided form of `s` that fits `max_w`, plus whether it was shortened.
pub fn fit_middle(p: &Painter, s: &str, font: &FontId, max_w: f32) -> (String, bool) {
    let width = |t: &str| {
        p.layout_no_wrap(t.to_owned(), font.clone(), Color32::WHITE)
            .size()
            .x
    };
    if width(s) <= max_w {
        return (s.to_string(), false);
    }
    let (mut lo, mut hi) = (1, s.chars().count());
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if width(&middle_ellipsis(s, mid)) <= max_w {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    (middle_ellipsis(s, lo), true)
}

/// Like `paint_elided` but keeps both ends of the text (file names, paths).
pub fn paint_middle(
    p: &Painter,
    rect: Rect,
    text: &str,
    font: FontId,
    color: Color32,
    h: Align,
) -> bool {
    let (shown, cut) = fit_middle(p, text, &font, rect.width());
    paint_in(&p.with_clip_rect(rect), rect, &shown, font, color, h);
    cut
}

#[cfg(test)]
mod tests {
    use super::middle_ellipsis;

    #[test]
    fn middle_ellipsis_keeps_both_ends() {
        assert_eq!(middle_ellipsis("short", 10), "short");
        assert_eq!(middle_ellipsis("abcdefghij", 6), "abc\u{2026}ij");
        assert_eq!(middle_ellipsis("abcdefghij", 5), "ab\u{2026}ij");
        assert_eq!(middle_ellipsis("abcdef", 1), "\u{2026}");
        assert_eq!(middle_ellipsis("", 0), "");
    }
}
