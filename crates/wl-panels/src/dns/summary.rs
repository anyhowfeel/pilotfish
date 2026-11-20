//! Summary strip (queries, NXDOMAIN share, RTT) and the top-queried-names chips.

use wl_kit::egui::{
    self, Align2, Color32, CornerRadius, FontId, Rect, Sense, Stroke, Ui, pos2, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::{Severity, pill_toggle};

use super::model::{DnsStats, ms_text};

const CELL_H: f32 = 52.0;
/// Below this width the strip folds into two rows.
const WIDE_W: f32 = 720.0;

fn pct(f: f64) -> String {
    format!("{:.1}%", f * 100.0)
}

fn kpis(s: &DnsStats) -> [(&'static str, String, String, Color32); 5] {
    let nx = match s.nx_share() {
        _ if s.nxdomain == 0 => Palette::text(),
        r if r < 0.1 => Severity::Warning.color(),
        _ => Severity::Critical.color(),
    };
    let ms = |v: Option<f64>| v.map_or("-".to_owned(), ms_text);
    [
        (
            "Queries",
            format::count(s.total as u64),
            format!("{} unique names", s.unique_names),
            Palette::text(),
        ),
        (
            "NXDOMAIN",
            pct(s.nx_share()),
            format!("{} queries", s.nxdomain),
            nx,
        ),
        (
            "Avg RTT",
            ms(s.avg_ms),
            "query to response".to_owned(),
            Palette::text(),
        ),
        (
            "p95 RTT",
            ms(s.p95_ms),
            format!("slowest {}", ms(s.max_ms)),
            Palette::text(),
        ),
        (
            "Unanswered",
            format::count(s.no_response as u64),
            format!("{} retransmitted", s.retransmissions),
            if s.no_response > 0 {
                Severity::Warning.color()
            } else {
                Palette::text()
            },
        ),
    ]
}

/// Five KPI cells in one framed strip (3 + 2 when narrow).
pub fn strip(ui: &mut Ui, s: &DnsStats) {
    let w = ui.available_width();
    let cols = if w >= WIDE_W { 5 } else { 3 };
    let rows = 5usize.div_ceil(cols);
    let (rect, _) = ui.allocate_exact_size(vec2(w, CELL_H * rows as f32), Sense::hover());
    let p = ui.painter();
    let r = CornerRadius::same(RADIUS);
    p.rect_filled(rect, r, Palette::surface());
    p.rect_stroke(
        rect,
        r,
        Stroke::new(1.0, Palette::border()),
        egui::StrokeKind::Inside,
    );
    let cw = w / cols as f32;
    for (i, (title, value, sub, color)) in kpis(s).into_iter().enumerate() {
        let (col, row) = (i % cols, i / cols);
        let cell = Rect::from_min_size(
            rect.min + vec2(cw * col as f32, CELL_H * row as f32),
            vec2(cw, CELL_H),
        );
        if col > 0 {
            let x = cell.left();
            p.line_segment(
                [pos2(x, cell.top() + 10.0), pos2(x, cell.bottom() - 10.0)],
                Stroke::new(1.0, Palette::border()),
            );
        }
        let x = cell.left() + spacing::LG;
        let clip = p.with_clip_rect(cell.shrink2(vec2(spacing::XS, 0.0)));
        let small = FontId::proportional(11.5);
        let text = |y: f32, t: String, f: FontId, c: Color32| {
            clip.text(pos2(x, cell.top() + y), Align2::LEFT_CENTER, t, f, c);
        };
        text(12.0, title.to_owned(), small.clone(), Palette::muted());
        text(29.0, value, FontId::monospace(17.0), color);
        text(44.0, sub, small, Palette::muted());
    }
}

/// "Top queried" chips; clicking one filters the table to it (click again to clear).
/// Returns true when `query` changed.
pub fn top_names(ui: &mut Ui, s: &DnsStats, query: &mut String) -> bool {
    if s.top.is_empty() {
        return false;
    }
    let mut changed = false;
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(spacing::SM, spacing::SM);
        ui.label(
            egui::RichText::new("Top queried")
                .small()
                .color(Palette::muted()),
        );
        for (name, n) in &s.top {
            let mut on = query == name;
            if pill_toggle(ui, &mut on, &format!("{name}  \u{d7}{n}")).changed() {
                *query = if on { name.clone() } else { String::new() };
                changed = true;
            }
        }
    });
    changed
}
