//! Top of the page: KPI strip and the filter toolbar.

use wl_kit::egui::{self, Align2, CornerRadius, FontId, Rect, Sense, Stroke, Ui, pos2, vec2};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::{pill_toggle, segmented_w};

use super::cells::latency;
use super::model::{CLASS_LABELS, Filter, KindFilter};
use super::stats::WebStats;
use crate::overview::filter_box;

const CELL_H: f32 = 64.0;
/// Vertical centres of title / value / sub inside a cell: equal 17 pt steps, equal margins.
const LINE_Y: [f32; 3] = [15.0, 32.0, 49.0];
/// Below this width the KPI strip folds into two rows of three.
const WIDE_W: f32 = 700.0;
/// Below this width the search box wraps to its own line.
const WIDE_TOOLBAR_W: f32 = 740.0;

fn pct(f: f64) -> String {
    format!("{:.0}%", f * 100.0)
}

fn kpis(s: &WebStats) -> [(&'static str, String, String, egui::Color32); 6] {
    let err_color = match s.error_rate {
        r if s.errors == 0 || r < 0.05 => Palette::text(),
        r if r < 0.2 => Palette::warn(),
        _ => Palette::danger(),
    };
    let ms = |v: Option<f64>| v.map_or("-".to_owned(), latency);
    [
        (
            "Requests",
            format::count(s.requests as u64),
            format!("{} HTTP", s.requests),
            Palette::text(),
        ),
        (
            "Hosts",
            format::count(s.hosts as u64),
            "distinct".to_owned(),
            Palette::text(),
        ),
        (
            "Error rate",
            pct(s.error_rate),
            format!("{} with 4xx/5xx", s.errors),
            err_color,
        ),
        (
            "Avg latency",
            ms(s.avg_ms),
            "request to response".to_owned(),
            Palette::text(),
        ),
        (
            "p95 latency",
            ms(s.p95_ms),
            format!("slowest {}", latency(s.max_ms)),
            Palette::text(),
        ),
        (
            "HTTPS",
            pct(s.https_share),
            format!("{} TLS sessions", s.tls),
            Palette::text(),
        ),
    ]
}

/// Six KPI cells in one framed strip; folds to 3 + 3 when narrow.
pub fn summary_strip(ui: &mut Ui, s: &WebStats) {
    let w = ui.available_width();
    let cols = if w >= WIDE_W { 6 } else { 3 };
    let rows = 6 / cols;
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
            let (y0, y1) = (cell.top() + 12.0, cell.bottom() - 12.0);
            p.line_segment(
                [pos2(x, y0), pos2(x, y1)],
                Stroke::new(1.0, Palette::border()),
            );
        }
        let x = cell.left() + spacing::LG;
        let clip = p.with_clip_rect(cell.shrink2(vec2(spacing::XS, 0.0)));
        let small = FontId::proportional(11.5);
        clip.text(
            pos2(x, cell.top() + LINE_Y[0]),
            Align2::LEFT_CENTER,
            title,
            small.clone(),
            Palette::muted(),
        );
        clip.text(
            pos2(x, cell.top() + LINE_Y[1]),
            Align2::LEFT_CENTER,
            value,
            FontId::monospace(17.0),
            color,
        );
        clip.text(
            pos2(x, cell.top() + LINE_Y[2]),
            Align2::LEFT_CENTER,
            sub,
            small,
            Palette::muted(),
        );
    }
}

fn kind_seg(ui: &mut Ui, f: &mut Filter) -> bool {
    let kinds = [
        (KindFilter::All, "All"),
        (KindFilter::Http, "HTTP"),
        (KindFilter::Https, "HTTPS"),
    ];
    segmented_w(ui, &mut f.kind, &kinds, 200.0)
}

fn search(ui: &mut Ui, f: &mut Filter) -> bool {
    filter_box(ui, &mut f.query, "Host, URL, status, method\u{2026}", 260.0)
}

fn chips(ui: &mut Ui, f: &mut Filter) -> bool {
    let mut changed = false;
    for (i, label) in CLASS_LABELS.iter().enumerate() {
        changed |= pill_toggle(ui, &mut f.classes[i], label).changed();
    }
    changed
}

/// Segmented kind filter, search box and status-class chips. True when the filter changed.
/// Wide: kind, search, chips; narrow: kind and chips first so the search wraps onto its own line.
pub fn toolbar(ui: &mut Ui, f: &mut Filter, shown: usize, total: usize) -> bool {
    let mut changed = false;
    let wide = ui.available_width() >= WIDE_TOOLBAR_W;
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(spacing::SM, spacing::SM);
        changed |= kind_seg(ui, f);
        if wide {
            changed |= search(ui, f);
            changed |= chips(ui, f);
        } else {
            changed |= chips(ui, f);
            changed |= search(ui, f);
        }
        ui.label(
            egui::RichText::new(format!("{shown} of {total}"))
                .small()
                .color(Palette::muted()),
        );
    });
    changed
}
