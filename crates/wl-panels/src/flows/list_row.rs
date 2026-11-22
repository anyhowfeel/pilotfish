use wl_kit::egui::text::{LayoutJob, TextFormat};
use wl_kit::egui::{
    Align, Color32, CornerRadius, CursorIcon, Rect, Sense, Stroke, StrokeKind, Ui, pos2, vec2,
};
use wl_kit::theme::{Palette, spacing, tint};
use wl_kit::widgets::text::paint_in;
use wl_kit::widgets::{PillStyle, pill_at};

use super::paint::{label_font, mono_font};

pub const ROW: f32 = 56.0;
const LEAD_W: f32 = 14.0;
const BAR_H: f32 = 3.0;

pub enum Lead<'a> {
    Dot(Color32),
    Protocol(&'a str, Color32),
}

/// One right-aligned figure; the lowest `rank` is kept longest when the row is narrow.
pub struct Cell {
    pub text: String,
    pub width: f32,
    pub rank: u8,
}

impl Cell {
    pub fn new(text: String, width: f32, rank: u8) -> Self {
        Self { text, width, rank }
    }
}

pub struct Row<'a> {
    pub selected: bool,
    pub title: &'a [(String, bool)],
    pub lead: Lead<'a>,
    pub cells: &'a [Cell],
    pub share: f32,
}

fn title_job(parts: &[(String, bool)], width: f32) -> LayoutJob {
    let mut job = LayoutJob::default();
    for (text, muted) in parts {
        let color = if *muted {
            Palette::muted()
        } else {
            Palette::text()
        };
        job.append(text, 0.0, TextFormat::simple(label_font(), color));
    }
    job.wrap.max_width = width;
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    job
}

fn share_bar(ui: &Ui, rect: Rect, frac: f32) {
    let r = CornerRadius::same(2);
    ui.painter().rect_filled(rect, r, Palette::surface_hi());
    let mut fill = rect;
    fill.set_width((rect.width() * frac.clamp(0.0, 1.0)).max(if frac > 0.0 { 2.0 } else { 0.0 }));
    ui.painter()
        .rect_filled(fill, r, tint(Palette::accent(), 200));
}

/// Cells are right-aligned in display order; the highest-ranked ones are dropped first when narrow.
fn paint_cells(ui: &Ui, cells: &[Cell], left: f32, right: f32, cy: f32) {
    let mut order: Vec<usize> = (0..cells.len()).collect();
    order.sort_by_key(|&i| cells[i].rank);
    let mut used = 0.0;
    let mut shown = vec![false; cells.len()];
    for i in order {
        let need = cells[i].width + spacing::XS;
        if right - left - used < need {
            break;
        }
        used += need;
        shown[i] = true;
    }
    let mut x = right;
    for (cell, _) in cells.iter().zip(&shown).rev().filter(|(_, s)| **s) {
        let rect = Rect::from_min_max(pos2(x - cell.width, cy - 8.0), pos2(x, cy + 8.0));
        paint_in(
            ui.painter(),
            rect,
            &cell.text,
            mono_font(),
            Palette::muted(),
            Align::Max,
        );
        x -= cell.width + spacing::XS;
    }
}

pub fn item(ui: &mut Ui, row: &Row) -> bool {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), ROW), Sense::click());
    let p = ui.painter().with_clip_rect(rect);
    let inner = rect.shrink2(vec2(0.0, 2.0));
    let radius = CornerRadius::same(6);
    if row.selected {
        p.rect_filled(inner, radius, Palette::selection_bg());
        p.rect_stroke(
            inner,
            radius,
            Stroke::new(1.0, Palette::accent()),
            StrokeKind::Inside,
        );
    } else if resp.hovered() {
        p.rect_filled(inner, radius, Palette::surface_hi());
    }
    let x0 = inner.left() + spacing::MD;
    let right = inner.right() - spacing::MD;
    let title_x = match row.lead {
        Lead::Dot(_) => x0 + LEAD_W,
        Lead::Protocol(..) => x0,
    };
    let title = p.layout_job(title_job(row.title, right - title_x));
    let title_y = inner.top() + 8.0;
    if let Lead::Dot(c) = row.lead {
        p.circle_filled(
            pos2(x0 + 3.0, (title_y + title.size().y / 2.0).round()),
            3.5,
            c,
        );
    }
    p.galley(
        pos2(title_x, title_y.round()),
        title.clone(),
        Palette::text(),
    );

    let line_cy = title_y + title.size().y + 10.0;
    let cells_left = match row.lead {
        Lead::Protocol(name, color) => {
            let pill = pill_at(
                ui,
                x0,
                line_cy,
                name,
                color,
                PillStyle::column(48.0).with_dot(false),
            );
            pill.right() + spacing::SM
        }
        Lead::Dot(_) => title_x,
    };
    paint_cells(ui, row.cells, cells_left, right, line_cy);
    let bar_top = inner.bottom() - BAR_H - 3.0;
    let bar = Rect::from_min_size(pos2(x0, bar_top), vec2((right - x0).max(0.0), BAR_H));
    share_bar(ui, bar, row.share);
    resp.on_hover_cursor(CursorIcon::PointingHand).clicked()
}
