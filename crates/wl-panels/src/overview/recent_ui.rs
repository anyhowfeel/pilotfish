//! Recent files list: pin star, middle-elided name and folder, size / packets / date columns.

use std::f32::consts::{PI, TAU};

use wl_kit::egui::{
    Align, Color32, CursorIcon, FontId, Mesh, Painter, Pos2, Rect, Response, RichText, Sense,
    Shape, Stroke, TextStyle, Ui, pos2, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{paint_elided, paint_middle, text_width};

use super::actions::OverviewAction;
use super::recent::{RecentEntry, format_date, format_datetime};

const ROW_H: f32 = 36.0;
const STAR_W: f32 = 28.0;
const SIZE_W: f32 = 72.0;
const PACKETS_W: f32 = 96.0;
const DATE_W: f32 = 84.0;
/// Below this row width the packet-count column is dropped.
const WIDE: f32 = 760.0;

/// Section header with a "Clear" action, then one row per entry.
pub fn recent_section(ui: &mut Ui, entries: &[RecentEntry], out: &mut Vec<OverviewAction>) {
    ui.add_space(spacing::XS);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Recent files").strong().size(15.0));
        ui.with_layout(wl_kit::egui::Layout::right_to_left(Align::Center), |ui| {
            if entries.is_empty() {
                return;
            }
            let clear = ui.add(
                wl_kit::egui::Button::new("Clear recent")
                    .small()
                    .frame(false),
            );
            if clear.on_hover_cursor(CursorIcon::PointingHand).clicked() {
                out.push(OverviewAction::ClearRecent);
            }
        });
    });
    let (line, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(line, 0.0, Palette::border());
    ui.add_space(spacing::XS);
    if entries.is_empty() {
        ui.add_space(spacing::SM);
        ui.label(
            RichText::new("Captures you open appear here. Drop a .pcap or .pcapng file on the window, or use Open pcap\u{2026}")
                .color(Palette::muted()),
        );
    }
    for e in entries {
        recent_row(ui, e, out);
    }
}

fn recent_row(ui: &mut Ui, e: &RecentEntry, out: &mut Vec<OverviewAction>) {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::click());
    let star_rect = Rect::from_min_size(rect.min, vec2(STAR_W, ROW_H));
    let star = ui.interact(star_rect, resp.id.with("pin"), Sense::click());
    if resp.hovered() || star.hovered() {
        ui.painter().rect_filled(rect, 6.0, Palette::surface_hi());
    }
    paint_star(
        ui.painter(),
        star_rect.center(),
        e.pinned,
        star.hovered(),
        resp.hovered(),
    );
    let wide = rect.width() >= WIDE;
    let cols = layout_columns(rect, wide);
    let p = ui.painter();
    let small = TextStyle::Small.resolve(ui.style());
    let body = TextStyle::Body.resolve(ui.style());
    let strong = FontId::new(body.size, body.family.clone());
    let mono = FontId::monospace(small.size);
    let text_w = cols.text.width();
    let name_w = text_width(ui, &e.name, strong.clone()).min(text_w * 0.55);
    let name_r = Rect::from_min_size(cols.text.min, vec2(name_w, ROW_H));
    paint_middle(p, name_r, &e.name, strong, Palette::text(), Align::Min);
    let dir_r = Rect::from_min_max(
        pos2(name_r.right() + spacing::SM, cols.text.top()),
        cols.text.max,
    );
    if dir_r.width() > 24.0 {
        paint_middle(
            p,
            dir_r,
            &e.dir,
            small.clone(),
            Palette::muted(),
            Align::Min,
        );
    }
    paint_elided(
        p,
        cols.size,
        &format::bytes(e.size),
        mono.clone(),
        Palette::muted(),
        Align::Max,
    );
    if let Some(r) = cols.packets {
        let n = e.packets.map_or("\u{2013}".to_string(), |n| {
            format!("{} pkts", format::count(n))
        });
        paint_elided(p, r, &n, mono.clone(), Palette::muted(), Align::Max);
    }
    let date = e.modified.map_or("\u{2013}".to_string(), format_date);
    paint_elided(p, cols.date, &date, mono, Palette::muted(), Align::Max);
    handle(resp, star, e, out);
}

struct Columns {
    text: Rect,
    size: Rect,
    packets: Option<Rect>,
    date: Rect,
}

fn layout_columns(row: Rect, wide: bool) -> Columns {
    let pad = spacing::SM;
    let col = |right: f32, w: f32| {
        Rect::from_min_max(pos2(right - w, row.top()), pos2(right, row.bottom()))
    };
    let date = col(row.right() - pad, DATE_W);
    let mut left = date.left() - spacing::MD;
    let packets = wide.then(|| {
        let r = col(left, PACKETS_W);
        left = r.left() - spacing::MD;
        r
    });
    let size = col(left, SIZE_W);
    let text = Rect::from_min_max(
        pos2(row.left() + STAR_W + pad, row.top()),
        pos2(size.left() - spacing::LG, row.bottom()),
    );
    Columns {
        text,
        size,
        packets,
        date,
    }
}

fn handle(row: Response, star: Response, e: &RecentEntry, out: &mut Vec<OverviewAction>) {
    if star.clicked() {
        out.push(OverviewAction::TogglePin(e.path.clone()));
    } else if row.clicked() {
        out.push(OverviewAction::OpenFile(e.path.clone()));
    }
    let when = e.modified.map_or(String::new(), |m| {
        format!("\nmodified {}", format_datetime(m))
    });
    let tip = format!("{}\n{}{when}", e.path.display(), format::bytes(e.size));
    row.on_hover_text(tip)
        .on_hover_cursor(CursorIcon::PointingHand);
    star.on_hover_text(if e.pinned { "Unpin" } else { "Pin to the top" });
}

fn star_points(c: Pos2, r: f32) -> Vec<Pos2> {
    (0..10)
        .map(|i| {
            let rad = if i % 2 == 0 { r } else { r * 0.45 };
            let a = -PI / 2.0 + TAU * i as f32 / 10.0;
            pos2(c.x + rad * a.cos(), c.y + rad * a.sin())
        })
        .collect()
}

/// Filled when pinned, outlined on row hover, invisible otherwise.
fn paint_star(p: &Painter, c: Pos2, pinned: bool, star_hot: bool, row_hot: bool) {
    if !pinned && !row_hot && !star_hot {
        return;
    }
    let color: Color32 = if pinned || star_hot {
        Palette::accent()
    } else {
        Palette::muted()
    };
    let pts = star_points(c, 7.0);
    if pinned {
        let mut mesh = Mesh::default();
        mesh.colored_vertex(c, color);
        for q in &pts {
            mesh.colored_vertex(*q, color);
        }
        for i in 0..10u32 {
            mesh.add_triangle(0, 1 + i, 1 + (i + 1) % 10);
        }
        p.add(Shape::mesh(mesh));
    } else {
        p.add(Shape::closed_line(pts, Stroke::new(1.3, color)));
    }
}
