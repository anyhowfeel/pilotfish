//! Virtualized hex dump: offset | hex (8+8) | ascii, with range highlight + hover cross-highlight.

use std::ops::Range;

use eframe::egui::{
    self, Align2, Color32, FontId, Rect, Sense, Stroke, StrokeKind, TextStyle, Ui, pos2, vec2,
};
use wl_model::FrameDetail;

use crate::packets::hex_model as m;
use crate::packets::kit::{Palette, row_h};

#[derive(Default)]
pub struct HexView {
    buf: String,
}

fn cell_rect(x0: f32, cw: f32, row: &Rect, a: f32, b: f32) -> Rect {
    Rect::from_min_max(
        pos2(x0 + a * cw, row.top() + 2.0),
        pos2(x0 + b * cw, row.bottom() - 2.0),
    )
}

impl HexView {
    fn draw_row(
        &mut self,
        ui: &Ui,
        (rect, cw): (Rect, f32),
        row: usize,
        d: &FrameDetail,
        (sel, hover): (&Option<Range<usize>>, Option<usize>),
    ) {
        let p = ui.painter();
        let v = ui.visuals();
        let font = FontId::monospace(ui.style().text_styles[&TextStyle::Monospace].size);
        let x0 = rect.left() + 6.0;
        let base = row * m::ROW_BYTES;
        let bytes = &d.bytes[base..(base + m::ROW_BYTES).min(d.bytes.len())];

        // Subtle column rules separating offset | hex | ascii.
        let rule = Stroke::new(1.0, Palette::border());
        for col_x in [m::HEX_START - 1.0, m::ASCII_START - 1.0] {
            let x = x0 + col_x * cw;
            p.line_segment([pos2(x, rect.top()), pos2(x, rect.bottom())], rule);
        }

        if let Some(cols) = sel
            .as_ref()
            .and_then(|s| m::cols_in_row(row, s, d.bytes.len()))
        {
            let fill = v.selection.bg_fill;
            let border = Stroke::new(1.0, wl_kit::theme::tint(Palette::accent(), 140));
            let hr = cell_rect(
                x0,
                cw,
                &rect,
                m::hex_x(cols.start) - 0.4,
                m::hex_x(cols.end - 1) + 2.4,
            );
            let ar = cell_rect(x0, cw, &rect, m::ascii_x(cols.start), m::ascii_x(cols.end));
            p.rect_filled(hr, 3.0, fill);
            p.rect_stroke(hr, 3.0, border, StrokeKind::Inside);
            p.rect_filled(ar, 3.0, fill);
            p.rect_stroke(ar, 3.0, border, StrokeKind::Inside);
        }
        if let Some(i) = hover
            .filter(|i| i / m::ROW_BYTES == row)
            .map(|i| i % m::ROW_BYTES)
        {
            let c = Palette::surface_hi();
            p.rect_filled(
                cell_rect(x0, cw, &rect, m::hex_x(i) - 0.4, m::hex_x(i) + 2.4),
                3.0,
                c,
            );
            p.rect_filled(
                cell_rect(x0, cw, &rect, m::ascii_x(i), m::ascii_x(i + 1)),
                3.0,
                c,
            );
        }
        let cy = rect.center().y;
        let put = |cells: f32, text: &str, color: Color32| {
            p.text(
                pos2(x0 + cells * cw, cy),
                Align2::LEFT_CENTER,
                text,
                font.clone(),
                color,
            );
        };
        m::offset_text(row, &mut self.buf);
        put(0.0, &self.buf, Palette::muted());
        m::hex_text(bytes, &mut self.buf);
        put(m::HEX_START, &self.buf, Palette::text());
        m::ascii_text(bytes, &mut self.buf);
        put(m::ASCII_START, &self.buf, Palette::text());
    }

    pub fn ui(
        &mut self,
        ui: &mut Ui,
        detail: Option<&FrameDetail>,
        selected: Option<(usize, usize)>,
    ) {
        let Some(d) = detail.filter(|d| !d.bytes.is_empty()) else {
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new("No bytes to show").color(Palette::muted()));
            });
            return;
        };
        let font = FontId::monospace(ui.style().text_styles[&TextStyle::Monospace].size);
        let cw = ui.fonts_mut(|f| f.glyph_width(&font, '0'));
        let width = (m::TOTAL_CHARS * cw + 12.0).max(ui.available_width());
        let sel = m::span(selected, d.bytes.len());
        let mut hover = None;
        ui.spacing_mut().item_spacing.y = 0.0;
        egui::ScrollArea::both()
            .id_salt("hex_view_scroll")
            .auto_shrink([false, false])
            .show_rows(ui, row_h(), m::rows(d.bytes.len()), |ui, range| {
                for row in range {
                    let (rect, resp) = ui.allocate_exact_size(vec2(width, row_h()), Sense::hover());
                    if let Some(pos) = resp.hover_pos()
                        && let Some((i, _)) = m::byte_at((pos.x - rect.left() - 6.0) / cw)
                    {
                        let idx = row * m::ROW_BYTES + i;
                        hover = (idx < d.bytes.len()).then_some(idx);
                    }
                    self.draw_row(ui, (rect, cw), row, d, (&sel, hover));
                }
            });
    }
}
