//! 20 px borderless icon button with vector glyphs (move up / down, remove) for dense lists.

use eframe::egui::{CornerRadius, CursorIcon, Response, Sense, Stroke, Ui, pos2, vec2};

use crate::theme::Palette;

pub const MINI_BUTTON: f32 = 20.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MiniGlyph {
    Up,
    Down,
    Cross,
}

/// Square button painting `glyph`; greyed out and inert when `enabled` is false.
pub fn mini_button(ui: &mut Ui, glyph: MiniGlyph, tip: &str, enabled: bool) -> Response {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(vec2(MINI_BUTTON, MINI_BUTTON), sense);
    let hot = enabled && resp.hovered();
    let p = ui.painter();
    if hot {
        p.rect_filled(rect, CornerRadius::same(4), Palette::surface_hi());
    }
    let color = if !enabled {
        Palette::border()
    } else if hot {
        Palette::text()
    } else {
        Palette::muted()
    };
    let s = Stroke::new(1.5, color);
    let c = rect.center();
    match glyph {
        MiniGlyph::Up => {
            p.line_segment([pos2(c.x - 3.5, c.y + 1.5), pos2(c.x, c.y - 2.0)], s);
            p.line_segment([pos2(c.x, c.y - 2.0), pos2(c.x + 3.5, c.y + 1.5)], s);
        }
        MiniGlyph::Down => {
            p.line_segment([pos2(c.x - 3.5, c.y - 1.5), pos2(c.x, c.y + 2.0)], s);
            p.line_segment([pos2(c.x, c.y + 2.0), pos2(c.x + 3.5, c.y - 1.5)], s);
        }
        MiniGlyph::Cross => {
            p.line_segment([pos2(c.x - 3.0, c.y - 3.0), pos2(c.x + 3.0, c.y + 3.0)], s);
            p.line_segment([pos2(c.x + 3.0, c.y - 3.0), pos2(c.x - 3.0, c.y + 3.0)], s);
        }
    }
    if enabled {
        resp.on_hover_cursor(CursorIcon::PointingHand)
            .on_hover_text(tip)
    } else {
        resp
    }
}
