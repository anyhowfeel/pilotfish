//! Drag-resizable splitters and the serializable `Layout` they persist into.

use eframe::egui::{self, CursorIcon, Rect, Sense, Ui, UiBuilder, pos2, vec2};
use serde::{Deserialize, Serialize};

use crate::packets::kit::Palette;

const GRIP: f32 = 8.0;
const MIN_FRAC: f32 = 0.12;
const MIN_PANE_PX: f32 = 72.0;

/// Splitter positions as fractions, so they survive window resizes.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Layout {
    /// Share of the height taken by the packet table.
    pub table_frac: f32,
    /// Share of the bottom area's width taken by the detail tree.
    pub detail_frac: f32,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            table_frac: 0.52,
            detail_frac: 0.5,
        }
    }
}

impl Layout {
    pub fn sanitized(self) -> Self {
        let c = |v: f32| {
            if v.is_finite() {
                v.clamp(MIN_FRAC, 1.0 - MIN_FRAC)
            } else {
                0.5
            }
        };
        Self {
            table_frac: c(self.table_frac),
            detail_frac: c(self.detail_frac),
        }
    }
}

fn clamp_frac(frac: f32, span: f32) -> f32 {
    let min_f = if span > MIN_PANE_PX * 2.0 {
        (MIN_PANE_PX / span).max(MIN_FRAC)
    } else {
        MIN_FRAC
    };
    frac.clamp(min_f, 1.0 - min_f)
}

fn grip(ui: &mut Ui, rect: Rect, id: &str, vertical_bar: bool) -> egui::Response {
    let resp = ui.interact(rect, ui.scope_id().with(id), Sense::drag());
    let icon = if vertical_bar {
        CursorIcon::ResizeHorizontal
    } else {
        CursorIcon::ResizeVertical
    };
    let resp = resp.on_hover_cursor(icon);
    let active = resp.hovered() || resp.dragged();
    let line_color = if active {
        Palette::accent()
    } else {
        Palette::border()
    };
    let c = rect.center();
    let line = if vertical_bar {
        [pos2(c.x, rect.top()), pos2(c.x, rect.bottom())]
    } else {
        [pos2(rect.left(), c.y), pos2(rect.right(), c.y)]
    };
    let p = ui.painter();
    p.line_segment(line, egui::Stroke::new(1.0, line_color));
    let pill = if vertical_bar {
        Rect::from_center_size(c, vec2(3.0, 28.0))
    } else {
        Rect::from_center_size(c, vec2(28.0, 3.0))
    };
    let pill_color = if active {
        Palette::accent()
    } else {
        Palette::muted().gamma_multiply(0.55)
    };
    p.rect_filled(pill, 2.0, pill_color);
    resp
}

/// Two panes stacked (`top` over `bottom`); returns after drawing both.
pub fn vertical(
    ui: &mut Ui,
    frac: &mut f32,
    top: impl FnOnce(&mut Ui),
    bottom: impl FnOnce(&mut Ui),
) {
    let full = ui.available_rect_before_wrap();
    let span = (full.height() - GRIP).max(1.0);
    let eff = clamp_frac(*frac, span);
    let split = full.top() + span * eff;
    let top_r = Rect::from_min_max(full.min, pos2(full.right(), split));
    let grip_r = Rect::from_min_size(pos2(full.left(), split), vec2(full.width(), GRIP));
    let bot_r = Rect::from_min_max(pos2(full.left(), split + GRIP), full.max);
    let resp = grip(ui, grip_r, "vgrip", false);
    if resp.dragged() && full.height() > GRIP {
        *frac = clamp_frac(eff + resp.drag_delta().y / span, span);
    }
    ui.allocate_rect(full, Sense::hover());
    ui.scope_builder(UiBuilder::new().max_rect(top_r), |ui| {
        ui.set_clip_rect(top_r.intersect(ui.clip_rect()));
        top(ui)
    });
    ui.scope_builder(UiBuilder::new().max_rect(bot_r), |ui| {
        ui.set_clip_rect(bot_r.intersect(ui.clip_rect()));
        bottom(ui)
    });
}

/// Two panes side by side (`left` | `right`).
pub fn horizontal(
    ui: &mut Ui,
    frac: &mut f32,
    left: impl FnOnce(&mut Ui),
    right: impl FnOnce(&mut Ui),
) {
    let full = ui.available_rect_before_wrap();
    let span = (full.width() - GRIP).max(1.0);
    let eff = clamp_frac(*frac, span);
    let split = full.left() + span * eff;
    let left_r = Rect::from_min_max(full.min, pos2(split, full.bottom()));
    let grip_r = Rect::from_min_size(pos2(split, full.top()), vec2(GRIP, full.height()));
    let right_r = Rect::from_min_max(pos2(split + GRIP, full.top()), full.max);
    let resp = grip(ui, grip_r, "hgrip", true);
    if resp.dragged() && full.width() > GRIP {
        *frac = clamp_frac(eff + resp.drag_delta().x / span, span);
    }
    ui.allocate_rect(full, Sense::hover());
    ui.scope_builder(UiBuilder::new().max_rect(left_r), |ui| {
        ui.set_clip_rect(left_r.intersect(ui.clip_rect()));
        left(ui)
    });
    ui.scope_builder(UiBuilder::new().max_rect(right_r), |ui| {
        ui.set_clip_rect(right_r.intersect(ui.clip_rect()));
        right(ui)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_roundtrips_and_sanitizes() {
        let l = Layout {
            table_frac: 0.3,
            detail_frac: 0.6,
        };
        let s = serde_json::to_string(&l).unwrap();
        assert_eq!(serde_json::from_str::<Layout>(&s).unwrap(), l);
        let bad = Layout {
            table_frac: f32::NAN,
            detail_frac: 7.0,
        }
        .sanitized();
        assert_eq!(
            bad,
            Layout {
                table_frac: 0.5,
                detail_frac: 1.0 - MIN_FRAC
            }
        );
    }
}
