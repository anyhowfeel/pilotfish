//! Pure geometry of the settings dialog (testable without egui painting).
use wl_kit::egui::{Rect, pos2, vec2};
use wl_kit::theme::spacing;

pub const HEADER_H: f32 = 52.0;
pub const FOOTER_H: f32 = 56.0;
pub const RAIL_W: f32 = 168.0;
const MAX_W: f32 = 720.0;
const MAX_H: f32 = 620.0;
/// Below this dialog width the category rail becomes a tab strip.
pub const RAIL_MIN_DIALOG_W: f32 = 600.0;
pub const TABS_H: f32 = 44.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Geometry {
    pub dialog: Rect,
    pub header: Rect,
    pub footer: Rect,
    /// Category rail (side) or tab strip (top) - see `rail`.
    pub nav: Rect,
    pub rail: bool,
    pub body: Rect,
}

/// Centered dialog: width <= 720 (clamped to the window minus gutters), height <= 80% of window.
pub fn geometry(screen: Rect) -> Geometry {
    let gutter = spacing::XL;
    let w = MAX_W.min(screen.width() - 2.0 * gutter).max(280.0);
    let h = (screen.height() * 0.8).clamp(240.0, MAX_H);
    let dialog = Rect::from_center_size(screen.center(), vec2(w, h));
    let header = Rect::from_min_size(dialog.min, vec2(w, HEADER_H));
    let footer = Rect::from_min_size(
        pos2(dialog.min.x, dialog.max.y - FOOTER_H),
        vec2(w, FOOTER_H),
    );
    let mid = Rect::from_min_max(header.left_bottom(), footer.right_top());
    let rail = w >= RAIL_MIN_DIALOG_W;
    let (nav, body) = if rail {
        (
            Rect::from_min_size(mid.min, vec2(RAIL_W, mid.height())),
            Rect::from_min_max(pos2(mid.min.x + RAIL_W, mid.min.y), mid.max),
        )
    } else {
        (
            Rect::from_min_size(mid.min, vec2(w, TABS_H)),
            Rect::from_min_max(pos2(mid.min.x, mid.min.y + TABS_H), mid.max),
        )
    };
    Geometry {
        dialog,
        header,
        footer,
        nav,
        rail,
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(w: f32, h: f32) -> Rect {
        Rect::from_min_size(pos2(0.0, 0.0), vec2(w, h))
    }

    #[test]
    fn fits_window_at_all_widths() {
        for (w, h) in [
            (700.0, 500.0),
            (1000.0, 640.0),
            (1600.0, 900.0),
            (667.0, 427.0),
        ] {
            for scale in [1.0, 1.5] {
                let s = screen(w / scale, h / scale);
                let g = geometry(s);
                assert!(g.dialog.width() <= s.width() - spacing::XL || g.dialog.width() <= 280.0);
                assert!(g.dialog.height() <= s.height() * 0.8 + 240.0);
                assert!(g.body.height() > 80.0, "body visible at {w}x{h}@{scale}");
                assert!(g.header.max.y <= g.body.min.y + 0.1);
                assert!(g.body.max.y <= g.footer.min.y + 0.1);
            }
        }
    }

    #[test]
    fn rail_collapses_when_narrow() {
        assert!(geometry(screen(1600.0, 900.0)).rail);
        assert!(!geometry(screen(620.0, 600.0)).rail);
    }

    #[test]
    fn header_and_footer_are_pinned_to_dialog_edges() {
        let g = geometry(screen(1000.0, 640.0));
        assert_eq!(g.header.min, g.dialog.min);
        assert_eq!(g.footer.max, g.dialog.max);
    }
}
