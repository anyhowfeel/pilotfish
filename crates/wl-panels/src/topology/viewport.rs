//! Pan/zoom transform between world space (layout units) and the canvas rect on screen.

use wl_kit::egui::{Pos2, Rect, Vec2, pos2, vec2};

pub const ZOOM_MIN: f32 = 0.1;
pub const ZOOM_MAX: f32 = 8.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Viewport {
    /// World point shown at the canvas centre.
    pub center: Vec2,
    pub zoom: f32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            center: Vec2::ZERO,
            zoom: 1.0,
        }
    }
}

impl Viewport {
    pub fn to_screen(self, rect: Rect, w: Vec2) -> Pos2 {
        rect.center() + (w - self.center) * self.zoom
    }

    pub fn to_world(self, rect: Rect, s: Pos2) -> Vec2 {
        (s - rect.center()) / self.zoom + self.center
    }

    /// Zoom by `factor` keeping the world point under `anchor` fixed.
    pub fn zoom_at(&mut self, rect: Rect, anchor: Pos2, factor: f32) {
        let before = self.to_world(rect, anchor);
        self.zoom = (self.zoom * factor).clamp(ZOOM_MIN, ZOOM_MAX);
        let after = self.to_world(rect, anchor);
        self.center += before - after;
    }

    pub fn pan_by_screen(&mut self, delta: Vec2) {
        self.center -= delta / self.zoom;
    }

    /// The viewport showing `bounds` (world rect) inside `rect` with `pad` screen pixels around.
    pub fn fit(bounds: Rect, rect: Rect, pad: f32) -> Self {
        let avail = vec2(
            (rect.width() - 2.0 * pad).max(1.0),
            (rect.height() - 2.0 * pad).max(1.0),
        );
        let size = vec2(bounds.width().max(1.0), bounds.height().max(1.0));
        let zoom = (avail.x / size.x)
            .min(avail.y / size.y)
            .clamp(ZOOM_MIN, 2.5);
        Self {
            center: bounds.center().to_vec2(),
            zoom,
        }
    }

    /// Distance to `other`, used to stop easing animations.
    pub fn distance(&self, other: &Viewport) -> f32 {
        (self.center - other.center).length() * self.zoom + (self.zoom - other.zoom).abs() * 100.0
    }

    pub fn ease_to(&mut self, target: &Viewport, k: f32) {
        self.center += (target.center - self.center) * k;
        self.zoom += (target.zoom - self.zoom) * k;
    }
}

/// Bounding box of world points (`None` when empty).
pub fn bounds(points: impl IntoIterator<Item = Vec2>, margin: f32) -> Option<Rect> {
    let mut it = points.into_iter();
    let first = it.next()?;
    let (mut lo, mut hi) = (first, first);
    for p in it {
        lo = vec2(lo.x.min(p.x), lo.y.min(p.y));
        hi = vec2(hi.x.max(p.x), hi.y.max(p.y));
    }
    Some(Rect::from_min_max(
        pos2(lo.x - margin, lo.y - margin),
        pos2(hi.x + margin, hi.y + margin),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canvas() -> Rect {
        Rect::from_min_size(pos2(100.0, 50.0), vec2(800.0, 600.0))
    }

    #[test]
    fn roundtrip_world_screen() {
        let v = Viewport {
            center: vec2(30.0, -20.0),
            zoom: 1.7,
        };
        let w = vec2(123.0, 45.0);
        let back = v.to_world(canvas(), v.to_screen(canvas(), w));
        assert!((back - w).length() < 1e-3);
        assert_eq!(v.to_screen(canvas(), v.center), canvas().center());
    }

    #[test]
    fn zoom_keeps_anchor_fixed_and_clamps() {
        let mut v = Viewport::default();
        let anchor = pos2(300.0, 200.0);
        let w = v.to_world(canvas(), anchor);
        v.zoom_at(canvas(), anchor, 2.0);
        assert!((v.to_screen(canvas(), w) - anchor).length() < 1e-3);
        v.zoom_at(canvas(), anchor, 1e6);
        assert_eq!(v.zoom, ZOOM_MAX);
        v.zoom_at(canvas(), anchor, 1e-9);
        assert_eq!(v.zoom, ZOOM_MIN);
    }

    #[test]
    fn fit_contains_bounds_with_padding() {
        let b = Rect::from_min_max(pos2(-400.0, -100.0), pos2(400.0, 100.0));
        let v = Viewport::fit(b, canvas(), 40.0);
        let lo = v.to_screen(canvas(), b.min.to_vec2());
        let hi = v.to_screen(canvas(), b.max.to_vec2());
        assert!(lo.x >= canvas().left() + 39.0 && hi.x <= canvas().right() - 39.0);
        assert!(canvas().contains(lo) && canvas().contains(hi));
    }

    #[test]
    fn pan_moves_content_with_the_pointer() {
        let mut v = Viewport {
            center: Vec2::ZERO,
            zoom: 2.0,
        };
        let before = v.to_screen(canvas(), vec2(10.0, 10.0));
        v.pan_by_screen(vec2(30.0, -10.0));
        let after = v.to_screen(canvas(), vec2(10.0, 10.0));
        assert!((after - before - vec2(30.0, -10.0)).length() < 1e-4);
    }

    #[test]
    fn bounds_of_points() {
        assert!(bounds([], 5.0).is_none());
        let b = bounds([vec2(1.0, 2.0), vec2(-3.0, 8.0)], 1.0).unwrap();
        assert_eq!((b.min, b.max), (pos2(-4.0, 1.0), pos2(2.0, 9.0)));
    }
}
