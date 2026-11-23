//! The arrowhead of a one-way link: its tip touches the disc of the host the traffic goes to.

use wl_kit::egui::{Pos2, Vec2, vec2};

/// Space between the tip and the edge of the destination disc.
const GAP: f32 = 2.5;
/// Least visible link length, in head lengths, for an arrow to be drawn.
const ROOM: f32 = 2.5;

/// Length of the head in pixels for a link stroked `width` wide.
pub fn head_len(width: f32) -> f32 {
    6.5 + 0.35 * width.min(10.0)
}

/// Tip and the two rear corners of the head on the way from `from` to `to`, or `None` when the
/// visible part of the link (between the two discs) is too short to carry one.
pub fn head(from: Pos2, to: Pos2, reach: (f32, f32), width: f32) -> Option<[Pos2; 3]> {
    let v = to - from;
    let len = v.length();
    let d = v / len;
    let size = head_len(width);
    if !d.x.is_finite() || len - reach.0 - reach.1 < size * ROOM {
        return None;
    }
    let tip = to - d * (reach.1 + GAP);
    let rear = tip - d * size;
    let side: Vec2 = vec2(-d.y, d.x) * size * 0.5;
    Some([tip, rear + side, rear - side])
}

#[cfg(test)]
#[path = "arrow_tests.rs"]
mod tests;
