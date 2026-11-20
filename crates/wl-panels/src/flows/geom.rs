//! Column geometry of the flow graph. All x values are relative to the left edge of the
//! diagram, so the sticky header and the scrolling rows share exactly the same numbers.

use wl_kit::theme::spacing;

pub const ROW_H: f32 = 32.0;
pub const HEAD_H: f32 = 48.0;
const FRAME_W: f32 = 52.0;
const TIME_W: f32 = 80.0;
const NOTE_W: f32 = 196.0;
/// Narrowest lane: below it the diagram scrolls horizontally.
pub const MIN_LANE_W: f32 = 120.0;
/// Narrowest lane that still leaves room for the annotation column.
const MIN_LANE_W_NOTE: f32 = 150.0;
const PAD: f32 = spacing::SM;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cols {
    /// `(left, right)` of the frame-number and time columns (text is right aligned in them).
    pub frame: (f32, f32),
    pub time: (f32, f32),
    pub lanes_x0: f32,
    pub lane_w: f32,
    pub lanes: usize,
    /// Annotation column (`Seq / Ack / Len`), absent when the lanes need the room.
    pub note: Option<(f32, f32)>,
    pub width: f32,
}

impl Cols {
    /// Centre x of the lifeline of host `i`.
    pub fn lane_x(&self, i: usize) -> f32 {
        self.lanes_x0 + self.lane_w * (i as f32 + 0.5)
    }
}

pub fn cols(avail: f32, lanes: usize) -> Cols {
    let n = lanes.max(1) as f32;
    let frame = (PAD, PAD + FRAME_W);
    let time = (frame.1 + spacing::SM, frame.1 + spacing::SM + TIME_W);
    let lanes_x0 = time.1 + spacing::LG;
    let pick = |note: bool| {
        let right = PAD + if note { NOTE_W + spacing::SM } else { 0.0 };
        let min = if note { MIN_LANE_W_NOTE } else { MIN_LANE_W };
        let lane_w = (avail - lanes_x0 - right) / n;
        (lane_w >= min).then_some((lane_w, right))
    };
    let (lane_w, right, note) = match (pick(true), pick(false)) {
        (Some((w, r)), _) => (w, r, true),
        (None, Some((w, r))) => (w, r, false),
        (None, None) => (MIN_LANE_W, PAD, false),
    };
    let width = lanes_x0 + lane_w * n + right;
    Cols {
        frame,
        time,
        lanes_x0,
        lane_w,
        lanes: lanes.max(1),
        note: note.then_some((width - PAD - NOTE_W, width - PAD)),
        width,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_hosts_on_a_wide_page_get_the_note_column() {
        let c = cols(1000.0, 2);
        assert!(c.note.is_some());
        assert!((c.width - 1000.0).abs() < 0.01);
        assert!(c.lane_w > 250.0);
        let (l, r) = c.note.unwrap();
        assert!(l > c.lane_x(1) + c.lane_w * 0.5 - 0.01 && (r - l - NOTE_W).abs() < 0.01);
    }

    #[test]
    fn narrow_page_drops_the_note_then_scrolls() {
        let c = cols(560.0, 2);
        assert!(c.note.is_none() && (c.width - 560.0).abs() < 0.01);
        let many = cols(560.0, 8);
        assert_eq!(many.lane_w, MIN_LANE_W);
        assert!(many.width > 560.0);
    }

    #[test]
    fn lanes_are_evenly_spaced_and_inside() {
        let c = cols(900.0, 3);
        let (a, b, d) = (c.lane_x(0), c.lane_x(1), c.lane_x(2));
        assert!(((b - a) - (d - b)).abs() < 0.01);
        assert!(a - c.lane_w / 2.0 >= c.time.1 && d + c.lane_w / 2.0 <= c.width);
    }
}
