//! The arrow of a link, drawn at its middle: one head when the traffic only goes one way, two heads
//! back to back when it goes both ways. Around a host with dozens of links the arrows slide along
//! their link so that they do not pile up.

use std::collections::HashMap;

use wl_kit::egui::{Pos2, Vec2, vec2};

/// Space between the two heads of a two-way arrow, where the line shows through.
const GAP: f32 = 9.0;
/// A head never grows past this base, in pixels, however much traffic it stands for.
const MAX_BASE: f32 = 26.0;
/// How much larger the head of the busier direction is, and how much smaller the other one, when
/// all the traffic goes that way (they are the same size when it is shared evenly).
const GROW: f32 = 0.25;
const SHRINK: f32 = 0.45;
/// The visible part of the link must be this many times longer than the arrow, or there is none.
const ROOM: f32 = 1.8;
/// Where an arrow that does not fit at the middle tries next, in arrow lengths from the middle.
const SLIDES: [f32; 5] = [0.0, 1.0, -1.0, 2.0, -2.0];
/// Margin around an arrow, in pixels, that no other arrow may enter (the outline and some air).
const AIR: f32 = 1.5;
/// Side of a cell of the grid that finds the arrows close to another one: at least twice the radius of
/// the largest arrow (a two-way arrow on the widest link, about 26 px), so that two arrows that touch
/// are always in neighbouring cells.
const CELL: f32 = 56.0;

/// Width of the base of a head in pixels for a link stroked `width` wide: clearly wider than the
/// stroke, or the head reads as a blunt end of the line.
pub fn head_base(width: f32) -> f32 {
    (2.6 * width).clamp(10.0, 22.0)
}

/// Length of a head in pixels for a link stroked `width` wide.
pub fn head_len(width: f32) -> f32 {
    0.9 * head_base(width)
}

/// Which way the traffic of a link goes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Way {
    /// Only from `from` to `to`.
    OneWay,
    /// Both ways; the share of the bytes that go from `from` to `to` (`from` is the busier end, so
    /// at least one half). The head of the busier direction is drawn larger.
    TwoWay(f32),
}

/// A link that may carry an arrow: the two ends, the radius of their discs, the width of the stroke
/// and which way the traffic goes. For a one-way link `from` sends and `to` receives.
#[derive(Debug, Clone, Copy)]
pub struct Link {
    pub from: Pos2,
    pub to: Pos2,
    pub reach: (f32, f32),
    pub width: f32,
    pub way: Way,
}

/// The corners of the heads of an arrow: the tip first, then the two rear corners.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Arrow {
    /// The head that points to `to`.
    pub forward: [Pos2; 3],
    /// The head that points back to `from`, on a two-way link.
    pub back: Option<[Pos2; 3]>,
    /// The middle of the arrow and the radius of a circle that holds it.
    pub centre: Pos2,
    pub radius: f32,
}

impl Arrow {
    pub fn heads(&self) -> impl Iterator<Item = [Pos2; 3]> {
        std::iter::once(self.forward).chain(self.back)
    }
}

fn head_at(rear: Pos2, d: Vec2, len: f32, base: f32) -> [Pos2; 3] {
    let side = vec2(-d.y, d.x) * base * 0.5;
    let tip = rear + d * len;
    [tip, rear + side, rear - side]
}

/// Length and base of the heads of `l`: the one that points to `to`, and the one that points back.
fn sizes(l: &Link) -> ((f32, f32), Option<(f32, f32)>) {
    let (len, base) = (head_len(l.width), head_base(l.width));
    let scale = |k: f32| {
        let b = (base * k).min(MAX_BASE);
        (b * len / base, b)
    };
    match l.way {
        Way::OneWay => (scale(1.0), None),
        Way::TwoWay(share) => {
            let lead = (2.0 * share - 1.0).abs().clamp(0.0, 1.0);
            (scale(1.0 + GROW * lead), Some(scale(1.0 - SHRINK * lead)))
        }
    }
}

/// Length of the whole arrow along the link.
fn span(l: &Link) -> f32 {
    match sizes(l) {
        ((len, _), None) => len,
        ((len, _), Some((back, _))) => len + GAP + back,
    }
}

/// The arrow of `l` centred `shift` pixels from the middle of the visible part of the link, or
/// `None` when that part is too short to carry it or the arrow would run into a disc.
pub fn arrow(l: &Link, shift: f32) -> Option<Arrow> {
    let v = l.to - l.from;
    let length = v.length();
    let d = v / length;
    if !d.x.is_finite() || !d.y.is_finite() {
        return None;
    }
    let span = span(l);
    let visible = length - l.reach.0 - l.reach.1;
    if visible < span * ROOM || visible / 2.0 - shift.abs() < span / 2.0 + 2.0 {
        return None;
    }
    let mid = l.from + d * (l.reach.0 + visible / 2.0 + shift);
    let start = mid - d * (span / 2.0);
    let ((len, base), back) = sizes(l);
    let (forward, back_head) = match back {
        None => (head_at(start, d, len, base), None),
        Some((blen, bbase)) => (
            head_at(start + d * (blen + GAP), d, len, base),
            Some(head_at(start + d * blen, -d, blen, bbase)),
        ),
    };
    let widest = base.max(back.map_or(0.0, |(_, b)| b));
    let radius = (span / 2.0).hypot(widest / 2.0) + AIR;
    Some(Arrow {
        forward,
        back: back_head,
        centre: mid,
        radius,
    })
}

/// The arrow of every link, in the order of `links`, or `None` for a link that has no room or whose
/// arrow would sit on another one. The widest links are placed first, so on a host with dozens of
/// links the heavy flows keep the middle of their link, and a blocked arrow slides along its link.
pub fn place(links: &[Link]) -> Vec<Option<Arrow>> {
    let mut order: Vec<usize> = (0..links.len()).collect();
    order.sort_by(|&a, &b| links[b].width.total_cmp(&links[a].width).then(a.cmp(&b)));
    let mut placed = vec![None; links.len()];
    let mut taken: HashMap<(i32, i32), Vec<(Pos2, f32)>> = HashMap::new();
    for i in order {
        let l = links[i];
        let step = span(&l) + 2.0 * AIR;
        for slide in SLIDES {
            let Some(a) = arrow(&l, slide * step) else {
                continue;
            };
            if !crowded(&taken, a.centre, a.radius) {
                taken
                    .entry(cell(a.centre))
                    .or_default()
                    .push((a.centre, a.radius));
                placed[i] = Some(a);
                break;
            }
        }
    }
    placed
}

fn cell(p: Pos2) -> (i32, i32) {
    ((p.x / CELL).floor() as i32, (p.y / CELL).floor() as i32)
}

fn crowded(taken: &HashMap<(i32, i32), Vec<(Pos2, f32)>>, at: Pos2, radius: f32) -> bool {
    let (cx, cy) = cell(at);
    (cx - 1..=cx + 1).any(|x| {
        (cy - 1..=cy + 1).any(|y| {
            taken
                .get(&(x, y))
                .is_some_and(|arrows| arrows.iter().any(|&(o, r)| (o - at).length() < r + radius))
        })
    })
}

#[cfg(test)]
#[path = "arrow_tests.rs"]
mod tests;
