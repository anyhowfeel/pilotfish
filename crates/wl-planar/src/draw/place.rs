//! Draws every connected component and packs the drawings into rows.
//!
//! The shift method gives an exact crossing-free drawing on the integer grid; the smoothing then
//! spreads it out as far as it can certify.

use super::augment::triangulate;
use super::canonical::canonical;
use super::grid::bounds;
use super::rot::Rot;
use super::shift;
use super::smooth::smooth;
use crate::embedding::Embedding;
use crate::geometry::Point;
use crate::graph::Graph;

/// Empty space left between two drawings.
const GAP: f64 = 2.0;
/// Sweeps of the smoothing at most.
const SWEEPS: usize = 300;

pub fn straight_line(g: &Graph, e: &Embedding) -> Vec<Point> {
    let mut local = vec![0usize; g.vertex_count()];
    let mut blocks = Vec::new();
    for verts in g.components() {
        for (i, &v) in verts.iter().enumerate() {
            local[v] = i;
        }
        let lists: Vec<Vec<usize>> = verts
            .iter()
            .map(|&v| e.rotation(v).iter().map(|&w| local[w]).collect())
            .collect();
        blocks.push((verts, draw_component(&lists)));
    }
    pack(g.vertex_count(), &blocks)
}

/// Positions of the vertices of one connected component, given its rotation system.
fn draw_component(lists: &[Vec<usize>]) -> Vec<Point> {
    match lists.len() {
        1 => return vec![Point::new(0.0, 0.0)],
        2 => return vec![Point::new(0.0, 0.0), Point::new(2.0, 0.0)],
        _ => {}
    }
    let mut rot = Rot::new(lists);
    let outer = triangulate(&mut rot);
    let grid = shift::place(&canonical(&rot, outer), rot.vertex_count());
    let mut pos: Vec<Point> = grid
        .iter()
        .map(|&(x, y)| Point::new(x as f64, y as f64))
        .collect();
    smooth(&rot, &mut pos, outer, SWEEPS);
    pos.truncate(lists.len());
    pos
}

/// Shelf packing: blocks go left to right in rows about as wide as the packing is tall, then the
/// whole is centred on the origin.
fn pack(n: usize, blocks: &[(Vec<usize>, Vec<Point>)]) -> Vec<Point> {
    let boxes: Vec<(Point, f64, f64)> = blocks
        .iter()
        .map(|b| {
            let (lo, hi) = bounds(&b.1);
            (lo, hi.x - lo.x + GAP, hi.y - lo.y + GAP)
        })
        .collect();
    let area: f64 = boxes.iter().map(|b| b.1 * b.2).sum();
    let widest = boxes.iter().map(|b| b.1).fold(0.0, f64::max);
    let limit = widest.max(area.sqrt());
    let mut pos = vec![Point::default(); n];
    let (mut x, mut y, mut row) = (0.0, 0.0, 0.0f64);
    for ((verts, pts), &(lo, w, h)) in blocks.iter().zip(&boxes) {
        if x > 0.0 && x + w > limit {
            (x, y, row) = (0.0, y + row, 0.0);
        }
        for (&v, p) in verts.iter().zip(pts) {
            pos[v] = Point::new(p.x - lo.x + x, p.y - lo.y + y);
        }
        x += w;
        row = row.max(h);
    }
    centre(&mut pos);
    pos
}

pub fn centre(pos: &mut [Point]) {
    let (lo, hi) = bounds(pos);
    let (cx, cy) = ((lo.x + hi.x) / 2.0, (lo.y + hi.y) / 2.0);
    for p in pos {
        *p = Point::new(p.x - cx, p.y - cy);
    }
}

#[cfg(test)]
#[path = "place_tests.rs"]
mod tests;
