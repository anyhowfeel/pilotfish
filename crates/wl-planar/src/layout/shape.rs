//! Small geometric helpers the stages share: scaling a drawing, keeping discs apart.

use crate::geometry::{Point, edges_cross};
use crate::graph::Graph;

/// Whether two edges, given by endpoint indices, cross or touch in `pos`.
pub fn crosses(pos: &[Point], e: (usize, usize), f: (usize, usize)) -> bool {
    let shared = e.0 == f.0 || e.0 == f.1 || e.1 == f.0 || e.1 == f.1;
    edges_cross(pos[e.0], pos[e.1], pos[f.0], pos[f.1], shared)
}

pub fn is_finite(pos: &[Point]) -> bool {
    pos.iter().all(|p| p.x.is_finite() && p.y.is_finite())
}

/// `n` vertices on a circle that gives neighbours about `edge_len` between them.
pub fn circle(n: usize, edge_len: f64) -> Vec<Point> {
    let r = edge_len * (n as f64).sqrt().max(1.0);
    (0..n)
        .map(|i| {
            let a = std::f64::consts::TAU * i as f64 / n as f64;
            Point::new(r * a.cos(), r * a.sin())
        })
        .collect()
}

/// Scales around the centroid so the mean edge length is `len`. A similarity: crossings stay.
pub fn scale_edges(g: &Graph, pos: &mut [Point], len: f64) {
    let lengths: Vec<f64> = g
        .valid_edges()
        .map(|e| {
            let (a, b) = g.endpoints(e);
            pos[a].dist(pos[b])
        })
        .collect();
    let mean = lengths.iter().sum::<f64>() / lengths.len().max(1) as f64;
    if mean > 1e-12 {
        scale(pos, len / mean);
    }
}

/// Scales up, never down, until every two discs are `gap` apart. A similarity: crossings stay.
pub fn separate_discs(pos: &mut [Point], radius: &[f64], gap: f64) {
    let mut need = 1.0_f64;
    for i in 0..pos.len() {
        for j in i + 1..pos.len() {
            let d = pos[i].dist(pos[j]);
            if d > 1e-12 {
                need = need.max((radius[i] + radius[j] + gap) / d);
            }
        }
    }
    if need > 1.0 {
        scale(pos, need);
    }
}

fn scale(pos: &mut [Point], k: f64) {
    let n = pos.len().max(1) as f64;
    let cx = pos.iter().map(|p| p.x).sum::<f64>() / n;
    let cy = pos.iter().map(|p| p.y).sum::<f64>() / n;
    for p in pos {
        *p = Point::new((p.x - cx) * k, (p.y - cy) * k);
    }
}

#[cfg(test)]
#[path = "shape_tests.rs"]
mod tests;
