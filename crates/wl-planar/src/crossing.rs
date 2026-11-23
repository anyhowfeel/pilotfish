//! Counting the crossings of a straight-line drawing.

use crate::geometry::{Point, edges_cross};
use crate::graph::Graph;

/// Pairs of valid edges (as slot indices, first < second) that cross, touch or overlap in `pos`.
/// Edges sharing a vertex are only listed when they run along each other.
pub fn crossing_pairs(g: &Graph, pos: &[Point]) -> Vec<(usize, usize)> {
    let edges: Vec<usize> = g.valid_edges().collect();
    let boxes: Vec<(f64, f64, f64, f64)> = edges
        .iter()
        .map(|&e| {
            let (a, b) = g.endpoints(e);
            (
                pos[a].x.min(pos[b].x),
                pos[a].x.max(pos[b].x),
                pos[a].y.min(pos[b].y),
                pos[a].y.max(pos[b].y),
            )
        })
        .collect();
    let mut out = Vec::new();
    for i in 0..edges.len() {
        for j in i + 1..edges.len() {
            let (p, q) = (boxes[i], boxes[j]);
            if p.1 < q.0 - 1e-9 || q.1 < p.0 - 1e-9 || p.3 < q.2 - 1e-9 || q.3 < p.2 - 1e-9 {
                continue;
            }
            let ((a, b), (c, d)) = (g.endpoints(edges[i]), g.endpoints(edges[j]));
            let shared = a == c || a == d || b == c || b == d;
            if edges_cross(pos[a], pos[b], pos[c], pos[d], shared) {
                out.push((edges[i], edges[j]));
            }
        }
    }
    out
}

pub fn count_crossings(g: &Graph, pos: &[Point]) -> usize {
    crossing_pairs(g, pos).len()
}

#[cfg(test)]
#[path = "crossing_tests.rs"]
mod tests;
