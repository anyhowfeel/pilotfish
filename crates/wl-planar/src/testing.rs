//! Graphs and stand-in stages shared by the tests of the layout modules.

use crate::embedding::Embedding;
use crate::geometry::Point;
use crate::graph::Graph;

pub fn complete(n: usize) -> Graph {
    let edges: Vec<_> = (0..n)
        .flat_map(|a| (a + 1..n).map(move |b| (a, b)))
        .collect();
    Graph::new(n, &edges)
}

pub fn k33() -> Graph {
    let edges: Vec<_> = (0..3).flat_map(|a| (3..6).map(move |b| (a, b))).collect();
    Graph::new(6, &edges)
}

pub fn petersen() -> Graph {
    let mut edges = Vec::new();
    for i in 0..5 {
        edges.push((i, (i + 1) % 5));
        edges.push((i, i + 5));
        edges.push((5 + i, 5 + (i + 2) % 5));
    }
    Graph::new(10, &edges)
}

/// Planar for the tests when no component has more edges than vertices; monotone like planarity.
pub fn pseudoforest(g: &Graph) -> bool {
    g.components().iter().all(|c| {
        let edges: usize = c.iter().map(|&v| g.degree(v)).sum::<usize>() / 2;
        edges <= c.len()
    })
}

/// Embeds the graphs `pseudoforest` accepts, in neighbour order.
pub fn embed_pseudoforest(g: &Graph) -> Option<Embedding> {
    pseudoforest(g).then(|| {
        Embedding::new(
            (0..g.vertex_count())
                .map(|v| g.neighbors(v).to_vec())
                .collect(),
        )
    })
}

/// Vertices on a circle in depth-first order: crossing-free for paths and cycles.
pub fn draw_on_circle(g: &Graph, _: &Embedding) -> Vec<Point> {
    let n = g.vertex_count();
    let (mut seen, mut order) = (vec![false; n], Vec::new());
    for s in 0..n {
        let mut stack = vec![s];
        while let Some(v) = stack.pop() {
            if !seen[v] {
                seen[v] = true;
                order.push(v);
                stack.extend(g.neighbors(v).iter().rev());
            }
        }
    }
    let mut pos = vec![Point::default(); n];
    for (i, &v) in order.iter().enumerate() {
        let a = std::f64::consts::TAU * i as f64 / n as f64;
        pos[v] = Point::new(50.0 * a.cos(), 50.0 * a.sin());
    }
    pos
}

/// A small deterministic random source.
pub struct Lcg(pub u64);

impl Lcg {
    pub fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as usize % n
    }
}
