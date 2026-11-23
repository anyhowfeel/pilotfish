//! Fixtures and checks shared by the unit tests of the drawing code.

use super::check::point_segment;
use crate::{Embedding, Graph, Point, count_crossings};

/// The graph on `pts` with `edges`, and the embedding read off the picture: neighbours sorted
/// counter-clockwise by angle. The pictures are planar, which `is_planar_embedding` re-checks.
pub fn from_points(edges: &[(usize, usize)], pts: &[(f64, f64)]) -> (Graph, Embedding) {
    let g = Graph::new(pts.len(), edges);
    let rotation = (0..pts.len())
        .map(|v| {
            let mut nb = g.neighbors(v).to_vec();
            let angle = |w: usize| (pts[w].1 - pts[v].1).atan2(pts[w].0 - pts[v].0);
            nb.sort_by(|&a, &b| angle(a).total_cmp(&angle(b)));
            nb
        })
        .collect();
    let e = Embedding::new(rotation);
    assert!(e.is_planar_embedding(&g), "fixture is not planar");
    (g, e)
}

pub fn mirrored(e: &Embedding) -> Embedding {
    Embedding::new(
        (0..e.vertex_count())
            .map(|v| e.rotation(v).iter().rev().copied().collect())
            .collect(),
    )
}

pub fn circle(n: usize, r: f64) -> Vec<(f64, f64)> {
    (0..n)
        .map(|i| {
            let a = std::f64::consts::TAU * i as f64 / n as f64;
            (r * a.cos(), r * a.sin())
        })
        .collect()
}

pub fn grid(w: usize, h: usize) -> (Graph, Embedding) {
    let id = |x: usize, y: usize| y * w + x;
    let mut edges = Vec::new();
    for y in 0..h {
        for x in 0..w {
            if x + 1 < w {
                edges.push((id(x, y), id(x + 1, y)));
            }
            if y + 1 < h {
                edges.push((id(x, y), id(x, y + 1)));
            }
        }
    }
    let pts: Vec<_> = (0..w * h)
        .map(|v| ((v % w) as f64, (v / w) as f64))
        .collect();
    from_points(&edges, &pts)
}

/// The grid with one diagonal in every cell, so every inner face is a triangle.
pub fn triangulated_grid(w: usize, h: usize) -> (Graph, Embedding) {
    let id = |x: usize, y: usize| y * w + x;
    let mut edges = Vec::new();
    for y in 0..h {
        for x in 0..w {
            if x + 1 < w {
                edges.push((id(x, y), id(x + 1, y)));
            }
            if y + 1 < h {
                edges.push((id(x, y), id(x, y + 1)));
            }
            if x + 1 < w && y + 1 < h {
                edges.push((id(x, y), id(x + 1, y + 1)));
            }
        }
    }
    let pts: Vec<_> = (0..w * h)
        .map(|v| ((v % w) as f64, (v / w) as f64))
        .collect();
    from_points(&edges, &pts)
}

/// Hub 0 and a rim of `k` vertices.
pub fn wheel(k: usize) -> (Graph, Embedding) {
    let mut pts = vec![(0.0, 0.0)];
    pts.extend(circle(k, 1.0));
    let mut edges: Vec<_> = (1..=k).map(|i| (0, i)).collect();
    edges.extend((1..=k).map(|i| (i, i % k + 1)));
    from_points(&edges, &pts)
}

/// A triangulation grown by putting each new vertex in the middle of a face chosen by `seed`.
pub fn stacked(n: usize, seed: u64) -> (Graph, Embedding) {
    let mut pts = vec![(0.0, 0.0), (100.0, 0.0), (50.0, 90.0)];
    let mut edges = vec![(0, 1), (1, 2), (2, 0)];
    let mut faces = vec![[0, 1, 2]];
    let mut state = seed;
    while pts.len() < n {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let [a, b, c] = faces.swap_remove((state >> 33) as usize % faces.len());
        let v = pts.len();
        pts.push((
            (pts[a].0 + pts[b].0 + pts[c].0) / 3.0,
            (pts[a].1 + pts[b].1 + pts[c].1) / 3.0,
        ));
        edges.extend([(a, v), (b, v), (c, v)]);
        faces.extend([[a, b, v], [b, c, v], [c, a, v]]);
    }
    from_points(&edges, &pts)
}

/// Named small graphs of every shape the drawing has to handle, with their embeddings.
pub fn fixtures() -> Vec<(&'static str, Graph, Embedding)> {
    let mut out: Vec<(&str, Graph, Embedding)> = Vec::new();
    let mut add = |name, (g, e): (Graph, Embedding)| out.push((name, g, e));
    let path: Vec<_> = (0..6).map(|i| (i as f64, 0.0)).collect();
    add(
        "path",
        from_points(&[(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)], &path),
    );
    let mut star = vec![(0.0, 0.0)];
    star.extend(circle(7, 5.0));
    let star_edges: Vec<_> = (1..8).map(|i| (0, i)).collect();
    add("star", from_points(&star_edges, &star));
    let ring: Vec<_> = (0..7).map(|i| (i, (i + 1) % 7)).collect();
    add("cycle", from_points(&ring, &circle(7, 5.0)));
    let k4 = [(0.0, 0.0), (10.0, 0.0), (5.0, 9.0), (5.0, 3.0)];
    add(
        "k4",
        from_points(&[(0, 1), (1, 2), (2, 0), (3, 0), (3, 1), (3, 2)], &k4),
    );
    add("wheel", wheel(8));
    add("grid", grid(6, 6));
    let oct = [
        (0.0, 0.0),
        (10.0, 0.0),
        (5.0, 9.0),
        (5.0, 2.0),
        (6.2, 3.5),
        (3.8, 3.5),
    ];
    let oct_edges = [
        (0, 1),
        (1, 2),
        (2, 0),
        (3, 4),
        (4, 5),
        (5, 3),
        (3, 0),
        (3, 1),
        (4, 1),
        (4, 2),
        (5, 2),
        (5, 0),
    ];
    add("octahedron", from_points(&oct_edges, &oct));
    let tree_pts: Vec<_> = (0..15usize)
        .map(|v| {
            let depth = (v + 1).ilog2() as usize;
            let slot = v + 1 - (1 << depth);
            (
                (slot as f64 + 0.5) * 16.0 / (1 << depth) as f64,
                -(depth as f64),
            )
        })
        .collect();
    let tree_edges: Vec<_> = (1..15).map(|v| ((v - 1) / 2, v)).collect();
    add("tree", from_points(&tree_edges, &tree_pts));
    let two = [
        (0.0, 0.0),
        (4.0, 0.0),
        (2.0, 3.0),
        (10.0, 0.0),
        (14.0, 0.0),
        (14.0, 4.0),
        (10.0, 4.0),
    ];
    let two_edges = [(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 6), (6, 3)];
    add("two components", from_points(&two_edges, &two));
    let cut = [
        (0.0, 0.0),
        (2.0, 0.0),
        (1.0, 1.5),
        (2.0, 3.0),
        (0.0, 3.0),
        (-2.0, 3.0),
        (-4.0, 3.0),
        (-4.0, 5.0),
        (-2.0, 5.0),
        (1.0, -2.0),
        (1.0, -4.0),
    ];
    let cut_edges = [
        (0, 1),
        (1, 2),
        (2, 0),
        (2, 3),
        (3, 4),
        (4, 2),
        (4, 5),
        (5, 6),
        (6, 7),
        (7, 8),
        (8, 5),
        (0, 9),
        (9, 10),
    ];
    add("cut vertices and bridges", from_points(&cut_edges, &cut));
    let inside = [
        (0.0, 0.0),
        (10.0, 0.0),
        (5.0, 8.0),
        (5.0, 3.0),
        (5.0, 5.0),
        (5.0, 9.0),
    ];
    let inside_edges = [(0, 1), (1, 2), (2, 0), (0, 3), (3, 4), (2, 5)];
    add(
        "pendants inside and outside a triangle",
        from_points(&inside_edges, &inside),
    );
    let iso = [(0.0, 0.0), (5.0, 0.0), (9.0, 0.0), (1.0, 4.0), (6.0, 4.0)];
    add("isolated vertices", from_points(&[(0, 1)], &iso));
    add(
        "one edge",
        from_points(&[(0, 1)], &[(0.0, 0.0), (1.0, 0.0)]),
    );
    add("one vertex", from_points(&[], &[(0.0, 0.0)]));
    add("empty", from_points(&[], &[]));
    add("stacked triangulation", stacked(40, 7));
    out
}

/// Finite, no crossing, no two vertices together, no vertex on an edge it does not belong to.
pub fn assert_clean(g: &Graph, pos: &[Point]) {
    assert_eq!(pos.len(), g.vertex_count());
    assert!(pos.iter().all(|p| p.x.is_finite() && p.y.is_finite()));
    assert_eq!(count_crossings(g, pos), 0, "crossings");
    for a in 0..pos.len() {
        for b in a + 1..pos.len() {
            assert!(pos[a].dist(pos[b]) > 1e-9, "vertices {a} and {b} coincide");
        }
    }
    for e in g.valid_edges() {
        let (a, b) = g.endpoints(e);
        for v in (0..pos.len()).filter(|&v| v != a && v != b) {
            assert!(
                point_segment(pos[v], pos[a], pos[b]) > 1e-7,
                "vertex {v} on edge {e}"
            );
        }
    }
}
