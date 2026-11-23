//! End-to-end tests of the real pipeline. They need `lr::embed`, `draw::straight_line` and
//! `draw::relax`, so they are ignored until those are merged:
//! `cargo test -p wl-planar --test pipeline -- --ignored`.

use std::time::{Duration, Instant};

use wl_planar::layout::{Layout, Options, layout};
use wl_planar::{Graph, Point, count_crossings};

struct Lcg(u64);

impl Lcg {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as usize % n
    }
}

fn complete(n: usize) -> Graph {
    let edges: Vec<_> = (0..n)
        .flat_map(|a| (a + 1..n).map(move |b| (a, b)))
        .collect();
    Graph::new(n, &edges)
}

fn k33(leaves: usize) -> Graph {
    let mut edges: Vec<_> = (0..3).flat_map(|a| (3..6).map(move |b| (a, b))).collect();
    edges.extend((0..leaves).map(|i| (i % 6, 6 + i)));
    Graph::new(6 + leaves, &edges)
}

fn petersen() -> Graph {
    let mut edges = Vec::new();
    for i in 0..5 {
        edges.push((i, (i + 1) % 5));
        edges.push((i, i + 5));
        edges.push((5 + i, 5 + (i + 2) % 5));
    }
    Graph::new(10, &edges)
}

fn grid(w: usize, h: usize) -> Graph {
    let mut edges = Vec::new();
    for y in 0..h {
        for x in 0..w {
            if x + 1 < w {
                edges.push((y * w + x, y * w + x + 1));
            }
            if y + 1 < h {
                edges.push((y * w + x, (y + 1) * w + x));
            }
        }
    }
    Graph::new(w * h, &edges)
}

fn wheel(rim: usize) -> Graph {
    let mut edges: Vec<_> = (0..rim).map(|i| (i, (i + 1) % rim)).collect();
    edges.extend((0..rim).map(|i| (i, rim)));
    Graph::new(rim + 1, &edges)
}

fn tree(n: usize) -> Graph {
    let edges: Vec<_> = (1..n).map(|v| ((v - 1) / 3, v)).collect();
    Graph::new(n, &edges)
}

/// A wheel with a tail on every rim vertex and a grid beside it: planar, with leaves.
fn planar_with_leaves(rng: &mut Lcg) -> Graph {
    let rim = 5 + rng.next(8);
    let mut edges: Vec<_> = (0..rim).map(|i| (i, (i + 1) % rim)).collect();
    edges.extend((0..rim).map(|i| (i, rim)));
    let mut n = rim + 1;
    for _ in 0..rng.next(20) + 5 {
        edges.push((rng.next(n), n));
        n += 1;
    }
    Graph::new(n, &edges)
}

fn random_graph(rng: &mut Lcg, n: usize, m: usize) -> Graph {
    let edges: Vec<_> = (0..m).map(|_| (rng.next(n), rng.next(n))).collect();
    Graph::new(n, &edges)
}

fn assert_sound(g: &Graph, out: &Layout) {
    assert_eq!(out.pos.len(), g.vertex_count());
    for (i, p) in out.pos.iter().enumerate() {
        assert!(
            p.x.is_finite() && p.y.is_finite(),
            "vertex {i} is not finite"
        );
        for (j, q) in out.pos.iter().enumerate().skip(i + 1) {
            assert!(p.dist(*q) > 1e-6, "vertices {i} and {j} coincide");
        }
    }
    assert_eq!(out.crossings, count_crossings(g, &out.pos));
    assert_eq!(out.planar && out.crossings == 0, out.planar);
}

fn assert_planar(name: &str, g: &Graph) {
    let out = layout(g, &Options::default());
    assert_sound(g, &out);
    assert!(out.planar, "{name} reported as not planar");
    assert_eq!(out.crossings, 0, "{name} drawn with crossings");
}

#[test]
#[ignore = "needs lr and draw"]
fn planar_graphs_are_drawn_without_crossings() {
    assert_planar("tree", &tree(60));
    assert_planar("grid", &grid(6, 5));
    assert_planar("wheel", &wheel(12));
    assert_planar("K4", &complete(4));
    assert_planar("path", &Graph::new(5, &[(0, 1), (1, 2), (2, 3), (3, 4)]));
    assert_planar("edgeless", &Graph::new(4, &[]));
    let mut rng = Lcg(3);
    for round in 0..25 {
        assert_planar(
            &format!("random planar {round}"),
            &planar_with_leaves(&mut rng),
        );
    }
}

#[test]
#[ignore = "needs lr and draw"]
fn several_components_are_drawn_apart_without_crossings() {
    let (a, b) = (wheel(6), tree(20));
    let mut all: Vec<_> = a.valid_edges().map(|e| a.endpoints(e)).collect();
    for e in b.valid_edges() {
        let (x, y) = b.endpoints(e);
        all.push((x + 7, y + 7));
    }
    let g = Graph::new(7 + 20 + 3, &all);
    assert_planar("components", &g);
}

fn assert_nonplanar(name: &str, g: &Graph, at_most: usize) {
    let out = layout(g, &Options::default());
    assert_sound(g, &out);
    assert!(!out.planar, "{name} reported as planar");
    assert!(out.crossings >= 1, "{name} drawn without crossings");
    assert!(
        out.crossings <= at_most,
        "{name} has {} crossings",
        out.crossings
    );
}

#[test]
#[ignore = "needs lr and draw"]
fn non_planar_graphs_keep_their_crossings_few() {
    assert_nonplanar("K5", &complete(5), 2);
    assert_nonplanar("K3,3", &k33(0), 2);
    assert_nonplanar("K3,3 with leaves", &k33(10), 2);
    assert_nonplanar("Petersen", &petersen(), 8);
}

#[test]
#[ignore = "needs lr and draw"]
fn random_graphs_give_sound_deterministic_layouts() {
    let mut rng = Lcg(5);
    for round in 0..20 {
        let n = 4 + rng.next(40);
        let m = n + rng.next(2 * n);
        let g = random_graph(&mut rng, n, m);
        let (a, b) = (
            layout(&g, &Options::default()),
            layout(&g, &Options::default()),
        );
        assert_sound(&g, &a);
        assert_eq!(a, b, "round {round} is not deterministic");
    }
}

#[test]
#[ignore = "needs lr and draw"]
fn weights_and_radii_are_honoured() {
    let g = complete(6);
    let weight: Vec<f64> = (0..g.edge_slots()).map(|e| 1.0 + e as f64).collect();
    let opts = Options {
        weight,
        radius: vec![20.0; 6],
        ..Options::default()
    };
    let out = layout(&g, &opts);
    assert_sound(&g, &out);
    for i in 0..6 {
        for j in i + 1..6 {
            assert!(out.pos[i].dist(out.pos[j]) >= 40.0, "{i} overlaps {j}");
        }
    }
}

#[test]
#[ignore = "needs lr and draw"]
fn the_budget_is_respected() {
    let mut rng = Lcg(9);
    let g = random_graph(&mut rng, 300, 700);
    let budget = Duration::from_millis(150);
    let start = Instant::now();
    let out = layout(
        &g,
        &Options {
            budget,
            ..Options::default()
        },
    );
    assert!(start.elapsed() < budget * 4, "took {:?}", start.elapsed());
    assert_sound(&g, &out);
}

#[test]
#[ignore = "needs lr and draw"]
fn a_layout_has_every_vertex_inside_a_sane_area() {
    let g = grid(8, 8);
    let out = layout(&g, &Options::default());
    let far = out
        .pos
        .iter()
        .map(|p| p.dist(Point::default()))
        .fold(0.0, f64::max);
    assert!(far < 100.0 * 8.0 * 2.0, "layout spreads to {far}");
}
