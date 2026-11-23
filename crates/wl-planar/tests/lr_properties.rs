//! Properties of `lr::embed` that need no oracle, and its behaviour on large inputs.

mod common;

use std::time::Instant;

use common::{Edges, Rng, Spec, grid, planar_by_construction, random_tree, stacked_triangulation};
use wl_planar::{Graph, lr};

fn graph(s: &Spec) -> Graph {
    Graph::new(s.n, &s.edges)
}

#[test]
fn graphs_planar_by_construction_always_embed() {
    let mut rng = Rng::new(7);
    for _ in 0..3000 {
        let s = planar_by_construction(&mut rng);
        let g = graph(&s);
        let e = lr::embed(&g).unwrap_or_else(|| panic!("rejected a planar graph {s:?}"));
        assert!(e.is_planar_embedding(&g), "invalid embedding of {s:?}");
    }
}

#[test]
fn maximal_planar_graphs_embed_and_one_more_edge_does_not() {
    let mut rng = Rng::new(11);
    for _ in 0..300 {
        let n = rng.range(5, 40);
        let mut s = stacked_triangulation(&mut rng, n);
        let g = graph(&s);
        let e = lr::embed(&g).expect("a triangulation is planar");
        assert!(e.is_planar_embedding(&g));
        let (a, b) = (0..n)
            .flat_map(|a| (a + 1..n).map(move |b| (a, b)))
            .find(|&(a, b)| !g.has_edge(a, b))
            .expect("a stacked triangulation on 5+ vertices is not complete");
        s.edges.push((a, b));
        assert!(
            lr::embed(&graph(&s)).is_none(),
            "3n-6 edges plus one: {s:?}"
        );
    }
}

#[test]
fn adding_edges_until_the_bound_is_exceeded_ends_non_planar() {
    let mut rng = Rng::new(13);
    for _ in 0..200 {
        let n = rng.range(5, 25);
        let mut s = random_tree(&mut rng, n);
        let mut seen_non_planar = false;
        while graph(&s).edge_count() <= 3 * n - 6 {
            let (a, b) = (rng.below(n), rng.below(n));
            if a == b || graph(&s).has_edge(a, b) {
                continue;
            }
            s.edges.push((a, b));
            let planar = lr::embed(&graph(&s)).is_some();
            assert!(!(seen_non_planar && planar), "planarity came back: {s:?}");
            seen_non_planar |= !planar;
        }
        assert!(lr::embed(&graph(&s)).is_none(), "above 3n-6 edges: {s:?}");
    }
}

fn embeds_fast(name: &str, s: &Spec) {
    let g = graph(s);
    let start = Instant::now();
    let e = lr::embed(&g).unwrap_or_else(|| panic!("{name} rejected"));
    let took = start.elapsed();
    assert!(e.is_planar_embedding(&g), "{name}: invalid embedding");
    eprintln!(
        "{name}: n={} m={} embedded in {took:?}",
        s.n,
        g.edge_count()
    );
    assert!(took.as_secs() < 20, "{name} took {took:?}");
}

#[test]
fn a_long_path_embeds_without_overflowing_the_stack() {
    let n = 200_000;
    let edges: Edges = (1..n).map(|i| (i - 1, i)).collect();
    embeds_fast("path", &Spec { n, edges });
}

#[test]
fn a_large_grid_embeds() {
    embeds_fast(
        "grid 100x100",
        &Spec {
            n: 10_000,
            edges: grid(100, 100),
        },
    );
}

#[test]
fn a_long_ladder_with_deep_nesting_embeds() {
    embeds_fast(
        "ladder 2x50000",
        &Spec {
            n: 100_000,
            edges: grid(50_000, 2),
        },
    );
}

#[test]
fn a_large_random_tree_embeds() {
    let mut rng = Rng::new(3);
    embeds_fast("tree", &random_tree(&mut rng, 100_000));
}

#[test]
fn a_large_triangulation_embeds() {
    let mut rng = Rng::new(5);
    embeds_fast("triangulation", &stacked_triangulation(&mut rng, 20_000));
}
