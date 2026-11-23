use std::cell::RefCell;

use super::*;
use crate::testing::{Lcg, complete, draw_on_circle, embed_pseudoforest, pseudoforest};

/// Stand-ins: a planar graph is one with at most as many edges as vertices per component.
fn run(g: &Graph, opts: &Options) -> (Layout, Vec<&'static str>) {
    let log = RefCell::new(Vec::new());
    let embed = |h: &Graph| {
        log.borrow_mut().push("embed");
        embed_pseudoforest(h)
    };
    let draw = |h: &Graph, e: &Embedding| {
        log.borrow_mut().push("draw");
        draw_on_circle(h, e)
    };
    let relax = |_: &Graph, _: &mut [Point], _: &Relax| log.borrow_mut().push("relax");
    let planar_part = |h: &Graph, p: &[usize]| {
        log.borrow_mut().push("planar_part");
        crate::planarize::maximal_planar_with(h, p, &pseudoforest)
    };
    let stages = Stages {
        embed: &embed,
        draw: &draw,
        relax: &relax,
        planar_part: &planar_part,
    };
    let out = layout_with(g, opts, &stages);
    (out, log.into_inner())
}

fn distinct(pos: &[Point], min: f64) -> bool {
    pos.iter().all(|p| p.x.is_finite() && p.y.is_finite())
        && (0..pos.len()).all(|i| (i + 1..pos.len()).all(|j| pos[i].dist(pos[j]) >= min))
}

#[test]
fn a_planar_component_is_embedded_drawn_and_relaxed() {
    let g = Graph::new(7, &[(0, 1), (1, 2), (2, 3), (3, 4), (4, 0), (2, 5), (5, 6)]);
    let (out, log) = run(&g, &Options::default());
    assert_eq!(log, ["embed", "draw", "relax"]);
    assert!(out.planar);
    assert_eq!(out.crossings, 0);
    assert!(distinct(&out.pos, 16.0));
}

#[test]
fn a_non_planar_component_draws_its_planar_part_and_adds_the_rest() {
    let g = complete(4);
    let (out, log) = run(&g, &Options::default());
    assert_eq!(log, ["embed", "planar_part", "embed", "draw", "relax"]);
    assert!(!out.planar);
    assert_eq!(out.crossings, count_crossings(&g, &out.pos));
    assert!(out.crossings <= 1);
    assert!(distinct(&out.pos, 16.0));
}

#[test]
fn heavy_edges_are_offered_to_the_planar_part_first() {
    let g = complete(4);
    let seen = RefCell::new(Vec::new());
    let planar_part = |h: &Graph, p: &[usize]| {
        *seen.borrow_mut() = p.to_vec();
        crate::planarize::maximal_planar_with(h, p, &pseudoforest)
    };
    let relax = |_: &Graph, _: &mut [Point], _: &Relax| {};
    let stages = Stages {
        embed: &embed_pseudoforest,
        draw: &draw_on_circle,
        relax: &relax,
        planar_part: &planar_part,
    };
    let opts = Options {
        weight: vec![1.0, 1.0, 9.0, 1.0, 5.0, 1.0],
        ..Options::default()
    };
    layout_with(&g, &opts, &stages);
    assert_eq!(seen.into_inner(), [2, 4, 0, 1, 3, 5]);
}

#[test]
fn components_are_packed_apart_without_crossings() {
    let mut edges = vec![(0, 1), (1, 2), (2, 0)];
    edges.extend((4..30).map(|v| (3, v)));
    edges.extend([(30, 31), (31, 32), (32, 33), (33, 30)]);
    let g = Graph::new(35, &edges);
    let (out, _) = run(&g, &Options::default());
    assert!(out.planar);
    assert_eq!(out.crossings, 0);
    assert!(distinct(&out.pos, 16.0));
}

#[test]
fn radii_keep_discs_apart() {
    let g = Graph::new(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]);
    let opts = Options {
        radius: vec![30.0, 30.0, 30.0, 30.0],
        ..Options::default()
    };
    let (out, _) = run(&g, &opts);
    assert!(distinct(&out.pos, 60.0));
}

#[test]
fn a_stage_returning_nonsense_falls_back_to_a_circle() {
    let g = Graph::new(5, &[(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)]);
    let bad = |h: &Graph, _: &Embedding| vec![Point::new(f64::NAN, 0.0); h.vertex_count()];
    let relax = |_: &Graph, _: &mut [Point], _: &Relax| {};
    let stages = Stages {
        embed: &embed_pseudoforest,
        draw: &bad,
        relax: &relax,
        planar_part: &|_, _| Vec::new(),
    };
    let out = layout_with(&g, &Options::default(), &stages);
    assert!(distinct(&out.pos, 16.0));
    assert_eq!(out.crossings, 0);
}

#[test]
fn empty_and_edgeless_graphs_are_fine() {
    let (empty, _) = run(&Graph::new(0, &[]), &Options::default());
    assert!(empty.pos.is_empty() && empty.planar);
    let (dots, _) = run(&Graph::new(5, &[]), &Options::default());
    assert!(dots.planar && distinct(&dots.pos, 16.0));
}

#[test]
fn random_graphs_keep_every_vertex_finite_and_the_count_honest() {
    let mut rng = Lcg(11);
    for _ in 0..20 {
        let n = 3 + rng.next(14);
        let edges: Vec<_> = (0..n + rng.next(2 * n))
            .map(|_| (rng.next(n), rng.next(n)))
            .collect();
        let g = Graph::new(n, &edges);
        let (a, _) = run(&g, &Options::default());
        let (b, _) = run(&g, &Options::default());
        assert_eq!(a, b);
        assert_eq!(a.crossings, count_crossings(&g, &a.pos));
        assert!(distinct(&a.pos, 1.0));
    }
}
