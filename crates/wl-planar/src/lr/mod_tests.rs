use super::*;

type Edges = Vec<(usize, usize)>;

fn complete(n: usize) -> Edges {
    (0..n)
        .flat_map(|a| (a + 1..n).map(move |b| (a, b)))
        .collect()
}

fn cycle(n: usize) -> Edges {
    (0..n).map(|i| (i, (i + 1) % n)).collect()
}

fn path(n: usize) -> Edges {
    (1..n).map(|i| (i - 1, i)).collect()
}

fn bipartite(a: usize, b: usize) -> Edges {
    (0..a)
        .flat_map(|x| (a..a + b).map(move |y| (x, y)))
        .collect()
}

fn wheel(rim: usize) -> Edges {
    let mut e: Edges = (1..=rim).map(|i| (0, i)).collect();
    e.extend((1..=rim).map(|i| (i, i % rim + 1)));
    e
}

fn grid(w: usize, h: usize) -> Edges {
    let mut e = Vec::new();
    for y in 0..h {
        for x in 0..w {
            if x + 1 < w {
                e.push((y * w + x, y * w + x + 1));
            }
            if y + 1 < h {
                e.push((y * w + x, (y + 1) * w + x));
            }
        }
    }
    e
}

fn petersen() -> Edges {
    let mut e = cycle(5);
    e.extend((0..5).map(|i| (i, i + 5)));
    e.extend((0..5).map(|i| (5 + i, 5 + (i + 2) % 5)));
    e
}

/// Every edge replaced by a path with `extra` inner vertices.
fn subdivide(n: usize, edges: &[(usize, usize)], extra: usize) -> (usize, Edges) {
    let mut next = n;
    let mut out = Vec::new();
    for &(a, b) in edges {
        let mut prev = a;
        for _ in 0..extra {
            out.push((prev, next));
            prev = next;
            next += 1;
        }
        out.push((prev, b));
    }
    (next, out)
}

fn shifted(edges: &Edges, by: usize) -> Edges {
    edges.iter().map(|&(a, b)| (a + by, b + by)).collect()
}

/// Verdict, with the embedding checked whenever there is one.
fn planar(n: usize, edges: &[(usize, usize)]) -> bool {
    let g = Graph::new(n, edges);
    match embed(&g) {
        Some(e) => {
            assert!(e.is_planar_embedding(&g), "invalid embedding of {edges:?}");
            assert!(is_planar(&g));
            true
        }
        None => {
            assert!(!is_planar(&g));
            false
        }
    }
}

#[test]
fn the_empty_graph_and_isolated_vertices_are_planar() {
    assert!(planar(0, &[]));
    assert!(planar(1, &[]));
    assert!(planar(7, &[]));
}

#[test]
fn one_edge_and_small_trees_are_planar() {
    assert!(planar(2, &[(0, 1)]));
    assert!(planar(5, &path(5)));
    assert!(planar(6, &[(0, 1), (0, 2), (0, 3), (3, 4), (3, 5)]));
    assert!(planar(
        100,
        &(1..100).map(|i| (i / 3, i)).collect::<Edges>()
    ));
}

#[test]
fn cycles_and_wheels_are_planar() {
    assert!(planar(3, &cycle(3)));
    assert!(planar(40, &cycle(40)));
    assert!(planar(5, &wheel(4)));
    assert!(planar(21, &wheel(20)));
}

#[test]
fn k4_is_planar_but_k5_is_not() {
    assert!(planar(4, &complete(4)));
    assert!(!planar(5, &complete(5)));
    assert!(!planar(6, &complete(6)));
    assert!(planar(5, &complete(5)[..9]));
}

#[test]
fn k33_is_not_planar_but_k23_is() {
    assert!(!planar(6, &bipartite(3, 3)));
    assert!(planar(5, &bipartite(2, 3)));
    assert!(planar(7, &bipartite(2, 5)));
    assert!(!planar(7, &bipartite(3, 4)));
}

#[test]
fn grids_are_planar() {
    assert!(planar(12, &grid(3, 4)));
    assert!(planar(400, &grid(20, 20)));
}

#[test]
fn the_petersen_graph_is_not_planar() {
    assert!(!planar(10, &petersen()));
}

#[test]
fn subdivisions_of_k5_and_k33_stay_non_planar() {
    for extra in 1..4 {
        let (n, e) = subdivide(5, &complete(5), extra);
        assert!(!planar(n, &e), "K5 with {extra} inner vertices");
        let (n, e) = subdivide(6, &bipartite(3, 3), extra);
        assert!(!planar(n, &e), "K3,3 with {extra} inner vertices");
    }
}

#[test]
fn subdividing_a_planar_graph_keeps_it_planar() {
    let (n, e) = subdivide(11, &wheel(10), 2);
    assert!(planar(n, &e));
    let (n, e) = subdivide(4, &complete(4), 3);
    assert!(planar(n, &e));
}

#[test]
fn disjoint_unions_are_planar_exactly_when_every_part_is() {
    let mut e = complete(4);
    e.extend(shifted(&wheel(5), 4));
    e.extend(shifted(&path(3), 10));
    assert!(planar(13 + 2, &e));
    e.extend(shifted(&complete(5), 13));
    assert!(!planar(18, &e));
    let mut e = shifted(&complete(5), 3);
    e.extend(complete(3));
    assert!(!planar(8, &e));
}

#[test]
fn cut_vertices_and_bridges_do_not_confuse_the_embedding() {
    // Two K4 sharing vertex 3, a bridge to a triangle, a pendant path.
    let mut e = complete(4);
    e.extend([(3, 4), (3, 5), (3, 6), (4, 5), (4, 6), (5, 6)]);
    e.extend([(6, 7), (7, 8), (8, 9), (9, 7), (9, 10)]);
    assert!(planar(11, &e));
    // The same with a K5 hanging on the bridge.
    e.extend(shifted(&complete(5), 11));
    e.push((10, 11));
    assert!(!planar(16, &e));
}

#[test]
fn one_extra_edge_can_make_a_planar_graph_non_planar() {
    // K5 minus an edge is planar.
    let mut e = complete(5);
    e.retain(|&p| p != (3, 4));
    assert!(planar(5, &e));
    e.push((3, 4));
    assert!(!planar(5, &e));
    // A subdivided K3,3 minus one edge is planar; the edge itself closes the K3,3.
    let (n, mut k33) = subdivide(6, &bipartite(3, 3)[1..], 1);
    assert!(planar(n, &k33));
    k33.push((0, 3));
    assert!(!planar(n, &k33));
}

#[test]
fn loops_repeats_and_out_of_range_slots_are_ignored() {
    let mut e = complete(4);
    e.extend([(2, 2), (0, 1), (1, 0), (9, 1), (3, 40)]);
    assert!(planar(4, &e));
    let mut e = complete(5);
    e.extend([(1, 1), (5, 0)]);
    assert!(!planar(5, &e));
}

#[test]
fn the_edge_bound_rejects_dense_components_without_a_search() {
    let g = Graph::new(8, &complete(8));
    assert!(too_dense(&g));
    assert!(!too_dense(&Graph::new(3, &complete(3))));
    assert!(!too_dense(&Graph::new(2, &[(0, 1)])));
    assert!(!too_dense(&Graph::new(6, &complete(4))));
}

#[test]
fn the_result_does_not_depend_on_anything_but_the_graph() {
    let g = Graph::new(30, &grid(5, 6));
    assert_eq!(embed(&g), embed(&g));
}
