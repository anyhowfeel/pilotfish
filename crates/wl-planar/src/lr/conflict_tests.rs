use super::*;
use crate::graph::Graph;
use crate::lr::orient::orient;

fn passes(n: usize, edges: &[(usize, usize)]) -> bool {
    check(&orient(&Graph::new(n, edges))).is_some()
}

fn complete(n: usize) -> Vec<(usize, usize)> {
    (0..n)
        .flat_map(|a| (a + 1..n).map(move |b| (a, b)))
        .collect()
}

#[test]
fn k4_passes_and_k5_fails() {
    assert!(passes(4, &complete(4)));
    assert!(!passes(5, &complete(5)));
}

#[test]
fn k33_fails() {
    let k33: Vec<_> = (0..3).flat_map(|a| (3..6).map(move |b| (a, b))).collect();
    assert!(!passes(6, &k33));
}

#[test]
fn k5_minus_an_edge_passes() {
    let mut k5 = complete(5);
    k5.pop();
    assert!(passes(5, &k5));
}

#[test]
fn a_failing_component_fails_the_whole_graph() {
    let mut edges = complete(5);
    edges.extend([(5, 6), (6, 7)]);
    assert!(!passes(8, &edges));
}

#[test]
fn a_tree_needs_no_constraints() {
    let c = check(&orient(&Graph::new(4, &[(0, 1), (0, 2), (2, 3)]))).map(|c| c.reference);
    assert_eq!(c, Some(vec![None; 3]));
}
