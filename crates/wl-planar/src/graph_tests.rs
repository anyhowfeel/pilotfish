use super::*;

#[test]
fn loops_repeats_and_out_of_range_pairs_are_invalid_but_keep_their_slot() {
    let g = Graph::new(3, &[(0, 1), (1, 1), (1, 0), (1, 2), (2, 9)]);
    assert_eq!(g.edge_slots(), 5);
    assert_eq!(g.edge_count(), 2);
    assert_eq!(g.valid_edges().collect::<Vec<_>>(), [0, 3]);
    assert!(!g.is_valid(1) && !g.is_valid(2) && !g.is_valid(4));
}

#[test]
fn adjacency_is_sorted_and_edge_indices_line_up() {
    let g = Graph::new(4, &[(2, 0), (0, 3), (0, 1)]);
    assert_eq!(g.neighbors(0), [1, 2, 3]);
    assert_eq!(g.incident(0), [2, 0, 1]);
    assert_eq!(g.degree(0), 3);
    assert!(g.has_edge(3, 0) && !g.has_edge(1, 2));
}

#[test]
fn components_are_found_with_isolated_vertices() {
    let g = Graph::new(6, &[(0, 1), (1, 2), (4, 3)]);
    assert_eq!(g.components(), [vec![0, 1, 2], vec![3, 4], vec![5]]);
    assert!(Graph::new(0, &[]).components().is_empty());
}

#[test]
fn with_edges_keeps_slots_and_drops_the_rest() {
    let g = Graph::new(3, &[(0, 1), (1, 2), (0, 2)]);
    let h = g.with_edges(&[true, false, true]);
    assert_eq!(h.edge_slots(), 3);
    assert_eq!(h.valid_edges().collect::<Vec<_>>(), [0, 2]);
    assert!(!h.has_edge(1, 2));
}

#[test]
fn induced_renumbers_and_reports_origins() {
    let g = Graph::new(5, &[(0, 1), (1, 2), (3, 4), (2, 3)]);
    let (h, origin) = g.induced(&[3, 2, 1]);
    assert_eq!(h.vertex_count(), 3);
    assert_eq!(origin, [1, 3]);
    assert!(h.has_edge(1, 2) && h.has_edge(0, 1) && !h.has_edge(0, 2));
}
