use super::*;

fn p(x: f64, y: f64) -> Point {
    Point::new(x, y)
}

#[test]
fn a_square_with_both_diagonals_has_one_crossing() {
    let g = Graph::new(4, &[(0, 1), (1, 2), (2, 3), (3, 0), (0, 2), (1, 3)]);
    let pos = [p(0., 0.), p(2., 0.), p(2., 2.), p(0., 2.)];
    assert_eq!(crossing_pairs(&g, &pos), [(4, 5)]);
    assert_eq!(count_crossings(&g, &pos), 1);
}

#[test]
fn a_planar_drawing_has_none() {
    let g = Graph::new(4, &[(0, 1), (1, 2), (2, 3), (3, 0), (0, 2)]);
    let pos = [p(0., 0.), p(2., 0.), p(2., 2.), p(0., 2.)];
    assert_eq!(count_crossings(&g, &pos), 0);
}

#[test]
fn invalid_edges_are_ignored() {
    let g = Graph::new(4, &[(0, 2), (1, 3), (0, 2), (1, 1)]);
    let pos = [p(0., 0.), p(2., 0.), p(2., 2.), p(0., 2.)];
    assert_eq!(count_crossings(&g, &pos), 1);
}

#[test]
fn edges_meeting_at_a_vertex_do_not_cross_but_overlapping_ones_do() {
    let g = Graph::new(3, &[(0, 1), (0, 2)]);
    assert_eq!(count_crossings(&g, &[p(0., 0.), p(1., 0.), p(0., 1.)]), 0);
    assert_eq!(count_crossings(&g, &[p(0., 0.), p(2., 0.), p(1., 0.)]), 1);
}

#[test]
fn a_vertex_lying_on_an_unrelated_edge_counts() {
    let g = Graph::new(4, &[(0, 1), (2, 3)]);
    let pos = [p(0., 0.), p(4., 0.), p(2., 0.), p(2., 3.)];
    assert_eq!(count_crossings(&g, &pos), 1);
}

#[test]
fn empty_and_single_edge_graphs_have_no_crossings() {
    assert_eq!(count_crossings(&Graph::new(0, &[]), &[]), 0);
    assert_eq!(
        count_crossings(&Graph::new(2, &[(0, 1)]), &[p(0., 0.), p(1., 1.)]),
        0
    );
}
