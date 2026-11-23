use super::*;

#[test]
fn a_cycle_with_a_tail_keeps_only_the_cycle() {
    let g = Graph::new(6, &[(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (3, 5)]);
    let p = peel(&g);
    assert_eq!(p.core, [true, true, true, false, false, false]);
    assert_eq!(p.parent[3], Some(2));
    assert_eq!(p.parent[4], Some(3));
    assert_eq!(p.children(3), [4, 5]);
    assert_eq!(p.roots().count(), 0);
    assert_eq!(p.core_len(), 3);
}

#[test]
fn a_path_has_no_core_and_is_rooted_at_its_centre() {
    let g = Graph::new(5, &[(0, 1), (1, 2), (2, 3), (3, 4)]);
    let p = peel(&g);
    assert_eq!(p.core_len(), 0);
    assert_eq!(p.roots().collect::<Vec<_>>(), [2]);
    assert_eq!(p.parent[0], Some(1));
    assert_eq!(p.parent[1], Some(2));
}

#[test]
fn a_star_is_rooted_at_its_hub() {
    let g = Graph::new(5, &[(0, 1), (0, 2), (0, 3), (0, 4)]);
    assert_eq!(peel(&g).roots().collect::<Vec<_>>(), [0]);
}

#[test]
fn two_vertices_and_an_isolated_one() {
    let g = Graph::new(3, &[(0, 1)]);
    let p = peel(&g);
    assert_eq!(p.core_len(), 0);
    assert_eq!(p.roots().count(), 2);
    assert!(p.parent[2].is_none());
}

#[test]
fn children_are_removed_before_their_parents() {
    let g = Graph::new(7, &[(0, 1), (1, 2), (2, 3), (2, 4), (4, 5), (4, 6)]);
    let p = peel(&g);
    let at = |v: usize| p.order.iter().position(|&x| x == v).unwrap();
    for (v, parent) in p.parent.iter().enumerate() {
        if let Some(u) = parent {
            assert!(at(v) < at(*u));
        }
    }
}

#[test]
fn a_dense_graph_is_its_own_core() {
    let g = Graph::new(4, &[(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]);
    assert_eq!(peel(&g).core_len(), 4);
}
