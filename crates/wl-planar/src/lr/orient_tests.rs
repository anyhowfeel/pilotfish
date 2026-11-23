use super::*;

fn triangle_with_tail() -> Oriented {
    // 0-1-2 triangle, 2-3 pendant: edges 0:(0,1) 1:(1,2) 2:(2,0) 3:(2,3)
    orient(&Graph::new(4, &[(0, 1), (1, 2), (2, 0), (2, 3)]))
}

#[test]
fn heights_follow_the_search_tree() {
    let o = triangle_with_tail();
    assert_eq!(o.height, vec![0, 1, 2, 3]);
    assert_eq!(o.roots, vec![0]);
    assert_eq!(o.parent_edge, vec![None, Some(0), Some(1), Some(3)]);
}

#[test]
fn the_return_edge_sets_the_lowpoints_of_the_tree_edges_above_it() {
    let o = triangle_with_tail();
    assert_eq!((o.tail[2], o.head[2]), (2, 0));
    assert_eq!(o.lowpt[2], 0);
    assert_eq!(&o.lowpt[..2], &[0, 0]);
    assert_eq!(o.lowpt[3], 2);
}

#[test]
fn edges_leaving_a_vertex_are_ordered_by_nesting_depth() {
    let o = triangle_with_tail();
    assert_eq!(o.out[2], vec![2, 3]);
    assert!(o.nesting[2] < o.nesting[3]);
}

#[test]
fn every_component_gets_a_root_and_invalid_slots_stay_untouched() {
    let o = orient(&Graph::new(5, &[(0, 1), (1, 1), (0, 1), (3, 4)]));
    assert_eq!(o.roots, vec![0, 2, 3]);
    assert_eq!(o.edges, vec![0, 3]);
    assert!(o.out.iter().map(Vec::len).sum::<usize>() == 2);
}

#[test]
fn order_out_is_stable_and_handles_negative_keys() {
    let (tail, key) = (vec![0, 0, 0, 1], vec![3, -2, 3, 0]);
    let out = order_out(2, &tail, &[0, 1, 2, 3], &key);
    assert_eq!(out, vec![vec![1, 0, 2], vec![3]]);
    assert_eq!(order_out(3, &[], &[], &[]), vec![Vec::<usize>::new(); 3]);
}
