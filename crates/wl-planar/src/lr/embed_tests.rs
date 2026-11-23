use super::*;

#[test]
fn a_chain_of_references_multiplies_the_sides_down_to_its_root() {
    let mut c = Constraints {
        side: vec![-1, -1, 1, -1],
        reference: vec![Some(1), Some(2), None, Some(1)],
    };
    resolve_sides(&mut c, &[0, 1, 2, 3]);
    assert_eq!(c.side, vec![1, -1, 1, 1]);
    assert!(c.reference.iter().all(Option::is_none));

    let mut c = Constraints {
        side: vec![-1, -1, -1],
        reference: vec![Some(1), Some(2), None],
    };
    resolve_sides(&mut c, &[0, 1, 2]);
    assert_eq!(c.side, vec![-1, 1, -1]);
}

#[test]
fn a_reference_chain_a_million_long_does_not_overflow_the_stack() {
    let n = 1_000_000;
    let mut c = Constraints {
        side: vec![-1; n],
        reference: (0..n).map(|i| (i + 1 < n).then_some(i + 1)).collect(),
    };
    let edges: Vec<usize> = (0..n).collect();
    resolve_sides(&mut c, &edges);
    assert_eq!(c.side[0], if n % 2 == 0 { 1 } else { -1 });
}

#[test]
fn ring_inserts_next_to_a_half_edge() {
    let mut r = Ring::new(4);
    r.insert_after(0, 1);
    r.insert_before(0, 2);
    r.insert_after(1, 3);
    let mut order = vec![0];
    let mut h = r.next[0];
    while h != 0 {
        order.push(h);
        h = r.next[h];
    }
    assert_eq!(order, vec![0, 1, 3, 2]);
}
