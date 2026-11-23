use super::super::test_support::*;
use super::*;

#[test]
fn triangulating_gives_a_simple_triangulation_that_keeps_the_original_edges() {
    let (g, e) = from_points(
        &[(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)],
        &(0..6).map(|i| (i as f64, 0.0)).collect::<Vec<_>>(),
    );
    let lists: Vec<Vec<usize>> = (0..6).map(|v| e.rotation(v).to_vec()).collect();
    let mut rot = Rot::new(&lists);
    triangulate(&mut rot);
    let n = rot.vertex_count();
    let faces = rot.faces();
    assert!(faces.iter().all(|f| f.len() == 3), "{faces:?}");
    let edges: usize = (0..n).map(|v| rot.neighbors(v).len()).sum::<usize>() / 2;
    assert_eq!(n + faces.len(), edges + 2);
    for v in 0..n {
        let mut nb = rot.neighbors(v).to_vec();
        nb.sort_unstable();
        nb.dedup();
        assert_eq!(nb.len(), rot.neighbors(v).len(), "multi-edge at {v}");
    }
    for v in 0..g.vertex_count() {
        assert!(g.neighbors(v).iter().all(|w| rot.neighbors(v).contains(w)));
    }
}
