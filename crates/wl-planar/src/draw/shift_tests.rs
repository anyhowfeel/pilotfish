use super::super::augment::triangulate;
use super::super::canonical::canonical;
use super::super::rot::Rot;
use super::super::test_support::*;
use super::*;
use crate::{Graph, Point, count_crossings};

/// Runs the pipeline up to the grid on a triangulation of the fixture and returns it with the
/// graph of the triangulation.
fn triangulation_drawing(lists: &[Vec<usize>]) -> (Graph, Vec<(i64, i64)>, Canonical) {
    let mut rot = Rot::new(lists);
    let outer = triangulate(&mut rot);
    let canon = canonical(&rot, outer);
    let grid = place(&canon, rot.vertex_count());
    let edges: Vec<(usize, usize)> = (0..rot.vertex_count())
        .flat_map(|v| rot.neighbors(v).iter().map(move |&w| (v, w)))
        .filter(|&(v, w)| v < w)
        .collect();
    (Graph::new(rot.vertex_count(), &edges), grid, canon)
}

#[test]
fn the_grid_drawing_of_a_triangulation_is_planar_and_small() {
    for (name, g, e) in fixtures()
        .into_iter()
        .filter(|f| f.1.vertex_count() >= 3 && f.1.components().len() == 1)
    {
        let lists: Vec<Vec<usize>> = (0..g.vertex_count())
            .map(|v| e.rotation(v).to_vec())
            .collect();
        let (tri, grid, canon) = triangulation_drawing(&lists);
        let n = tri.vertex_count() as i64;
        let pos: Vec<Point> = grid
            .iter()
            .map(|&(x, y)| Point::new(x as f64, y as f64))
            .collect();
        assert_eq!(count_crossings(&tri, &pos), 0, "{name}");
        assert!(
            grid.iter()
                .all(|&(x, y)| (0..=2 * n - 4).contains(&x) && (0..=n - 2).contains(&y)),
            "{name}"
        );
        let mut order = canon.order.clone();
        order.sort_unstable();
        assert_eq!(
            order,
            (0..n as usize).collect::<Vec<_>>(),
            "{name}: order is not a permutation"
        );
        let rank: Vec<usize> = (0..n as usize)
            .map(|v| canon.order.iter().position(|&u| u == v).unwrap_or(0))
            .collect();
        for &v in &canon.order[2..] {
            assert!(
                canon.cover[v].len() >= 2 && canon.cover[v].iter().all(|&w| rank[w] < rank[v]),
                "{name}: cover of {v}"
            );
        }
    }
}
