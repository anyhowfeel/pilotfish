use super::super::augment::triangulate;
use super::super::canonical::canonical;
use super::super::rot::Rot;
use super::super::shift;
use super::super::test_support::*;
use super::*;
use crate::{Graph, count_crossings};

fn start(lists: &[Vec<usize>]) -> (Rot, Vec<Point>, [usize; 3]) {
    let mut rot = Rot::new(lists);
    let outer = triangulate(&mut rot);
    let grid = shift::place(&canonical(&rot, outer), rot.vertex_count());
    let pos = grid
        .iter()
        .map(|&(x, y)| Point::new(x as f64, y as f64))
        .collect();
    (rot, pos, outer)
}

fn graph_of(rot: &Rot) -> Graph {
    let edges: Vec<(usize, usize)> = (0..rot.vertex_count())
        .flat_map(|v| rot.neighbors(v).iter().map(move |&w| (v, w)))
        .filter(|&(v, w)| v < w)
        .collect();
    Graph::new(rot.vertex_count(), &edges)
}

#[test]
fn the_drawing_stays_planar_after_any_number_of_sweeps() {
    let (_, e) = stacked(60, 9);
    let lists: Vec<Vec<usize>> = (0..60).map(|v| e.rotation(v).to_vec()).collect();
    for sweeps in [0, 1, 2, 5, 50, 400] {
        let (rot, mut pos, outer) = start(&lists);
        smooth(&rot, &mut pos, outer, sweeps);
        assert_eq!(count_crossings(&graph_of(&rot), &pos), 0, "{sweeps} sweeps");
    }
}

#[test]
fn smoothing_spreads_the_vertices_and_keeps_the_outer_triangle() {
    let (_, e) = triangulated_grid(9, 9);
    let lists: Vec<Vec<usize>> = (0..81).map(|v| e.rotation(v).to_vec()).collect();
    let (rot, mut pos, outer) = start(&lists);
    let tri = graph_of(&rot);
    let spread = |pos: &[Point]| {
        let mut lens: Vec<f64> = tri
            .valid_edges()
            .map(|e| {
                let (a, b) = tri.endpoints(e);
                pos[a].dist(pos[b])
            })
            .collect();
        lens.sort_by(f64::total_cmp);
        lens[lens.len() / 20] / lens[lens.len() / 2]
    };
    smooth(&rot, &mut pos, outer, 0);
    let flat = spread(&pos);
    let corners = outer.map(|v| pos[v]);
    smooth(&rot, &mut pos, outer, 300);
    assert_eq!(outer.map(|v| pos[v]), corners);
    assert!(spread(&pos) > 2.0 * flat);
}

#[test]
fn a_flat_outer_triangle_is_left_alone() {
    let (rot, mut pos, outer) = start(&[vec![1, 2], vec![2, 0], vec![0, 1]]);
    for p in pos.iter_mut() {
        p.y = 0.0;
    }
    let before = pos.clone();
    smooth(&rot, &mut pos, outer, 10);
    assert_eq!(pos, before);
}
