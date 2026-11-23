use super::*;
use crate::count_crossings;

#[test]
fn scaling_keeps_crossings_and_sets_the_mean_edge_length() {
    let g = Graph::new(4, &[(0, 2), (1, 3)]);
    let mut pos = vec![
        Point::new(0., 0.),
        Point::new(2., 0.),
        Point::new(2., 2.),
        Point::new(0., 2.),
    ];
    scale_edges(&g, &mut pos, 100.0);
    assert!((pos[0].dist(pos[2]) - 100.0).abs() < 1e-9);
    assert_eq!(count_crossings(&g, &pos), 1);
}

#[test]
fn discs_are_pushed_apart_but_never_pulled_together() {
    let mut near = vec![Point::new(0., 0.), Point::new(1., 0.)];
    separate_discs(&mut near, &[8.0, 8.0], 2.0);
    assert!((near[0].dist(near[1]) - 18.0).abs() < 1e-9);
    let mut far = vec![Point::new(0., 0.), Point::new(500., 0.)];
    separate_discs(&mut far, &[8.0, 8.0], 2.0);
    assert_eq!(far[0].dist(far[1]), 500.0);
}

#[test]
fn degenerate_input_does_not_blow_up() {
    let g = Graph::new(2, &[]);
    let mut pos = vec![Point::default(); 2];
    scale_edges(&g, &mut pos, 100.0);
    separate_discs(&mut pos, &[8.0, 8.0], 2.0);
    assert!(is_finite(&pos));
    assert!(is_finite(&circle(0, 100.0)));
}
