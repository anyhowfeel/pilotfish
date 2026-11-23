use super::*;

fn splitmix(state: &mut u64) -> f64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64
}

fn segment(state: &mut u64, spread: f64) -> (Point, Point) {
    let mut p = || {
        Point::new(
            splitmix(state) * spread - spread / 4.0,
            splitmix(state) * spread - spread / 4.0,
        )
    };
    (p(), p())
}

#[test]
fn segments_that_meet_share_a_bucket_even_outside_the_frame() {
    let mut state = 7;
    // The frame is built for points in 0..100; the segments go well beyond.
    let frame = |s: f64| Frame::new(&[Point::new(0.0, 0.0), Point::new(s, s)], 10.0, 64);
    for spread in [100.0, 400.0] {
        let mut b = Buckets::new(frame(100.0));
        let segs: Vec<_> = (0..120).map(|_| segment(&mut state, spread)).collect();
        for (i, s) in segs.iter().enumerate() {
            b.add(s.0, s.1, i as u32);
        }
        for (i, s) in segs.iter().enumerate() {
            let mut found = Vec::new();
            b.gather(s.0, s.1, 0.0, &mut found);
            for (j, t) in segs.iter().enumerate().filter(|(j, _)| *j != i) {
                if crate::edges_cross(s.0, s.1, t.0, t.1, false) {
                    assert!(
                        found.contains(&(j as u32)),
                        "segments {i} and {j} cross but share no cell"
                    );
                }
            }
        }
    }
}

#[test]
fn a_margin_finds_what_is_near() {
    let mut state = 3;
    let mut b = Buckets::new(Frame::new(
        &[Point::new(0.0, 0.0), Point::new(100.0, 100.0)],
        10.0,
        64,
    ));
    let pts: Vec<Point> = (0..200)
        .map(|_| Point::new(splitmix(&mut state) * 100.0, splitmix(&mut state) * 100.0))
        .collect();
    for (i, p) in pts.iter().enumerate() {
        b.add(*p, *p, i as u32);
    }
    for _ in 0..50 {
        let (a, c) = segment(&mut state, 100.0);
        let mut found = Vec::new();
        b.gather(a, c, 5.0, &mut found);
        for (i, p) in pts.iter().enumerate() {
            if super::super::check::point_segment(*p, a, c) <= 5.0 {
                assert!(found.contains(&(i as u32)));
            }
        }
    }
}

#[test]
fn removing_takes_an_id_out_of_every_cell() {
    let mut b = Buckets::new(Frame::new(
        &[Point::new(0.0, 0.0), Point::new(100.0, 100.0)],
        10.0,
        64,
    ));
    let (p, q) = (Point::new(3.0, 4.0), Point::new(90.0, 80.0));
    b.add(p, q, 1);
    b.remove(p, q, 1);
    let mut found = Vec::new();
    b.gather(
        Point::new(0.0, 0.0),
        Point::new(100.0, 100.0),
        0.0,
        &mut found,
    );
    assert!(found.is_empty());
}

#[test]
fn bounds_of_nothing_and_of_a_few_points() {
    assert_eq!(bounds(&[]), (Point::default(), Point::default()));
    let (lo, hi) = bounds(&[Point::new(1.0, 5.0), Point::new(-2.0, 3.0)]);
    assert_eq!((lo, hi), (Point::new(-2.0, 3.0), Point::new(1.0, 5.0)));
}
