use super::*;

fn overlap(a: (Point, (f64, f64)), b: (Point, (f64, f64))) -> bool {
    a.0.x < b.0.x + b.1.0 - 1e-9
        && b.0.x < a.0.x + a.1.0 - 1e-9
        && a.0.y < b.0.y + b.1.1 - 1e-9
        && b.0.y < a.0.y + a.1.1 - 1e-9
}

#[test]
fn nothing_gives_nothing_and_one_box_is_centred() {
    assert!(pack(&[]).is_empty());
    assert_eq!(pack(&[(100.0, 40.0)]), [Point::new(-50.0, -20.0)]);
}

#[test]
fn boxes_do_not_overlap() {
    let sizes: Vec<(f64, f64)> = (0..40)
        .map(|i| (20.0 + (i * 37 % 90) as f64, 20.0 + (i * 53 % 70) as f64))
        .collect();
    let at = pack(&sizes);
    for i in 0..sizes.len() {
        for j in i + 1..sizes.len() {
            assert!(
                !overlap((at[i], sizes[i]), (at[j], sizes[j])),
                "{i} and {j}"
            );
        }
    }
}

#[test]
fn many_equal_boxes_form_a_four_by_three_block() {
    let sizes = vec![(50.0, 50.0); 48];
    let at = pack(&sizes);
    let w = at.iter().map(|p| p.x).fold(f64::MIN, f64::max)
        - at.iter().map(|p| p.x).fold(f64::MAX, f64::min)
        + 50.0;
    let h = at.iter().map(|p| p.y).fold(f64::MIN, f64::max)
        - at.iter().map(|p| p.y).fold(f64::MAX, f64::min)
        + 50.0;
    assert!((1.0..1.8).contains(&(w / h)), "aspect {}", w / h);
}

#[test]
fn the_largest_comes_first_and_the_result_is_deterministic() {
    let sizes = [(10.0, 10.0), (200.0, 150.0), (10.0, 10.0)];
    let at = pack(&sizes);
    assert!(at[1].x <= at[0].x && at[1].y <= at[0].y && at[1].y <= at[2].y);
    assert_eq!(at, pack(&sizes));
}

#[test]
fn a_box_wider_than_the_target_still_fits() {
    let at = pack(&[(900.0, 10.0), (10.0, 10.0)]);
    assert!(!overlap((at[0], (900.0, 10.0)), (at[1], (10.0, 10.0))));
}
