use wl_kit::egui::pos2;

use super::*;

fn dist(a: Pos2, b: Pos2) -> f32 {
    (a - b).length()
}

#[test]
fn the_tip_stops_just_outside_the_destination_disc() {
    let (from, to) = (pos2(0.0, 0.0), pos2(200.0, 0.0));
    let [tip, ..] = head(from, to, (8.0, 12.0), 3.0).expect("room");
    assert!((dist(tip, to) - (12.0 + GAP)).abs() < 1e-3);
    assert!(tip.x < to.x);
}

#[test]
fn the_head_points_along_the_link_in_every_direction() {
    let c = pos2(100.0, 100.0);
    for (dx, dy) in [
        (150.0, 0.0),
        (-150.0, 0.0),
        (0.0, 150.0),
        (0.0, -150.0),
        (110.0, 110.0),
    ] {
        let to = c + vec2(dx, dy);
        let [tip, a, b] = head(c, to, (6.0, 6.0), 2.0).expect("room");
        let mid = pos2((a.x + b.x) / 2.0, (a.y + b.y) / 2.0);
        let along = (tip - mid).normalized();
        let link = (to - c).normalized();
        assert!((along - link).length() < 1e-3, "{dx},{dy}");
        assert!((dist(a, mid) - dist(b, mid)).abs() < 1e-3);
    }
}

#[test]
fn the_head_grows_a_little_with_the_width_but_not_without_limit() {
    assert!(head_len(8.0) > head_len(1.0));
    assert!((head_len(10.0) - head_len(40.0)).abs() < 1e-6);
    assert!(head_len(40.0) < 12.0);
}

#[test]
fn a_link_too_short_between_its_discs_gets_no_arrow() {
    assert!(head(pos2(0.0, 0.0), pos2(40.0, 0.0), (12.0, 12.0), 2.0).is_none());
    assert!(head(pos2(0.0, 0.0), pos2(60.0, 0.0), (12.0, 12.0), 2.0).is_some());
}

#[test]
fn a_zero_length_link_gets_no_arrow() {
    assert!(head(pos2(5.0, 5.0), pos2(5.0, 5.0), (0.0, 0.0), 2.0).is_none());
}

#[test]
fn the_head_stays_clear_of_the_source_disc() {
    let (from, to) = (pos2(0.0, 0.0), pos2(100.0, 0.0));
    let [_, a, b] = head(from, to, (20.0, 8.0), 2.0).expect("room");
    assert!(dist(a, from) > 20.0 && dist(b, from) > 20.0);
}
