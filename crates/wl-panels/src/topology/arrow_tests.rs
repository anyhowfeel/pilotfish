use wl_kit::egui::{pos2, vec2};

use super::*;

fn dist(a: Pos2, b: Pos2) -> f32 {
    (a - b).length()
}

fn link(from: Pos2, to: Pos2, way: Way) -> Link {
    Link {
        from,
        to,
        reach: (8.0, 12.0),
        width: 3.0,
        way,
    }
}

fn centre_of(t: [Pos2; 3]) -> Pos2 {
    pos2(
        (t[0].x + t[1].x + t[2].x) / 3.0,
        (t[0].y + t[1].y + t[2].y) / 3.0,
    )
}

/// Direction a head points in: from the middle of its base to its tip.
fn pointing(t: [Pos2; 3]) -> Vec2 {
    let base = pos2((t[1].x + t[2].x) / 2.0, (t[1].y + t[2].y) / 2.0);
    (t[0] - base).normalized()
}

#[test]
fn a_one_way_arrow_sits_in_the_middle_of_the_visible_link_and_points_to_the_receiver() {
    let l = link(pos2(0.0, 0.0), pos2(300.0, 0.0), Way::OneWay);
    let a = arrow(&l, 0.0).expect("room");
    // The visible part runs from x = 8 to x = 288, so its middle is x = 148.
    assert!((a.centre.x - 148.0).abs() < 1e-3 && a.centre.y.abs() < 1e-3);
    assert!(a.back.is_none());
    assert!(
        pointing(a.forward).x > 0.99,
        "it points from the sender to the receiver"
    );
}

#[test]
fn the_arrow_points_the_other_way_when_the_receiver_is_on_the_left() {
    let l = link(pos2(300.0, 0.0), pos2(0.0, 0.0), Way::OneWay);
    let a = arrow(&l, 0.0).expect("room");
    assert!(pointing(a.forward).x < -0.99);
}

#[test]
fn a_two_way_arrow_has_two_heads_back_to_back_around_the_middle() {
    let l = link(pos2(0.0, 0.0), pos2(300.0, 0.0), Way::TwoWay(0.5));
    let a = arrow(&l, 0.0).expect("room");
    let back = a.back.expect("a second head");
    assert!(pointing(a.forward).x > 0.99 && pointing(back).x < -0.99);
    let (f, b) = (centre_of(a.forward), centre_of(back));
    assert!(
        f.x > a.centre.x && b.x < a.centre.x,
        "one head on each side of the middle"
    );
    assert!(
        ((f.x - a.centre.x) - (a.centre.x - b.x)).abs() < 1e-3,
        "they are symmetrical"
    );
    // Tips point away from each other, bases face each other with a small gap.
    assert!(a.forward[0].x > a.forward[1].x && back[0].x < back[1].x);
    assert!(a.forward[1].x > back[1].x);
}

#[test]
fn the_arrow_points_along_the_link_in_every_direction() {
    let c = pos2(100.0, 100.0);
    for (dx, dy) in [
        (220.0, 0.0),
        (-220.0, 0.0),
        (0.0, 220.0),
        (0.0, -220.0),
        (170.0, 170.0),
    ] {
        let to = c + vec2(dx, dy);
        let a = arrow(&link(c, to, Way::OneWay), 0.0).expect("room");
        let along = (to - c).normalized();
        assert!(pointing(a.forward).dot(along) > 0.999, "{dx} {dy}");
    }
}

#[test]
fn a_link_too_short_between_its_discs_gets_no_arrow() {
    // Between the discs there are 10 px left, and a head needs 1.8 times its own 9 px.
    assert!(arrow(&link(pos2(0.0, 0.0), pos2(30.0, 0.0), Way::OneWay), 0.0).is_none());
    // A two-way arrow is 21 px long and needs 37.8 px; 35 are left.
    assert!(
        arrow(
            &link(pos2(0.0, 0.0), pos2(55.0, 0.0), Way::TwoWay(0.5)),
            0.0
        )
        .is_none()
    );
    assert!(
        arrow(
            &link(pos2(0.0, 0.0), pos2(80.0, 0.0), Way::TwoWay(0.5)),
            0.0
        )
        .is_some()
    );
}

#[test]
fn a_zero_length_link_gets_no_arrow() {
    let p = pos2(5.0, 5.0);
    assert!(arrow(&link(p, p, Way::OneWay), 0.0).is_none());
}

#[test]
fn the_arrow_never_touches_a_disc() {
    let l = link(pos2(0.0, 0.0), pos2(300.0, 0.0), Way::TwoWay(0.5));
    for slide in [-2.0, -1.0, 0.0, 1.0, 2.0] {
        if let Some(a) = arrow(&l, slide * 30.0) {
            for t in a.heads() {
                for p in t {
                    assert!(p.x > l.reach.0 && p.x < 300.0 - l.reach.1, "{p:?}");
                }
            }
        }
    }
}

#[test]
fn the_head_is_clearly_wider_than_the_link_it_sits_on() {
    for w in [0.7_f32, 1.0, 2.0, 4.0, 5.0, 7.5] {
        assert!(
            head_base(w) >= 2.0 * w,
            "a head of {} px on a link of {w} px",
            head_base(w)
        );
    }
    assert!(head_len(8.0) > head_len(1.0) && (head_len(10.0) - head_len(40.0)).abs() < 1e-6);
    assert!(head_len(40.0) < 22.0);
}

/// `n` links from spread-out hosts to a hub, the widths varying, half of them two-way.
fn hub(n: usize, disc: f32) -> Vec<Link> {
    let c = pos2(300.0, 300.0);
    (0..n)
        .map(|i| {
            let a = std::f32::consts::TAU * (i as f32 + 0.37 * (i % 3) as f32) / n as f32;
            Link {
                from: c + vec2(a.cos(), a.sin()) * (190.0 + 9.0 * (i % 5) as f32),
                to: c,
                reach: (6.0, disc),
                width: 2.0 + (i * 7 % 9) as f32,
                way: if i % 2 == 0 {
                    Way::TwoWay(0.5 + 0.045 * (i % 11) as f32)
                } else {
                    Way::OneWay
                },
            }
        })
        .collect()
}

#[test]
fn one_link_keeps_its_arrow_in_the_middle() {
    let l = link(pos2(0.0, 0.0), pos2(300.0, 0.0), Way::TwoWay(0.5));
    assert_eq!(place(&[l]), vec![arrow(&l, 0.0)]);
}

#[test]
fn the_arrows_around_a_busy_host_do_not_overlap() {
    let links = hub(50, 40.0);
    let placed = place(&links);
    let arrows: Vec<&Arrow> = placed.iter().flatten().collect();
    assert!(
        arrows.len() >= 12,
        "only {} of 50 links got an arrow",
        arrows.len()
    );
    for (i, a) in arrows.iter().enumerate() {
        for b in &arrows[i + 1..] {
            assert!(
                dist(a.centre, b.centre) >= a.radius + b.radius - 1e-3,
                "two arrows sit on each other"
            );
        }
    }
}

#[test]
fn the_widest_links_keep_the_middle_of_their_link() {
    let links = hub(50, 40.0);
    let placed = place(&links);
    let widest = (0..links.len())
        .max_by(|&a, &b| links[a].width.total_cmp(&links[b].width).then(b.cmp(&a)))
        .expect("links");
    assert_eq!(
        placed[widest],
        arrow(&links[widest], 0.0),
        "the widest link is served first"
    );
}

#[test]
fn placing_is_deterministic() {
    let links = hub(40, 30.0);
    assert_eq!(place(&links), place(&links));
}

#[test]
fn a_two_way_arrow_leaves_room_between_its_heads_for_the_line_to_show() {
    let a = arrow(
        &link(pos2(0.0, 0.0), pos2(300.0, 0.0), Way::TwoWay(0.5)),
        0.0,
    )
    .expect("room");
    let back = a.back.expect("a second head");
    assert!(
        a.forward[1].x - back[1].x >= 8.0,
        "the bases are {} px apart",
        a.forward[1].x - back[1].x
    );
}

#[test]
fn the_head_of_the_busier_direction_is_larger() {
    let size = |t: [Pos2; 3]| dist(t[1], t[2]);
    let even = arrow(
        &link(pos2(0.0, 0.0), pos2(400.0, 0.0), Way::TwoWay(0.5)),
        0.0,
    )
    .expect("room");
    let back = even.back.expect("two heads");
    assert!(
        (size(even.forward) - size(back)).abs() < 1e-3,
        "an even exchange has equal heads"
    );
    let lopsided = arrow(
        &link(pos2(0.0, 0.0), pos2(400.0, 0.0), Way::TwoWay(0.95)),
        0.0,
    )
    .expect("room");
    let back = lopsided.back.expect("two heads");
    assert!(
        size(lopsided.forward) > 1.5 * size(back),
        "{} against {}",
        size(lopsided.forward),
        size(back)
    );
    assert!(size(lopsided.forward) <= MAX_BASE + 1e-3);
}
