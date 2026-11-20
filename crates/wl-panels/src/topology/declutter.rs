//! Label declutter: greedy placement in priority order; a label is dropped when it would
//! overlap an already placed label or another node's disc.

use wl_kit::egui::{Pos2, Rect, pos2, vec2};

/// Gap kept between two labels and between a label and a node (screen px).
pub const GAP: f32 = 3.0;

#[derive(Debug, Clone, Copy)]
pub struct Candidate {
    pub node: usize,
    pub center: Pos2,
    /// Node radius on screen.
    pub radius: f32,
    /// Label size on screen.
    pub w: f32,
    pub h: f32,
    /// Forced labels (selected / hovered / search hit) are always kept.
    pub forced: bool,
}

pub fn label_rect(c: &Candidate) -> Rect {
    Rect::from_min_size(
        pos2(c.center.x - c.w / 2.0, c.center.y + c.radius + GAP),
        vec2(c.w, c.h),
    )
}

/// Fills `out` with `(node, rect)` of the labels to draw. `cands` must be priority ordered
/// (forced ones first); `discs` are all visible node discs `(centre, radius)` by node index.
/// `out` is cleared and reused (no per-frame allocation once warm).
pub fn place(cands: &[Candidate], discs: &[(Pos2, f32)], max: usize, out: &mut Vec<(usize, Rect)>) {
    out.clear();
    for c in cands {
        if out.len() >= max && !c.forced {
            break;
        }
        let r = label_rect(c);
        let grown = r.expand(GAP);
        let clash = !c.forced
            && (out.iter().any(|(_, o)| o.intersects(grown))
                || discs
                    .iter()
                    .enumerate()
                    .any(|(i, (p, rad))| i != c.node && r.expand(1.0).distance_to_pos(*p) < *rad));
        if !clash {
            out.push((c.node, r));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(node: usize, x: f32, y: f32, forced: bool) -> Candidate {
        Candidate {
            node,
            center: pos2(x, y),
            radius: 8.0,
            w: 80.0,
            h: 16.0,
            forced,
        }
    }

    fn discs(c: &[Candidate]) -> Vec<(Pos2, f32)> {
        c.iter().map(|c| (c.center, c.radius)).collect()
    }

    #[test]
    fn overlapping_lower_priority_label_is_dropped() {
        let c = [cand(0, 100.0, 100.0, false), cand(1, 120.0, 100.0, false)];
        let mut out = Vec::new();
        place(&c, &discs(&c), 10, &mut out);
        assert_eq!(out.iter().map(|o| o.0).collect::<Vec<_>>(), [0]);
    }

    #[test]
    fn separated_labels_are_all_kept_without_overlap() {
        let c: Vec<_> = (0..4)
            .map(|i| cand(i, 100.0 + 120.0 * i as f32, 50.0, false))
            .collect();
        let mut out = Vec::new();
        place(&c, &discs(&c), 10, &mut out);
        assert_eq!(out.len(), 4);
        for (i, a) in out.iter().enumerate() {
            assert!(out.iter().skip(i + 1).all(|b| !a.1.intersects(b.1)));
        }
    }

    #[test]
    fn forced_labels_survive_and_cap_applies_to_the_rest() {
        let c = [
            cand(0, 100.0, 100.0, true),
            cand(1, 110.0, 100.0, true),
            cand(2, 400.0, 100.0, false),
            cand(3, 600.0, 100.0, false),
        ];
        let mut out = Vec::new();
        place(&c, &discs(&c), 3, &mut out);
        assert_eq!(out.len(), 3);
        place(&c, &discs(&c), 2, &mut out);
        assert_eq!(out.iter().map(|o| o.0).collect::<Vec<_>>(), [0, 1]);
    }

    #[test]
    fn label_does_not_cover_a_neighbouring_node() {
        let c = [cand(0, 100.0, 100.0, false), cand(1, 100.0, 118.0, false)];
        let mut out = Vec::new();
        place(&c, &discs(&c), 10, &mut out);
        assert_eq!(out.iter().map(|o| o.0).collect::<Vec<_>>(), [1]);
    }
}
