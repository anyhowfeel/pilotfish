//! Radial layout targets: the focus host in the centre, its peers on a first ring
//! (heaviest link first), everything else on an outer ring.

use std::f32::consts::{FRAC_PI_2, TAU};

use wl_kit::egui::{Vec2, vec2};

use super::model::Graph;

const RING_GAP: f32 = 120.0;
/// Minimum arc length between two neighbours on a ring (keeps discs and labels apart).
const MIN_ARC: f32 = 46.0;

fn ring(out: &mut [Vec2], members: &[usize], radius: f32, phase: f32) {
    let n = members.len().max(1) as f32;
    for (k, &i) in members.iter().enumerate() {
        let a = phase - FRAC_PI_2 + TAU * k as f32 / n;
        out[i] = vec2(a.cos(), a.sin()) * radius;
    }
}

/// Target position per node. `focus` defaults to the heaviest hub (or heaviest node).
pub fn radial_targets(g: &Graph, focus: Option<usize>) -> Vec<Vec2> {
    let mut out = vec![Vec2::ZERO; g.nodes.len()];
    let Some(c) = focus
        .filter(|&f| f < g.nodes.len())
        .or_else(|| g.nodes.iter().position(|n| n.hub))
        .or(if g.nodes.is_empty() { None } else { Some(0) })
    else {
        return out;
    };
    let first: Vec<usize> = g
        .peers(c)
        .into_iter()
        .map(|p| p.0)
        .filter(|&p| p != c)
        .collect();
    let mut seen = vec![false; g.nodes.len()];
    seen[c] = true;
    first.iter().for_each(|&i| seen[i] = true);
    let rest: Vec<usize> = (0..g.nodes.len()).filter(|&i| !seen[i]).collect();
    let r1 = (first.len() as f32 * MIN_ARC / TAU).max(RING_GAP);
    ring(&mut out, &first, r1, 0.0);
    let r2 = (r1 + RING_GAP).max(rest.len() as f32 * MIN_ARC / TAU);
    ring(&mut out, &rest, r2, TAU / (2.0 * rest.len().max(1) as f32));
    out
}

#[cfg(test)]
mod tests {
    use super::super::model::{Filters, test_data::star};
    use super::*;

    #[test]
    fn focus_in_centre_peers_inside_outer_ring() {
        let g = Graph::build(&star(), &Filters::default(), &|_| None);
        let gw = g.find("192.168.74.1").unwrap();
        let t = radial_targets(&g, Some(gw));
        assert_eq!(t[gw], Vec2::ZERO);
        let peers: Vec<usize> = g.peers(gw).iter().map(|p| p.0).collect();
        let outer = (0..g.nodes.len()).find(|i| *i != gw && !peers.contains(i));
        for p in &peers {
            assert!(t[*p].length() >= RING_GAP - 0.01);
            if let Some(o) = outer {
                assert!(t[o].length() > t[*p].length());
            }
        }
    }

    #[test]
    fn default_focus_is_the_hub_and_empty_graph_is_safe() {
        let g = Graph::build(&star(), &Filters::default(), &|_| None);
        let hub = g.nodes.iter().position(|n| n.hub).unwrap();
        assert_eq!(radial_targets(&g, None)[hub], Vec2::ZERO);
        assert!(radial_targets(&Graph::default(), None).is_empty());
    }
}
