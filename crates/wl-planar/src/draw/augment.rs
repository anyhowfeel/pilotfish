//! Completes the rotation of a connected component to a triangulation by adding dummy vertices.
//!
//! The shift method needs a simple triangulation. A face that touches a vertex twice (a cut
//! vertex, a leaf) is first cut into simple faces, then every simple face longer than a triangle
//! gets a vertex joined to all its corners. Dummy vertices are numbered after the real ones, and
//! every edge added has a dummy end, so the graph stays simple.

use std::collections::HashSet;

use super::rot::Rot;

/// Returns a triangle `[a, b, c]` of the result to use as the outer face. It is the one at the
/// longest face, so the drawing keeps that face outside, and `c` is that face's new vertex.
pub fn triangulate(rot: &mut Rot) -> [usize; 3] {
    for walk in rot.faces() {
        split_repeats(rot, walk);
    }
    let faces = rot.faces();
    let longest = faces.iter().map(Vec::len).max().unwrap_or(0);
    let mut outer = [faces[0][0], faces[0][1], faces[0][2]];
    let mut chosen = false;
    for walk in &faces {
        if walk.len() > 3 {
            let reversed: Vec<usize> = walk.iter().rev().copied().collect();
            let star = rot.add_vertex(&reversed);
            for i in 0..walk.len() {
                rot.insert_after(walk[i], walk[(i + walk.len() - 1) % walk.len()], star);
            }
            if walk.len() == longest && !chosen {
                (outer, chosen) = ([walk[0], walk[1], star], true);
            }
        }
    }
    outer
}

/// Replaces every repeated corner `v` of the face by a new vertex joined to the corners on both
/// sides of it. `v` then closes a 4-cycle off the face. A repeated vertex has two neighbours or
/// more, so those two corners differ.
///
/// The walk is edited as the face changes, so later corners see the dummy vertices. Corner 0 is
/// never replaced, and the other faces are untouched: a corner is identified by the half-edge
/// that enters it.
fn split_repeats(rot: &mut Rot, mut walk: Vec<usize>) {
    let k = walk.len();
    let mut seen: HashSet<usize> = HashSet::from([walk[0]]);
    for i in 1..k {
        let v = walk[i];
        if seen.insert(v) {
            continue;
        }
        let (a, b, p) = (walk[i - 1], walk[(i + 1) % k], walk[(i + k - 2) % k]);
        let d = rot.add_vertex(&[a, b]);
        rot.insert_after(a, p, d);
        rot.insert_after(b, v, d);
        walk[i] = d;
    }
}

#[cfg(test)]
#[path = "augment_tests.rs"]
mod tests;
