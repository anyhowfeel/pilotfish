//! Planarity test and embedding by the left-right criterion (Brandes, "The Left-Right Planarity
//! Test", 2009), linear in the size of the graph. Every search is iterative, so the depth of the
//! graph is bounded by memory and not by the stack.

mod conflict;
mod embed;
mod orient;

use crate::embedding::Embedding;
use crate::graph::Graph;

/// A planar embedding of `g`, or `None` when `g` is not planar. Works on any simple graph:
/// disconnected, with isolated vertices, trees. The result satisfies
/// `Embedding::is_planar_embedding`.
pub fn embed(g: &Graph) -> Option<Embedding> {
    if too_dense(g) {
        return None;
    }
    let mut oriented = orient::orient(g);
    let constraints = conflict::check(&oriented)?;
    Some(embed::build(&mut oriented, constraints))
}

pub fn is_planar(g: &Graph) -> bool {
    embed(g).is_some()
}

/// A planar component with `n >= 3` vertices has at most `3n - 6` edges.
fn too_dense(g: &Graph) -> bool {
    g.components().iter().any(|c| {
        let edges: usize = c.iter().map(|&v| g.degree(v)).sum::<usize>() / 2;
        c.len() >= 3 && edges > 3 * c.len() - 6
    })
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
