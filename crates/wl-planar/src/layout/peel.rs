//! Peeling the leaf hosts: what remains after removing vertices of degree one again and again is
//! the 2-core, the only part that has to be tested for planarity and drawn as a graph.

use std::collections::VecDeque;

use crate::graph::Graph;

#[derive(Debug, Clone)]
pub struct Peeled {
    /// Vertices of the 2-core.
    pub core: Vec<bool>,
    /// The neighbour a removed vertex hung from when it was removed; `None` for core vertices and
    /// for the root of a tree component (and for an isolated vertex).
    pub parent: Vec<Option<usize>>,
    /// Removed vertices, children before their parents.
    pub order: Vec<usize>,
    children: Vec<Vec<usize>>,
}

impl Peeled {
    pub fn children(&self, v: usize) -> &[usize] {
        &self.children[v]
    }

    /// Roots of the peeled trees that hang from nothing: one per tree component.
    pub fn roots(&self) -> impl Iterator<Item = usize> + '_ {
        self.order
            .iter()
            .copied()
            .filter(|&v| self.parent[v].is_none())
    }

    #[cfg(test)]
    pub fn core_len(&self) -> usize {
        self.core.iter().filter(|c| **c).count()
    }
}

/// First-in first-out removal peels layer by layer, so the last vertex of a tree is a centre.
pub fn peel(g: &Graph) -> Peeled {
    let n = g.vertex_count();
    let mut degree: Vec<usize> = (0..n).map(|v| g.degree(v)).collect();
    let mut queue: VecDeque<usize> = (0..n).filter(|&v| degree[v] <= 1).collect();
    let mut removed = vec![false; n];
    let mut parent = vec![None; n];
    let mut children = vec![Vec::new(); n];
    let mut order = Vec::new();
    while let Some(v) = queue.pop_front() {
        removed[v] = true;
        order.push(v);
        let up = g.neighbors(v).iter().copied().find(|&w| !removed[w]);
        parent[v] = up;
        if let Some(w) = up {
            children[w].push(v);
            degree[w] -= 1;
            if degree[w] == 1 {
                queue.push_back(w);
            }
        }
    }
    Peeled {
        core: removed.iter().map(|r| !r).collect(),
        parent,
        order,
        children,
    }
}

#[cfg(test)]
#[path = "peel_tests.rs"]
mod tests;
