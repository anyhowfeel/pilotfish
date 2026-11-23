//! A combinatorial embedding: the cyclic order of the neighbours around every vertex.

use std::collections::HashMap;

use crate::graph::Graph;

/// `rotation(v)` lists the neighbours of `v` in cyclic order around it. The mirror image of an
/// embedding is the same embedding, so no orientation is promised.
///
/// Faces are traced half-edge by half-edge: arriving at `v` from `u`, leave towards the neighbour
/// that follows `u` in `rotation(v)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Embedding {
    rotation: Vec<Vec<usize>>,
}

impl Embedding {
    pub fn new(rotation: Vec<Vec<usize>>) -> Self {
        Self { rotation }
    }

    pub fn vertex_count(&self) -> usize {
        self.rotation.len()
    }

    pub fn rotation(&self, v: usize) -> &[usize] {
        &self.rotation[v]
    }

    /// Every face as the cycle of vertices along its boundary (a vertex repeats when a cut vertex
    /// or a bridge touches the face twice). Isolated vertices have no face here.
    pub fn faces(&self) -> Vec<Vec<usize>> {
        let at: Vec<HashMap<usize, usize>> = self
            .rotation
            .iter()
            .map(|r| r.iter().enumerate().map(|(i, &w)| (w, i)).collect())
            .collect();
        let mut seen: HashMap<(usize, usize), bool> = HashMap::new();
        let mut faces = Vec::new();
        for (u, r) in self.rotation.iter().enumerate() {
            for &v in r {
                if seen.contains_key(&(u, v)) {
                    continue;
                }
                let (mut face, mut half) = (Vec::new(), (u, v));
                while seen.insert(half, true).is_none() {
                    face.push(half.0);
                    let (from, to) = half;
                    let Some(&i) = at[to].get(&from) else { break };
                    let ring = &self.rotation[to];
                    half = (to, ring[(i + 1) % ring.len()]);
                }
                faces.push(face);
            }
        }
        faces
    }

    /// Whether this is a planar embedding of `g`: every rotation is exactly the neighbour set of
    /// its vertex, and Euler's formula `V - E + F = 2` holds in every connected component.
    pub fn is_planar_embedding(&self, g: &Graph) -> bool {
        if self.rotation.len() != g.vertex_count() {
            return false;
        }
        for (v, rotation) in self.rotation.iter().enumerate() {
            let mut have = rotation.clone();
            have.sort_unstable();
            if have != g.neighbors(v) {
                return false;
            }
        }
        let comps = g.components();
        let mut comp_of = vec![0; g.vertex_count()];
        for (c, vs) in comps.iter().enumerate() {
            vs.iter().for_each(|&v| comp_of[v] = c);
        }
        let mut faces = vec![0usize; comps.len()];
        for f in self.faces() {
            faces[comp_of[f[0]]] += 1;
        }
        comps.iter().enumerate().all(|(c, vs)| {
            let edges: usize = vs.iter().map(|&v| g.degree(v)).sum::<usize>() / 2;
            let f = if edges == 0 { 1 } else { faces[c] };
            vs.len() + f == edges + 2
        })
    }
}

#[cfg(test)]
#[path = "embedding_tests.rs"]
mod tests;
