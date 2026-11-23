//! Straight-line drawings of planar embeddings, and a polish that never adds a crossing.

use std::time::Instant;

mod augment;
mod canonical;
mod check;
mod field;
mod force;
mod grid;
mod place;
mod relax;
mod rot;
mod shift;
mod smooth;
#[cfg(test)]
mod test_support;

pub use place::straight_line;
pub use relax::relax;

#[derive(Debug, Clone)]
pub struct Relax {
    pub iterations: usize,
    /// Stop early when this moment has passed.
    pub deadline: Option<Instant>,
    /// Preferred edge length; the drawing is scaled around it.
    pub ideal_len: f64,
    /// Vertices that must not move.
    pub fixed: Vec<bool>,
}

impl Default for Relax {
    fn default() -> Self {
        Self {
            iterations: 200,
            deadline: None,
            ideal_len: 100.0,
            fixed: Vec::new(),
        }
    }
}
