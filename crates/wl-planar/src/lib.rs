//! Crossing-free layouts for host graphs, and the fewest crossings when that is not possible.
//!
//! Pure graph and geometry code: no UI, no I/O, no dependencies. A graph is planar when it can be
//! drawn without crossings; a host graph often is not, so the layout keeps the largest planar part
//! crossing-free and reports how many crossings are left.
//!
//! Pipeline, one connected component at a time: peel the leaf hosts, test the rest for planarity
//! and embed it (`lr`), draw the embedding with straight lines (`draw`), polish the drawing without
//! ever creating a crossing, put the leaves back in free angles, then pack the components.

mod crossing;
pub mod draw;
mod embedding;
mod geometry;
mod graph;
pub mod layout;
pub mod lr;
pub mod planarize;
#[cfg(test)]
mod testing;

pub use crossing::{count_crossings, crossing_pairs};
pub use embedding::Embedding;
pub use geometry::{Point, edges_cross};
pub use graph::Graph;
