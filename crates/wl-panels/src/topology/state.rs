//! View state shared by the topology modules: options, selection, reusable per-frame buffers.

use std::sync::Arc;

use wl_kit::egui::{Galley, Pos2, Rect};

use super::declutter::Candidate;
use super::layout::Mode;
use super::model::{Filters, Graph};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Options {
    pub filters: Filters,
    pub labels: bool,
    pub directions: bool,
    /// Highlight encrypted flows (TLS, QUIC, SSH, IPsec...) and dim the rest.
    pub encrypted: bool,
    pub mode: Mode,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            filters: Filters::default(),
            labels: true,
            directions: false,
            encrypted: false,
            mode: Mode::Force,
        }
    }
}

/// Selection by address so it survives graph rebuilds.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Selection {
    #[default]
    None,
    Node(Arc<str>),
    Pair(Arc<str>, Arc<str>),
}

/// Selection resolved against the current graph (indices), recomputed every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    None,
    Node(usize),
    Link(usize),
}

impl Selection {
    pub fn resolve(&self, g: &Graph) -> Resolved {
        match self {
            Selection::None => Resolved::None,
            Selection::Node(a) => g.find(a).map_or(Resolved::None, Resolved::Node),
            Selection::Pair(a, b) => g
                .links
                .iter()
                .position(|l| g.nodes[l.a].addr == *a && g.nodes[l.b].addr == *b)
                .map_or(Resolved::None, Resolved::Link),
        }
    }

    pub fn of_link(g: &Graph, link: usize) -> Selection {
        let l = &g.links[link];
        Selection::Pair(g.nodes[l.a].addr.clone(), g.nodes[l.b].addr.clone())
    }
}

impl Resolved {
    /// Whether `node` belongs to the selection (the node itself, a selected link's end, or a neighbour).
    pub fn touches_node(self, g: &Graph, node: usize) -> bool {
        match self {
            Resolved::None => true,
            Resolved::Node(n) => {
                n == node || g.adj[n].iter().any(|&l| g.other(l as usize, n) == node)
            }
            Resolved::Link(l) => g.links[l].a == node || g.links[l].b == node,
        }
    }

    pub fn touches_link(self, g: &Graph, link: usize) -> bool {
        match self {
            Resolved::None => true,
            Resolved::Node(n) => g.links[link].a == n || g.links[link].b == n,
            Resolved::Link(l) => l == link,
        }
    }
}

/// Buffers reused every frame (cleared, never reallocated once warm).
#[derive(Default)]
pub struct Buffers {
    pub screen: Vec<Pos2>,
    pub discs: Vec<(Pos2, f32)>,
    pub segs: Vec<(Pos2, Pos2, f32)>,
    pub cands: Vec<Candidate>,
    pub labels: Vec<(usize, Rect)>,
    pub matches: Vec<usize>,
    /// Elided label galleys per node (colour-less), cleared when the graph or DPI changes.
    pub galleys: Vec<Option<Arc<Galley>>>,
    /// Theme mode the galleys were laid out under: a theme switch rebuilds the font atlas, which
    /// leaves older galleys drawing garbage glyphs.
    pub galley_mode: Option<wl_kit::theme::Mode>,
    pub galley_ppp: f32,
}

#[cfg(test)]
mod tests {
    use super::super::model::test_data::star;
    use super::*;

    #[test]
    fn selection_survives_rebuild_and_dims_non_neighbours() {
        let g = Graph::build(&star(), &Filters::default(), &|_| None);
        let sel = Selection::Node("192.168.74.7".into());
        let Resolved::Node(n) = sel.resolve(&g) else {
            panic!("unresolved")
        };
        let gw = g.find("192.168.74.1").unwrap();
        let far = g.find("72.30.35.9").unwrap();
        assert!(Resolved::Node(n).touches_node(&g, gw));
        assert!(!Resolved::Node(n).touches_node(&g, far));
        assert_eq!(Selection::Node("gone".into()).resolve(&g), Resolved::None);
    }

    #[test]
    fn pair_selection_resolves_to_its_link() {
        let g = Graph::build(&star(), &Filters::default(), &|_| None);
        let sel = Selection::of_link(&g, 1);
        assert_eq!(sel.resolve(&g), Resolved::Link(1));
        assert!(Resolved::Link(1).touches_link(&g, 1));
        assert!(!Resolved::Link(1).touches_link(&g, 0));
    }
}
