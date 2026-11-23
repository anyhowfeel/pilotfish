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
    /// Several links picked with Shift+click (two or more, each as its pair of addresses).
    Links(Vec<(Arc<str>, Arc<str>)>),
}

/// Selection resolved against the current graph (indices), recomputed every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    None,
    Node(usize),
    Link(usize),
    /// Several links; their indices are in the list filled by `Selection::resolve`.
    Many,
}

impl Selection {
    /// Resolves the selection; `multi` receives the indices of the selected links (empty unless
    /// several links are picked, or one link is).
    pub fn resolve(&self, g: &Graph, multi: &mut Vec<usize>) -> Resolved {
        multi.clear();
        let find = |a: &Arc<str>, b: &Arc<str>| {
            g.links
                .iter()
                .position(|l| g.nodes[l.a].addr == *a && g.nodes[l.b].addr == *b)
        };
        match self {
            Selection::None => Resolved::None,
            Selection::Node(a) => g.find(a).map_or(Resolved::None, Resolved::Node),
            Selection::Pair(a, b) => find(a, b).map_or(Resolved::None, |i| {
                multi.push(i);
                Resolved::Link(i)
            }),
            Selection::Links(pairs) => {
                multi.extend(pairs.iter().filter_map(|(a, b)| find(a, b)));
                match multi.as_slice() {
                    [] => Resolved::None,
                    [one] => Resolved::Link(*one),
                    _ => Resolved::Many,
                }
            }
        }
    }

    /// The selection after a Shift+click on `link`: the link joins the picked ones, or leaves them when
    /// it was already picked. A host that was selected is replaced.
    pub fn toggled_link(&self, g: &Graph, link: usize) -> Selection {
        let mut pairs: Vec<(Arc<str>, Arc<str>)> = match self {
            Selection::Pair(a, b) => vec![(a.clone(), b.clone())],
            Selection::Links(v) => v.clone(),
            Selection::None | Selection::Node(_) => Vec::new(),
        };
        let l = &g.links[link];
        let pair = (g.nodes[l.a].addr.clone(), g.nodes[l.b].addr.clone());
        match pairs.iter().position(|p| *p == pair) {
            Some(at) => {
                pairs.remove(at);
            }
            None => pairs.push(pair),
        }
        match pairs.len() {
            0 => Selection::None,
            1 => {
                let (a, b) = pairs.remove(0);
                Selection::Pair(a, b)
            }
            _ => Selection::Links(pairs),
        }
    }

    pub fn of_link(g: &Graph, link: usize) -> Selection {
        let l = &g.links[link];
        Selection::Pair(g.nodes[l.a].addr.clone(), g.nodes[l.b].addr.clone())
    }
}

impl Resolved {
    /// Whether `node` belongs to the selection (the node itself, a selected link's end, or a neighbour).
    pub fn touches_node(self, g: &Graph, multi: &[usize], node: usize) -> bool {
        match self {
            Resolved::None => true,
            Resolved::Many => multi
                .iter()
                .any(|&l| g.links[l].a == node || g.links[l].b == node),
            Resolved::Node(n) => {
                n == node || g.adj[n].iter().any(|&l| g.other(l as usize, n) == node)
            }
            Resolved::Link(l) => g.links[l].a == node || g.links[l].b == node,
        }
    }

    pub fn touches_link(self, g: &Graph, multi: &[usize], link: usize) -> bool {
        match self {
            Resolved::None => true,
            Resolved::Many => multi.contains(&link),
            Resolved::Node(n) => g.links[link].a == n || g.links[link].b == n,
            Resolved::Link(l) => l == link,
        }
    }
}

/// Buffers reused every frame (cleared, never reallocated once warm).
#[derive(Default)]
pub struct Buffers {
    /// Links of the selection when several are picked (filled every frame).
    pub multi: Vec<usize>,
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

    fn none() -> Vec<usize> {
        Vec::new()
    }

    #[test]
    fn selection_survives_rebuild_and_dims_non_neighbours() {
        let g = Graph::build(&star(), &Filters::default(), &|_| None);
        let sel = Selection::Node("192.168.74.7".into());
        let Resolved::Node(n) = sel.resolve(&g, &mut none()) else {
            panic!("unresolved")
        };
        let gw = g.find("192.168.74.1").unwrap();
        let far = g.find("72.30.35.9").unwrap();
        assert!(Resolved::Node(n).touches_node(&g, &[], gw));
        assert!(!Resolved::Node(n).touches_node(&g, &[], far));
        assert_eq!(
            Selection::Node("gone".into()).resolve(&g, &mut none()),
            Resolved::None
        );
    }

    #[test]
    fn pair_selection_resolves_to_its_link() {
        let g = Graph::build(&star(), &Filters::default(), &|_| None);
        let sel = Selection::of_link(&g, 1);
        assert_eq!(sel.resolve(&g, &mut none()), Resolved::Link(1));
        assert!(Resolved::Link(1).touches_link(&g, &[], 1));
        assert!(!Resolved::Link(1).touches_link(&g, &[], 0));
    }

    #[test]
    fn shift_click_builds_a_selection_of_several_links_and_takes_a_link_out_again() {
        let g = Graph::build(&star(), &Filters::default(), &|_| None);
        assert!(g.links.len() >= 3, "the fixture has enough links");
        let one = Selection::of_link(&g, 0);
        let two = one.toggled_link(&g, 1);
        assert!(matches!(&two, Selection::Links(v) if v.len() == 2));
        let three = two.toggled_link(&g, 2);
        assert!(matches!(&three, Selection::Links(v) if v.len() == 3));
        // Picking a link that is already picked takes it out.
        assert_eq!(three.toggled_link(&g, 2), two);
        // Down to one link, the selection is a plain pair again, then nothing.
        assert_eq!(two.toggled_link(&g, 1), one);
        assert_eq!(one.toggled_link(&g, 0), Selection::None);
        // A selected host is replaced by the first link picked.
        let host = Selection::Node("192.168.74.7".into());
        assert_eq!(host.toggled_link(&g, 1), Selection::of_link(&g, 1));
    }

    #[test]
    fn several_links_resolve_to_their_indices_and_light_their_hosts() {
        let g = Graph::build(&star(), &Filters::default(), &|_| None);
        let sel = Selection::of_link(&g, 0).toggled_link(&g, 2);
        let mut multi = none();
        let r = sel.resolve(&g, &mut multi);
        assert_eq!(r, Resolved::Many);
        assert_eq!(multi, vec![0, 2]);
        for link in 0..g.links.len() {
            assert_eq!(r.touches_link(&g, &multi, link), multi.contains(&link));
        }
        let (l0, l2) = (&g.links[0], &g.links[2]);
        for n in [l0.a, l0.b, l2.a, l2.b] {
            assert!(r.touches_node(&g, &multi, n));
        }
        // A link that left the graph (a filter changed) just drops out of the selection.
        let gone = Selection::Links(vec![
            ("1.1.1.1".into(), "2.2.2.2".into()),
            ("3.3.3.3".into(), "4.4.4.4".into()),
        ]);
        assert_eq!(gone.resolve(&g, &mut multi), Resolved::None);
    }
}
