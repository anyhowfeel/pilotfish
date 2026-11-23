//! The planar layout mode: crossing-free where possible, fewest crossings otherwise. The solver
//! takes up to a quarter of a second, so it runs on a worker thread and its answer becomes the
//! positions the nodes glide to.

use std::sync::Arc;
use std::time::Duration;

use wl_kit::egui::{Vec2, vec2};
use wl_planar::layout::Options;
use wl_planar::{Graph as Planar, Point, count_crossings};

use super::model::Graph;
use super::planner::{Job, Planner, Solver};

/// Distance between linked hosts, about what the force layout settles at.
const EDGE_LEN: f64 = 120.0;
/// Room kept around each disc beyond its radius, for the glow and the label anchor.
const PAD: f32 = 6.0;
/// A busy capture changes the graph all the time; the solver starts at most this often.
const MIN_GAP: Duration = Duration::from_secs(1);

/// What the layout is built from: who is there and who talks to whom, not how much.
#[derive(PartialEq)]
struct Shape {
    addrs: Vec<Arc<str>>,
    links: Vec<(usize, usize)>,
}

impl Shape {
    fn of(g: &Graph) -> Self {
        Self {
            addrs: g.nodes.iter().map(|n| n.addr.clone()).collect(),
            links: g.links.iter().map(|l| (l.a, l.b)).collect(),
        }
    }
}

/// The count shown next to the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Readout {
    pub crossings: usize,
    pub planar: bool,
}

impl Readout {
    pub fn text(&self) -> String {
        match self.crossings {
            0 => "No crossings".to_owned(),
            1 => "1 crossing".to_owned(),
            n => format!("{n} crossings"),
        }
    }

    pub fn tooltip(&self) -> &'static str {
        match (self.planar, self.crossings) {
            (true, 0) => "The graph is planar: no link crosses another.",
            (false, 1..) => {
                "This graph cannot be drawn without crossings; this layout keeps them to a minimum."
            }
            _ => "Counted with the hosts where they are now.",
        }
    }
}

pub struct PlanarState {
    planner: Planner,
    shape: Option<Shape>,
    solved: Option<Readout>,
    readout: Option<Readout>,
}

impl Default for PlanarState {
    fn default() -> Self {
        Self::with_solver(wl_planar::layout::layout, MIN_GAP)
    }
}

impl PlanarState {
    pub fn with_solver(solver: Solver, min_gap: Duration) -> Self {
        Self {
            planner: Planner::new(solver, min_gap),
            shape: None,
            solved: None,
            readout: None,
        }
    }

    pub fn readout(&self) -> Option<Readout> {
        self.readout
    }

    pub fn busy(&self) -> bool {
        self.planner.busy()
    }

    /// Asks for a layout of `g` unless the one asked for last has the same hosts and links.
    /// Returns whether a new one was asked for.
    pub fn request(&mut self, g: &Graph) -> bool {
        let shape = Shape::of(g);
        if self.shape.as_ref() == Some(&shape) {
            return false;
        }
        let at_once = self.shape.is_none();
        self.shape = Some(shape);
        self.planner.submit(job(g), at_once);
        true
    }

    /// Forgets everything, for when another mode takes over.
    pub fn reset(&mut self) {
        self.planner.cancel();
        self.shape = None;
        self.solved = None;
        self.readout = None;
    }

    /// Target positions of a finished layout, when one has arrived.
    pub fn poll(&mut self) -> Option<Vec<Vec2>> {
        let solved = self.planner.poll()?;
        let shown = Readout {
            crossings: solved.crossings,
            planar: solved.planar,
        };
        (self.solved, self.readout) = (Some(shown), Some(shown));
        Some(
            solved
                .pos
                .iter()
                .map(|p| vec2(p.x as f32, p.y as f32))
                .collect(),
        )
    }

    /// Shows the crossings of the hosts where they are now when the user moved some by hand,
    /// the solver's count otherwise.
    pub fn refresh(&mut self, pos: &[Vec2], edited: bool) {
        let (Some(shape), Some(solved), Some(shown)) =
            (&self.shape, self.solved, &mut self.readout)
        else {
            return;
        };
        *shown = solved;
        if edited {
            let g = Planar::new(pos.len(), &shape.links);
            let points: Vec<Point> = pos
                .iter()
                .map(|p| Point::new(f64::from(p.x), f64::from(p.y)))
                .collect();
            shown.crossings = count_crossings(&g, &points);
        }
    }
}

fn job(g: &Graph) -> Job {
    let links: Vec<_> = g.links.iter().map(|l| (l.a, l.b)).collect();
    let opts = Options {
        weight: g.links.iter().map(|l| f64::from(l.t) + 0.05).collect(),
        radius: g.nodes.iter().map(|n| f64::from(n.radius + PAD)).collect(),
        edge_len: EDGE_LEN,
        ..Options::default()
    };
    Job {
        graph: Planar::new(g.nodes.len(), &links),
        opts,
    }
}
