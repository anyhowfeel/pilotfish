//! Stable incremental layout: planar (fewest crossings, solved off-thread) or force-directed
//! (fjadra, a d3-force port with Barnes-Hut many-body). Positions persist across graph updates.

use std::collections::HashMap;
use std::f32::consts::TAU;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fjadra::{Collide, Link, ManyBody, Node, PositionX, PositionY, Simulation, SimulationBuilder};
use wl_kit::egui::{Vec2, vec2};

use super::model::Graph;
use super::planar::{PlanarState, Readout};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Planar,
    Force,
}

/// Ticks per frame are bounded so a frame never spends more than the caller's budget.
const MAX_TICKS_PER_FRAME: usize = 8;
const ALPHA_REHEAT: f64 = 0.3;

#[derive(Default)]
pub struct Layout {
    pub pos: Vec<Vec2>,
    pub pinned: Vec<bool>,
    addrs: Vec<Arc<str>>,
    mode: Mode,
    sim: Option<Simulation>,
    stored: HashMap<Arc<str>, (Vec2, bool)>,
    targets: Vec<Vec2>,
    planar: PlanarState,
    moving: bool,
}

fn hash_angle(s: &str) -> f32 {
    let h = s.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    (h % 3600) as f32 / 3600.0 * TAU
}

impl Layout {
    #[cfg(test)]
    pub fn is_moving(&self) -> bool {
        self.moving
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn set_mode(&mut self, m: Mode, g: &Graph) {
        if m != self.mode {
            self.planar.reset();
        }
        self.mode = m;
        self.sync(g);
    }

    /// Call when the graph changed: re-seeds positions and restarts relaxation.
    pub fn sync(&mut self, g: &Graph) {
        self.remember();
        let mut placed: Vec<Option<Vec2>> = vec![None; g.nodes.len()];
        let mut fresh = false;
        for (i, n) in g.nodes.iter().enumerate() {
            placed[i] = Some(match self.stored.get(&n.addr) {
                Some(&(p, _)) => p,
                None => {
                    fresh = true;
                    spawn_near(g, i, &placed)
                }
            });
        }
        self.pos = placed.into_iter().flatten().collect();
        self.addrs = g.nodes.iter().map(|n| n.addr.clone()).collect();
        self.pinned = g
            .nodes
            .iter()
            .map(|n| self.stored.get(&n.addr).is_some_and(|s| s.1))
            .collect();
        match self.mode {
            Mode::Force => self.rebuild(g, if fresh { 1.0 } else { ALPHA_REHEAT }),
            Mode::Planar => {
                self.sim = None;
                if self.planar.request(g) {
                    self.targets = self.pos.clone();
                }
            }
        }
        self.moving = !g.nodes.is_empty();
    }

    /// Crossing count of the planar layout, once it is known.
    pub fn readout(&self) -> Option<Readout> {
        self.planar.readout().filter(|_| self.mode == Mode::Planar)
    }

    #[cfg(test)]
    pub fn use_solver(&mut self, solver: super::planner::Solver, min_gap: Duration) {
        self.planar = PlanarState::with_solver(solver, min_gap);
    }

    fn remember(&mut self) {
        for ((a, p), &pin) in self.addrs.iter().zip(&self.pos).zip(&self.pinned) {
            self.stored.insert(a.clone(), (*p, pin));
        }
    }

    fn rebuild(&mut self, g: &Graph, alpha: f64) {
        let nodes = self.pos.iter().zip(&self.pinned).map(|(p, &pin)| {
            let (x, y) = (f64::from(p.x), f64::from(p.y));
            if pin {
                Node::default().fixed_position(x, y)
            } else {
                Node::default().position(x, y)
            }
        });
        let radii: Vec<f64> = g.nodes.iter().map(|n| f64::from(n.radius)).collect();
        let dist: Vec<f64> = g
            .links
            .iter()
            .map(|l| 70.0 + 80.0 * f64::from(1.0 - l.t) + radii[l.a] + radii[l.b])
            .collect();
        let sim = SimulationBuilder::default()
            .with_alpha(alpha)
            .build(nodes)
            .add_force(
                "link",
                Link::new(g.links.iter().map(|l| (l.a, l.b)))
                    .distance(move |_: &_, i: usize| dist[i]),
            )
            .add_force("charge", ManyBody::new().strength(-240.0))
            .add_force(
                "collide",
                Collide::new()
                    .radius(move |i: usize| radii[i] + 12.0)
                    .iterations(2),
            )
            .add_force("x", PositionX::new().strength(0.04))
            .add_force("y", PositionY::new().strength(0.04));
        self.sim = Some(sim);
    }

    /// Moves node `i` to `p` and pins it; relaxation restarts around it.
    pub fn drag(&mut self, i: usize, p: Vec2, g: &Graph) {
        if i >= self.pos.len() {
            return;
        }
        self.pos[i] = p;
        self.pinned[i] = true;
        match self.mode {
            Mode::Force => {
                self.rebuild(g, ALPHA_REHEAT);
                self.moving = true;
            }
            Mode::Planar => self.planar.refresh(&self.pos, true),
        }
    }

    pub fn unpin(&mut self, i: usize, g: &Graph) {
        if let Some(p) = self.pinned.get_mut(i) {
            *p = false;
            if self.mode == Mode::Force {
                self.rebuild(g, ALPHA_REHEAT);
            }
            self.moving = true;
        }
    }

    /// Moves every free node a fraction of the way to its target; the largest distance left.
    fn glide(&mut self) -> f32 {
        let mut worst = 0.0_f32;
        for (i, p) in self.pos.iter_mut().enumerate() {
            if self.pinned[i] {
                continue;
            }
            let d = self.targets[i] - *p;
            worst = worst.max(d.length());
            *p += d * 0.22;
        }
        worst
    }

    /// Relaxes for at most `budget`; returns whether the layout is still moving.
    pub fn step(&mut self, budget: Duration) -> bool {
        if !self.moving {
            return false;
        }
        let start = Instant::now();
        match (self.mode, self.sim.as_mut()) {
            (Mode::Force, Some(sim)) => {
                for _ in 0..MAX_TICKS_PER_FRAME {
                    sim.tick(1);
                    if sim.is_finished() || start.elapsed() >= budget {
                        break;
                    }
                }
                for (p, q) in self.pos.iter_mut().zip(sim.positions()) {
                    *p = vec2(q[0] as f32, q[1] as f32);
                }
                self.moving = !sim.is_finished();
            }
            (Mode::Planar, _) => {
                if let Some(t) = self.planar.poll() {
                    self.targets = t;
                }
                self.moving = self.glide() > 0.4 || self.planar.busy();
                if !self.moving {
                    self.planar.refresh(&self.pos, self.pinned.contains(&true));
                }
            }
            _ => self.moving = false,
        }
        self.moving
    }
}

/// New nodes appear next to the neighbours already placed (deterministic offset), else on a spiral.
fn spawn_near(g: &Graph, i: usize, placed: &[Option<Vec2>]) -> Vec2 {
    let near: Vec<Vec2> = g.adj[i]
        .iter()
        .filter_map(|&l| placed[g.other(l as usize, i)])
        .collect();
    let a = hash_angle(&g.nodes[i].addr);
    if near.is_empty() {
        let r = 36.0 * ((i + 1) as f32).sqrt();
        return vec2(a.cos(), a.sin()) * r;
    }
    let mean = near.iter().fold(Vec2::ZERO, |s, p| s + *p) / near.len() as f32;
    mean + vec2(a.cos(), a.sin()) * 45.0
}
