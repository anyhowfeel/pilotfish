//! One planar-layout run at a time on a worker thread, with stale answers dropped.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};

use wl_planar::Graph as Planar;
use wl_planar::layout::{Layout as Solved, Options};

pub type Solver = fn(&Planar, &Options) -> Solved;

pub struct Job {
    pub graph: Planar,
    pub opts: Options,
}

struct Reply {
    generation: u64,
    solved: Solved,
}

/// One solver run at a time. Every request bumps the generation, so an answer for a graph that
/// has since changed is dropped when it arrives.
pub struct Planner {
    solver: Solver,
    min_gap: Duration,
    generation: u64,
    flying: Option<JoinHandle<()>>,
    queued: Option<Job>,
    started: Option<Instant>,
    tx: Sender<Reply>,
    rx: Receiver<Reply>,
}

impl Planner {
    pub fn new(solver: Solver, min_gap: Duration) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            solver,
            min_gap,
            generation: 0,
            flying: None,
            queued: None,
            started: None,
            tx,
            rx,
        }
    }

    /// `at_once` skips the wait since the last run.
    pub fn submit(&mut self, job: Job, at_once: bool) {
        self.generation += 1;
        self.queued = Some(job);
        if at_once {
            self.started = None;
        }
        self.start_queued();
    }

    pub fn cancel(&mut self) {
        self.generation += 1;
        self.queued = None;
    }

    pub fn busy(&self) -> bool {
        self.flying.is_some() || self.queued.is_some()
    }

    /// The answer to the latest request, once it has arrived.
    pub fn poll(&mut self) -> Option<Solved> {
        let mut fresh = None;
        while let Ok(r) = self.rx.try_recv() {
            if r.generation == self.generation {
                fresh = Some(r.solved);
            }
        }
        if self.flying.as_ref().is_some_and(JoinHandle::is_finished) {
            self.flying = None;
        }
        self.start_queued();
        fresh
    }

    fn start_queued(&mut self) {
        let ready = self.started.is_none_or(|s| s.elapsed() >= self.min_gap);
        if self.flying.is_some() || !ready {
            return;
        }
        let Some(job) = self.queued.take() else {
            return;
        };
        let (solver, tx, generation) = (self.solver, self.tx.clone(), self.generation);
        self.started = Some(Instant::now());
        self.flying = Builder::new()
            .name("planar-layout".into())
            .spawn(move || {
                let solved = solver(&job.graph, &job.opts);
                let _ = tx.send(Reply { generation, solved });
            })
            .ok();
    }
}
