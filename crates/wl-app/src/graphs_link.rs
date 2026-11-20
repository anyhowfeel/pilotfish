//! Feeds the Graphs page: runs `CaptureBackend::io_series` on a helper thread, caches the result per
//! (file, interval, series spec) and refreshes live captures every few seconds while the page is
//! visible. The UI never waits: it draws whatever is cached and a pass fills in the rest.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use wl_model::{CaptureBackend, CaptureError, IoGraph, IoSeries, IoSpec};
use wl_panels::graphs::GraphsRequest;

/// Live captures are re-read this often while the Graphs page is visible.
pub const LIVE_REFRESH: Duration = Duration::from_secs(4);

type SeriesMap = HashMap<IoSpec, Arc<IoSeries>>;

struct Done {
    generation: u64,
    interval: f64,
    specs: Vec<IoSpec>,
    result: Result<IoGraph, CaptureError>,
    live: bool,
}

/// What the page should draw right now.
pub struct LinkView<'a> {
    pub interval: f64,
    pub duration: f64,
    pub loading: bool,
    pub series: &'a SeriesMap,
}

pub struct GraphsLink {
    backend: Arc<dyn CaptureBackend>,
    ctx: egui::Context,
    tx: Sender<Done>,
    rx: Receiver<Done>,
    file: Option<PathBuf>,
    cache: HashMap<u64, SeriesMap>,
    shown: Option<(u64, f64)>,
    duration: f64,
    generation: u64,
    in_flight: bool,
    refreshed: Option<Instant>,
    was_live: bool,
    empty: SeriesMap,
}

fn error_series(msg: &str) -> Arc<IoSeries> {
    Arc::new(IoSeries {
        error: Some(msg.to_owned()),
        ..IoSeries::default()
    })
}

impl GraphsLink {
    pub fn new(backend: Arc<dyn CaptureBackend>, ctx: egui::Context) -> Self {
        let (tx, rx) = unbounded();
        Self {
            backend,
            ctx,
            tx,
            rx,
            file: None,
            cache: HashMap::new(),
            shown: None,
            duration: 0.0,
            generation: 0,
            in_flight: false,
            refreshed: None,
            was_live: false,
            empty: HashMap::new(),
        }
    }

    /// Call every frame while the page is visible: stores finished results and starts a pass for
    /// whatever `req` needs that is not cached (everything again when a live capture is stale).
    pub fn tick(&mut self, file: Option<PathBuf>, req: &GraphsRequest, live: bool) {
        if file != self.file {
            self.cache.clear();
            self.shown = None;
            self.generation += 1;
            self.in_flight = false;
            self.refreshed = None;
            self.file = file;
        }
        self.drain();
        let Some(file) = self.file.clone() else {
            return;
        };
        let stale = (live && self.refreshed.is_none_or(|t| t.elapsed() >= LIVE_REFRESH))
            || (self.was_live && !live);
        self.was_live = live;
        if live {
            self.ctx.request_repaint_after(LIVE_REFRESH);
        }
        let missing = self.missing(req, stale);
        if self.in_flight || missing.is_empty() {
            return;
        }
        self.in_flight = true;
        let (backend, tx, ctx) = (self.backend.clone(), self.tx.clone(), self.ctx.clone());
        let (generation, interval) = (self.generation, req.interval);
        std::thread::spawn(move || {
            let result = backend.io_series(&file, &missing, interval);
            let _ = tx.send(Done {
                generation,
                interval,
                specs: missing,
                result,
                live,
            });
            ctx.request_repaint();
        });
    }

    fn missing(&self, req: &GraphsRequest, stale: bool) -> Vec<IoSpec> {
        let have = self.cache.get(&req.interval.to_bits());
        req.specs
            .iter()
            .filter(|s| stale || have.is_none_or(|m| !m.contains_key(*s)))
            .cloned()
            .collect()
    }

    fn drain(&mut self) {
        while let Ok(d) = self.rx.try_recv() {
            if d.generation != self.generation {
                continue;
            }
            self.in_flight = false;
            self.refreshed = Some(Instant::now());
            let bits = d.interval.to_bits();
            let map = self.cache.entry(bits).or_default();
            match d.result {
                Ok(g) if g.series.len() == d.specs.len() => {
                    self.duration = g.duration;
                    for (spec, s) in d.specs.into_iter().zip(g.series) {
                        map.insert(spec, Arc::new(s));
                    }
                }
                // A live file is read while it is being written: errors are expected, retry later.
                Err(_) if d.live => continue,
                other => {
                    let msg = other.err().map_or_else(
                        || "the backend returned no data".to_owned(),
                        |e| e.to_string(),
                    );
                    for spec in d.specs {
                        map.insert(spec, error_series(&msg));
                    }
                }
            }
            self.shown = Some((bits, d.interval));
        }
    }

    /// The requested interval's cache when it has data, else the last one shown (no flash while
    /// a new interval is computed).
    pub fn view(&self, req: &GraphsRequest) -> LinkView<'_> {
        let want = req.interval.to_bits();
        let (map, interval) = match self.cache.get(&want).filter(|m| !m.is_empty()) {
            Some(m) => (m, req.interval),
            None => match self.shown.and_then(|(b, i)| Some((self.cache.get(&b)?, i))) {
                Some(found) => found,
                None => (&self.empty, req.interval),
            },
        };
        LinkView {
            interval,
            duration: self.duration,
            loading: self.in_flight || !self.missing(req, false).is_empty(),
            series: map,
        }
    }
}

#[cfg(test)]
#[path = "graphs_link_tests.rs"]
mod tests;
