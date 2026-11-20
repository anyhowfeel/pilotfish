//! Controller: owns the capture `Session`, feeds `Metrics`, delegates helper jobs to `BgJobs`.
use std::path::PathBuf;
use std::sync::Arc;

use wl_model::{
    CaptureBackend, CaptureError, CaptureEvent, CaptureSource, FrameDetail, PacketRow, Session,
    StatsSnapshot,
};

use crate::bg::BgJobs;
use crate::metrics::Metrics;
use crate::state::{RunState, StatusInfo, describe_source};
use crate::web_jobs::WebState;

/// Rows handed to the UI per `poll` call at most (keeps frames short while a big file streams in).
pub const MAX_ROWS_PER_POLL: usize = 30_000;

/// What happened during one `poll`, so the app knows what to repaint.
#[derive(Default, Debug)]
pub struct Polled {
    pub rows: Vec<PacketRow>,
    pub changed: bool,
}

pub struct Controller {
    backend: Arc<dyn CaptureBackend>,
    bg: BgJobs,
    web: WebState,
    metrics: Metrics,
    session: Option<Session>,
    backing_file: Option<PathBuf>,
    source: Option<CaptureSource>,
    display_filter: Option<String>,
    paused: bool,
    status: StatusInfo,
    notice: Option<String>,
    error: Option<CaptureError>,
}

impl Controller {
    pub fn new(backend: Arc<dyn CaptureBackend>) -> Self {
        Controller {
            bg: BgJobs::new(backend.clone()),
            web: WebState::new(backend.clone()),
            metrics: Metrics::new(),
            backend,
            session: None,
            backing_file: None,
            source: None,
            display_filter: None,
            paused: false,
            status: StatusInfo::default(),
            notice: None,
            error: None,
        }
    }

    pub fn status(&self) -> &StatusInfo {
        &self.status
    }
    pub fn snapshot(&self) -> &Arc<StatsSnapshot> {
        self.metrics.snapshot()
    }
    pub fn detail(&self) -> Option<&FrameDetail> {
        self.bg.detail()
    }
    pub fn error(&self) -> Option<&CaptureError> {
        self.error.as_ref()
    }
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }
    pub fn dismiss_messages(&mut self) {
        self.error = None;
        self.notice = None;
    }
    pub fn take_filter_result(&mut self) -> Option<(String, Result<(), CaptureError>)> {
        self.bg.take_filter_result()
    }
    /// The display filter currently applied to the capture, if any.
    pub fn display_filter(&self) -> Option<&str> {
        self.display_filter.as_deref().filter(|f| !f.is_empty())
    }

    pub fn set_stats_hz(&mut self, hz: u32) {
        self.metrics.set_hz(hz);
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self.source,
            Some(CaptureSource::Live { .. } | CaptureSource::Capture(_))
        )
    }
    pub fn is_paused(&self) -> bool {
        self.paused
    }
    pub fn source(&self) -> Option<&CaptureSource> {
        self.source.as_ref()
    }

    /// Starts (or restarts) a capture; clears stats. The caller must clear its packet list.
    pub fn start(&mut self, source: CaptureSource, filter: Option<String>) {
        self.stop();
        self.reset_counters();
        let filter = filter.filter(|f| !f.trim().is_empty());
        match self.backend.start(source.clone(), filter.clone()) {
            Ok(s) => {
                self.status.source = describe_source(&source);
                self.status.filter = filter.clone().unwrap_or_default();
                self.status.state = RunState::Running;
                self.backing_file = Some(s.backing_file.clone());
                self.session = Some(s);
                self.source = Some(source);
                self.display_filter = filter;
            }
            Err(e) => self.fail(e),
        }
    }

    /// Re-runs the current source with a new display filter. A live capture is stopped and its
    /// backing file re-read with the filter. Returns false when nothing could be restarted.
    pub fn apply_filter(&mut self, filter: Option<String>) -> bool {
        let Some(path) = self.backing() else {
            return false;
        };
        let name = self.status.source.clone();
        self.start(CaptureSource::File(path), filter);
        self.status.source = name;
        true
    }

    pub fn toggle_pause(&mut self) {
        if self.session.is_none() {
            return;
        }
        self.paused = !self.paused;
        self.status.state = if self.paused {
            RunState::Paused
        } else {
            RunState::Running
        };
    }

    pub fn stop(&mut self) {
        self.paused = false;
        self.web.on_stop(self.is_live() && self.session.is_some());
        if let Some(mut s) = self.session.take() {
            (s.stop)();
            if matches!(self.status.state, RunState::Running | RunState::Paused) {
                self.status.state = RunState::Finished;
            }
        }
    }

    fn reset_counters(&mut self) {
        self.metrics.reset();
        self.status = StatusInfo::default();
        self.bg.clear_detail();
        self.web.on_new_capture();
        self.backing_file = None;
        self.paused = false;
        self.error = None;
    }

    fn fail(&mut self, e: CaptureError) {
        self.paused = false;
        self.status.state = RunState::Failed;
        self.error = Some(e);
        self.session = None;
    }

    /// Drains capture events (bounded) and finished background jobs. Never blocks.
    pub fn poll(&mut self) -> Polled {
        let mut out = Polled::default();
        let (mut finished, mut failed) = (false, None);
        if !self.paused
            && let Some(s) = &self.session
        {
            while out.rows.len() < MAX_ROWS_PER_POLL {
                match s.events.try_recv() {
                    Ok(CaptureEvent::Rows(mut r)) => out.rows.append(&mut r),
                    Ok(CaptureEvent::Finished) => finished = true,
                    Ok(CaptureEvent::Failed(e)) => failed = Some(e),
                    Err(_) => break,
                }
                if finished || failed.is_some() {
                    break;
                }
            }
        }
        if !out.rows.is_empty() {
            self.metrics.ingest(&out.rows, &mut self.status);
            out.changed = true;
        }
        if finished {
            self.session = None;
            self.status.state = RunState::Finished;
            out.changed = true;
        }
        if let Some(e) = failed {
            self.fail(e);
            out.changed = true;
        }
        let is_live = self.is_live();
        out.changed |= self
            .metrics
            .tick(&mut self.status, is_live, self.session.is_none());
        self.poll_web_jobs();
        let (bg_changed, notice, err) = self.bg.drain();
        out.changed |= bg_changed;
        if let Some(n) = notice {
            self.notice = Some(n);
        }
        if let Some(e) = err {
            self.error = Some(e);
        }
        out
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop();
    }
}

#[path = "worker_web.rs"]
mod web_api;

#[path = "worker_jobs.rs"]
mod jobs;

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
