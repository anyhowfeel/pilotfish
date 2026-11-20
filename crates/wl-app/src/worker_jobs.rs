//! Controller helpers that hand work to the background jobs (child of `worker`: sees its fields).
use std::path::PathBuf;

use wl_model::CaptureSource;

use super::Controller;

impl Controller {
    pub fn is_busy(&self) -> bool {
        (self.session.is_some() && !self.paused)
            || self.metrics.is_dirty()
            || self.web.jobs.is_busy()
    }

    pub fn backing(&self) -> Option<PathBuf> {
        self.backing_file.clone().or_else(|| match &self.source {
            Some(CaptureSource::File(p)) => Some(p.clone()),
            _ => None,
        })
    }

    pub fn request_detail(&mut self, frame_no: u64) {
        if let Some(file) = self.backing() {
            self.bg.request_detail(file, frame_no);
        }
    }

    pub fn validate_filter(&self, filter: String) {
        self.bg.validate_filter(filter);
    }

    pub fn export(&self, frames: Option<Vec<u64>>, dest: PathBuf) {
        if let Some(file) = self.backing() {
            self.bg.export(file, frames, dest);
        }
    }
}
