//! The requests `wl-native` can answer, as plain methods. `wl-hybrid` calls them.
//! Each method is a one-line delegation; the work lives in the module named in the call.

use std::path::Path;

use wl_model::{CaptureError, CaptureProperties, ClockZone, FrameDetail, IoGraph, IoSpec, Session};

use crate::{decode, filter, hash, io_series, properties, session};

#[derive(Debug, Default, Clone, Copy)]
pub struct NativeBackend;

impl NativeBackend {
    pub fn new() -> Self {
        Self
    }

    /// Streams the rows of a capture file; with a filter only the matching ones.
    pub fn start_file(&self, path: &Path, filter: Option<&str>) -> Result<Session, CaptureError> {
        session::start_file(path, filter)
    }

    /// Whether `filter` can be evaluated here. An empty filter can.
    pub fn supports_filter(&self, filter: &str) -> bool {
        filter.trim().is_empty() || filter::parse(filter).is_some()
    }

    pub fn capture_properties(
        &self,
        path: &Path,
        zone: ClockZone,
    ) -> Result<CaptureProperties, CaptureError> {
        properties::read(path, zone)
    }

    /// `None` when a spec uses a filter this backend cannot evaluate.
    pub fn io_series(
        &self,
        path: &Path,
        specs: &[IoSpec],
        interval: f64,
    ) -> Option<Result<IoGraph, CaptureError>> {
        io_series::compute(path, specs, interval)
    }

    pub fn file_sha256(&self, path: &Path) -> Result<String, CaptureError> {
        hash::sha256_hex(path)
    }

    /// Layer summary and raw bytes of one frame, without dissectors.
    pub fn frame_detail(&self, path: &Path, frame_no: u64) -> Result<FrameDetail, CaptureError> {
        decode::detail::basic(path, frame_no)
    }
}
