use std::path::Path;

use wl_model::{CaptureError, CaptureProperties, ClockZone, FrameDetail, IoGraph, IoSpec, Session};
use wl_native::NativeBackend;

/// What the router asks of the native side; the seam between the two backends.
pub trait FastPath: Send + Sync {
    fn supports_filter(&self, filter: &str) -> bool;
    fn start_file(&self, path: &Path, filter: Option<&str>) -> Result<Session, CaptureError>;
    fn capture_properties(
        &self,
        path: &Path,
        zone: ClockZone,
    ) -> Result<CaptureProperties, CaptureError>;
    fn file_sha256(&self, path: &Path) -> Result<String, CaptureError>;
    /// `None` when a spec uses a filter the native side cannot evaluate.
    fn io_series(
        &self,
        path: &Path,
        specs: &[IoSpec],
        interval: f64,
    ) -> Option<Result<IoGraph, CaptureError>>;
    fn frame_detail(&self, path: &Path, frame_no: u64) -> Result<FrameDetail, CaptureError>;
}

impl FastPath for NativeBackend {
    fn supports_filter(&self, filter: &str) -> bool {
        NativeBackend::supports_filter(self, filter)
    }

    fn start_file(&self, path: &Path, filter: Option<&str>) -> Result<Session, CaptureError> {
        NativeBackend::start_file(self, path, filter)
    }

    fn capture_properties(
        &self,
        path: &Path,
        zone: ClockZone,
    ) -> Result<CaptureProperties, CaptureError> {
        NativeBackend::capture_properties(self, path, zone)
    }

    fn file_sha256(&self, path: &Path) -> Result<String, CaptureError> {
        NativeBackend::file_sha256(self, path)
    }

    fn io_series(
        &self,
        path: &Path,
        specs: &[IoSpec],
        interval: f64,
    ) -> Option<Result<IoGraph, CaptureError>> {
        NativeBackend::io_series(self, path, specs, interval)
    }

    fn frame_detail(&self, path: &Path, frame_no: u64) -> Result<FrameDetail, CaptureError> {
        NativeBackend::frame_detail(self, path, frame_no)
    }
}
