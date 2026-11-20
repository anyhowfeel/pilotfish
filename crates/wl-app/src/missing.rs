//! Stand-in backend used when tshark cannot be found: every call reports the original error.
use std::path::Path;

use wl_model::{CaptureBackend, CaptureError, CaptureSource, FrameDetail, Interface, Session};

pub struct Missing(pub CaptureError);

impl CaptureBackend for Missing {
    fn interfaces(&self) -> Result<Vec<Interface>, CaptureError> {
        Err(self.0.clone())
    }

    fn start(&self, _: CaptureSource, _: Option<String>) -> Result<Session, CaptureError> {
        Err(self.0.clone())
    }

    fn frame_detail(&self, _: &Path, _: u64) -> Result<FrameDetail, CaptureError> {
        Err(self.0.clone())
    }

    fn check_filter(&self, _: &str) -> Result<(), CaptureError> {
        Err(self.0.clone())
    }

    fn export(&self, _: &Path, _: Option<&[u64]>, _: &Path) -> Result<(), CaptureError> {
        Err(self.0.clone())
    }
}
