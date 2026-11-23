//! Checks that run before the worker starts, with the wording of the tshark backend.

use std::fs::File;
use std::io::ErrorKind;
use std::path::Path;

use wl_model::CaptureError;

pub fn readable_file(file: &Path) -> Result<(), CaptureError> {
    let denied = |e: &std::io::Error| CaptureError::Permission(format!("{}: {e}", file.display()));
    let meta = std::fs::metadata(file).map_err(|e| match e.kind() {
        ErrorKind::NotFound => CaptureError::Other(format!("file not found: {}", file.display())),
        ErrorKind::PermissionDenied => denied(&e),
        _ => CaptureError::Other(format!("open capture file: {e}")),
    })?;
    if meta.is_dir() {
        return Err(CaptureError::Other(format!(
            "expected a capture file, not a directory: {}",
            file.display()
        )));
    }
    if !meta.is_file() {
        return Err(CaptureError::Other(format!(
            "not a regular file: {}",
            file.display()
        )));
    }
    File::open(file).map_err(|e| match e.kind() {
        ErrorKind::PermissionDenied => denied(&e),
        _ => CaptureError::Other(format!("open capture file: {e}")),
    })?;
    Ok(())
}
