//! SHA-256 of a capture file, streamed.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use sha2::{Digest, Sha256};
use wl_model::CaptureError;

const CHUNK: usize = 64 * 1024;

/// Lowercase hex SHA-256 of the file at `path`, read in 64 KiB chunks.
pub fn sha256_hex(path: &Path) -> Result<String, CaptureError> {
    let mut file = File::open(path).map_err(|e| failure(path, &e))?;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; CHUNK];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => hasher.update(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(failure(path, &e)),
        }
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn failure(path: &Path, e: &std::io::Error) -> CaptureError {
    let message = format!("{}: {e}", path.display());
    match e.kind() {
        ErrorKind::PermissionDenied => CaptureError::Permission(message),
        _ => CaptureError::Other(message),
    }
}

#[cfg(test)]
#[path = "hash_tests.rs"]
mod tests;
