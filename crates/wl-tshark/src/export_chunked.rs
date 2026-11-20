//! Exporting a large scattered selection. `editcap` silently keeps only the first 512 frame
//! ranges and the list must fit one command line (`E2BIG`), so frames go through several
//! `editcap -r` runs (in parallel, each stops reading at its last frame) joined by `mergecap -a`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use wl_model::CaptureError;

use crate::error::{from_stderr, io_error};
use crate::process::{Tools, run};

/// Conservative budget for the frame arguments of one editcap run (Linux allows ~2 MiB total).
const CHUNK_ARG_BYTES: usize = 256 * 1024;

/// editcap's hard limit is 512 selections; stay below it.
const CHUNK_RANGES: usize = 500;
const WORKERS: usize = 4;

pub fn needs_chunks(tokens: &[String]) -> bool {
    tokens.len() > CHUNK_RANGES
        || tokens.iter().map(|t| t.len() + 1).sum::<usize>() > CHUNK_ARG_BYTES
}

/// Splits tokens so each chunk stays under the argument budget.
pub fn split(tokens: &[String]) -> Vec<&[String]> {
    let (mut out, mut start, mut size) = (Vec::new(), 0, 0);
    for (i, t) in tokens.iter().enumerate() {
        if (size + t.len() + 1 > CHUNK_ARG_BYTES || i - start >= CHUNK_RANGES) && i > start {
            out.push(&tokens[start..i]);
            (start, size) = (i, 0);
        }
        size += t.len() + 1;
    }
    if start < tokens.len() {
        out.push(&tokens[start..]);
    }
    out
}

fn extract(editcap: &Path, file: &Path, part: &Path, chunk: &[String]) -> Result<(), CaptureError> {
    let mut a: Vec<String> = ["-r", "-F", "pcapng"].map(String::from).into();
    a.push(file.to_string_lossy().into_owned());
    a.push(part.to_string_lossy().into_owned());
    a.extend(chunk.iter().cloned());
    let out = run(editcap, &a)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(from_stderr(&String::from_utf8_lossy(&out.stderr)))
    }
}

pub fn export(
    tools: &Tools,
    editcap: &Path,
    file: &Path,
    tokens: &[String],
    fmt: &str,
    dest: &Path,
) -> Result<(), CaptureError> {
    let Some(mergecap) = &tools.mergecap else {
        return Err(CaptureError::Other(
            "selection too large to export without mergecap; export the whole capture or select fewer frames".into(),
        ));
    };
    let dir = tempfile::Builder::new()
        .prefix("wl-export-")
        .tempdir()
        .map_err(|e| io_error("create temp dir", &e))?;
    let chunks = split(tokens);
    let parts: Vec<PathBuf> = (0..chunks.len())
        .map(|i| dir.path().join(format!("part-{i:05}.pcapng")))
        .collect();
    let (next, failure) = (AtomicUsize::new(0), Mutex::new(None));
    thread::scope(|s| {
        for _ in 0..WORKERS.min(chunks.len()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= chunks.len() || failure.lock().is_ok_and(|f| f.is_some()) {
                        return;
                    }
                    if let Err(e) = extract(editcap, file, &parts[i], chunks[i])
                        && let Ok(mut f) = failure.lock()
                    {
                        f.get_or_insert(e);
                    }
                }
            });
        }
    });
    if let Some(e) = failure.into_inner().ok().flatten() {
        return Err(e);
    }
    let mut a = vec![
        "-a".to_string(),
        "-F".into(),
        fmt.into(),
        "-w".into(),
        dest.to_string_lossy().into_owned(),
    ];
    a.extend(parts.iter().map(|p| p.to_string_lossy().into_owned()));
    let out = run(mergecap, &a)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(from_stderr(&String::from_utf8_lossy(&out.stderr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_under_budget_and_preserves_order() {
        let tokens: Vec<String> = (0..200_000).map(|i| (i * 2).to_string()).collect();
        assert!(needs_chunks(&tokens));
        let chunks = split(&tokens);
        assert!(chunks.len() > 1);
        assert!(
            chunks
                .iter()
                .all(|c| c.iter().map(|t| t.len() + 1).sum::<usize>() <= CHUNK_ARG_BYTES)
        );
        let flat: Vec<&String> = chunks.iter().flat_map(|c| c.iter()).collect();
        assert_eq!(flat.len(), tokens.len());
        assert!(flat.iter().zip(&tokens).all(|(a, b)| *a == b));
        assert!(chunks.iter().all(|c| c.len() <= CHUNK_RANGES));
        assert!(!needs_chunks(&tokens[..100]));
        assert!(
            needs_chunks(&tokens[..CHUNK_RANGES + 1]),
            "editcap caps at 512 ranges"
        );
    }
}
