//! `frame_detail`: bounded LRU cache + fast single-frame extraction (PDML tree + `-x` hex bytes).
//! Uses `-c N` for early frames (preserves stateful dissection) and `editcap -r` for deep frames.

use std::io::ErrorKind;
use std::path::Path;
use std::thread;

use wl_model::{CaptureError, DetailNode, FrameDetail};

use crate::error::{from_stderr, io_error};
use crate::frame_cache::{CacheKey, FrameCache};
use crate::process::{Tools, run};
use crate::{hexdump, pdml};

const DIRECT_MAX_FRAME: u64 = 1_000;
type Dissected = (Vec<DetailNode>, Vec<u8>);

pub(crate) fn cache_key(file: &Path, frame_no: u64) -> Result<CacheKey, CaptureError> {
    let meta = std::fs::metadata(file).map_err(|e| match e.kind() {
        ErrorKind::NotFound => CaptureError::Other(format!("file not found: {}", file.display())),
        ErrorKind::PermissionDenied => CaptureError::Permission(format!("{}: {e}", file.display())),
        _ => io_error("read capture metadata", &e),
    })?;
    if meta.is_dir() {
        return Err(CaptureError::Other(format!(
            "expected a capture file, not a directory: {}",
            file.display()
        )));
    }
    let path = std::fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
    Ok(CacheKey {
        path,
        len: meta.len(),
        modified: meta.modified().ok(),
        frame_no,
    })
}

fn run_tshark(tools: &Tools, base: &[String], extra: &[&str]) -> Result<Vec<u8>, CaptureError> {
    let args = base.iter().map(String::as_str).chain(extra.iter().copied());
    let out = run(&tools.tshark, args)?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(from_stderr(&String::from_utf8_lossy(&out.stderr)))
    }
}

fn dissect_pair(tools: &Tools, base: &[String]) -> Result<Dissected, CaptureError> {
    let (xml, hex) = thread::scope(|s| {
        let h = s.spawn(|| run_tshark(tools, base, &["-x"]));
        let x = run_tshark(tools, base, &["-T", "pdml"]);
        let h = h
            .join()
            .unwrap_or_else(|_| Err(CaptureError::Other("hex dump thread panicked".into())));
        (x, h)
    });
    Ok((
        pdml::parse(&xml?)?,
        hexdump::parse(&String::from_utf8_lossy(&hex?)),
    ))
}

fn rewrite_frame_number(layers: &mut [DetailNode], n: u64) {
    let Some(frame) = layers.first_mut() else {
        return;
    };
    if let Some(rest) = frame.label.strip_prefix("Frame 1:") {
        frame.label = format!("Frame {n}:{rest}");
    }
    if let Some(c) = frame
        .children
        .iter_mut()
        .find(|c| c.label == "Frame Number: 1")
    {
        c.label = format!("Frame Number: {n}");
    }
}

fn try_editcap(
    tools: &Tools,
    editcap: &Path,
    file: &Path,
    n: u64,
) -> Result<Option<Dissected>, CaptureError> {
    let tmp = tempfile::Builder::new()
        .prefix("wl-frame-")
        .tempfile()
        .map_err(|e| io_error("create temp frame file", &e))?;
    let range = format!("{n}-{n}");
    let out = run(
        editcap,
        [
            "-r".as_ref(),
            file.as_os_str(),
            tmp.path().as_os_str(),
            range.as_ref(),
        ],
    )?;
    if !out.status.success() {
        return Ok(None);
    }
    let base = vec!["-r".into(), tmp.path().to_string_lossy().into_owned()];
    let (mut layers, bytes) = dissect_pair(tools, &base)?;
    rewrite_frame_number(&mut layers, n);
    Ok(Some((layers, bytes)))
}

pub fn frame_detail(
    tools: &Tools,
    cache: &FrameCache,
    file: &Path,
    n: u64,
    opts: &[String],
) -> Result<FrameDetail, CaptureError> {
    if n == 0 {
        return Err(CaptureError::Other(format!(
            "frame 0 not found in {}",
            file.display()
        )));
    }
    let key = cache_key(file, n)?;
    if let Some(hit) = cache.get(&key) {
        return Ok(hit);
    }
    let extracted = if n > DIRECT_MAX_FRAME
        && let Some(editcap) = &tools.editcap
    {
        try_editcap(tools, editcap, file, n)?
    } else {
        None
    };
    let (layers, bytes) = match extracted {
        Some(pair) => pair,
        None => {
            let mut base = vec!["-r".to_string(), file.to_string_lossy().into_owned()];
            base.extend(opts.iter().cloned());
            base.extend([
                "-c".into(),
                n.to_string(),
                "-Y".into(),
                format!("frame.number=={n}"),
            ]);
            dissect_pair(tools, &base)?
        }
    };
    if layers.is_empty() {
        return Err(CaptureError::Other(format!(
            "frame {n} not found in {}",
            file.display()
        )));
    }
    let detail = FrameDetail {
        frame_no: n,
        layers,
        bytes,
    };
    cache.insert(key, detail.clone());
    Ok(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_extracted_frame_number() {
        let child = DetailNode {
            label: "Frame Number: 1".into(),
            ..Default::default()
        };
        let mut layers = vec![DetailNode {
            label: "Frame 1: Packet, 66 bytes".into(),
            range: Some((0, 66)),
            children: vec![child],
        }];
        rewrite_frame_number(&mut layers, 50_000);
        assert_eq!(layers[0].label, "Frame 50000: Packet, 66 bytes");
        assert_eq!(layers[0].children[0].label, "Frame Number: 50000");
    }
}
