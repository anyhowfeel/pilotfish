//! Export Objects: `tshark --export-objects <proto>,<dir>` into a scratch directory, then a
//! listing enriched (HTTP) with host / frame / content type. Extraction is size capped.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use wl_model::{CaptureError, ExportObject, HttpExchange, ObjectSet, sanitize_filename};

use crate::error::{from_stderr, io_error};
use crate::object_names::{content_type_for, match_http, percent_decode};
use crate::process::{Proc, StderrTap, Tools, spawn};

/// Protocols `--export-objects` handles that the UI offers.
pub const PROTOCOLS: [&str; 5] = ["http", "smb", "tftp", "imf", "dicom"];
/// Extraction is stopped once the scratch directory holds this many bytes.
pub const SIZE_CAP: u64 = 512 * 1024 * 1024;

pub struct Request<'a> {
    pub tools: &'a Tools,
    pub file: &'a Path,
    pub protocol: &'a str,
    pub dir: PathBuf,
    pub opts: &'a [String],
    pub cap: u64,
}

/// Total size of the regular files directly inside `dir`.
fn dir_size(dir: &Path) -> u64 {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()))
        .map(|m| m.len())
        .sum()
}

/// Runs the extraction; returns true when it was stopped at the size cap.
fn extract(r: &Request) -> Result<bool, CaptureError> {
    let mut args: Vec<String> = ["-n", "-q", "-r"].map(String::from).into();
    args.push(r.file.to_string_lossy().into_owned());
    args.extend(r.opts.iter().cloned());
    args.push("--export-objects".into());
    args.push(format!("{},{}", r.protocol, r.dir.to_string_lossy()));
    let mut child = spawn(&r.tools.tshark, &args, false)?;
    let (out, err) = (child.stdout.take(), child.stderr.take());
    let proc = Proc::new(child);
    let (Some(out), Some(err)) = (out, err) else {
        proc.kill();
        return Err(CaptureError::Other("tshark pipes unavailable".into()));
    };
    let (_out, tap) = (StderrTap::spawn(out), StderrTap::spawn(err));
    loop {
        if let Some(status) = proc.try_exit() {
            let text = tap.finish();
            return if status.success() {
                Ok(false)
            } else {
                Err(from_stderr(&text))
            };
        }
        if dir_size(&r.dir) > r.cap {
            proc.kill();
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(40));
    }
}

/// Regular files directly inside `dir` as (file name, size); symlinks and folders are ignored.
fn list_files(dir: &Path) -> Vec<(String, u64)> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_type().ok().filter(|t| t.is_file())?;
            let size = e.metadata().ok()?.len();
            Some((e.file_name().to_string_lossy().into_owned(), size))
        })
        .collect()
}

fn build(
    r: &Request,
    files: Vec<(String, u64)>,
    http: &[HttpExchange],
    truncated: bool,
) -> ObjectSet {
    let matches = match_http(&files, http);
    let mut objects: Vec<ExportObject> = files
        .into_iter()
        .zip(matches)
        .map(|((file, size), m)| {
            let name = percent_decode(&file);
            let ex = m.map(|i| &http[i]);
            let ctype = ex
                .and_then(|e| e.content_type.as_deref())
                .map(|c| c.split(';').next().unwrap_or(c).trim().to_owned())
                .filter(|c| !c.is_empty())
                .unwrap_or_else(|| content_type_for(&name).to_owned());
            ExportObject {
                id: 0,
                save_name: sanitize_filename(&name),
                name,
                content_type: ctype,
                size,
                host: ex.map(|e| e.host.to_string()).unwrap_or_default(),
                packet: ex.and_then(|e| e.resp_frame),
                path: r.dir.join(&file),
            }
        })
        .collect();
    objects.sort_by(|a, b| {
        (a.packet.is_none(), a.packet, &a.name).cmp(&(b.packet.is_none(), b.packet, &b.name))
    });
    for (i, o) in objects.iter_mut().enumerate() {
        o.id = i as u32;
    }
    ObjectSet {
        protocol: r.protocol.to_owned(),
        dir: r.dir.clone(),
        objects,
        truncated,
    }
}

/// Extracts and lists the objects of `r.protocol`. `http` is the exchange list used to enrich
/// HTTP objects (empty for other protocols).
pub fn export(
    r: &Request,
    http_exchanges: impl FnOnce() -> Vec<HttpExchange> + Send,
) -> Result<ObjectSet, CaptureError> {
    if !PROTOCOLS.contains(&r.protocol) {
        return Err(CaptureError::Other(format!(
            "unsupported object protocol: {}",
            r.protocol
        )));
    }
    let _ = fs::remove_dir_all(&r.dir);
    fs::create_dir_all(&r.dir).map_err(|e| io_error("create objects dir", &e))?;
    let (truncated, http) = thread::scope(|s| {
        let h = (r.protocol == "http").then(|| s.spawn(http_exchanges));
        let t = extract(r);
        (t, h.and_then(|h| h.join().ok()).unwrap_or_default())
    });
    Ok(build(r, list_files(&r.dir), &http, truncated?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_size_sums_regular_files() {
        let d = tempfile::tempdir().expect("tmp");
        fs::write(d.path().join("a"), [0u8; 10]).expect("w");
        fs::write(d.path().join("b"), [0u8; 5]).expect("w");
        fs::create_dir(d.path().join("sub")).expect("d");
        assert_eq!(dir_size(d.path()), 15);
        assert_eq!(list_files(d.path()).len(), 2);
    }

    #[test]
    fn rejects_unknown_protocol() {
        let d = tempfile::tempdir().expect("tmp");
        let tools = Tools {
            tshark: "tshark".into(),
            dumpcap: "dumpcap".into(),
            editcap: None,
            mergecap: None,
        };
        let r = Request {
            tools: &tools,
            file: Path::new("x.pcap"),
            protocol: "../../x",
            dir: d.path().join("o"),
            opts: &[],
            cap: 1,
        };
        assert!(export(&r, Vec::new).is_err());
    }
}
