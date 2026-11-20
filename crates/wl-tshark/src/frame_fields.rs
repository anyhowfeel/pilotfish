//! `frame_fields`: one streamed tshark pass returning `frame.number` + chosen fields per frame.

use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, FrameFields};

use crate::process::Tools;
use crate::tsv_pass::{Pass, run_pass};

/// Safety cap so a pathological request cannot exhaust memory (frames beyond it are dropped).
const MAX_FRAMES: usize = 2_000_000;

pub fn frame_fields(
    tools: &Tools,
    file: &Path,
    filter: &str,
    fields: &[String],
    opts: &[String],
) -> Result<Vec<FrameFields>, CaptureError> {
    let mut names: Vec<&str> = vec!["frame.number"];
    names.extend(fields.iter().map(String::as_str));
    let pass = Pass {
        file,
        filter: filter.trim(),
        fields: &names,
        opts,
    };
    let mut out = Vec::new();
    run_pass(tools, &pass, |line| {
        if let Some(f) = parse_line(line, fields.len()) {
            out.push(f);
        }
        if out.len() >= MAX_FRAMES {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })?;
    Ok(out)
}

/// `no \t v1 \t v2 ...` -> frame number and exactly `n` values (missing ones are empty).
fn parse_line(line: &str, n: usize) -> Option<FrameFields> {
    let mut it = line.split('\t');
    let no = it.next()?.trim().parse().ok()?;
    let mut vals: Vec<String> = it.take(n).map(str::to_owned).collect();
    vals.resize(n, String::new());
    Some((no, vals))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_pads_values() {
        assert_eq!(
            parse_line("7\t64\t", 2),
            Some((7, vec!["64".into(), String::new()]))
        );
        assert_eq!(parse_line("9", 1), Some((9, vec![String::new()])));
        assert_eq!(parse_line("x\t1", 1), None);
        assert_eq!(parse_line("3\t1\t2", 0), Some((3, vec![])));
    }

    #[test]
    fn finds_frames_in_sample_capture() {
        let Some(tools) = Tools::locate().ok() else {
            return;
        };
        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sample.pcapng");
        // tshark occasionally fails when many sibling tests spawn it at once: retry.
        let run = |f: &str, e: &[String]| {
            (0..4)
                .find_map(|_| frame_fields(&tools, &file, f, e, &[]).ok())
                .expect("tshark pass")
        };
        let hits = run("frame contains 00:00", &[]);
        assert!(hits.iter().all(|(no, v)| *no > 0 && v.is_empty()));
        let ttl = run("icmp", &["ip.ttl".to_owned()]);
        assert!(ttl.iter().any(|(_, v)| v[0] == "64"));
    }
}
