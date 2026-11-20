//! One streamed `tshark -T fields` pass over a file (tab separated, first occurrence).
//! Lines are handed to a callback one by one, so memory stays flat on million-packet files.

use std::io::{BufRead, BufReader};
use std::ops::ControlFlow;
use std::path::Path;
use std::time::Duration;

use wl_model::CaptureError;

use crate::error::from_display_filter_failure;
use crate::process::{Proc, StderrTap, Tools, spawn};

/// Description of a field-extraction pass.
pub struct Pass<'a> {
    pub file: &'a Path,
    pub filter: &'a str,
    pub fields: &'a [&'a str],
    /// Extra `-o` style options (TLS keylog, reassembly switches ...).
    pub opts: &'a [String],
}

impl Pass<'_> {
    fn args(&self, occurrence: &str) -> Vec<String> {
        let mut a: Vec<String> = ["-n", "-r"].map(String::from).into();
        a.push(self.file.to_string_lossy().into_owned());
        a.extend(self.opts.iter().cloned());
        for s in ["-T", "fields", "-E", "separator=/t"] {
            a.push(s.into());
        }
        if !self.filter.is_empty() {
            a.extend(["-Y".into(), self.filter.into()]);
        }
        a.extend(["-E".into(), format!("occurrence={occurrence}")]);
        for f in self.fields {
            a.extend(["-e".into(), (*f).into()]);
        }
        a
    }
}

/// Runs the pass; `on_line` may stop early with `Break`. Errors come from tshark's stderr.
pub fn run_pass(
    tools: &Tools,
    pass: &Pass,
    on_line: impl FnMut(&str) -> ControlFlow<()>,
) -> Result<(), CaptureError> {
    run_occurrence(tools, pass, "f", on_line)
}

/// Like `run_pass`, but fields with several values (DNS answers) keep all of them, comma joined.
pub fn run_pass_all(
    tools: &Tools,
    pass: &Pass,
    on_line: impl FnMut(&str) -> ControlFlow<()>,
) -> Result<(), CaptureError> {
    run_occurrence(tools, pass, "a", on_line)
}

fn run_occurrence(
    tools: &Tools,
    pass: &Pass,
    occurrence: &str,
    mut on_line: impl FnMut(&str) -> ControlFlow<()>,
) -> Result<(), CaptureError> {
    let mut child = spawn(&tools.tshark, &pass.args(occurrence), false)?;
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    let proc = Proc::new(child);
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        proc.kill();
        return Err(CaptureError::Other("tshark pipes unavailable".into()));
    };
    let tap = StderrTap::spawn(stderr);
    let mut rdr = BufReader::with_capacity(256 * 1024, stdout);
    let (mut buf, mut stopped) = (Vec::new(), false);
    loop {
        buf.clear();
        match rdr.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = String::from_utf8_lossy(&buf);
        if on_line(line.trim_end_matches(['\n', '\r'])).is_break() {
            stopped = true;
            break;
        }
    }
    if stopped {
        proc.kill();
        return Ok(());
    }
    let status = proc.wait_exit(Duration::from_secs(5));
    let stderr = tap.finish();
    match status {
        Some(s) if !s.success() => Err(from_display_filter_failure(&stderr, s.code())),
        _ => Ok(()),
    }
}

/// Splits a tab separated line into exactly `N` columns (missing ones are empty).
pub fn columns<const N: usize>(line: &str) -> [&str; N] {
    let mut out = [""; N];
    for (slot, v) in out.iter_mut().zip(line.split('\t')) {
        *slot = v;
    }
    out
}

pub fn opt(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_pad_and_truncate() {
        assert_eq!(columns::<3>("a\t\tc\td"), ["a", "", "c"]);
        assert_eq!(columns::<3>("a"), ["a", "", ""]);
    }

    #[test]
    fn pass_args_emits_filter_at_most_once() {
        let with_filter = Pass {
            file: Path::new("a.pcap"),
            filter: "http || http2",
            fields: &["frame.number"],
            opts: &[],
        }
        .args("f");
        assert_eq!(with_filter.iter().filter(|s| s.as_str() == "-Y").count(), 1);

        let no_filter = Pass {
            file: Path::new("a.pcap"),
            filter: "",
            fields: &["frame.number"],
            opts: &[],
        }
        .args("f");
        assert_eq!(no_filter.iter().filter(|s| s.as_str() == "-Y").count(), 0);
    }
}
