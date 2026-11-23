//! Writes a copy of a capture with the TLS keys embedded as a pcapng decryption secrets block.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use wl_model::CaptureError;

use crate::error::{from_stderr, io_error};
use crate::keylog::SessionIds;
use crate::process::{Tools, run};
use crate::tsv_pass::{Pass, columns, run_pass_all};

pub fn inject_args(keylog: &Path, input: &Path, output: &Path) -> Vec<String> {
    vec![
        "--inject-secrets".into(),
        format!("tls,{}", keylog.to_string_lossy()),
        "-F".into(),
        "pcapng".into(),
        input.to_string_lossy().into_owned(),
        output.to_string_lossy().into_owned(),
    ]
}

pub(crate) fn same_file(a: &Path, b: &Path) -> bool {
    matches!((a.canonicalize(), b.canonicalize()), (Ok(a), Ok(b)) if a == b)
}

fn session_ids(tools: &Tools, file: &Path) -> Result<SessionIds, CaptureError> {
    let pass = Pass {
        scope: None,
        file,
        filter: "tls.handshake.type==1 || tls.handshake.type==16",
        fields: &["tls.handshake.random", "tls.handshake.epms"],
        opts: &[],
    };
    let mut ids = SessionIds::default();
    run_pass_all(tools, &pass, |line| {
        let f: [&str; 2] = columns(line);
        ids.add(f[0], f[1]);
        ControlFlow::Continue(())
    })?;
    Ok(ids)
}

/// Copies only the key log lines of this capture's sessions into a scratch file: embedding must
/// not hand out the secrets of unrelated connections.
fn filtered_keylog(
    tools: &Tools,
    input: &Path,
    keylog: &Path,
    dir: &Path,
) -> Result<PathBuf, CaptureError> {
    let text = std::fs::read(keylog).map_err(|e| io_error("read key log", &e))?;
    let kept = session_ids(tools, input)?.filter(&String::from_utf8_lossy(&text));
    if kept.is_empty() {
        return Err(CaptureError::Other(
            "No key in the key log belongs to this capture.".into(),
        ));
    }
    let out = dir.join("session-keys.log");
    std::fs::write(&out, kept).map_err(|e| io_error("write key log", &e))?;
    Ok(out)
}

pub fn embed(
    tools: &Tools,
    input: &Path,
    keylog: &Path,
    output: &Path,
) -> Result<(), CaptureError> {
    let editcap = tools
        .editcap
        .as_ref()
        .ok_or_else(|| CaptureError::ToolMissing("editcap".into()))?;
    if same_file(input, output) {
        return Err(CaptureError::Other(
            "Choose a new file: the original capture is never overwritten.".into(),
        ));
    }
    let scratch = tempfile::tempdir().map_err(|e| io_error("create temp dir", &e))?;
    let keys = filtered_keylog(tools, input, keylog, scratch.path())?;
    let out = run(editcap, inject_args(&keys, input, output))?;
    if out.status.success() {
        return Ok(());
    }
    let _ = std::fs::remove_file(output);
    Err(from_stderr(&String::from_utf8_lossy(&out.stderr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_editcap_arguments() {
        let a = inject_args(
            Path::new("k.log"),
            Path::new("in.pcap"),
            Path::new("out.pcapng"),
        );
        assert_eq!(
            a,
            [
                "--inject-secrets",
                "tls,k.log",
                "-F",
                "pcapng",
                "in.pcap",
                "out.pcapng"
            ]
        );
    }

    #[test]
    fn refuses_to_overwrite_the_input() {
        let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert!(same_file(&f, &f));
        assert!(!same_file(&f, &f.with_extension("nope")));
    }
}
