//! Writes a copy of a capture with the TLS keys embedded as a pcapng decryption secrets block.

use std::path::Path;

use wl_model::CaptureError;

use crate::error::from_stderr;
use crate::process::{Tools, run};

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
    let out = run(editcap, inject_args(keylog, input, output))?;
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
