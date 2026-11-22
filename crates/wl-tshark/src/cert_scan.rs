//! Server certificate chains per TCP stream: one cheap pass over the Certificate handshakes.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, CertInfo};

use crate::cert_parse::parse_chain;
use crate::process::Tools;
use crate::tsv_pass::{Pass, columns, run_pass_all};

pub const FIELDS: [&str; 2] = ["tcp.stream", "tls.handshake.certificate"];

/// `stream <tab> hex,hex,...` -> the chain of that stream.
pub fn parse_line(line: &str) -> Option<(u32, Vec<CertInfo>)> {
    let f: [&str; FIELDS.len()] = columns(line);
    let stream = f[0].trim().parse().ok()?;
    let chain = parse_chain(f[1]);
    (!chain.is_empty()).then_some((stream, chain))
}

/// The first Certificate of a stream is the server's (a client certificate comes later).
pub fn chains(
    tools: &Tools,
    file: &Path,
    opts: &[String],
) -> Result<HashMap<u32, Vec<CertInfo>>, CaptureError> {
    let pass = Pass {
        file,
        filter: "tls.handshake.type==11",
        fields: &FIELDS,
        opts,
    };
    let mut out = HashMap::new();
    run_pass_all(tools, &pass, |line| {
        if let Some((stream, chain)) = parse_line(line) {
            out.entry(stream).or_insert(chain);
        }
        ControlFlow::Continue(())
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_rows_without_a_parsable_chain() {
        assert!(parse_line("3\t").is_none());
        assert!(parse_line("x\t0102").is_none());
        assert!(parse_line("3\t0102").is_none());
    }
}
