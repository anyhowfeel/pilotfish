//! `http_exchanges`: one streamed tshark pass over the file, paired on the fly.

use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, HttpExchange};

use crate::http_pair::{MAX_EXCHANGES, Pairer};
use crate::http_row::{FIELDS, parse};
use crate::process::Tools;
use crate::tsv_pass::{Pass, run_pass};
use wl_model::Interner;

pub fn http_exchanges(
    tools: &Tools,
    file: &Path,
    opts: &[String],
    scope: Option<&str>,
) -> Result<Vec<HttpExchange>, CaptureError> {
    let pass = Pass {
        scope,
        file,
        filter: "http || http2",
        fields: &FIELDS,
        opts,
    };
    let (mut pairer, mut interner) = (Pairer::default(), Interner::default());
    run_pass(tools, &pass, |line| match parse(line, &mut interner) {
        Some(rec) => pairer.push(rec),
        None => ControlFlow::Continue(()),
    })?;
    if pairer.truncated {
        eprintln!(
            "wl-tshark: {} has more than {MAX_EXCHANGES} HTTP exchanges; list truncated",
            file.display()
        );
    }
    Ok(pairer.finish())
}
