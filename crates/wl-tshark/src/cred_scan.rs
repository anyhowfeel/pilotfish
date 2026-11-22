//! `credentials`: one streamed pass over the cleartext authentication protocols.

use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, Credential};

use crate::cred_parse::{FIELDS, FILTER, Parser};
use crate::process::Tools;
use crate::tsv_pass::{Pass, run_pass_all};

const MAX_CREDENTIALS: usize = 5_000;

pub fn credentials(
    tools: &Tools,
    file: &Path,
    opts: &[String],
) -> Result<Vec<Credential>, CaptureError> {
    let pass = Pass {
        file,
        filter: FILTER,
        fields: &FIELDS,
        opts,
    };
    let (mut parser, mut found) = (Parser::default(), Vec::new());
    run_pass_all(tools, &pass, |line| {
        parser.push_line(line, &mut found);
        if found.len() >= MAX_CREDENTIALS {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })?;
    Ok(found)
}
