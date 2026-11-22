//! `credentials`: one streamed pass over the cleartext authentication protocols.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, CredKind, Credential};

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
    let (mut parser, mut found, mut seen) = (Parser::default(), Vec::new(), HashMap::new());
    let mut batch = Vec::new();
    run_pass_all(tools, &pass, |line| {
        parser.push_line(line, &mut batch);
        for c in batch.drain(..) {
            merge(&mut found, &mut seen, c);
        }
        if found.len() >= MAX_CREDENTIALS {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })?;
    Ok(found)
}

type Identity = (
    CredKind,
    std::sync::Arc<str>,
    std::sync::Arc<str>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Keep-alive and retry repeats of the same login become one entry with a count.
fn merge(found: &mut Vec<Credential>, seen: &mut HashMap<Identity, usize>, c: Credential) {
    let key = (
        c.kind,
        c.src.clone(),
        c.dst.clone(),
        c.user.clone(),
        c.secret.clone(),
        c.field.clone(),
    );
    match seen.get(&key) {
        Some(&at) => found[at].count += 1,
        None => {
            seen.insert(key, found.len());
            found.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(frame: u64, secret: &str) -> Credential {
        Credential {
            kind: CredKind::HttpBasic,
            frame,
            src: "10.0.0.2".into(),
            dst: "10.0.0.9".into(),
            user: Some("alice".into()),
            secret: Some(secret.into()),
            field: Some("Authorization".into()),
            count: 1,
        }
    }

    #[test]
    fn identical_logins_are_merged_with_a_count() {
        let (mut found, mut seen) = (Vec::new(), HashMap::new());
        for (frame, secret) in [(1, "pw"), (5, "pw"), (9, "other"), (12, "pw")] {
            merge(&mut found, &mut seen, login(frame, secret));
        }
        let got: Vec<_> = found.iter().map(|c| (c.frame, c.count)).collect();
        assert_eq!(got, [(1, 3), (9, 1)]);
    }
}
