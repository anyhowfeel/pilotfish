//! Packet comments of pcapng files: reading them (`frame.comment`) and writing a copy with a new
//! set of comments through `editcap -a <frame>:<text>`.

use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, PacketBookmark};

use crate::error::from_stderr;
use crate::process::{Tools, run};
use crate::tsv_pass::{Pass, columns, run_pass};

const FIELDS: [&str; 2] = ["frame.number", "frame.comment"];

pub fn read(
    tools: &Tools,
    file: &Path,
    opts: &[String],
) -> Result<Vec<PacketBookmark>, CaptureError> {
    let pass = Pass {
        file,
        filter: "frame.comment",
        fields: &FIELDS,
        opts,
    };
    let mut out = Vec::new();
    run_pass(tools, &pass, |line| {
        let f: [&str; 2] = columns(line);
        if let Ok(frame_no) = f[0].trim().parse() {
            out.push(PacketBookmark {
                frame_no,
                comment: f[1].to_owned(),
            });
        }
        ControlFlow::Continue(())
    })?;
    Ok(out)
}

/// editcap takes one comment per `-a`; line breaks would not survive a round trip.
fn one_line(comment: &str) -> String {
    comment.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Replaces every comment of the file by `comments` (empty ones are skipped).
pub fn write_args(comments: &[PacketBookmark], input: &Path, output: &Path) -> Vec<String> {
    let mut args = vec![
        "--discard-packet-comments".to_owned(),
        "-F".into(),
        "pcapng".into(),
    ];
    for c in comments.iter().filter(|c| !one_line(&c.comment).is_empty()) {
        args.extend([
            "-a".into(),
            format!("{}:{}", c.frame_no, one_line(&c.comment)),
        ]);
    }
    args.push(input.to_string_lossy().into_owned());
    args.push(output.to_string_lossy().into_owned());
    args
}

pub fn write(
    tools: &Tools,
    input: &Path,
    comments: &[PacketBookmark],
    output: &Path,
) -> Result<(), CaptureError> {
    let editcap = tools
        .editcap
        .as_ref()
        .ok_or_else(|| CaptureError::ToolMissing("editcap".into()))?;
    if crate::keys_embed::same_file(input, output) {
        return Err(CaptureError::Other(
            "Choose a new file: the original capture is never overwritten.".into(),
        ));
    }
    let out = run(editcap, write_args(comments, input, output))?;
    if out.status.success() {
        return Ok(());
    }
    let _ = std::fs::remove_file(output);
    Err(from_stderr(&String::from_utf8_lossy(&out.stderr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bm(frame_no: u64, comment: &str) -> PacketBookmark {
        PacketBookmark {
            frame_no,
            comment: comment.into(),
        }
    }

    #[test]
    fn arguments_discard_old_comments_and_skip_empty_ones() {
        let a = write_args(
            &[bm(3, "first: note"), bm(5, ""), bm(9, "two\nlines  here")],
            Path::new("in.pcapng"),
            Path::new("out.pcapng"),
        );
        assert_eq!(
            a,
            [
                "--discard-packet-comments",
                "-F",
                "pcapng",
                "-a",
                "3:first: note",
                "-a",
                "9:two lines here",
                "in.pcapng",
                "out.pcapng"
            ]
        );
    }
}
