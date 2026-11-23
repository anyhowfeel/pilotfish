//! Packet comments of pcapng files: reading them (`frame.comment`) and writing a copy with a new
//! set of comments through `editcap -a <frame>:<text>`.

use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, PacketBookmark};

use crate::error::from_stderr;
use crate::process::{Tools, run};
use crate::tsv_pass::{Pass, columns, run_pass_all};

const FIELDS: [&str; 4] = [
    "frame.number",
    "_ws.expert.group",
    "_ws.expert.severity",
    "_ws.expert.message",
];
const SEP: char = '\u{1f}';
/// Expert group and severity tshark gives to packet comments (PI_COMMENTS_GROUP, PI_COMMENT).
const COMMENT_GROUP: &str = "184549376";
const COMMENT_SEVERITY: &str = "1048576";
/// editcap keeps one comment per packet, so several are saved as one text with this between them.
pub const COMMENT_JOIN: &str = "\n\n";

pub fn read(
    tools: &Tools,
    file: &Path,
    opts: &[String],
) -> Result<Vec<PacketBookmark>, CaptureError> {
    let mut all = opts.to_vec();
    all.extend(["-E".into(), format!("aggregator={SEP}")]);
    let pass = Pass {
        scope: None,
        file,
        filter: "frame.comment",
        fields: &FIELDS,
        opts: &all,
    };
    let mut out = Vec::new();
    run_pass_all(tools, &pass, |line| {
        if let Some(b) = parse_line(line) {
            out.push(b);
        }
        ControlFlow::Continue(())
    })?;
    Ok(out)
}

/// tshark escapes backslash, line feed, carriage return and tab in field values.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// The expert items of a packet include its comments, told apart by group and severity.
fn parse_line(line: &str) -> Option<PacketBookmark> {
    let f: [&str; 4] = columns(line);
    let frame_no = f[0].trim().parse().ok()?;
    let comments: Vec<String> = f[1]
        .split(SEP)
        .zip(f[2].split(SEP))
        .zip(f[3].split(SEP))
        .filter(|((g, s), _)| *g == COMMENT_GROUP && *s == COMMENT_SEVERITY)
        .map(|(_, m)| unescape(m))
        .collect();
    (!comments.is_empty()).then(|| PacketBookmark {
        frame_no,
        comment: comments.join(COMMENT_JOIN),
    })
}

/// Replaces every comment of the file by `comments` (blank ones are skipped).
pub fn write_args(comments: &[PacketBookmark], input: &Path, output: &Path) -> Vec<String> {
    let mut args = vec![
        "--discard-packet-comments".to_owned(),
        "-F".into(),
        "pcapng".into(),
    ];
    for c in comments.iter().filter(|c| !c.comment.trim().is_empty()) {
        args.extend(["-a".into(), format!("{}:{}", c.frame_no, c.comment)]);
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
                "9:two\nlines  here",
                "in.pcapng",
                "out.pcapng"
            ]
        );
    }

    #[test]
    fn all_comments_of_a_packet_are_read_and_unescaped() {
        let s = SEP.to_string();
        let line = [
            "7".to_owned(),
            format!("{COMMENT_GROUP}{s}117440512{s}{COMMENT_GROUP}"),
            format!("{COMMENT_SEVERITY}{s}8388608{s}{COMMENT_SEVERITY}"),
            format!("a\\nb\\\\c{s}Malformed{s}second"),
        ]
        .join("\t");
        let b = parse_line(&line).expect("comments");
        assert_eq!(b.comment, "a\nb\\c\n\nsecond");
        assert_eq!(parse_line("7\t117440512\t8388608\tMalformed"), None);
    }
}
