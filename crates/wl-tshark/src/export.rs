//! Save (a subset of) a capture. `editcap -r` keeps only the listed frames and handles format
//! conversion; without editcap we fall back to `tshark -Y "frame.number in {..}" -w`.

use std::path::Path;

use wl_model::CaptureError;

use crate::error::from_stderr;
use crate::process::{Tools, run};

/// `[1,2,3,7,9,10]` -> `["1-3","7","9-10"]` (sorted, deduplicated).
pub fn compress(frames: &[u64], sep: &str) -> Vec<String> {
    let mut v = frames.to_vec();
    v.sort_unstable();
    v.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let mut j = i;
        while j + 1 < v.len() && v[j + 1] == v[j] + 1 {
            j += 1;
        }
        out.push(if j == i {
            v[i].to_string()
        } else {
            format!("{}{sep}{}", v[i], v[j])
        });
        i = j + 1;
    }
    out
}

fn format_for(dest: &Path) -> &'static str {
    match dest
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase)
        .as_deref()
    {
        Some("pcap" | "cap") => "pcap",
        _ => "pcapng",
    }
}

pub fn export(
    tools: &Tools,
    file: &Path,
    frames: Option<&[u64]>,
    dest: &Path,
) -> Result<(), CaptureError> {
    if frames.is_some_and(<[u64]>::is_empty) {
        return Err(CaptureError::Other("no frames selected".into()));
    }
    let fmt = format_for(dest);
    if let (Some(editcap), Some(sel)) = (&tools.editcap, frames) {
        let tokens = compress(sel, "-");
        if crate::export_chunked::needs_chunks(&tokens) {
            return crate::export_chunked::export(tools, editcap, file, &tokens, fmt, dest);
        }
    }
    let (tool, args): (_, Vec<String>) = match (&tools.editcap, frames) {
        (Some(editcap), sel) => {
            let mut a = vec!["-F".to_string(), fmt.into()];
            if sel.is_some() {
                a.push("-r".into());
            }
            a.push(file.to_string_lossy().into_owned());
            a.push(dest.to_string_lossy().into_owned());
            a.extend(sel.map(|f| compress(f, "-")).unwrap_or_default());
            (editcap, a)
        }
        (None, sel) => {
            let mut a = vec!["-r".to_string(), file.to_string_lossy().into_owned()];
            if let Some(f) = sel {
                a.extend([
                    "-Y".into(),
                    format!("frame.number in {{{}}}", compress(f, "..").join(",")),
                ]);
            }
            a.extend([
                "-F".into(),
                fmt.into(),
                "-w".into(),
                dest.to_string_lossy().into_owned(),
            ]);
            (&tools.tshark, a)
        }
    };
    let out = run(tool, &args)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(from_stderr(&String::from_utf8_lossy(&out.stderr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compresses_ranges() {
        assert_eq!(compress(&[9, 1, 2, 3, 7, 10, 2], "-"), ["1-3", "7", "9-10"]);
        assert_eq!(compress(&[4], ".."), ["4"]);
        assert!(compress(&[], "-").is_empty());
    }

    #[test]
    fn format_by_extension() {
        assert_eq!(format_for(Path::new("a.pcap")), "pcap");
        assert_eq!(format_for(Path::new("a.PCAP")), "pcap");
        assert_eq!(format_for(Path::new("a.pcapng")), "pcapng");
        assert_eq!(format_for(Path::new("a")), "pcapng");
    }
}
