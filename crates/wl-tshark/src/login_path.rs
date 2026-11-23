//! The PATH of the user's login shell. A macOS app started from Finder or the Dock gets only
//! /usr/bin:/bin:/usr/sbin:/sbin, so a tool the user installed with a shell profile is invisible.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(2);

/// Absolute entries only: a relative one would run whatever sits in the current folder.
pub(crate) fn parse_path(output: &str) -> Vec<PathBuf> {
    std::env::split_paths(output.trim())
        .filter(|p| p.is_absolute())
        .collect()
}

/// Asked once per process; any failure (no shell, timeout, odd output) gives an empty list.
pub(crate) fn login_shell_path() -> &'static [PathBuf] {
    static CACHE: OnceLock<Vec<PathBuf>> = OnceLock::new();
    CACHE.get_or_init(|| ask_shell().map(|s| parse_path(&s)).unwrap_or_default())
}

fn ask_shell() -> Option<String> {
    let shell = std::env::var_os("SHELL").map(PathBuf::from)?;
    if !shell.is_absolute() {
        return None;
    }
    let mut child = Command::new(shell)
        .args(["-l", "-c", "printf %s \"$PATH\""])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match child.try_wait().ok()? {
            Some(status) if status.success() => break,
            Some(_) => return None,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_output_gives_no_entries() {
        assert!(parse_path("").is_empty());
        assert!(parse_path("\n").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_trailing_newline_and_relative_entries_are_dropped() {
        let got = parse_path("/opt/homebrew/bin:bin:./x::/usr/bin\n");
        assert_eq!(
            got,
            [
                PathBuf::from("/opt/homebrew/bin"),
                PathBuf::from("/usr/bin")
            ]
        );
    }
}
