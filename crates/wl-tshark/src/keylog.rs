//! TLS key log support: `-o tls.keylog_file:<path>` for every dissection when configured,
//! and detection of key log files (for drag and drop).

use std::path::{Path, PathBuf};

/// `SSLKEYLOGFILE` (the variable browsers and curl honour), if set and non-empty.
pub fn from_env() -> Option<PathBuf> {
    std::env::var_os("SSLKEYLOGFILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// tshark arguments enabling decryption with `path` (empty when no key log is configured).
pub fn options(path: Option<&Path>) -> Vec<String> {
    match path {
        Some(p) => vec![
            "-o".into(),
            format!("tls.keylog_file:{}", p.to_string_lossy()),
        ],
        None => Vec::new(),
    }
}

const LABELS: [&str; 8] = [
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
    "RSA ",
];

/// True when `head` (the start of a file) looks like an NSS key log rather than a capture.
pub fn looks_like_keylog(head: &[u8]) -> bool {
    let Ok(text) =
        std::str::from_utf8(head).or_else(|e| std::str::from_utf8(&head[..e.valid_up_to()]))
    else {
        return false;
    };
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .is_some_and(|l| LABELS.iter().any(|p| l.starts_with(p)))
}

/// Reads the start of `path` and tells whether it is a TLS key log.
pub fn is_keylog_file(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 2048];
    std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .is_ok_and(|n| looks_like_keylog(&head[..n]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_option_only_when_set() {
        assert!(options(None).is_empty());
        assert_eq!(
            options(Some(Path::new("/tmp/k.log"))),
            ["-o", "tls.keylog_file:/tmp/k.log"]
        );
    }

    #[test]
    fn recognises_key_logs_but_not_captures() {
        assert!(looks_like_keylog(b"# comment\nCLIENT_RANDOM aa bb\n"));
        assert!(looks_like_keylog(b"SERVER_TRAFFIC_SECRET_0 aa bb"));
        assert!(!looks_like_keylog(b"hello\nCLIENT_RANDOM aa bb"));
        assert!(!looks_like_keylog(&[
            0x0a, 0x0d, 0x0d, 0x0a, 0xff, 0xfe, 0x00
        ]));
        assert!(!looks_like_keylog(b""));
    }
}
