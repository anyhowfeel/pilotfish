//! TLS key log support: `-o tls.keylog_file:<path>` for every dissection when configured,
//! and detection of key log files (for drag and drop).

use std::collections::HashSet;
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

/// Lowercase hex identifiers of the sessions of a capture: ClientHello randoms and the leading
/// bytes of RSA-encrypted pre-master secrets.
#[derive(Default)]
pub struct SessionIds {
    pub randoms: HashSet<String>,
    pub epms: HashSet<String>,
}

fn hex(v: &str) -> String {
    v.chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase()
}

impl SessionIds {
    pub fn add(&mut self, randoms: &str, epms: &str) {
        for r in randoms.split(',').map(hex).filter(|r| !r.is_empty()) {
            self.randoms.insert(r);
        }
        for e in epms.split(',').map(hex).filter(|e| e.len() >= 16) {
            self.epms.insert(e[..16].to_owned());
        }
    }

    fn matches(&self, line: &str) -> bool {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("RSA"), Some(id)) => self.epms.contains(&id.to_ascii_lowercase()),
            (Some(label), Some(id)) if LABELS.contains(&label) => {
                self.randoms.contains(&id.to_ascii_lowercase())
            }
            _ => false,
        }
    }

    /// The lines of a key log that belong to these sessions; comments and others are dropped.
    pub fn filter(&self, keylog: &str) -> String {
        keylog
            .lines()
            .filter(|l| self.matches(l.trim()))
            .flat_map(|l| [l.trim(), "\n"])
            .collect()
    }
}

/// Reads the start of `path` and tells whether it is a TLS key log. Only regular files are
/// opened: a FIFO or device would block the caller.
pub fn is_keylog_file(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 2048];
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return false;
    }
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
    fn keeps_only_the_lines_of_known_sessions() {
        let mut ids = SessionIds::default();
        ids.add("AA:bb,cc", "0102030405060708090a");
        let log = "# c\nCLIENT_RANDOM aabb 11\nCLIENT_RANDOM dead 22\nSERVER_TRAFFIC_SECRET_0 CC 33\n\
                   RSA 0102030405060708 44\nRSA ffffffffffffffff 55\n";
        assert_eq!(
            ids.filter(log),
            "CLIENT_RANDOM aabb 11\nSERVER_TRAFFIC_SECRET_0 CC 33\nRSA 0102030405060708 44\n"
        );
    }

    #[test]
    fn only_regular_files_are_probed() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("k.log");
        std::fs::write(&log, "CLIENT_RANDOM aa bb\n").unwrap();
        assert!(is_keylog_file(&log));
        assert!(!is_keylog_file(dir.path()));
        assert!(!is_keylog_file(&dir.path().join("missing")));
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
