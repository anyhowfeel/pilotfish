//! TLS key log support: `-o tls.keylog_file:<path>` for every dissection when configured.

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
}
