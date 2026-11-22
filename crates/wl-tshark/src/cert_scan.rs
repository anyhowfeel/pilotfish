//! Server certificate chains per TCP stream: one cheap pass over the Certificate handshakes.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use wl_model::{CaptureError, CertInfo};

use crate::cert_parse::parse_chain;
use crate::process::Tools;
use crate::tsv_pass::{Pass, columns, run_pass_all};

pub const FIELDS: [&str; 2] = ["tcp.stream", "tls.handshake.certificate"];

/// `stream <tab> hex,hex,...` -> the chain of that stream.
pub fn parse_line(line: &str) -> Option<(u32, Vec<CertInfo>)> {
    let f: [&str; FIELDS.len()] = columns(line);
    let stream = f[0].trim().parse().ok()?;
    let chain = parse_chain(f[1]);
    (!chain.is_empty()).then_some((stream, chain))
}

type Chains = HashMap<u32, Vec<CertInfo>>;

/// Chains of the last scanned file with the number of certificate-bearing streams they cover:
/// a growing capture only needs a new pass once that number changes.
#[derive(Default)]
pub struct CertCache(Mutex<Option<(PathBuf, usize, Chains)>>);

impl CertCache {
    pub fn knows(&self, file: &Path) -> bool {
        self.lock().as_ref().is_some_and(|(f, ..)| f == file)
    }

    pub fn get(&self, file: &Path, streams: usize) -> Option<Chains> {
        match self.lock().as_ref() {
            Some((f, n, c)) if f == file && *n == streams => Some(c.clone()),
            _ => None,
        }
    }

    pub fn put(&self, file: &Path, streams: usize, chains: &Chains) {
        *self.lock() = Some((file.to_path_buf(), streams, chains.clone()));
    }

    pub fn clear(&self) {
        *self.lock() = None;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<(PathBuf, usize, Chains)>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The first Certificate of a stream is the server's (a client certificate comes later).
pub fn chains(
    tools: &Tools,
    file: &Path,
    opts: &[String],
) -> Result<HashMap<u32, Vec<CertInfo>>, CaptureError> {
    let pass = Pass {
        file,
        filter: "tls.handshake.type==11",
        fields: &FIELDS,
        opts,
    };
    let mut out = HashMap::new();
    run_pass_all(tools, &pass, |line| {
        if let Some((stream, chain)) = parse_line(line) {
            out.entry(stream).or_insert(chain);
        }
        ControlFlow::Continue(())
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_serves_a_file_until_its_certificate_streams_change() {
        let cache = CertCache::default();
        let file = Path::new("a.pcap");
        assert!(!cache.knows(file));
        cache.put(file, 2, &HashMap::new());
        assert!(cache.knows(file) && !cache.knows(Path::new("b.pcap")));
        assert!(cache.get(file, 2).is_some());
        assert!(cache.get(file, 3).is_none());
    }

    #[test]
    fn ignores_rows_without_a_parsable_chain() {
        assert!(parse_line("3\t").is_none());
        assert!(parse_line("x\t0102").is_none());
        assert!(parse_line("3\t0102").is_none());
    }
}
