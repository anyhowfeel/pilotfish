//! A `Read` adapter that keeps the I/O error text, which `pcap-parser` drops.

use std::io::{ErrorKind, Read};
use std::sync::{Arc, Mutex};

/// Last I/O error seen by a `Fill`, shared with the stream that reports it.
#[derive(Debug, Clone, Default)]
pub(super) struct IoErrors(Arc<Mutex<Option<String>>>);

impl IoErrors {
    pub fn record(&self, e: &std::io::Error) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(e.to_string());
        }
    }

    pub fn take(&self) -> String {
        self.0
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .unwrap_or_else(|| "read error".to_string())
    }
}

/// Fills the whole buffer on every read unless the input ends, so a short read never looks like
/// a short file to the parser.
pub(super) struct Fill<R> {
    inner: R,
    errors: IoErrors,
}

impl<R> Fill<R> {
    pub fn new(inner: R, errors: IoErrors) -> Self {
        Self { inner, errors }
    }
}

impl<R: Read> Read for Fill<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match self.inner.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => {
                    self.errors.record(&e);
                    if filled > 0 {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        Ok(filled)
    }
}
