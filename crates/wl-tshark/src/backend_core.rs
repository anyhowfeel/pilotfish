//! Construction, key-log setting and shared tool options of `TsharkBackend`.
use super::*;

impl TsharkBackend {
    /// Locates tshark and dumpcap on `PATH` and the usual install folders; `ToolMissing` otherwise.
    pub fn new() -> Result<Self, CaptureError> {
        Self::with_dir(None)
    }

    /// Like `new`, looking in the user's Wireshark folder first.
    pub fn with_dir(dir: Option<PathBuf>) -> Result<Self, CaptureError> {
        let tools = Tools::locate(dir.as_deref())?;
        let scratch = tempfile::Builder::new()
            .prefix("pilotfish-")
            .tempdir()
            .map_err(|e| error::io_error("create scratch dir", &e))?;
        let empty_pcap = scratch.path().join("empty.pcap");
        std::fs::write(&empty_pcap, validate::EMPTY_PCAP)
            .map_err(|e| error::io_error("write scratch file", &e))?;
        Ok(Self {
            tools,
            scratch,
            empty_pcap,
            counter: AtomicU64::new(0),
            frame_cache: frame_cache::FrameCache::default(),
            http_cache: http_detail::DetailCache::default(),
            keylog: Mutex::new(keylog::from_env()),
            decode_as: Mutex::new(Vec::new()),
            clock_zone: Mutex::new(ClockZone::default()),
            scans: Scans::default(),
        })
    }

    /// Sets (or clears) the TLS key log file (`-o tls.keylog_file:`) used by every dissection.
    /// Decrypted HTTPS then shows up as ordinary HTTP. Cached details are dropped.
    pub fn set_tls_keylog(&self, path: Option<PathBuf>) {
        *self.keylog.lock().unwrap_or_else(|e| e.into_inner()) = path;
        self.frame_cache.clear();
        self.http_cache.clear();
        self.scans.clear();
    }

    pub fn tls_keylog(&self) -> Option<PathBuf> {
        self.keylog
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn can_embed_tls_keys(&self) -> bool {
        self.tools.editcap.is_some()
    }

    /// Writes `dest` (a new file) with the current key log embedded in `file`.
    pub fn embed_tls_keys(&self, file: &Path, dest: &Path) -> Result<(), CaptureError> {
        let keylog = self
            .tls_keylog()
            .ok_or_else(|| CaptureError::Other("No TLS key log is loaded.".into()))?;
        keys_embed::embed(&self.tools, file, &keylog, dest)
    }

    pub(crate) fn start_live(
        &self,
        options: &CaptureOptions,
        display: Option<&str>,
        opts: &[String],
    ) -> Result<Session, CaptureError> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let save = options.save_to.trim();
        // Without a ring the saved file *is* the live backing file; with one, a recorder writes it.
        let backing = if save.is_empty() || options.ring.enabled {
            self.scratch.path().join(format!("live-{n}.pcapng"))
        } else {
            PathBuf::from(save)
        };
        live::start(
            &self.tools,
            &live::LiveArgs {
                options,
                display_filter: display,
                backing_file: &backing,
                empty_pcap: &self.empty_pcap,
                opts,
            },
        )
    }

    /// Options every dissection pass gets: TLS key log and "Decode As" rules (the one place).
    pub(crate) fn dissect_opts(&self) -> Vec<String> {
        let mut opts = keylog::options(self.tls_keylog().as_deref());
        let rules = self.decode_as.lock().unwrap_or_else(|e| e.into_inner());
        opts.extend(decode_as::args(&rules));
        opts
    }
}
