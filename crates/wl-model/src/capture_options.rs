//! Capture > Options: everything `dumpcap` needs to start a live capture. Pure data.
use serde::{Deserialize, Serialize};

use crate::RemoteTarget;

/// Default (and maximum) snap length: whole packets.
pub const SNAPLEN_MAX: u32 = 262_144;

/// Ring buffer: rotate over `files` files of `file_mb` MB or `secs` seconds (0 = unused limit).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RingBuffer {
    pub enabled: bool,
    pub file_mb: u32,
    pub secs: u32,
    pub files: u32,
}

/// Auto-stop conditions (0 = never).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoStop {
    pub packets: u32,
    pub mb: u32,
    pub secs: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureOptions {
    pub interfaces: Vec<String>,
    pub capture_filter: String,
    pub promiscuous: bool,
    /// Wi-Fi monitor mode (`dumpcap -I`).
    pub monitor: bool,
    pub snaplen: u32,
    /// Kernel capture buffer in MiB (0 = driver default).
    pub buffer_mb: u32,
    pub ring: RingBuffer,
    pub stop: AutoStop,
    pub remote: RemoteTarget,
    /// Where to keep the capture (ring buffer base name when the ring is enabled). Empty = the saved
    /// captures folder of the settings, or a temporary file when automatic saving is off.
    pub save_to: String,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        CaptureOptions {
            interfaces: Vec::new(),
            capture_filter: String::new(),
            promiscuous: true,
            monitor: false,
            snaplen: SNAPLEN_MAX,
            buffer_mb: 0,
            ring: RingBuffer {
                enabled: false,
                file_mb: 100,
                secs: 0,
                files: 10,
            },
            stop: AutoStop::default(),
            remote: RemoteTarget::default(),
            save_to: String::new(),
        }
    }
}

impl CaptureOptions {
    /// One interface, optional filter, everything else default.
    pub fn single(interface: &str, filter: Option<&str>) -> Self {
        CaptureOptions {
            interfaces: vec![interface.to_string()],
            capture_filter: filter.unwrap_or_default().to_string(),
            ..Self::default()
        }
    }

    pub fn clamped(mut self) -> Self {
        self.snaplen = self.snaplen.clamp(64, SNAPLEN_MAX);
        self.buffer_mb = self.buffer_mb.min(4096);
        self.ring.files = self.ring.files.clamp(2, 10_000);
        self.ring.file_mb = self.ring.file_mb.min(100_000);
        self
    }

    /// Why this configuration cannot be started, in plain words.
    pub fn problem(&self) -> Option<&'static str> {
        if self.remote.enabled {
            return self.remote.problem();
        }
        if self.interfaces.is_empty() {
            return Some("Select at least one interface.");
        }
        if self.ring.enabled && self.ring.file_mb == 0 && self.ring.secs == 0 {
            return Some("A ring buffer needs a file size or duration limit.");
        }
        None
    }

    /// Short label for the status bar ("eth0" / "eth0 + 2 more").
    pub fn label(&self) -> String {
        if self.remote.enabled {
            return self.remote.label();
        }
        match self.interfaces.as_slice() {
            [] => String::new(),
            [one] => one.clone(),
            [first, rest @ ..] => format!("{first} + {} more", rest.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problems_are_reported_in_priority_order() {
        let mut o = CaptureOptions::default();
        assert!(o.problem().is_some_and(|p| p.contains("interface")));
        o.interfaces.push("lo".into());
        assert_eq!(o.problem(), None);
        o.ring.enabled = true;
        assert_eq!(
            o.problem(),
            None,
            "the app picks the folder of a ring buffer"
        );
        o.ring.file_mb = 0;
        assert!(o.problem().is_some_and(|p| p.contains("limit")));
    }

    #[test]
    fn clamps_and_labels() {
        let o = CaptureOptions {
            snaplen: 1,
            buffer_mb: 99_999,
            interfaces: vec!["a".into(), "b".into(), "c".into()],
            ..CaptureOptions::default()
        }
        .clamped();
        assert_eq!((o.snaplen, o.buffer_mb), (64, 4096));
        assert_eq!(o.label(), "a + 2 more");
    }

    #[test]
    fn old_json_keeps_defaults() {
        let o: CaptureOptions = serde_json::from_str("{}").unwrap_or_default();
        assert_eq!(o, CaptureOptions::default());
    }
}
