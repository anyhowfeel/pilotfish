//! The one handle to tshark. Nothing starts it until a feature that needs it asks, and the
//! capture backend shares the same instance.

use std::path::PathBuf;
use std::sync::Arc;

use wl_hybrid::{HybridBackend, Lazy};
use wl_model::{CaptureBackend, CaptureError, Wireshark, needs_message};
use wl_tshark::TsharkBackend;

pub type LazyTshark = Arc<Lazy<TsharkBackend>>;

/// The user's Wireshark folder: the setting, else `PILOTFISH_WIRESHARK_DIR`, else none.
pub fn wireshark_dir(setting: &str) -> Option<PathBuf> {
    let setting = setting.trim();
    if setting.is_empty() {
        crate::app_paths::env_override("WIRESHARK_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    } else {
        Some(PathBuf::from(setting))
    }
}

/// A failed lookup is kept for the session, so a changed folder applies at the next start.
pub fn lazy_tshark(dir: Option<PathBuf>) -> LazyTshark {
    Arc::new(Lazy::new(move || {
        TsharkBackend::with_dir(dir.clone()).map(Arc::new)
    }))
}

/// Native for what it can read, the shared tshark for the rest.
pub fn hybrid(tshark: &LazyTshark) -> HybridBackend {
    let tshark = tshark.clone();
    HybridBackend::new(wl_hybrid::NativeBackend::new(), move || {
        Ok(tshark.get()? as Arc<dyn CaptureBackend>)
    })
}

/// Decided once at start from the same lookup every later request goes through.
pub fn availability(tshark: &LazyTshark) -> Wireshark {
    Wireshark::from_tools(&tshark.get())
}

/// A missing tool reads as the feature that needed it; any other error passes through.
pub fn explain(e: CaptureError, feature: &str) -> CaptureError {
    if e.is_tool_missing() {
        CaptureError::Other(needs_message(feature))
    } else {
        e
    }
}

/// tshark, or the message to show when it is not installed.
pub fn require(tshark: &LazyTshark, feature: &str) -> Result<Arc<TsharkBackend>, String> {
    tshark.get().map_err(|_| needs_message(feature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_follows_the_lookup() {
        let missing: LazyTshark = Arc::new(Lazy::new(|| {
            Err(CaptureError::ToolMissing("tshark".into()))
        }));
        let broken: LazyTshark = Arc::new(Lazy::new(|| Err(CaptureError::Other("x".into()))));
        assert_eq!(availability(&missing), Wireshark::Missing);
        assert_eq!(availability(&broken), Wireshark::Available);
    }

    #[test]
    fn the_setting_wins_over_nothing_and_blank_means_none() {
        assert_eq!(wireshark_dir(" /w "), Some(PathBuf::from("/w")));
        if crate::app_paths::env_override("WIRESHARK_DIR").is_none() {
            assert_eq!(wireshark_dir("  "), None);
        }
    }

    #[test]
    fn explain_rewrites_only_a_missing_tool() {
        let missing = CaptureError::ToolMissing("tshark".into());
        assert_eq!(
            explain(missing, "Follow stream"),
            CaptureError::Other(needs_message("Follow stream"))
        );
        let other = CaptureError::BadFilter("x".into());
        assert_eq!(explain(other.clone(), "Follow stream"), other);
    }

    #[test]
    fn a_missing_tshark_gives_the_message_every_time() {
        let t: LazyTshark = Arc::new(Lazy::new(|| Err(CaptureError::ToolMissing("x".into()))));
        for _ in 0..2 {
            assert_eq!(
                require(&t, "Loading a TLS key log").err(),
                Some(needs_message("Loading a TLS key log"))
            );
        }
    }
}
