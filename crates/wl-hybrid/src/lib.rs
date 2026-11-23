//! `CaptureBackend` that answers from `wl-native` when it can and from a deep backend (tshark)
//! otherwise. The deep backend is built on the first request that needs it.

mod backend;
mod fast;
mod lazy;
pub mod route;
#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use wl_model::{CaptureBackend, CaptureError, ClockZone, DecodeAs};

pub use fast::FastPath;
pub use lazy::Lazy;
pub use route::Route;
pub use wl_native::NativeBackend;

/// What the deep backend must know whenever it is built, and what the native side is given
/// per request.
#[derive(Default)]
struct Settings {
    rules: Vec<DecodeAs>,
    zone: ClockZone,
}

pub struct HybridBackend<F = NativeBackend> {
    fast: F,
    deep: Lazy<dyn CaptureBackend>,
    settings: Arc<Mutex<Settings>>,
}

impl<F: FastPath> HybridBackend<F> {
    /// `build_deep` runs at most once, on the first request only the deep backend can answer.
    pub fn new(
        fast: F,
        build_deep: impl Fn() -> Result<Arc<dyn CaptureBackend>, CaptureError> + Send + Sync + 'static,
    ) -> Self {
        let settings: Arc<Mutex<Settings>> = Arc::default();
        let shared = settings.clone();
        // Holding the lock across the build keeps the setters from slipping between the build
        // and the replay of the stored settings.
        let deep = Lazy::new(move || {
            let stored = lock(&shared);
            let backend = build_deep()?;
            backend.set_decode_as(stored.rules.clone());
            backend.set_clock_zone(stored.zone);
            Ok(backend)
        });
        Self {
            fast,
            deep,
            settings,
        }
    }

    /// The deep backend, built if it was not yet.
    pub fn deep(&self) -> Result<Arc<dyn CaptureBackend>, CaptureError> {
        self.deep.get()
    }

    fn decode_as_active(&self) -> bool {
        !lock(&self.settings).rules.is_empty()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
