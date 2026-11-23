use std::sync::{Arc, OnceLock};

use wl_model::CaptureError;

type Factory<T> = Box<dyn Fn() -> Result<Arc<T>, CaptureError> + Send + Sync>;

/// A value built on first use. A failed build is kept too, so the factory runs at most once
/// and every caller sees the same error.
pub struct Lazy<T: ?Sized> {
    factory: Factory<T>,
    cell: OnceLock<Result<Arc<T>, CaptureError>>,
}

impl<T: ?Sized> Lazy<T> {
    pub fn new(factory: impl Fn() -> Result<Arc<T>, CaptureError> + Send + Sync + 'static) -> Self {
        Self {
            factory: Box::new(factory),
            cell: OnceLock::new(),
        }
    }

    pub fn get(&self) -> Result<Arc<T>, CaptureError> {
        self.cell.get_or_init(|| (self.factory)()).clone()
    }

    /// The value if it was built successfully; never builds.
    pub fn built(&self) -> Option<Arc<T>> {
        self.cell.get()?.as_ref().ok().cloned()
    }
}
