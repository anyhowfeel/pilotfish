//! Optional reverse-DNS names, injected by the app (the panels never do I/O).

use std::sync::Arc;

pub trait NameResolver {
    /// Cached name for `addr`, if known. Must not block.
    fn name(&self, addr: &str) -> Option<Arc<str>>;
}

/// Default resolver: knows nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoNames;

impl NameResolver for NoNames {
    fn name(&self, _addr: &str) -> Option<Arc<str>> {
        None
    }
}

/// Maps a flow to its tshark stream index, when the app knows it (enables "Follow").
pub type StreamLookup = Box<dyn Fn(&wl_model::FlowKey) -> Option<u32>>;
