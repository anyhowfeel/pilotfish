//! Optional reverse-DNS names, injected by the app (the panels never do I/O).

use std::sync::Arc;

pub trait NameResolver {
    /// Cached name for `addr`, if known. Must not block.
    fn name(&self, addr: &str) -> Option<Arc<str>>;

    /// Country / AS data for `addr`. Must not block.
    fn geo(&self, _addr: &str) -> Option<GeoInfo> {
        None
    }

    /// Name of the offline blocklist that lists `addr`. Must not block.
    fn threat(&self, _addr: &str) -> Option<Arc<str>> {
        None
    }

    /// True when threat lists are loaded (the Hosts table then shows a Threat column).
    fn has_threats(&self) -> bool {
        false
    }

    /// Why country / AS data is unavailable (shown instead of the Location column); `None`
    /// when a database is loaded.
    fn geo_hint(&self) -> Option<String> {
        Some("No GeoIP database found".to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoInfo {
    pub country_code: Option<Arc<str>>,
    pub country: Option<Arc<str>>,
    pub asn: Option<u32>,
    pub org: Option<Arc<str>>,
}

impl GeoInfo {
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(c) = &self.country_code {
            parts.push(c.to_string());
        }
        if let Some(n) = self.asn {
            parts.push(format!("AS{n}"));
        }
        if let Some(o) = &self.org {
            parts.push(o.to_string());
        }
        parts.join("  ")
    }
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
