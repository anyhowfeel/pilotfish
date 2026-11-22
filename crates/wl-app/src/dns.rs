//! Lightweight non-blocking reverse-DNS cache for `HostsPanel`.
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crossbeam_channel::{Receiver, Sender, bounded};
use eframe::egui;
use wl_panels::overview::{GeoInfo, NameResolver};

use crate::geo::GeoDb;
use crate::intel_store::IntelHandle;

const MAX_CACHE: usize = 4096;
const QUEUE_CAP: usize = 256;

#[derive(Default)]
struct Cache {
    resolved: HashMap<String, Option<Arc<str>>>,
    pending: HashSet<String>,
}

/// Shared handle: cheap to clone; UI reads cached names and enqueues unknown IPs.
#[derive(Clone)]
pub struct AsyncResolver {
    cache: Arc<Mutex<Cache>>,
    req_tx: Sender<String>,
    done_rx: Receiver<()>,
    /// Settings > Names > "Resolve DNS names": off = no lookups (cached names still show).
    enabled: Arc<std::sync::atomic::AtomicBool>,
    geo: Arc<std::sync::RwLock<Option<Arc<GeoDb>>>>,
    intel: IntelHandle,
}

impl AsyncResolver {
    pub fn spawn(ctx: egui::Context) -> Self {
        let cache = Arc::new(Mutex::new(Cache::default()));
        let (req_tx, req_rx) = bounded::<String>(QUEUE_CAP);
        let (done_tx, done_rx) = bounded::<()>(8);
        let bg_cache = cache.clone();
        std::thread::spawn(move || {
            while let Ok(addr) = req_rx.recv() {
                let name = resolve_ip(&addr);
                if let Ok(mut guard) = bg_cache.lock() {
                    guard.pending.remove(&addr);
                    if guard.resolved.len() < MAX_CACHE {
                        guard.resolved.insert(addr, name);
                    }
                }
                let _ = done_tx.try_send(());
                ctx.request_repaint();
            }
        });
        Self {
            cache,
            req_tx,
            done_rx,
            enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            geo: Arc::new(std::sync::RwLock::new(GeoDb::discover())),
            intel: IntelHandle::default(),
        }
    }

    /// Re-reads the location databases (after one was downloaded, added or removed).
    pub fn reload_geo(&self) {
        if let Ok(mut g) = self.geo.write() {
            *g = GeoDb::discover();
        }
    }

    fn geo_db(&self) -> Option<Arc<GeoDb>> {
        self.geo.read().ok()?.clone()
    }

    /// Shares the threat lists the Hosts table marks addresses with.
    pub fn set_intel(&mut self, intel: IntelHandle) {
        self.intel = intel;
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Returns true if at least one new name finished resolving since the last poll.
    pub fn take_updated(&self) -> bool {
        let mut any = false;
        while self.done_rx.try_recv().is_ok() {
            any = true;
        }
        any
    }
}

impl NameResolver for AsyncResolver {
    fn geo(&self, addr: &str) -> Option<GeoInfo> {
        self.geo_db()?.lookup(addr)
    }

    fn threat(&self, addr: &str) -> Option<Arc<str>> {
        self.intel.read().ok()?.ip(addr).map(Arc::from)
    }

    fn has_threats(&self) -> bool {
        self.intel.read().is_ok_and(|i| !i.is_empty())
    }

    fn geo_hint(&self) -> Option<String> {
        self.geo_db()
            .is_none()
            .then(|| "No location database: add one in Settings > Locations".to_owned())
    }

    fn name(&self, addr: &str) -> Option<Arc<str>> {
        let mut guard = self.cache.lock().ok()?;
        if let Some(entry) = guard.resolved.get(addr) {
            return entry.clone();
        }
        if self.enabled.load(std::sync::atomic::Ordering::Relaxed)
            && addr.parse::<IpAddr>().is_ok()
            && guard.resolved.len() < MAX_CACHE
            && guard.pending.insert(addr.to_owned())
            && self.req_tx.try_send(addr.to_owned()).is_err()
        {
            guard.pending.remove(addr);
        }
        None
    }
}

fn resolve_ip(addr: &str) -> Option<Arc<str>> {
    let ip: IpAddr = addr.parse().ok()?;
    if ip.is_loopback() {
        return Some(Arc::from("localhost"));
    }
    let name = dns_lookup::lookup_addr(&ip).ok()?;
    (name != addr).then(|| Arc::from(name))
}
