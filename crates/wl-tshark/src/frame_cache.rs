//! Bounded LRU cache of dissected frames (count and approximate byte budget).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use wl_model::{DetailNode, FrameDetail};

pub const CACHE_CAP: usize = 64;
/// Approximate heap budget of the cache: a few pathological jumbo frames must not pin hundreds of MiB.
pub const CACHE_MAX_BYTES: usize = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    pub path: PathBuf,
    pub len: u64,
    pub modified: Option<SystemTime>,
    pub frame_no: u64,
}

/// Approximate heap size of a cached value.
pub trait Weigh {
    fn weight(&self) -> usize;
}

impl Weigh for FrameDetail {
    fn weight(&self) -> usize {
        fn nodes(ns: &[DetailNode]) -> usize {
            ns.iter()
                .map(|n| 96 + n.label.len() + nodes(&n.children))
                .sum()
        }
        self.bytes.len() + nodes(&self.layers)
    }
}

pub struct LruCache<V>(Mutex<VecDeque<(CacheKey, V)>>);

impl<V> Default for LruCache<V> {
    fn default() -> Self {
        Self(Mutex::default())
    }
}

pub type FrameCache = LruCache<FrameDetail>;

impl<V: Weigh + Clone> LruCache<V> {
    pub fn clear(&self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub fn get(&self, key: &CacheKey) -> Option<V> {
        let mut q = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let pos = q.iter().position(|(k, _)| k == key)?;
        if pos > 0
            && let Some(entry) = q.remove(pos)
        {
            q.push_front(entry);
        }
        q.front().map(|(_, d)| d.clone())
    }

    pub fn insert(&self, key: CacheKey, detail: V) {
        let mut q = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = q.iter().position(|(k, _)| k == &key) {
            q.remove(pos);
        }
        q.push_front((key, detail));
        q.truncate(CACHE_CAP);
        let mut total: usize = q.iter().map(|(_, d)| d.weight()).sum();
        while total > CACHE_MAX_BYTES && q.len() > 1 {
            if let Some((_, d)) = q.pop_back() {
                total -= d.weight();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u64, len: u64) -> CacheKey {
        CacheKey {
            path: PathBuf::from("/tmp/a.pcapng"),
            len,
            modified: None,
            frame_no: n,
        }
    }

    #[test]
    fn cache_lru_evicts_oldest_and_promotes_hits() {
        let c = FrameCache::default();
        let mk = |n| FrameDetail {
            frame_no: n,
            layers: vec![],
            bytes: vec![1],
        };
        for i in 1..=(CACHE_CAP as u64) {
            c.insert(key(i, 100), mk(i));
        }
        assert_eq!(c.get(&key(1, 100)).unwrap().frame_no, 1);
        c.insert(key(999, 100), mk(999));
        assert!(c.get(&key(1, 100)).is_some() && c.get(&key(2, 100)).is_none());
        assert!(c.get(&key(999, 100)).is_some() && c.get(&key(1, 200)).is_none());
    }

    #[test]
    fn cache_is_byte_bounded_and_keeps_newest_jumbo() {
        let c = FrameCache::default();
        let jumbo = |n| FrameDetail {
            frame_no: n,
            layers: vec![],
            bytes: vec![0; CACHE_MAX_BYTES / 2 + 1],
        };
        c.insert(key(1, 1), jumbo(1));
        c.insert(key(2, 1), jumbo(2));
        assert!(c.get(&key(1, 1)).is_none(), "older jumbo must be evicted");
        assert!(c.get(&key(2, 1)).is_some());
    }
}
