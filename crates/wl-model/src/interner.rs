//! Tiny `Arc<str>` interner: protocols and addresses repeat a lot, so rows share allocations.

use std::collections::HashSet;
use std::sync::Arc;

/// Above this many distinct strings the table is reset (bounds memory on huge captures).
const MAX_ENTRIES: usize = 100_000;

#[derive(Default)]
pub struct Interner {
    set: HashSet<Arc<str>>,
}

impl Interner {
    pub fn intern(&mut self, s: &str) -> Arc<str> {
        if let Some(hit) = self.set.get(s) {
            return hit.clone();
        }
        if self.set.len() >= MAX_ENTRIES {
            self.set.clear();
        }
        let arc: Arc<str> = Arc::from(s);
        self.set.insert(arc.clone());
        arc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_string_shares_allocation() {
        let mut i = Interner::default();
        let a = i.intern("TCP");
        let b = i.intern("TCP");
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &i.intern("UDP")));
    }
}
