//! In-memory display-filter history (newest first, deduplicated, capped).

pub const MAX_HISTORY: usize = 20;

#[derive(Debug, Clone, Default)]
pub struct History {
    items: Vec<String>,
}

impl History {
    pub fn push(&mut self, filter: &str) {
        let f = filter.trim();
        if f.is_empty() {
            return;
        }
        self.items.retain(|i| i != f);
        self.items.insert(0, f.to_owned());
        self.items.truncate(MAX_HISTORY);
    }

    pub fn items(&self) -> &[String] {
        &self.items
    }

    pub fn set(&mut self, items: Vec<String>) {
        self.items.clear();
        for i in items.into_iter().rev() {
            self.push(&i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_and_caps() {
        let mut h = History::default();
        h.push("tcp");
        h.push("udp");
        h.push("tcp");
        assert_eq!(h.items(), ["tcp", "udp"]);
        for i in 0..40 {
            h.push(&format!("p{i}"));
        }
        assert_eq!(h.items().len(), MAX_HISTORY);
        assert_eq!(h.items()[0], "p39");
    }

    #[test]
    fn set_keeps_order_and_ignores_blank() {
        let mut h = History::default();
        h.set(vec!["a".into(), " ".into(), "b".into(), "a".into()]);
        assert_eq!(h.items(), ["a", "b"]);
    }
}
