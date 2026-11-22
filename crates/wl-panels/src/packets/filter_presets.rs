//! Named display filters the user saved from the filter bar.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedFilter {
    pub name: String,
    pub expr: String,
}

#[derive(Debug, Clone, Default)]
pub struct Presets {
    items: Vec<SavedFilter>,
}

impl Presets {
    pub fn items(&self) -> &[SavedFilter] {
        &self.items
    }

    pub fn set(&mut self, items: Vec<SavedFilter>) {
        self.items.clear();
        for i in items {
            self.save(&i.name, &i.expr);
        }
    }

    /// Adds the filter, or replaces the expression of the preset with that name.
    pub fn save(&mut self, name: &str, expr: &str) -> bool {
        let (name, expr) = (name.trim(), expr.trim());
        if name.is_empty() || expr.is_empty() {
            return false;
        }
        match self.items.iter_mut().find(|i| i.name == name) {
            Some(i) => i.expr = expr.to_owned(),
            None => self.items.push(SavedFilter {
                name: name.to_owned(),
                expr: expr.to_owned(),
            }),
        }
        true
    }

    /// Fails when the new name is blank or belongs to another preset.
    pub fn rename(&mut self, index: usize, name: &str) -> bool {
        let name = name.trim();
        let taken = self
            .items
            .iter()
            .enumerate()
            .any(|(i, p)| i != index && p.name == name);
        match self.items.get_mut(index) {
            Some(p) if !name.is_empty() && !taken => {
                p.name = name.to_owned();
                true
            }
            _ => false,
        }
    }

    pub fn remove(&mut self, index: usize) {
        if index < self.items.len() {
            self.items.remove(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(p: &Presets) -> Vec<&str> {
        p.items().iter().map(|i| i.name.as_str()).collect()
    }

    #[test]
    fn saving_the_same_name_replaces_the_expression() {
        let mut p = Presets::default();
        assert!(p.save(" web ", " tcp.port == 443 "));
        assert!(p.save("web", "tcp.port == 80"));
        assert_eq!(p.items().len(), 1);
        assert_eq!(p.items()[0].expr, "tcp.port == 80");
    }

    #[test]
    fn blank_name_or_filter_is_refused() {
        let mut p = Presets::default();
        assert!(!p.save("  ", "tcp"));
        assert!(!p.save("tcp", " "));
        assert!(p.items().is_empty());
    }

    #[test]
    fn rename_refuses_blank_and_taken_names() {
        let mut p = Presets::default();
        p.save("a", "tcp");
        p.save("b", "udp");
        assert!(!p.rename(1, "a"));
        assert!(!p.rename(1, " "));
        assert!(p.rename(1, "c"));
        assert!(p.rename(0, "a"));
        assert_eq!(names(&p), ["a", "c"]);
    }

    #[test]
    fn remove_and_set_keep_order_and_drop_invalid() {
        let mut p = Presets::default();
        p.set(vec![
            SavedFilter {
                name: "a".into(),
                expr: "tcp".into(),
            },
            SavedFilter {
                name: "".into(),
                expr: "udp".into(),
            },
            SavedFilter {
                name: "b".into(),
                expr: "dns".into(),
            },
        ]);
        assert_eq!(names(&p), ["a", "b"]);
        p.remove(0);
        p.remove(9);
        assert_eq!(names(&p), ["b"]);
    }
}
