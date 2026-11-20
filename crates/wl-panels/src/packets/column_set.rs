//! Which packet-list columns exist, their order and visibility; persisted in the prefs.
//! Pure and tested (the menu in `columns_menu` only edits this).

use serde::{Deserialize, Serialize};

use crate::packets::columns::{ALL, Col, ColKey};
use crate::packets::time_format::TimeFormat;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColSpec {
    /// `ColKey::key()`.
    pub key: String,
    pub visible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ColumnSet {
    specs: Vec<ColSpec>,
}

/// Everything about the packet-list columns that survives a restart.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TablePrefs {
    pub columns: ColumnSet,
    pub time: TimeFormat,
}

impl Default for ColumnSet {
    fn default() -> Self {
        Self {
            specs: ALL
                .iter()
                .map(|c| ColSpec {
                    key: c.key().to_owned(),
                    visible: true,
                })
                .collect(),
        }
    }
}

impl ColumnSet {
    /// Drops unknown / duplicate entries, re-adds missing built-ins, keeps one column visible.
    pub fn sanitized(mut self) -> Self {
        let mut seen: Vec<String> = Vec::new();
        self.specs.retain(|s| {
            let fresh = ColKey::parse(&s.key).is_some() && !seen.contains(&s.key);
            if fresh {
                seen.push(s.key.clone());
            }
            fresh
        });
        for c in ALL {
            if !seen.iter().any(|k| k == c.key()) {
                self.specs.push(ColSpec {
                    key: c.key().to_owned(),
                    visible: true,
                });
            }
        }
        if !self.specs.iter().any(|s| s.visible) {
            self.specs[0].visible = true;
        }
        self
    }

    pub fn specs(&self) -> &[ColSpec] {
        &self.specs
    }

    pub fn visible(&self) -> Vec<ColKey> {
        self.specs
            .iter()
            .filter(|s| s.visible)
            .filter_map(|s| ColKey::parse(&s.key))
            .collect()
    }

    /// Custom fields currently shown (their values must be fetched).
    pub fn visible_fields(&self) -> Vec<String> {
        self.visible()
            .into_iter()
            .filter_map(|k| match k {
                ColKey::Field(f) => Some(f),
                ColKey::Std(_) => None,
            })
            .collect()
    }

    pub fn is_default(&self) -> bool {
        *self == ColumnSet::default()
    }

    /// Shows / hides column `i`; the last visible column cannot be hidden.
    pub fn toggle(&mut self, i: usize) {
        let visible = self.specs.iter().filter(|s| s.visible).count();
        if let Some(s) = self.specs.get_mut(i) {
            if s.visible && visible <= 1 {
                return;
            }
            s.visible = !s.visible;
        }
    }

    pub fn move_by(&mut self, i: usize, delta: isize) {
        let Some(j) = i.checked_add_signed(delta) else {
            return;
        };
        if i < self.specs.len() && j < self.specs.len() {
            self.specs.swap(i, j);
        }
    }

    /// Adds (or re-shows) a custom field column. Returns false for an empty/invalid name.
    pub fn add_field(&mut self, field: &str) -> bool {
        let f = field.trim();
        let ok = !f.is_empty()
            && f.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !ok {
            return false;
        }
        let key = ColKey::Field(f.to_owned()).key();
        match self.specs.iter_mut().find(|s| s.key == key) {
            Some(s) => s.visible = true,
            None => self.specs.push(ColSpec { key, visible: true }),
        }
        true
    }

    /// Removes a custom column (built-ins can only be hidden).
    pub fn remove(&mut self, i: usize) {
        if self
            .specs
            .get(i)
            .is_some_and(|s| matches!(ColKey::parse(&s.key), Some(ColKey::Field(_))))
        {
            self.specs.remove(i);
        }
    }

    pub fn is_shown(&self, c: Col) -> bool {
        self.specs.iter().any(|s| s.key == c.key() && s.visible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_all_builtins_visible() {
        let s = ColumnSet::default();
        assert_eq!(s.visible().len(), 7);
        assert!(s.is_default());
    }

    #[test]
    fn toggle_keeps_one_visible_and_move_swaps() {
        let mut s = ColumnSet::default();
        for i in 1..7 {
            s.toggle(i);
        }
        s.toggle(0);
        assert_eq!(s.visible(), [ColKey::Std(Col::No)]);
        s.toggle(2);
        s.move_by(2, -1);
        assert_eq!(s.specs()[1].key, "src");
        s.move_by(0, -1);
        s.move_by(99, 1);
        assert_eq!(s.specs()[0].key, "no");
    }

    #[test]
    fn custom_fields_add_remove_and_validate() {
        let mut s = ColumnSet::default();
        assert!(!s.add_field(" "));
        assert!(!s.add_field("ip ttl"));
        assert!(s.add_field(" ip.ttl "));
        assert_eq!(s.visible_fields(), ["ip.ttl"]);
        s.toggle(7);
        assert!(s.visible_fields().is_empty());
        assert!(s.add_field("ip.ttl"), "re-shows the hidden one");
        assert_eq!(s.specs().len(), 8);
        s.remove(0);
        assert_eq!(s.specs().len(), 8, "built-ins are never removed");
        s.remove(7);
        assert_eq!(s.specs().len(), 7);
        assert!(s.is_default());
    }

    #[test]
    fn sanitize_repairs_garbage_and_prefs_roundtrip() {
        let spec = |k: &str, v| ColSpec {
            key: k.into(),
            visible: v,
        };
        let s = ColumnSet {
            specs: vec![
                spec("bogus", true),
                spec("time", false),
                spec("time", true),
                spec("f:", true),
            ],
        }
        .sanitized();
        assert_eq!(s.specs().len(), 7);
        assert_eq!(s.specs()[0].key, "time");
        assert!(!s.is_shown(Col::Time), "the first duplicate wins");
        assert!(s.is_shown(Col::No));
        let json = serde_json::to_string(&TablePrefs::default()).unwrap();
        let back: TablePrefs = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TablePrefs::default());
        let partial: TablePrefs = serde_json::from_str("{}").unwrap();
        assert!(partial.columns.is_default());
    }
}
