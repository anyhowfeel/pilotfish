//! Values of custom (tshark field) columns: fetched by one backend pass per field, cached per
//! frame, refreshed (throttled) while a live capture grows. Pure bookkeeping, no egui.

use std::collections::HashMap;

use wl_model::FrameFields;

use crate::packets::actions::PacketsAction;

/// Request ids at or above this belong to custom columns (Find uses small ids).
pub const ID_BASE: u64 = 1 << 32;
/// Minimum seconds between two passes for the same field.
const REFRESH_S: f64 = 3.0;

#[derive(Default)]
struct Entry {
    values: HashMap<u64, String>,
    /// Rows the table had when the last completed pass started.
    fetched_rows: Option<usize>,
    /// (request id, rows at request time)
    pending: Option<(u64, usize)>,
    error: Option<String>,
    last_try: f64,
}

#[derive(Default)]
pub struct CustomCols {
    map: HashMap<String, Entry>,
    next_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldStatus {
    Ready,
    Loading,
    Failed(String),
}

pub fn is_custom_id(id: u64) -> bool {
    id >= ID_BASE
}

impl CustomCols {
    /// Starts a pass for every shown field that has no (or outdated) values.
    pub fn request(
        &mut self,
        fields: &[String],
        total_rows: usize,
        now: f64,
        out: &mut Vec<PacketsAction>,
    ) {
        if total_rows == 0 {
            return;
        }
        for f in fields {
            let e = self.map.entry(f.clone()).or_insert_with(|| Entry {
                last_try: f64::NEG_INFINITY,
                ..Entry::default()
            });
            let stale = e.fetched_rows.is_none_or(|n| n < total_rows);
            if e.pending.is_some() || e.error.is_some() || !stale || now - e.last_try < REFRESH_S {
                continue;
            }
            self.next_id += 1;
            let id = ID_BASE + self.next_id;
            e.pending = Some((id, total_rows));
            e.last_try = now;
            out.push(PacketsAction::RunFields {
                id,
                filter: String::new(),
                fields: vec![f.clone()],
            });
        }
    }

    /// Stores a finished pass; false when the id is not ours / stale.
    pub fn on_result(&mut self, id: u64, res: &Result<Vec<FrameFields>, String>) -> bool {
        let Some(e) = self
            .map
            .values_mut()
            .find(|e| e.pending.is_some_and(|p| p.0 == id))
        else {
            return false;
        };
        let rows = e.pending.take().map_or(0, |p| p.1);
        match res {
            Ok(frames) => {
                for (no, v) in frames {
                    if let Some(first) = v.first().filter(|s| !s.is_empty()) {
                        e.values.insert(*no, first.clone());
                    }
                }
                e.fetched_rows = Some(rows);
                e.error = None;
            }
            Err(err) => e.error = Some(err.clone()),
        }
        true
    }

    pub fn get(&self, field: &str, frame: u64) -> Option<&str> {
        self.map.get(field)?.values.get(&frame).map(String::as_str)
    }

    pub fn status(&self, field: &str) -> FieldStatus {
        match self.map.get(field) {
            Some(e) if e.error.is_some() => {
                FieldStatus::Failed(e.error.clone().unwrap_or_default())
            }
            Some(e) if e.pending.is_some() && e.fetched_rows.is_none() => FieldStatus::Loading,
            _ => FieldStatus::Ready,
        }
    }

    /// Forget everything (new capture); fields are fetched again on demand.
    pub fn clear(&mut self) {
        self.map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(c: &mut CustomCols, rows: usize, now: f64) -> Vec<PacketsAction> {
        let mut out = vec![];
        c.request(&["ip.ttl".to_owned()], rows, now, &mut out);
        out
    }

    #[test]
    fn fetches_once_then_refreshes_when_rows_grow_throttled() {
        let mut c = CustomCols::default();
        assert!(
            req(&mut c, 0, 0.0).is_empty(),
            "nothing to fetch for an empty table"
        );
        let out = req(&mut c, 10, 0.0);
        let [PacketsAction::RunFields { id, fields, filter }] = &out[..] else {
            panic!("{out:?}")
        };
        assert!(is_custom_id(*id) && filter.is_empty() && fields == &["ip.ttl"]);
        assert_eq!(c.status("ip.ttl"), FieldStatus::Loading);
        assert!(req(&mut c, 10, 5.0).is_empty(), "already pending");
        let id = *id;
        assert!(!c.on_result(id + 1, &Ok(vec![])));
        let frames = vec![(1, vec!["64".to_owned()]), (2, vec![String::new()])];
        assert!(c.on_result(id, &Ok(frames)));
        assert_eq!(c.get("ip.ttl", 1), Some("64"));
        assert_eq!(c.get("ip.ttl", 2), None);
        assert_eq!(c.status("ip.ttl"), FieldStatus::Ready);
        assert!(req(&mut c, 10, 1.0).is_empty(), "up to date");
        assert!(req(&mut c, 12, 1.5).is_empty(), "throttled");
        assert_eq!(req(&mut c, 12, 4.0).len(), 1, "rows grew");
    }

    #[test]
    fn errors_stop_retries_until_cleared() {
        let mut c = CustomCols::default();
        let id = match &req(&mut c, 3, 0.0)[..] {
            [PacketsAction::RunFields { id, .. }] => *id,
            o => panic!("{o:?}"),
        };
        assert!(c.on_result(id, &Err("bad".into())));
        assert_eq!(c.status("ip.ttl"), FieldStatus::Failed("bad".into()));
        assert!(req(&mut c, 3, 100.0).is_empty());
        c.clear();
        assert_eq!(req(&mut c, 3, 100.0).len(), 1);
        c.clear();
        assert_eq!(c.get("ip.ttl", 1), None);
    }
}
