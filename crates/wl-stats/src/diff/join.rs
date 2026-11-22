use std::collections::BTreeMap;

use super::model::{Metric, Row};

pub type Side<V> = BTreeMap<String, V>;

/// Full outer join of two labelled sides, unchanged items dropped, biggest movement first.
pub fn rows<V: Metric>(before: Side<V>, mut after: Side<V>) -> Vec<Row<V>> {
    let mut out: Vec<Row<V>> = Vec::new();
    for (label, b) in before {
        let a = after.remove(&label);
        if a.is_none_or(|a| !a.same(&b)) {
            out.push(Row {
                label,
                before: Some(b),
                after: a,
            });
        }
    }
    out.extend(after.into_iter().map(|(label, a)| Row {
        label,
        before: None,
        after: Some(a),
    }));
    out.sort_by(|x, y| y.movement().cmp(&x.movement()).then(x.label.cmp(&y.label)));
    out
}

/// Sums `value` per label.
pub fn tally<T, V: Default>(
    items: impl IntoIterator<Item = T>,
    mut key: impl FnMut(&T) -> Option<String>,
    mut add: impl FnMut(&mut V, &T),
) -> Side<V> {
    let mut side = Side::new();
    for item in items {
        if let Some(k) = key(&item) {
            add(side.entry(k).or_default(), &item);
        }
    }
    side
}
