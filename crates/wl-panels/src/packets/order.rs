//! Parallel, cache-friendly construction of the visible row order (filter + sort).
//! Pure functions over `&[PacketRow]`; `TableState` owns the results.

use std::cmp::Ordering;

use rayon::prelude::*;
use wl_model::PacketRow;

use crate::packets::columns::Col;

/// Below this many rows the sequential path wins (thread hand-off costs more than the work).
const PAR_MIN: usize = 20_000;

/// Case-insensitive substring test; `needle` must already be lowercase.
pub fn contains_ci(hay: &str, needle: &str) -> bool {
    if needle.is_ascii() {
        let (h, n) = (hay.as_bytes(), needle.as_bytes());
        h.len() >= n.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
    } else {
        hay.to_lowercase().contains(needle)
    }
}

pub fn matches(r: &PacketRow, quick: &str) -> bool {
    quick.is_empty()
        || [&r.info, &r.src, &r.dst, &r.protocol]
            .iter()
            .any(|s| contains_ci(s, quick))
}

/// Indices (into `rows`) of the rows in `range` that match `quick`, in ascending order.
pub fn filter_range(rows: &[PacketRow], range: std::ops::Range<usize>, quick: &str) -> Vec<u32> {
    if quick.is_empty() {
        return range.map(|i| i as u32).collect();
    }
    let keep = |&i: &usize| matches(&rows[i], quick).then_some(i as u32);
    if range.len() < PAR_MIN {
        range.filter_map(|i| keep(&i)).collect()
    } else {
        range.into_par_iter().filter_map(|i| keep(&i)).collect()
    }
}

/// Order-preserving u64 image of an f64 (`total_cmp` order).
fn f64_key(x: f64) -> u64 {
    let b = x.to_bits() as i64;
    ((b ^ (((b >> 63) as u64) >> 1) as i64) as u64) ^ (1 << 63)
}

fn numeric_key(col: Col, r: &PacketRow) -> Option<u64> {
    match col {
        Col::No => Some(r.no),
        Col::Time => Some(f64_key(r.rel)),
        Col::Length => Some(u64::from(r.len)),
        _ => None,
    }
}

/// Sorts `order` by `col` (ties broken by row index); `asc == false` reverses the result.
pub fn sort(rows: &[PacketRow], order: &mut [u32], col: Col, asc: bool) {
    if rows.first().and_then(|r| numeric_key(col, r)).is_some() {
        let mut keyed: Vec<(u64, u32)> = order
            .iter()
            .map(|&i| (numeric_key(col, &rows[i as usize]).unwrap_or(0), i))
            .collect();
        if keyed.len() < PAR_MIN {
            keyed.sort_unstable();
        } else {
            keyed.par_sort_unstable();
        }
        for (o, (_, i)) in order.iter_mut().zip(keyed) {
            *o = i;
        }
    } else {
        sort_strings(rows, order, col);
    }
    if !asc {
        order.reverse();
    }
}

fn text(col: Col, r: &PacketRow) -> &str {
    match col {
        Col::Source => &r.src,
        Col::Destination => &r.dst,
        Col::Protocol => &r.protocol,
        _ => &r.info,
    }
}

/// First 16 bytes, zero padded, big endian: monotone w.r.t. bytewise `str` ordering.
fn prefix_key(s: &str) -> u128 {
    let mut b = [0u8; 16];
    let n = s.len().min(16);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    u128::from_be_bytes(b)
}

/// String sort: sort cheap `(prefix, idx)` pairs first, then fix up runs sharing a prefix with
/// the full comparison. Avoids a cache miss per comparison in the common case.
fn sort_strings(rows: &[PacketRow], order: &mut [u32], col: Col) {
    let key = |&i: &u32| (prefix_key(text(col, &rows[i as usize])), i);
    let mut keyed: Vec<(u128, u32)> = if order.len() < PAR_MIN {
        order.iter().map(key).collect()
    } else {
        order.par_iter().map(key).collect()
    };
    if keyed.len() < PAR_MIN {
        keyed.sort_unstable();
    } else {
        keyed.par_sort_unstable();
    }
    for (o, (_, i)) in order.iter_mut().zip(&keyed) {
        *o = *i;
    }
    let full = |&a: &u32, &b: &u32| {
        text(col, &rows[a as usize])
            .cmp(text(col, &rows[b as usize]))
            .then(a.cmp(&b))
    };
    let mut start = 0;
    while start < keyed.len() {
        let end = start + keyed[start..].partition_point(|k| k.0 == keyed[start].0);
        if end - start > 1 {
            let run = &mut order[start..end];
            if run.len() < PAR_MIN {
                run.sort_unstable_by(full);
            } else {
                run.par_sort_unstable_by(full);
            }
        }
        start = end;
    }
}

/// Merges rows `base..` (already filtered into `fresh`) into the sorted `order`.
pub fn merge_sorted(
    rows: &[PacketRow],
    order: &mut Vec<u32>,
    mut fresh: Vec<u32>,
    col: Col,
    asc: bool,
) {
    sort(rows, &mut fresh, col, asc);
    let cmp = |a: u32, b: u32| {
        let o = col
            .compare(&rows[a as usize], &rows[b as usize])
            .then(a.cmp(&b));
        if asc { o } else { o.reverse() }
    };
    let old = std::mem::take(order);
    order.reserve(old.len() + fresh.len());
    let (mut i, mut j) = (0, 0);
    while i < old.len() && j < fresh.len() {
        if cmp(old[i], fresh[j]) == Ordering::Greater {
            order.push(fresh[j]);
            j += 1;
        } else {
            order.push(old[i]);
            i += 1;
        }
    }
    order.extend_from_slice(&old[i..]);
    order.extend_from_slice(&fresh[j..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f64_key_matches_total_cmp() {
        let v = [-1e9, -2.5, -0.0, 0.0, 1e-9, 3.0, 1e12];
        for a in v {
            for b in v {
                assert_eq!(f64_key(a).cmp(&f64_key(b)), a.total_cmp(&b));
            }
        }
    }
}
