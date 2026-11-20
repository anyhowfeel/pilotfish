//! Partial-sort helper: the `n` smallest items under `cmp`, in order.

use std::cmp::Ordering;

/// Streaming selection: O(N) amortised with a buffer of at most `2n` items, so scanning a
/// 100k-entry table touches each item once and rejects most with a single comparison.
pub fn top_n_by<T>(
    items: impl IntoIterator<Item = T>,
    n: usize,
    cmp: impl Fn(&T, &T) -> Ordering + Copy,
) -> Vec<T> {
    if n == 0 {
        return Vec::new();
    }
    let cap = n.saturating_mul(2).max(n.saturating_add(1));
    let mut buf: Vec<T> = Vec::new();
    let mut worst_kept = false;
    for item in items {
        if worst_kept && cmp(&item, &buf[n - 1]) != Ordering::Less {
            continue;
        }
        buf.push(item);
        if buf.len() >= cap {
            buf.select_nth_unstable_by(n - 1, cmp);
            buf.truncate(n);
            // After `select_nth` the n-th element is the cut-off: index n-1 is the worst kept.
            worst_kept = true;
        }
    }
    if buf.len() > n {
        buf.select_nth_unstable_by(n - 1, cmp);
        buf.truncate(n);
    }
    buf.sort_unstable_by(cmp);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_and_orders() {
        let v = vec![5, 1, 9, 3, 7, 2];
        assert_eq!(top_n_by(v.clone(), 3, |a, b| b.cmp(a)), vec![9, 7, 5]);
        assert_eq!(top_n_by(v.clone(), 0, |a, b| b.cmp(a)), Vec::<i32>::new());
        assert_eq!(top_n_by(v, 99, |a, b| a.cmp(b)), vec![1, 2, 3, 5, 7, 9]);
    }

    #[test]
    fn usize_max_means_everything_sorted() {
        let v = vec![3, 1, 2];
        assert_eq!(top_n_by(v, usize::MAX, |a, b| a.cmp(b)), vec![1, 2, 3]);
    }

    #[test]
    fn streaming_matches_full_sort_on_large_input_with_ties() {
        let v: Vec<u32> = (0..50_000u32)
            .map(|i| i.wrapping_mul(2_654_435_761) % 997)
            .collect();
        let mut want = v.clone();
        want.sort_unstable_by(|a, b| b.cmp(a));
        want.truncate(200);
        assert_eq!(top_n_by(v.iter().copied(), 200, |a, b| b.cmp(a)), want);
    }
}
