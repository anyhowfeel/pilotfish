//! Unit tests for `TableState`.

use crate::packets::columns::Col;
use crate::packets::table_state::*;
use wl_model::{PacketRow, Transport};

fn row(no: u64, len: u32, info: &str) -> PacketRow {
    PacketRow {
        no,
        epoch: 0.0,
        rel: no as f64,
        src: "10.0.0.1".into(),
        dst: "10.0.0.2".into(),
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        transport: Transport::Tcp,
        protocol: "TCP".into(),
        len,
        info: info.into(),
        stream: None,
    }
}

fn state() -> TableState {
    let mut s = TableState::default();
    s.push_rows(vec![
        row(1, 30, "SYN"),
        row(2, 10, "ACK"),
        row(3, 20, "Hello World"),
    ]);
    s
}

fn nos(s: &TableState) -> Vec<u64> {
    (0..s.visible()).map(|i| s.row_at(i).unwrap().no).collect()
}

#[test]
fn sort_cycles_and_orders() {
    let mut s = state();
    s.cycle_sort(Col::Length);
    assert_eq!(nos(&s), [2, 3, 1]);
    s.cycle_sort(Col::Length);
    assert_eq!(nos(&s), [1, 3, 2]);
    s.cycle_sort(Col::Length);
    assert_eq!(nos(&s), [1, 2, 3]);
}

#[test]
fn quick_search_is_case_insensitive() {
    let mut s = state();
    s.set_quick("hello");
    assert_eq!(nos(&s), [3]);
    s.push_rows(vec![row(4, 1, "say HELLO")]);
    assert_eq!(nos(&s), [3, 4]);
    s.set_quick("");
    assert_eq!(s.visible(), 4);
}

#[test]
fn navigation_clamps_and_tracks_selection_through_sort() {
    let mut s = state();
    assert_eq!(s.navigate(Nav::Down), Some(1));
    assert_eq!(s.navigate(Nav::Up), Some(1));
    assert_eq!(s.navigate(Nav::End), Some(3));
    assert_eq!(s.navigate(Nav::PageUp(10)), Some(1));
    s.select_pos(2);
    s.cycle_sort(Col::Length);
    assert_eq!(s.selected(), Some(3));
    assert_eq!(s.selected_pos(), Some(1));
}

#[test]
fn live_rows_append_without_shuffling_until_resort_and_clear_keeps_prefs() {
    let mut s = state();
    s.cycle_sort(Col::Length);
    let before = nos(&s);
    s.push_rows(vec![row(4, 5, "x")]);
    let mut expect = before.clone();
    expect.push(4);
    assert_eq!(
        nos(&s),
        expect,
        "existing rows must not move while streaming"
    );
    s.resort();
    assert_eq!(nos(&s), [4, 2, 3, 1]);
    s.clear();
    assert_eq!(s.total(), 0);
    assert!(s.sort().is_some());
    assert!(s.row_by_no(1).is_none());
}

#[test]
fn lookup_by_frame_number() {
    let s = state();
    assert_eq!(s.row_by_no(2).unwrap().len, 10);
    assert!(s.row_by_no(9).is_none());
}

#[test]
fn sparse_and_unsorted_frame_numbers_lookup_correctly() {
    let mut sparse = TableState::default();
    sparse.push_rows(vec![row(5, 30, "a"), row(12, 10, "b"), row(100, 20, "c")]);
    assert_eq!(sparse.row_by_no(12).unwrap().len, 10);
    assert_eq!(sparse.pos_by_no(100), Some(2));
    assert!(sparse.row_by_no(13).is_none());
    assert!(sparse.pos_by_no(13).is_none());
    sparse.cycle_sort(Col::Length);
    assert_eq!(sparse.pos_by_no(12), Some(0));
    assert_eq!(sparse.pos_by_no(5), Some(2));

    let mut unsorted = TableState::default();
    unsorted.push_rows(vec![row(10, 1, "x"), row(3, 2, "y"), row(7, 3, "z")]);
    assert_eq!(unsorted.row_by_no(3).unwrap().len, 2);
    assert_eq!(unsorted.row_by_no(10).unwrap().len, 1);
    assert_eq!(unsorted.pos_by_no(3), Some(1));
    assert_eq!(unsorted.pos_by_no(7), Some(2));
}

#[test]
fn selection_survives_quick_search_and_empty_nav() {
    let mut empty = TableState::default();
    assert_eq!(empty.navigate(Nav::Down), None);
    assert_eq!(empty.select_pos(0), None);

    let mut s = state();
    assert_eq!(s.select_pos(1), Some(2));
    s.set_quick("hello");
    assert_eq!(s.selected(), Some(2));
    assert_eq!(s.selected_pos(), None);
    // Clearing quick search restores selection position.
    s.set_quick("");
    assert_eq!(s.selected(), Some(2));
    assert_eq!(s.selected_pos(), Some(1));
    // Navigating while selection is hidden picks a visible row.
    s.set_quick("hello");
    assert_eq!(s.navigate(Nav::Down), Some(3));
    assert_eq!(s.selected_pos(), Some(0));
}

fn big(n: u64) -> Vec<PacketRow> {
    (1..=n)
        .map(|i| {
            row(
                i,
                ((i * 7919) % 1500) as u32,
                &format!("shared long prefix info {}", (i * 31) % 997),
            )
        })
        .collect()
}

#[test]
fn incremental_merge_equals_full_sort_across_parallel_threshold() {
    for col in [Col::Length, Col::Info, Col::Time] {
        let mut inc = TableState::default();
        inc.push_rows(big(30_000));
        inc.cycle_sort(col);
        let more: Vec<_> = big(35_000).split_off(30_000);
        inc.push_rows(more);
        inc.resort();
        let mut full = TableState::default();
        full.push_rows(big(35_000));
        full.cycle_sort(col);
        assert_eq!(nos(&inc), nos(&full), "{col:?}");
        inc.cycle_sort(col);
        full.cycle_sort(col);
        assert_eq!(nos(&inc), nos(&full), "{col:?} desc");
    }
}

#[test]
fn parallel_quick_search_matches_sequential_semantics() {
    let mut s = TableState::default();
    s.push_rows(big(40_000));
    s.set_quick("INFO 99");
    let expect = (1..=40_000u64)
        .filter(|i| format!("shared long prefix info {}", (i * 31) % 997).contains("info 99"));
    assert_eq!(nos(&s), expect.collect::<Vec<_>>());
}

/// Manual benchmark: `cargo test -p wl-panels --release -- --ignored --nocapture bench_1m`.
#[test]
#[ignore]
fn bench_1m_rows_sort_and_search() {
    use std::time::Instant;
    let rows: Vec<PacketRow> = (1..=1_000_000u64)
        .map(|i| {
            row(
                i,
                ((i * 7919) % 1500) as u32,
                &format!(
                    "{} -> 443 [ACK] Seq={} Ack=1 Win=502 Len=0",
                    40000 + i % 20000,
                    i * 13
                ),
            )
        })
        .collect();
    let mut s = TableState::default();
    s.push_rows(rows);
    for col in [Col::Info, Col::Length, Col::Time, Col::Source] {
        let t = Instant::now();
        s.cycle_sort(col);
        println!("sort {col:?}: {:?}", t.elapsed());
    }
    let t = Instant::now();
    s.set_quick("seq=9999");
    println!("quick: {:?} -> {}", t.elapsed(), s.visible());
}
