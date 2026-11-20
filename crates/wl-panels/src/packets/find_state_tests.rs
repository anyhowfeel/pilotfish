//! Find Packet state machine tests.

use super::*;
use crate::packets::find_query::{FindMode, FindScope};
use wl_model::{PacketRow, Transport};

fn row(no: u64, info: &str) -> PacketRow {
    PacketRow {
        no,
        epoch: 0.0,
        rel: 0.0,
        src: "a".into(),
        dst: "b".into(),
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        transport: Transport::Tcp,
        protocol: "TCP".into(),
        len: 1,
        info: info.into(),
        stream: None,
    }
}

fn table() -> PacketTable {
    let mut t = PacketTable::default();
    t.push_rows(
        (1..=6)
            .map(|n| row(n, if n % 2 == 0 { "even" } else { "odd" }))
            .collect(),
    );
    t
}

#[test]
fn pick_wraps_both_ways() {
    let f = [2, 4, 6];
    assert_eq!(pick(&f, Some(2), true), Some(1));
    assert_eq!(pick(&f, Some(6), true), Some(0));
    assert_eq!(pick(&f, Some(3), true), Some(1));
    assert_eq!(pick(&f, Some(4), false), Some(0));
    assert_eq!(pick(&f, Some(2), false), Some(2));
    assert_eq!(pick(&f, None, false), Some(2));
    assert_eq!(pick(&[], None, true), None);
}

#[test]
fn local_search_steps_and_selects() {
    let mut t = table();
    let mut s = FindState::default();
    s.query.text = "even".into();
    let mut out = vec![];
    s.step(true, &mut t, &mut out);
    assert_eq!(out, [PacketsAction::Select(2)]);
    assert_eq!(
        s.status,
        Status::Found {
            index: 1,
            total: 3,
            capped: false
        }
    );
    s.step(true, &mut t, &mut out);
    assert_eq!(t.selected(), Some(4));
    s.step(false, &mut t, &mut out);
    assert_eq!(t.selected(), Some(2));
    s.query.text = "nothing".into();
    s.step(true, &mut t, &mut out);
    assert_eq!(s.status, Status::NotFound);
}

#[test]
fn backend_search_requests_then_jumps_and_caches() {
    let mut t = table();
    let mut s = FindState {
        query: FindQuery {
            mode: FindMode::Text,
            scope: FindScope::Bytes,
            case_sensitive: true,
            text: "x".into(),
        },
        ..FindState::default()
    };
    let mut out = vec![];
    s.step(true, &mut t, &mut out);
    let [PacketsAction::RunFields { id, filter, .. }] = &out[..] else {
        panic!("{out:?}")
    };
    assert_eq!(filter, r#"frame contains "x""#);
    assert_eq!(s.status, Status::Searching);
    let id = *id;
    assert!(!s.on_result(id + 9, &Ok(vec![]), &mut t, &mut vec![]));
    let hits = Ok(vec![(5, vec![]), (3, vec![])]);
    out.clear();
    assert!(s.on_result(id, &hits, &mut t, &mut out));
    assert_eq!(out, [PacketsAction::Select(3)]);
    assert_eq!(
        s.status,
        Status::Found {
            index: 1,
            total: 2,
            capped: false
        }
    );
    out.clear();
    s.step(true, &mut t, &mut out);
    assert_eq!(out, [PacketsAction::Select(5)], "cached: no new request");
    s.invalidate();
    assert_eq!(s.status, Status::Idle);
    s.step(true, &mut t, &mut out);
    assert!(matches!(out.last(), Some(PacketsAction::RunFields { .. })));
    let err = Err("boom".to_owned());
    let id2 = s.next_id;
    s.on_result(id2, &err, &mut t, &mut vec![]);
    assert_eq!(s.status, Status::Error("boom".into()));
}
