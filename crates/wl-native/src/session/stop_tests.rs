use std::time::{Duration, Instant};

use wl_model::{CaptureEvent, Session};

use super::test_support::*;
use crate::test_util::{collect, numbered_frames};

/// More batches than the channel holds, so the worker blocks until the consumer reads.
const BIG: usize = 40_000;

fn big_file(dir: &std::path::Path) -> std::path::PathBuf {
    pcap_file(dir, &numbered_frames(BIG))
}

#[test]
fn stop_midway_ends_the_thread_and_sends_no_terminal_event() {
    let _g = serial();
    let before = worker_threads();
    let dir = tempfile::tempdir().expect("dir");
    let mut session = started(&big_file(dir.path()));
    let first = session
        .events
        .recv_timeout(Duration::from_secs(5))
        .expect("rows");
    assert!(matches!(first, CaptureEvent::Rows(_)));
    let t = Instant::now();
    (session.stop)();
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "stop took {:?}",
        t.elapsed()
    );
    assert_eq!(worker_threads(), before);
    let rest = collect(&session);
    assert!(rest.terminals.is_empty(), "{:?}", rest.terminals);
    assert!(rest.rows().len() < BIG);
}

#[test]
fn stop_is_idempotent() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let mut session = started(&big_file(dir.path()));
    (session.stop)();
    (session.stop)();
}

#[test]
fn stop_after_finish_is_harmless() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let mut session = started(&pcap_file(dir.path(), &numbered_frames(10)));
    assert_eq!(collect(&session).terminals.len(), 1);
    (session.stop)();
}

#[test]
fn dropping_the_receiver_ends_the_thread() {
    let _g = serial();
    let Some(before) = worker_threads() else {
        return;
    };
    let dir = tempfile::tempdir().expect("dir");
    let session = started(&big_file(dir.path()));
    let Session { events, stop, .. } = session;
    events
        .recv_timeout(Duration::from_secs(5))
        .expect("first batch");
    wait_until("worker is blocked or running", || {
        worker_threads() == Some(before + 1)
    });
    drop(events);
    wait_until("worker ends after the receiver is dropped", || {
        worker_threads() == Some(before)
    });
    drop(stop);
}

#[test]
fn dropping_the_session_joins_the_thread() {
    let _g = serial();
    let Some(before) = worker_threads() else {
        return;
    };
    let dir = tempfile::tempdir().expect("dir");
    let session = started(&big_file(dir.path()));
    wait_until("worker runs", || worker_threads() == Some(before + 1));
    let t = Instant::now();
    drop(session);
    assert!(t.elapsed() < Duration::from_secs(1));
    assert_eq!(worker_threads(), Some(before));
}

#[test]
fn a_slow_consumer_holds_the_worker_at_the_channel_capacity() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let session = started(&big_file(dir.path()));
    wait_until("channel fills", || session.events.len() == 64);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(session.events.len(), 64, "the worker kept producing");
    assert!(!session.events.is_empty());
    let mut consumed = 0;
    let mut deepest = 0;
    loop {
        deepest = deepest.max(session.events.len());
        match session
            .events
            .recv_timeout(Duration::from_secs(5))
            .expect("event")
        {
            CaptureEvent::Rows(r) => consumed += r.len(),
            CaptureEvent::Finished => break,
            CaptureEvent::Failed(e) => panic!("{e}"),
        }
    }
    assert_eq!(consumed, BIG);
    assert!(deepest <= 64);
}
