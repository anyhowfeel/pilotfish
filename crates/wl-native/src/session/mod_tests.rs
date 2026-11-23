use wl_model::CaptureEvent;

use super::test_support::*;
use super::{BATCH_ROWS, start_file};
use crate::test_util::{numbered_frames, sample_frames, write_pcapng};

#[test]
fn pcap_rows_arrive_in_order_and_equal_the_decoder_output() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = pcap_file(dir.path(), &sample_frames());
    let got = run(&path).expect("start");
    let rows = got.rows();
    assert_eq!(rows, expected_rows(&path));
    assert_eq!(rows.len(), sample_frames().len());
    let numbers: Vec<u64> = rows.iter().map(|r| r.no).collect();
    assert_eq!(numbers, (1..=rows.len() as u64).collect::<Vec<_>>());
    assert_eq!(rows[0].rel, 0.0);
}

#[test]
fn pcapng_rows_equal_the_decoder_output() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("t.pcapng");
    write_pcapng(&path, &sample_frames());
    let got = run(&path).expect("start");
    assert_eq!(got.rows(), expected_rows(&path));
    assert_eq!(got.rows().len(), sample_frames().len());
}

#[test]
fn finished_comes_last_and_exactly_once() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = pcap_file(dir.path(), &numbered_frames(1200));
    let got = run(&path).expect("start");
    assert_eq!(got.terminals.len(), 1);
    assert!(matches!(got.terminals[0], CaptureEvent::Finished));
    assert_eq!(got.after_terminal, 0);
}

#[test]
fn an_empty_capture_finishes_without_rows() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = pcap_file(dir.path(), &[]);
    let got = run(&path).expect("start");
    assert!(got.batches.is_empty());
    assert!(matches!(got.terminals[..], [CaptureEvent::Finished]));
}

#[test]
fn a_large_file_arrives_in_batches_of_at_most_500() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = pcap_file(dir.path(), &numbered_frames(2500));
    let got = run(&path).expect("start");
    assert!(
        got.batches
            .iter()
            .all(|b| !b.is_empty() && b.len() <= BATCH_ROWS)
    );
    assert_eq!(got.rows().len(), 2500);
    assert!(got.batches.len() >= 5);
    assert_eq!(got.rows(), expected_rows(&path));
}

#[test]
fn the_backing_file_is_the_input_path() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = pcap_file(dir.path(), &sample_frames());
    let session = started(&path);
    assert_eq!(session.backing_file, path);
    crate::test_util::collect(&session);
}

#[test]
fn the_worker_thread_is_gone_after_finished() {
    let _g = serial();
    let Some(before) = worker_threads() else {
        return;
    };
    let dir = tempfile::tempdir().expect("dir");
    let path = pcap_file(dir.path(), &numbered_frames(3000));
    let session = started(&path);
    crate::test_util::collect(&session);
    wait_until("worker thread ends", || worker_threads() == Some(before));
    drop(session);
    assert_eq!(worker_threads(), Some(before));
}

#[test]
fn a_blank_filter_means_no_filter() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = pcap_file(dir.path(), &sample_frames());
    let session = start_file(&path, Some("   ")).expect("start");
    assert_eq!(
        crate::test_util::collect(&session).rows().len(),
        sample_frames().len()
    );
}

#[test]
fn a_filter_keeps_file_frame_numbers_and_the_first_frames_time_origin() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = pcap_file(dir.path(), &sample_frames());
    let session = start_file(&path, Some("tcp")).expect("start");
    let rows = crate::test_util::collect(&session).rows();
    let all = expected_rows(&path);
    let tcp: Vec<_> = all
        .iter()
        .filter(|r| r.transport == wl_model::Transport::Tcp)
        .cloned()
        .collect();
    assert!(!tcp.is_empty() && tcp.len() < all.len());
    assert_eq!(rows, tcp);
    assert_eq!(rows[0].no, 2);
    assert!(rows[0].rel > 0.0);
}

#[test]
fn a_filter_the_native_evaluator_cannot_handle_is_a_bad_filter() {
    let dir = tempfile::tempdir().expect("dir");
    let path = pcap_file(dir.path(), &sample_frames());
    let err = start_file(&path, Some("http.request.method == \"GET\"")).err();
    assert!(matches!(err, Some(wl_model::CaptureError::BadFilter(_))));
}
