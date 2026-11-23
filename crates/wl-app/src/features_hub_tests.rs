use eframe::egui;
use wl_model::{BehaviorData, ExpertReport, PacketBookmark, ProtocolHierarchy, SecurityData};

use super::*;

fn hub() -> FeaturesHub {
    let no_tshark = Arc::new(wl_hybrid::Lazy::new(|| {
        Err(CaptureError::ToolMissing("test".into()))
    }));
    FeaturesHub::new(no_tshark, Wireshark::Missing, egui::Context::default())
}

fn comment(frame_no: u64, text: &str) -> Msg {
    Msg::Comments(vec![PacketBookmark {
        frame_no,
        comment: text.into(),
    }])
}

#[test]
fn results_of_the_previous_capture_are_dropped() {
    let mut h = hub();
    let old = Some(h.generation);
    h.clear_capture();
    let empty = || SecurityData {
        credentials: Vec::new(),
        tls: Vec::new(),
    };
    h.tx.send((old, Msg::Security(Analysis::Ready(empty()))))
        .unwrap();
    h.tx.send((old, comment(1, "from the old file"))).unwrap();
    h.tx.send((Some(h.generation), Msg::Security(Analysis::Ready(empty()))))
        .unwrap();
    h.poll();
    assert!(h.analyses.security.ready().is_some());
    assert!(h.bookmarks.is_empty());
}

#[test]
fn imported_comments_only_fill_empty_bookmarks() {
    let mut h = hub();
    h.bookmarks.set(3, "typed by the user");
    h.bookmarks.toggle(4);
    h.tx.send((Some(h.generation), comment(3, "imported")))
        .unwrap();
    h.tx.send((Some(h.generation), comment(4, "imported")))
        .unwrap();
    h.poll();
    assert_eq!(h.bookmarks.comment(3), Some("typed by the user"));
    assert_eq!(h.bookmarks.comment(4), Some("imported"));
}

#[test]
fn a_new_capture_starts_without_the_old_bookmarks() {
    let mut h = hub();
    h.bookmarks.set(3, "x");
    h.clear_capture();
    assert!(h.bookmarks.is_empty());
}

fn stats() -> StatsSnapshot {
    StatsSnapshot {
        total_packets: 1523,
        ..Default::default()
    }
}

fn finished() -> Analyses {
    Analyses {
        expert: Analysis::Ready(ExpertReport::default()),
        hierarchy: Analysis::Ready(ProtocolHierarchy::default()),
        behavior: Analysis::Ready(BehaviorData::default()),
        security: Analysis::Ready(SecurityData::default()),
    }
}

fn deliver(h: &mut FeaturesHub, msg: Msg) {
    h.tx.send((Some(h.generation), msg)).unwrap();
    h.poll();
}

#[test]
fn a_report_without_wireshark_carries_no_findings_and_no_all_clear() {
    let mut h = hub();
    h.analyses = finished();
    assert!(h.insights_for(&stats()).is_empty());
}

#[test]
fn a_report_carries_the_all_clear_only_when_every_analysis_finished() {
    let mut h = hub();
    h.wireshark = Wireshark::Available;
    h.analyses = finished();
    assert_eq!(h.insights_for(&stats()).len(), 1);
    for broken in [
        |a: &mut Analyses| a.expert = Analysis::Failed("boom".into()),
        |a: &mut Analyses| a.security = Analysis::Pending,
        |a: &mut Analyses| a.behavior = Analysis::Idle,
    ] {
        h.analyses = finished();
        broken(&mut h.analyses);
        assert!(h.insights_for(&stats()).is_empty());
    }
}

#[test]
fn enrichment_without_wireshark_stays_quiet() {
    let mut h = hub();
    h.refresh_insights(std::path::PathBuf::from("x.pcap"), egui::Context::default());
    std::thread::sleep(std::time::Duration::from_millis(100));
    h.poll();
    assert!(h.error.is_none() && h.notice.is_none());
    assert!(h.analyses.failures().is_empty());
    assert!(h.analyses.expert.ready().is_none());
}

#[test]
fn a_new_capture_starts_with_nothing_analysed() {
    let mut h = hub();
    h.analyses = finished();
    h.clear_capture();
    assert_eq!(h.analyses, Analyses::default());
}

#[test]
fn re_analysing_starts_every_analysis_again() {
    let mut h = hub();
    h.analyses = finished();
    h.analyses.expert = Analysis::Failed("boom".into());
    h.refresh_insights(std::path::PathBuf::from("x.pcap"), egui::Context::default());
    assert!(h.analyses.any_pending());
    assert!(h.analyses.failures().is_empty());
}

#[test]
fn a_failed_analysis_reaches_the_state_and_leaves_the_others_alone() {
    let mut h = hub();
    h.analyses.start();
    deliver(
        &mut h,
        jobs::insights(
            Err(CaptureError::Other("tshark exited with status 2".into())),
            Ok(ProtocolHierarchy::default()),
        ),
    );
    assert_eq!(
        h.analyses.expert.failure(),
        Some("tshark exited with status 2")
    );
    assert!(h.analyses.hierarchy.ready().is_some());
    assert!(h.analyses.behavior.is_pending());
}

#[test]
fn a_failure_from_the_previous_capture_is_dropped() {
    let mut h = hub();
    let old = Some(h.generation);
    h.clear_capture();
    h.analyses.start();
    h.tx.send((
        old,
        jobs::insights(
            Err(CaptureError::Other("old".into())),
            Err(CaptureError::Other("old".into())),
        ),
    ))
    .unwrap();
    h.poll();
    assert!(h.analyses.failures().is_empty());
    assert!(h.analyses.expert.is_pending());
}

#[test]
fn a_tshark_that_cannot_start_fails_what_is_waiting_for_it() {
    let mut h = hub();
    h.analyses.start();
    deliver(
        &mut h,
        jobs::insights(
            Ok(ExpertReport::default()),
            Ok(ProtocolHierarchy::default()),
        ),
    );
    deliver(
        &mut h,
        Msg::Unavailable("could not create the scratch directory".into()),
    );
    assert!(h.analyses.expert.ready().is_some());
    assert_eq!(
        h.analyses.behavior.failure(),
        Some("could not create the scratch directory")
    );
    assert_eq!(
        h.analyses.security.failure(),
        Some("could not create the scratch directory")
    );
}

#[test]
fn a_retry_after_a_failure_can_succeed() {
    let mut h = hub();
    h.analyses.start();
    deliver(
        &mut h,
        jobs::insights(
            Err(CaptureError::Other("x".into())),
            Ok(ProtocolHierarchy::default()),
        ),
    );
    assert!(h.analyses.expert.failure().is_some());
    h.analyses.start();
    assert!(h.analyses.expert.is_pending());
    deliver(
        &mut h,
        jobs::insights(
            Ok(ExpertReport::default()),
            Ok(ProtocolHierarchy::default()),
        ),
    );
    assert!(h.analyses.expert.ready().is_some());
}
