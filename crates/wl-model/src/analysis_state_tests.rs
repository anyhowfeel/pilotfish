use super::*;

fn ready() -> Analyses {
    Analyses {
        expert: Analysis::Ready(ExpertReport::default()),
        hierarchy: Analysis::Ready(ProtocolHierarchy::default()),
        behavior: Analysis::Ready(BehaviorData::default()),
        security: Analysis::Ready(SecurityData::default()),
    }
}

#[test]
fn nothing_has_run_by_default() {
    let a = Analyses::default();
    assert!(a.any_idle());
    assert!(!a.any_pending());
    assert!(!a.complete());
    assert!(a.failures().is_empty());
}

#[test]
fn start_marks_every_analysis_as_running() {
    let mut a = Analyses::default();
    a.start();
    assert!(a.any_pending());
    assert!(!a.any_idle());
    assert!(!a.complete());
}

#[test]
fn only_four_ready_analyses_are_complete() {
    assert!(ready().complete());
    for broken in [
        |a: &mut Analyses| a.expert = Analysis::Pending,
        |a: &mut Analyses| a.hierarchy = Analysis::Idle,
        |a: &mut Analyses| a.behavior = Analysis::Failed("x".into()),
        |a: &mut Analyses| a.security = Analysis::Failed("x".into()),
    ] {
        let mut a = ready();
        broken(&mut a);
        assert!(!a.complete());
    }
}

#[test]
fn failures_name_what_failed_and_why() {
    let mut a = ready();
    a.expert = Analysis::Failed("tshark exited with status 2".into());
    a.security = Analysis::Failed("no such file".into());
    assert_eq!(
        a.failures(),
        [
            ("Expert info", "tshark exited with status 2"),
            ("Credential scan", "no such file")
        ]
    );
}

#[test]
fn a_result_becomes_ready_or_failed() {
    let ok: Analysis<u8> = Ok(7).into();
    assert_eq!(ok.ready(), Some(&7));
    let err: Analysis<u8> = Err(CaptureError::Other("boom".into())).into();
    assert_eq!(err.failure(), Some("boom"));
    assert_eq!(err.ready(), None);
}

#[test]
fn a_missing_tool_reads_as_a_failure_reason() {
    let err: Analysis<u8> = Err(CaptureError::ToolMissing("tshark".into())).into();
    assert!(err.failure().is_some_and(|r| r.contains("Wireshark")));
}

#[test]
fn fail_pending_spares_what_already_finished() {
    let mut a = ready();
    a.expert = Analysis::Pending;
    a.security = Analysis::Pending;
    a.fail_pending("tshark could not start");
    assert_eq!(
        a.failures(),
        [
            ("Expert info", "tshark could not start"),
            ("Credential scan", "tshark could not start")
        ]
    );
    assert!(a.hierarchy.ready().is_some() && a.behavior.ready().is_some());
}

#[test]
fn fail_pending_leaves_idle_analyses_alone() {
    let mut a = Analyses::default();
    a.fail_pending("x");
    assert!(a.failures().is_empty());
    assert!(a.any_idle());
}
