//! A failed tshark call reaches the page as a failure, never as an empty result.
use super::*;
use wl_model::{ChannelKind, Proto};

fn boom(what: &str) -> CaptureError {
    CaptureError::Other(what.into())
}

fn channel() -> Channel {
    Channel {
        src: "10.0.0.1".into(),
        dst: "10.0.0.2".into(),
        proto: Proto::Tcp,
        kind: ChannelKind::Stream,
        dport: 443,
        count: 3,
        gap_mean: 1.0,
        gap_jitter: 0.1,
    }
}

fn behavior_of(msg: Msg) -> Analysis<BehaviorData> {
    match msg {
        Msg::Behavior(b, _) => b,
        _ => panic!("not a behavior message"),
    }
}

fn security_of(msg: Msg) -> Analysis<SecurityData> {
    match msg {
        Msg::Security(s) => s,
        _ => panic!("not a security message"),
    }
}

#[test]
fn a_failed_expert_info_is_a_failure_and_the_hierarchy_is_unaffected() {
    let Msg::Insights(expert, hierarchy) = insights(
        Err(boom("tshark exited with status 2")),
        Ok(ProtocolHierarchy::default()),
    ) else {
        panic!("not an insights message");
    };
    assert_eq!(expert.failure(), Some("tshark exited with status 2"));
    assert!(hierarchy.ready().is_some());
}

#[test]
fn both_insight_scans_failing_gives_two_failures() {
    let Msg::Insights(expert, hierarchy) = insights(Err(boom("a")), Err(boom("b"))) else {
        panic!("not an insights message");
    };
    assert_eq!(
        (expert.failure(), hierarchy.failure()),
        (Some("a"), Some("b"))
    );
}

#[test]
fn successful_scans_are_ready() {
    let Msg::Insights(expert, hierarchy) = insights(
        Ok(ExpertReport::default()),
        Ok(ProtocolHierarchy::default()),
    ) else {
        panic!("not an insights message");
    };
    assert!(expert.ready().is_some() && hierarchy.ready().is_some());
}

#[test]
fn behavior_needs_channels_and_dns() {
    let ok = behavior_of(behavior(
        Ok(vec![channel()]),
        Ok(Vec::new()),
        Ok(Vec::new()),
        Ok(Vec::new()),
    ));
    assert_eq!(ok.ready().map(|d| d.channels.len()), Some(1));
    for (channels, dns, failed) in [
        (Err(boom("channels")), Ok(Vec::new()), "channels"),
        (Ok(Vec::new()), Err(boom("dns")), "dns"),
    ] {
        let got = behavior_of(behavior(channels, dns, Ok(Vec::new()), Ok(Vec::new())));
        assert_eq!(got.failure(), Some(failed));
    }
}

#[test]
fn failed_tls_and_http_scans_only_cost_name_suggestions() {
    let got = behavior_of(behavior(
        Ok(vec![channel()]),
        Ok(Vec::new()),
        Err(boom("tls")),
        Err(boom("http")),
    ));
    assert!(got.ready().is_some());
}

#[test]
fn a_failed_credential_scan_is_a_failure() {
    let got = security_of(security(Err(boom("no such file")), Ok(Vec::new())));
    assert_eq!(got.failure(), Some("no such file"));
}

#[test]
fn a_failed_tls_scan_is_a_failure_of_the_security_check() {
    let got = security_of(security(Ok(Vec::new()), Err(boom("tls"))));
    assert_eq!(got.failure(), Some("tls"));
}

#[test]
fn a_clean_security_scan_is_ready_and_empty() {
    let got = security_of(security(Ok(Vec::new()), Ok(Vec::new())));
    assert_eq!(got.ready().map(|d| d.credentials.len()), Some(0));
}

#[test]
fn a_panicked_scan_thread_counts_as_a_failed_scan() {
    let result: Scan<Vec<u8>> = std::thread::scope(|s| {
        let handle = s.spawn(|| -> Scan<Vec<u8>> { panic!("scan crashed") });
        join(handle)
    });
    assert!(result.is_err());
}
