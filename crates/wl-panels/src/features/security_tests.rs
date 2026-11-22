use std::sync::Arc;

use wl_model::{
    BehaviorData, CredKind, Credential, DnsQuery, HostStat, InsightSeverity, SecurityData,
    StatsSnapshot, ThreatIntel, TlsSession,
};

use super::*;
use crate::features::{InsightContext, synthesize_insights};
use crate::insights::InsightRules;

fn cred(kind: CredKind, frame: u64, user: Option<&str>, secret: Option<&str>) -> Credential {
    Credential {
        kind,
        frame,
        src: "10.0.0.2".into(),
        dst: "10.0.0.80".into(),
        user: user.map(Into::into),
        secret: secret.map(Into::into),
        field: None,
    }
}

fn dns(name: &str) -> DnsQuery {
    DnsQuery {
        frame: 1,
        response_frame: None,
        rel: 0.0,
        client: "10.0.0.1".into(),
        server: "10.0.0.2".into(),
        name: name.into(),
        qtype: "A".into(),
        rcode: None,
        answers: Vec::new(),
        rtt_ms: None,
        retransmission: false,
    }
}

fn tls(sni: &str, ja3: &str, ja4: &str) -> TlsSession {
    TlsSession {
        stream: None,
        first_frame: 1,
        start_rel: 0.0,
        start_epoch: None,
        server_name: sni.into(),
        version: "TLS 1.3".into(),
        cipher: None,
        alpn: None,
        cert_subject: None,
        certs: Vec::new(),
        ja3: Some(ja3.into()),
        ja4: Some(ja4.into()),
        ja3s: None,
        src: "10.0.0.2".into(),
        dst: "93.184.216.34".into(),
        bytes: 0,
        client: None,
        threat: None,
    }
}

fn host(addr: &str, packets: u64) -> HostStat {
    HostStat {
        addr: Arc::from(addr),
        packets_in: packets,
        ..Default::default()
    }
}

fn run(
    sec: Option<&SecurityData>,
    intel: &ThreatIntel,
    hosts: &[HostStat],
    names: &[DnsQuery],
    reveal: bool,
) -> Vec<HealthInsight> {
    let mut out = Vec::new();
    let inp = Inputs {
        security: sec,
        intel,
        hosts,
        dns: names,
        reveal_secrets: reveal,
    };
    detect(&inp, &mut out);
    out
}

fn creds(c: Vec<Credential>, reveal: bool) -> Vec<HealthInsight> {
    let sec = SecurityData {
        credentials: c,
        tls: Vec::new(),
    };
    run(Some(&sec), &ThreatIntel::default(), &[], &[], reveal)
}

#[test]
fn secrets_are_masked_by_default() {
    let out = creds(
        vec![cred(
            CredKind::HttpBasic,
            3,
            Some("alice"),
            Some("s3cretPass"),
        )],
        false,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, InsightSeverity::Critical);
    assert!(
        out[0]
            .title
            .starts_with("Cleartext HTTP Basic login: 10.0.0.2 to 10.0.0.80")
    );
    assert!(out[0].explanation.contains("user alice"));
    assert!(out[0].explanation.contains("**** (10 chars)"));
    assert!(!out[0].explanation.contains("s3cretPass"));
    assert_eq!(
        out[0].suggested_filter.as_deref(),
        Some("frame.number in {3}")
    );
}

#[test]
fn revealing_shows_the_secret() {
    let out = creds(
        vec![cred(CredKind::Ftp, 1, Some("bob"), Some("hunter2"))],
        true,
    );
    assert!(out[0].explanation.contains("secret hunter2"));
}

#[test]
fn same_kind_and_endpoints_share_one_card() {
    let c: Vec<_> = (1..=5)
        .map(|f| cred(CredKind::Ftp, f, Some("bob"), Some("pw12345")))
        .collect();
    let out = creds(c, false);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metric, "5 found");
    assert!(out[0].explanation.contains("and 2 more"));
    assert_eq!(
        out[0].suggested_filter.as_deref(),
        Some("frame.number in {1 2 3 4 5}")
    );
}

#[test]
fn ntlm_and_tokens_are_warnings_and_come_after_passwords() {
    let out = creds(
        vec![
            cred(CredKind::Ntlm, 1, Some("CORP\\alice"), None),
            cred(CredKind::ApiKey, 2, None, Some("abcdefgh")),
            cred(CredKind::Pop3, 3, Some("erin"), Some("pw")),
        ],
        false,
    );
    let sev: Vec<_> = out.iter().map(|f| f.severity).collect();
    assert_eq!(sev[0], InsightSeverity::Critical);
    assert!(sev[1..].iter().all(|s| *s == InsightSeverity::Warning));
    assert!(
        out.iter()
            .any(|f| f.explanation.contains("user CORP\\alice"))
    );
}

#[test]
fn many_frames_are_capped_in_the_filter() {
    let c: Vec<_> = (1..=40)
        .map(|f| cred(CredKind::Smtp, f, None, Some("x")))
        .collect();
    let out = creds(c, false);
    let flt = out[0].suggested_filter.as_deref().unwrap();
    assert_eq!(flt, "frame.number in {1 2 3 4 5 6 7 8 9 10}");
}

#[path = "security_intel_tests.rs"]
mod intel_matches;
