//! Cleartext credential detection over `tests/fixtures/credentials.pcap` (see gen_security.py)
//! and offline threat-intel matching over real TLS sessions. Skips when tshark is missing.

use std::path::PathBuf;

use wl_model::{CaptureBackend, CredKind, Credential, ThreatIntel};
use wl_tshark::TsharkBackend;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn of(all: &[Credential], kind: CredKind) -> Vec<(Option<&str>, Option<&str>, &str)> {
    all.iter()
        .filter(|c| c.kind == kind)
        .map(|c| (c.user.as_deref(), c.secret.as_deref(), &*c.dst))
        .collect()
}

#[test]
fn credentials_are_found_in_every_cleartext_protocol() {
    let Ok(b) = TsharkBackend::new() else { return };
    let all = b
        .credentials(&fixture("credentials.pcap"))
        .expect("credentials");
    assert_eq!(
        of(&all, CredKind::HttpBasic),
        [(Some("alice"), Some("s3cretPass"), "10.0.0.80")]
    );
    let bearer = of(&all, CredKind::HttpBearer);
    assert_eq!(bearer[0].1, Some("eyJhbGciOiJIUzI1NiJ9.payload.signature"));
    let keys: Vec<_> = all
        .iter()
        .filter(|c| c.kind == CredKind::ApiKey)
        .map(|c| (c.field.as_deref(), c.secret.as_deref()))
        .collect();
    assert_eq!(
        keys,
        [
            (Some("X-API-Key"), Some("sk_live_abcdef123456")),
            (Some("api_key"), Some("KEY123456789")),
        ]
    );
    assert_eq!(
        of(&all, CredKind::Ftp),
        [(Some("bob"), Some("hunter2"), "10.0.0.21")]
    );
    assert_eq!(
        of(&all, CredKind::Smtp),
        [
            (Some("carol"), Some("mailpass1"), "10.0.0.25"),
            (Some("dave"), Some("davepass"), "10.0.0.25"),
        ]
    );
    assert_eq!(
        of(&all, CredKind::Pop3),
        [(Some("erin"), Some("letmein99"), "10.0.0.110")]
    );
    assert_eq!(
        of(&all, CredKind::Ntlm),
        [(Some("CORP\\alice"), None, "10.0.0.80")]
    );
    assert_eq!(all.len(), 9, "{all:#?}");
}

#[test]
fn captures_without_logins_yield_nothing() {
    let Ok(b) = TsharkBackend::new() else { return };
    let all = b.credentials(&fixture("behavior.pcap")).expect("scan");
    assert!(all.is_empty());
}

#[test]
fn tls_sessions_are_matched_against_offline_lists() {
    let Ok(b) = TsharkBackend::new() else { return };
    let mut tls = b.tls_sessions(&fixture("web-tls.pcapng")).expect("tls");
    assert!(!tls.is_empty());
    let ja4 = tls[0].ja4.clone().expect("ja4");
    let ja3 = tls[0].ja3.clone().expect("ja3");

    let mut intel = ThreatIntel::default();
    intel
        .add_ja4db(&format!(
            r#"[{{"application":"openssl s_client","ja4_fingerprint":"{ja4}"}}]"#
        ))
        .expect("ja4db");
    intel.annotate_tls(&mut tls);
    assert!(
        tls.iter()
            .all(|t| t.client.as_deref() == Some("openssl s_client") && t.threat.is_none()),
        "{tls:#?}"
    );

    let mut intel = ThreatIntel::default();
    intel.add_blocklist("sslbl", &format!("# ja3\n{ja3},2024-01-01\n"));
    intel.annotate_tls(&mut tls);
    assert!(tls.iter().any(|t| t.threat.as_deref() == Some("sslbl")));
    assert!(tls.iter().all(|t| t.client.is_none()));
}
