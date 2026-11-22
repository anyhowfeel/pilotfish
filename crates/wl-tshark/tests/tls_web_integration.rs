//! TLS key log embedding, certificates, message streams and packet comments against the
//! committed fixtures. Skips when tshark / editcap are missing.

use std::path::PathBuf;

use wl_model::CaptureBackend;
use wl_tshark::TsharkBackend;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn backend() -> Option<TsharkBackend> {
    let b = TsharkBackend::new().ok()?;
    b.set_tls_keylog(None);
    b.can_embed_tls_keys().then_some(b)
}

#[test]
fn embedded_keys_decrypt_without_a_key_log() {
    let Some(b) = backend() else { return };
    let (pcap, keylog) = (fixture("web-tls.pcapng"), fixture("web-tls.keylog"));
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("with-keys.pcapng");

    assert!(b.embed_tls_keys(&pcap, &out).is_err(), "needs a key log");
    b.set_tls_keylog(Some(keylog));
    b.embed_tls_keys(&pcap, &out).expect("embed");
    b.set_tls_keylog(None);

    assert!(b.http_exchanges(&pcap).expect("plain").is_empty());
    assert_eq!(b.http_exchanges(&out).expect("embedded").len(), 2);
}

#[test]
fn embedding_never_overwrites_the_original() {
    let Some(b) = backend() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let copy = dir.path().join("orig.pcapng");
    std::fs::copy(fixture("web-tls.pcapng"), &copy).expect("copy");
    let before = std::fs::read(&copy).expect("read");
    b.set_tls_keylog(Some(fixture("web-tls.keylog")));
    assert!(b.embed_tls_keys(&copy, &copy).is_err());
    assert_eq!(std::fs::read(&copy).expect("read"), before);
}

#[test]
fn tls12_sessions_carry_the_parsed_certificate_chain() {
    let Ok(b) = TsharkBackend::new() else { return };
    b.set_tls_keylog(None);
    let tls = b.tls_sessions(&fixture("web-tls.pcapng")).expect("tls");
    let t12 = tls
        .iter()
        .find(|s| &*s.version == "TLS 1.2")
        .expect("TLS 1.2 session");
    let leaf = t12.certs.first().expect("leaf certificate");
    assert_eq!(leaf.subject, "CN=wirelens.test");
    assert!(leaf.is_self_signed());
    assert_eq!(leaf.sans, ["wirelens.test"]);
    assert_eq!(leaf.key, "RSA 2048 bit");
    assert_eq!(leaf.sig_alg, "sha256WithRSA");
    assert_eq!(wl_model::date_label(leaf.not_before), "2026-11-20");
    assert_eq!(wl_model::date_label(leaf.not_after), "2026-11-22");
    assert!(
        tls.iter()
            .filter(|s| &*s.version == "TLS 1.3")
            .all(|s| s.certs.is_empty()),
        "TLS 1.3 certificates are encrypted"
    );
    let now = leaf.not_before + 60;
    let found = wl_model::evaluate_chain(&t12.certs, &t12.server_name, now);
    let kinds: Vec<_> = found.iter().map(|f| f.warning).collect();
    assert_eq!(
        kinds,
        [
            wl_model::CertWarning::SelfSigned,
            wl_model::CertWarning::HostnameMismatch
        ],
        "SNI tls12.wirelens.test is not covered by the wirelens.test certificate"
    );
    let later = wl_model::evaluate_chain(&t12.certs, "wirelens.test", leaf.not_after + 1);
    assert!(
        later
            .iter()
            .any(|f| f.warning == wl_model::CertWarning::Expired)
    );
}
