//! Certificate chain of a TLS session: warnings first, then one table per certificate.

use std::time::{SystemTime, UNIX_EPOCH};

use wl_kit::egui::{RichText, Ui};
use wl_kit::theme::Palette;
use wl_kit::widgets::badge;
use wl_model::{CertInfo, CertWarning, TlsSession, date_label, evaluate_chain};

use super::card::{card, muted};
use super::headers::headers_table;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn role(depth: usize, cert: &CertInfo, last: bool) -> &'static str {
    match (depth, cert.is_self_signed() && last) {
        (0, _) => "Server certificate",
        (_, true) => "Root",
        _ => "Intermediate",
    }
}

fn validity_text(cert: &CertInfo, now: i64) -> String {
    let until = date_label(cert.not_after);
    match cert.validity_warning(now) {
        Some(CertWarning::Expired) => format!("{until} (expired)"),
        Some(CertWarning::NotYetValid) => {
            format!("{until} (not valid before {})", date_label(cert.not_before))
        }
        _ => until,
    }
}

pub fn cert_rows(cert: &CertInfo, now: i64) -> Vec<(String, String)> {
    let r = |k: &str, v: String| (k.to_owned(), v);
    let mut rows = vec![
        r("Subject", cert.subject.clone()),
        r("Issuer", cert.issuer.clone()),
        r("Valid from", date_label(cert.not_before)),
        r("Valid until", validity_text(cert, now)),
    ];
    if !cert.sans.is_empty() {
        rows.push(r("Alt names", cert.sans.join(", ")));
    }
    rows.push(r("Public key", cert.key.clone()));
    rows.push(r("Signature", cert.sig_alg.clone()));
    rows.push(r("Serial", cert.serial.clone()));
    if cert.is_ca {
        rows.push(r("CA", "yes".into()));
    }
    rows
}

fn warnings_row(ui: &mut Ui, t: &TlsSession, now: i64) {
    let found = evaluate_chain(&t.certs, &t.server_name, now);
    ui.horizontal_wrapped(|ui| {
        if found.is_empty() {
            badge(ui, "No problems found", Palette::ok());
        }
        for f in found {
            let text = match f.depth {
                0 => f.warning.label().to_owned(),
                d => format!("{} (chain #{d})", f.warning.label()),
            };
            badge(ui, &text, Palette::warn());
        }
    });
}

pub fn cert_card(ui: &mut Ui, t: &TlsSession) {
    let now = now_secs();
    card(
        ui,
        "Certificate chain",
        |_| {},
        |ui| {
            warnings_row(ui, t, now);
            for (i, cert) in t.certs.iter().enumerate() {
                let last = i + 1 == t.certs.len();
                ui.label(RichText::new(role(i, cert, last)).strong());
                headers_table(ui, &cert_rows(cert, now));
            }
            if t.certs.len() == 1 {
                muted(ui, "Only the server certificate was sent.");
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert() -> CertInfo {
        CertInfo {
            subject: "CN=a.test".into(),
            issuer: "CN=CA".into(),
            not_before: 0,
            not_after: 86_400,
            sans: vec!["a.test".into(), "b.test".into()],
            key: "EC P-256".into(),
            sig_alg: "ecdsa-with-SHA256".into(),
            serial: "0a".into(),
            is_ca: false,
        }
    }

    #[test]
    fn rows_flag_expiry_and_list_sans() {
        let rows = cert_rows(&cert(), 10);
        let get = |k: &str| rows.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("Valid until"), Some("1970-01-02"));
        assert_eq!(get("Alt names"), Some("a.test, b.test"));
        assert_eq!(get("CA"), None);
        let late = cert_rows(&cert(), 90_000);
        assert!(late.iter().any(|(_, v)| v == "1970-01-02 (expired)"));
    }

    #[test]
    fn roles_follow_chain_position() {
        let mut ca = cert();
        ca.issuer = ca.subject.clone();
        assert_eq!(role(0, &ca, true), "Server certificate");
        assert_eq!(role(1, &ca, true), "Root");
        assert_eq!(role(1, &cert(), false), "Intermediate");
    }
}
