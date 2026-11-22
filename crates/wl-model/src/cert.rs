//! X.509 certificate facts and the checks run on a chain (pure: time and host are inputs).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    /// Validity bounds, seconds since the Unix epoch.
    pub not_before: i64,
    pub not_after: i64,
    /// DNS names and IP addresses of the subject alternative name extension.
    pub sans: Vec<String>,
    /// "RSA 2048 bit", "EC P-256", "Ed25519" ...
    pub key: String,
    pub sig_alg: String,
    pub serial: String,
    pub is_ca: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertWarning {
    SelfSigned,
    Expired,
    NotYetValid,
    HostnameMismatch,
    WeakKey,
    NoAltNames,
}

impl CertWarning {
    pub fn label(self) -> &'static str {
        match self {
            CertWarning::SelfSigned => "Self-signed",
            CertWarning::Expired => "Expired",
            CertWarning::NotYetValid => "Not yet valid",
            CertWarning::HostnameMismatch => "Name mismatch",
            CertWarning::WeakKey => "Weak RSA key",
            CertWarning::NoAltNames => "No alt names (CN only)",
        }
    }
}

/// A warning and the position of the offending certificate in the chain (0 = leaf).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertFinding {
    pub depth: usize,
    pub warning: CertWarning,
}

impl CertInfo {
    pub fn is_self_signed(&self) -> bool {
        self.subject == self.issuer
    }

    pub fn common_name(&self) -> Option<&str> {
        self.subject
            .split(',')
            .map(str::trim)
            .find_map(|p| p.strip_prefix("CN="))
    }

    pub fn validity_warning(&self, now: i64) -> Option<CertWarning> {
        if now < self.not_before {
            Some(CertWarning::NotYetValid)
        } else if now > self.not_after {
            Some(CertWarning::Expired)
        } else {
            None
        }
    }

    /// RSA keys below 2048 bits; other key types are not judged.
    pub fn has_weak_key(&self) -> bool {
        let mut words = self.key.split_whitespace();
        words.next() == Some("RSA")
            && words
                .next()
                .and_then(|bits| bits.parse::<u32>().ok())
                .is_some_and(|bits| bits < 2048)
    }

    /// RFC 6125 matching: the SANs when present, the common name otherwise.
    pub fn matches_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let names: Vec<&str> = if self.sans.is_empty() {
            self.common_name().into_iter().collect()
        } else {
            self.sans.iter().map(String::as_str).collect()
        };
        names
            .iter()
            .any(|n| name_matches(&n.to_ascii_lowercase(), &host))
    }
}

fn name_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) if host.parse::<IpAddr>().is_err() => host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
        _ => pattern == host,
    }
}

/// Problems of a chain as presented for `host` (the SNI; empty skips the name check) at `at`.
pub fn evaluate(chain: &[CertInfo], host: &str, at: i64) -> Vec<CertFinding> {
    let mut out = Vec::new();
    for (depth, cert) in chain.iter().enumerate() {
        let mut add = |warning| out.push(CertFinding { depth, warning });
        if depth == 0 && cert.is_self_signed() {
            add(CertWarning::SelfSigned);
        }
        if let Some(w) = cert.validity_warning(at) {
            add(w);
        }
        if depth == 0 && !host.is_empty() && !cert.matches_host(host) {
            add(CertWarning::HostnameMismatch);
        }
        if cert.has_weak_key() {
            add(CertWarning::WeakKey);
        }
        if depth == 0 && !cert.is_ca && cert.sans.is_empty() {
            add(CertWarning::NoAltNames);
        }
    }
    out
}

/// Findings when the certificates were presented, and the validity findings that only hold now.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Assessment {
    pub at_capture: Vec<CertFinding>,
    pub only_now: Vec<CertFinding>,
}

/// Judges the chain at `captured_at` (a certificate that expired later was fine then); without
/// a capture time `now` is the reference and `only_now` stays empty.
pub fn assess(chain: &[CertInfo], host: &str, captured_at: Option<i64>, now: i64) -> Assessment {
    let at_capture = evaluate(chain, host, captured_at.unwrap_or(now));
    let only_now = match captured_at {
        Some(_) => evaluate(chain, host, now)
            .into_iter()
            .filter(|f| matches!(f.warning, CertWarning::Expired | CertWarning::NotYetValid))
            .filter(|f| !at_capture.contains(f))
            .collect(),
        None => Vec::new(),
    };
    Assessment {
        at_capture,
        only_now,
    }
}

/// "2026-11-20" from epoch seconds (UTC).
pub fn date_label(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(subject: &str, issuer: &str, sans: &[&str]) -> CertInfo {
        CertInfo {
            subject: subject.into(),
            issuer: issuer.into(),
            not_before: 1_000,
            not_after: 2_000,
            sans: sans.iter().map(|s| (*s).to_owned()).collect(),
            key: "RSA 2048 bit".into(),
            sig_alg: "sha256WithRSAEncryption".into(),
            serial: "01".into(),
            is_ca: false,
        }
    }

    fn warnings(chain: &[CertInfo], host: &str, now: i64) -> Vec<(usize, CertWarning)> {
        evaluate(chain, host, now)
            .into_iter()
            .map(|f| (f.depth, f.warning))
            .collect()
    }

    #[test]
    fn healthy_chain_has_no_findings() {
        let chain = [
            cert("CN=a.test", "CN=Root CA", &["a.test"]),
            cert("CN=Root CA", "CN=Root CA", &[]),
        ];
        assert!(warnings(&chain, "a.test", 1_500).is_empty());
    }

    #[test]
    fn flags_self_signed_leaf_only() {
        let chain = [cert("CN=a.test", "CN=a.test", &["a.test"])];
        assert_eq!(
            warnings(&chain, "a.test", 1_500),
            [(0, CertWarning::SelfSigned)]
        );
    }

    #[test]
    fn flags_expired_and_not_yet_valid_at_any_depth() {
        let chain = [
            cert("CN=a.test", "CN=CA", &["a.test"]),
            cert("CN=CA", "CN=CA", &[]),
        ];
        assert_eq!(
            warnings(&chain, "a.test", 3_000),
            [(0, CertWarning::Expired), (1, CertWarning::Expired)]
        );
        assert_eq!(
            warnings(&chain[..1], "a.test", 10),
            [(0, CertWarning::NotYetValid)]
        );
        assert_eq!(chain[0].validity_warning(2_000), None);
        assert_eq!(chain[0].validity_warning(1_000), None);
    }

    #[test]
    fn san_matching_rules() {
        let c = cert("CN=old.test", "CN=CA", &["a.test", "*.b.test", "10.0.0.1"]);
        assert!(c.matches_host("A.test."));
        assert!(c.matches_host("x.b.test"));
        assert!(!c.matches_host("b.test"));
        assert!(!c.matches_host("x.y.b.test"));
        assert!(c.matches_host("10.0.0.1"));
        assert!(!c.matches_host("old.test"), "SANs win over the common name");
        assert_eq!(
            warnings(&[c], "evil.test", 1_500),
            [(0, CertWarning::HostnameMismatch)]
        );
    }

    #[test]
    fn common_name_is_the_fallback_without_sans() {
        let c = cert("O=Ex, CN=a.test", "CN=CA", &[]);
        assert!(c.matches_host("a.test"));
        assert!(!c.matches_host("b.test"));
    }

    #[test]
    fn empty_host_skips_the_name_check() {
        let c = cert("CN=a.test", "CN=CA", &["a.test"]);
        assert!(warnings(&[c], "", 1_500).is_empty());
    }

    #[test]
    fn wildcard_never_matches_an_ip() {
        let c = cert("CN=x", "CN=CA", &["*.0.0.1"]);
        assert!(!c.matches_host("10.0.0.1"));
    }

    #[test]
    fn formats_dates() {
        assert_eq!(date_label(0), "1970-01-01");
        assert_eq!(date_label(1_795_194_348), "2026-11-20");
        assert_eq!(date_label(951_782_400), "2000-02-29");
    }

    #[test]
    fn weak_rsa_keys_and_missing_alt_names_are_flagged() {
        let mut leaf = cert("CN=a.test", "CN=CA", &[]);
        leaf.key = "RSA 1024 bit".into();
        assert_eq!(
            warnings(&[leaf.clone()], "", 1_500),
            [(0, CertWarning::WeakKey), (0, CertWarning::NoAltNames)]
        );
        leaf.key = "EC P-256".into();
        leaf.sans = vec!["a.test".into()];
        assert!(warnings(&[leaf.clone()], "a.test", 1_500).is_empty());
        let mut ca = cert("CN=CA", "CN=Root", &[]);
        ca.is_ca = true;
        ca.key = "RSA 4096 bit".into();
        assert!(warnings(&[leaf, ca], "a.test", 1_500).is_empty());
    }

    #[test]
    fn validity_is_judged_at_capture_time_and_now() {
        let chain = [cert("CN=a.test", "CN=CA", &["a.test"])];
        let a = assess(&chain, "a.test", Some(1_500), 3_000);
        assert!(a.at_capture.is_empty());
        assert_eq!(
            a.only_now,
            [CertFinding {
                depth: 0,
                warning: CertWarning::Expired
            }]
        );
        let late = assess(&chain, "a.test", Some(2_500), 3_000);
        assert_eq!(late.at_capture.len(), 1);
        assert!(late.only_now.is_empty());
        let unknown = assess(&chain, "a.test", None, 3_000);
        assert_eq!(unknown.at_capture.len(), 1);
        assert!(unknown.only_now.is_empty());
    }
}
