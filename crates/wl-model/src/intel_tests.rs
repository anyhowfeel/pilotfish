use super::*;

fn ind(line: &str) -> Option<Indicator> {
    parse_line(line)
}

fn domain(d: &str) -> Option<Indicator> {
    Some(Indicator::Domain(d.to_owned()))
}

fn ip(a: &str) -> Option<Indicator> {
    Some(Indicator::Ip(a.parse().unwrap()))
}

#[test]
fn comments_and_blank_lines_are_skipped() {
    for l in ["", "   ", "# comment", "; note", "// note"] {
        assert_eq!(ind(l), None, "{l:?}");
    }
}

#[test]
fn plain_entries() {
    assert_eq!(ind("203.0.113.9"), ip("203.0.113.9"));
    assert_eq!(ind("2001:db8::1"), ip("2001:db8::1"));
    assert_eq!(ind("Evil.Example.COM"), domain("evil.example.com"));
    assert_eq!(ind("evil.example.com."), domain("evil.example.com"));
    assert_eq!(ind("203.0.113.9:8080"), ip("203.0.113.9"));
}

#[test]
fn abuse_ch_csv_rows() {
    let feodo = "2024-05-01 10:00:00,198.51.100.7,443,online,2024-05-02,Emotet";
    assert_eq!(ind(feodo), ip("198.51.100.7"));
    let urlhaus = r#""1","2024-05-01 10:00:00","http://bad.example.net/a/payload.exe","online","malware_download""#;
    assert_eq!(ind(urlhaus), domain("bad.example.net"));
    let sslbl = "e7d705a3286e19ea42f587b344ee6865,2024-01-01,2024-02-02,Malware C2";
    assert_eq!(
        ind(sslbl),
        Some(Indicator::Fingerprint(
            "e7d705a3286e19ea42f587b344ee6865".to_owned()
        ))
    );
}

#[test]
fn hosts_file_sinks_are_not_indicators() {
    assert_eq!(
        ind("0.0.0.0 tracker.example.org"),
        domain("tracker.example.org")
    );
    assert_eq!(ind("127.0.0.1\tads.example.org"), domain("ads.example.org"));
    assert_eq!(ind("0.0.0.0"), None);
}

#[test]
fn filenames_and_numbers_are_not_domains() {
    for l in ["443", "payload.exe1", "12:00:00", "2024-05-01", "-bad-.com"] {
        assert_eq!(ind(l), None, "{l}");
    }
}

#[test]
fn ja4_strings_are_fingerprints() {
    let f = "t13d1516h2_8daaf6152771_02713d6af862";
    assert_eq!(ind(f), Some(Indicator::Fingerprint(f.to_owned())));
    assert!(!is_fingerprint("t13d1516h2_8daaf6152771"));
}

#[test]
fn blocklist_matches_addresses_and_parent_domains() {
    let mut intel = ThreatIntel::default();
    intel.add_blocklist("feodo", "# header\n198.51.100.7\nbad.example.net\n");
    assert_eq!(intel.ip("198.51.100.7"), Some("feodo"));
    assert_eq!(intel.ip("198.51.100.8"), None);
    assert_eq!(intel.ip("not an ip"), None);
    assert_eq!(intel.domain("bad.example.net"), Some("feodo"));
    assert_eq!(intel.domain("C2.Bad.Example.Net."), Some("feodo"));
    assert_eq!(intel.domain("example.net"), None);
    assert_eq!(intel.domain("net"), None);
    assert_eq!(intel.counts(), (1, 1, 0));
}

#[test]
fn first_list_wins_for_duplicates() {
    let mut intel = ThreatIntel::default();
    intel.add_blocklist("a", "bad.example.net");
    intel.add_blocklist("b", "bad.example.net");
    assert_eq!(intel.domain("bad.example.net"), Some("a"));
}

#[test]
fn ja4db_array_maps_both_fingerprints_to_the_application() {
    let json = r#"[
        {"application":"Chrome","library":"BoringSSL","ja4_fingerprint":"T13D1516H2_8DAAF6152771_02713D6AF862"},
        {"application":"curl","ja3_fingerprint":"AAAA0000AAAA0000AAAA0000AAAA0000","ja4_fingerprint":"t13d3112h1_aaaaaaaaaaaa_bbbbbbbbbbbb"},
        {"ja4_fingerprint":"t13d0000h2_000000000000_000000000000"},
        {"application":"Sliver","malware":"yes","ja3_fingerprint":"bbbb0000bbbb0000bbbb0000bbbb0000"}
    ]"#;
    let mut intel = ThreatIntel::default();
    assert_eq!(intel.add_ja4db(json), Ok(4));
    let chrome = intel
        .fingerprint("t13d1516h2_8daaf6152771_02713d6af862")
        .unwrap();
    assert_eq!((&*chrome.label, chrome.malicious), ("Chrome", false));
    assert_eq!(
        &*intel
            .fingerprint("aaaa0000aaaa0000aaaa0000aaaa0000")
            .unwrap()
            .label,
        "curl"
    );
    assert!(
        intel
            .fingerprint("bbbb0000bbbb0000bbbb0000bbbb0000")
            .unwrap()
            .malicious
    );
}

#[test]
fn ja4db_flat_map_and_errors() {
    let mut intel = ThreatIntel::default();
    assert_eq!(intel.add_ja4db(r#"{"ABCD":"Firefox","x":""}"#), Ok(1));
    assert_eq!(&*intel.fingerprint("abcd").unwrap().label, "Firefox");
    assert!(intel.add_ja4db("not json").is_err());
    assert!(intel.add_ja4db("42").is_err());
}

fn session(ja3: Option<&str>, ja4: Option<&str>, sni: &str, dst: &str) -> TlsSession {
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
        ja3: ja3.map(Into::into),
        ja4: ja4.map(Into::into),
        ja3s: None,
        src: "10.0.0.2".into(),
        dst: dst.into(),
        bytes: 0,
        client: None,
        threat: None,
    }
}

#[test]
fn tls_sessions_are_annotated() {
    let mut intel = ThreatIntel::default();
    intel
        .add_ja4db(r#"[{"application":"Chrome","ja4_fingerprint":"t13d1516h2_8daaf6152771_02713d6af862"}]"#)
        .unwrap();
    intel.add_blocklist(
        "sslbl",
        "e7d705a3286e19ea42f587b344ee6865\nbad.example.net\n198.51.100.7",
    );
    let mut all = vec![
        session(
            None,
            Some("t13d1516h2_8daaf6152771_02713d6af862"),
            "good.example.com",
            "93.184.216.34",
        ),
        session(
            Some("E7D705A3286E19EA42F587B344EE6865"),
            None,
            "good.example.com",
            "93.184.216.34",
        ),
        session(None, None, "x.bad.example.net", "93.184.216.34"),
        session(None, None, "good.example.com", "198.51.100.7"),
    ];
    intel.annotate_tls(&mut all);
    let got: Vec<_> = all
        .iter()
        .map(|t| (t.client.as_deref(), t.threat.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (Some("Chrome"), None),
            (None, Some("sslbl")),
            (None, Some("sslbl")),
            (None, Some("sslbl")),
        ]
    );
}
