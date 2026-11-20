//! Human labels for the numeric TLS values tshark prints in `-T fields` mode.

fn parse_hex(s: &str) -> Option<u32> {
    let t = s.trim();
    let digits = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"));
    match digits {
        Some(d) => u32::from_str_radix(d, 16).ok(),
        None => t.parse().ok(),
    }
}

/// `0x0304` -> "TLS 1.3". Unknown values are kept readable.
pub fn version_label(raw: &str) -> String {
    match parse_hex(raw) {
        Some(0x0304) => "TLS 1.3".into(),
        Some(0x0303) => "TLS 1.2".into(),
        Some(0x0302) => "TLS 1.1".into(),
        Some(0x0301) => "TLS 1.0".into(),
        Some(0x0300) => "SSL 3.0".into(),
        Some(0xfeff) => "DTLS 1.0".into(),
        Some(0xfefd) => "DTLS 1.2".into(),
        Some(_) | None => raw.trim().to_string(),
    }
}

const CIPHERS: &[(u32, &str)] = &[
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    (0x1304, "TLS_AES_128_CCM_SHA256"),
    (0xc02b, "ECDHE-ECDSA-AES128-GCM-SHA256"),
    (0xc02c, "ECDHE-ECDSA-AES256-GCM-SHA384"),
    (0xc02f, "ECDHE-RSA-AES128-GCM-SHA256"),
    (0xc030, "ECDHE-RSA-AES256-GCM-SHA384"),
    (0xcca8, "ECDHE-RSA-CHACHA20-POLY1305"),
    (0xcca9, "ECDHE-ECDSA-CHACHA20-POLY1305"),
    (0xc009, "ECDHE-ECDSA-AES128-SHA"),
    (0xc00a, "ECDHE-ECDSA-AES256-SHA"),
    (0xc013, "ECDHE-RSA-AES128-SHA"),
    (0xc014, "ECDHE-RSA-AES256-SHA"),
    (0xc023, "ECDHE-ECDSA-AES128-SHA256"),
    (0xc027, "ECDHE-RSA-AES128-SHA256"),
    (0x009c, "AES128-GCM-SHA256"),
    (0x009d, "AES256-GCM-SHA384"),
    (0x002f, "AES128-SHA"),
    (0x0035, "AES256-SHA"),
    (0x003c, "AES128-SHA256"),
    (0x009e, "DHE-RSA-AES128-GCM-SHA256"),
    (0x009f, "DHE-RSA-AES256-GCM-SHA384"),
    (0x000a, "DES-CBC3-SHA"),
    (0x0005, "RC4-SHA"),
];

/// `0x1302` -> "TLS_AES_256_GCM_SHA384"; unknown suites show as `0x....`.
pub fn cipher_label(raw: &str) -> String {
    match parse_hex(raw) {
        Some(v) => CIPHERS
            .iter()
            .find(|(c, _)| *c == v)
            .map_or_else(|| format!("0x{v:04x}"), |(_, n)| (*n).to_string()),
        None => raw.trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert_eq!(version_label("0x0304"), "TLS 1.3");
        assert_eq!(version_label("771"), "TLS 1.2");
        assert_eq!(version_label("weird"), "weird");
        assert_eq!(cipher_label("0xc030"), "ECDHE-RSA-AES256-GCM-SHA384");
        assert_eq!(cipher_label("0xdead"), "0xdead");
    }
}
