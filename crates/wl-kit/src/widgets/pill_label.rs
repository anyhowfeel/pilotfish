//! Short display labels for protocol names (pure logic, no egui).

use std::borrow::Cow;

/// Smart, concise display label for protocol names while preserving readability.
/// Full name is always preserved for tooltips whenever shortened or truncated.
pub fn abbreviate_protocol(raw: &str) -> Cow<'_, str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Cow::Borrowed("—");
    }
    let up = trimmed.to_ascii_uppercase();
    match up.as_str() {
        "TLSV1.3" => Cow::Borrowed("TLS 1.3"),
        "TLSV1.2" => Cow::Borrowed("TLS 1.2"),
        "TLSV1.1" => Cow::Borrowed("TLS 1.1"),
        "TLSV1" => Cow::Borrowed("TLS 1.0"),
        "HTTP/JSON" => Cow::Borrowed("HTTP"),
        "HTTP/XML" => Cow::Borrowed("HTTP"),
        "OCSP-OVER-HTTP" => Cow::Borrowed("OCSP"),
        "BROWSER" => Cow::Borrowed("NBNS"),
        _ if trimmed.len() <= 9 => Cow::Borrowed(trimmed),
        _ => {
            if let Some((head, _)) = trimmed.split_once('/')
                && !head.is_empty()
                && head.len() <= 9
            {
                return Cow::Borrowed(head);
            }
            Cow::Borrowed(trimmed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abbreviates_long_and_known_protocol_names() {
        assert_eq!(abbreviate_protocol("TLSv1.3"), "TLS 1.3");
        assert_eq!(abbreviate_protocol("tlsv1.2"), "TLS 1.2");
        assert_eq!(abbreviate_protocol("HTTP/JSON"), "HTTP");
        assert_eq!(abbreviate_protocol("ICMPv6"), "ICMPv6");
        assert_eq!(abbreviate_protocol("DHCPv6"), "DHCPv6");
        assert_eq!(abbreviate_protocol("GPRS-NS"), "GPRS-NS");
        assert_eq!(abbreviate_protocol("CUSTOM/EXTRA-LONG"), "CUSTOM");
        assert_eq!(abbreviate_protocol(""), "—");
    }
}
