//! DER certificate -> `CertInfo`, and the hex form tshark prints for `tls.handshake.certificate`.

use std::net::{Ipv4Addr, Ipv6Addr};

use wl_model::CertInfo;
use x509_parser::oid_registry::{
    OID_KEY_TYPE_EC_PUBLIC_KEY, OID_PKCS1_RSAENCRYPTION, OID_SIG_ED25519, Oid,
};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

fn curve_label(params: &Oid) -> &'static str {
    match params.to_id_string().as_str() {
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        _ => "curve",
    }
}

fn key_label(cert: &X509Certificate) -> String {
    let spki = cert.public_key();
    let alg = &spki.algorithm.algorithm;
    if *alg == OID_PKCS1_RSAENCRYPTION {
        return match spki.parsed() {
            Ok(PublicKey::RSA(rsa)) => format!("RSA {} bit", rsa.key_size()),
            _ => "RSA".into(),
        };
    }
    if *alg == OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map_or("curve", |o| curve_label(&o));
        return format!("EC {curve}");
    }
    match alg.to_id_string().as_str() {
        "1.3.101.112" => "Ed25519".into(),
        "1.3.101.113" => "Ed448".into(),
        other => other.to_owned(),
    }
}

fn sig_label(oid: &Oid) -> String {
    let id = oid.to_id_string();
    let known = match id.as_str() {
        "1.2.840.113549.1.1.5" => "sha1WithRSA",
        "1.2.840.113549.1.1.11" => "sha256WithRSA",
        "1.2.840.113549.1.1.12" => "sha384WithRSA",
        "1.2.840.113549.1.1.13" => "sha512WithRSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        _ if *oid == OID_SIG_ED25519 => "Ed25519",
        _ => return id,
    };
    known.to_owned()
}

fn san_label(name: &GeneralName) -> Option<String> {
    match name {
        GeneralName::DNSName(d) => Some((*d).to_owned()),
        GeneralName::IPAddress(b) => match b.len() {
            4 => Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
            16 => <[u8; 16]>::try_from(*b)
                .ok()
                .map(|a| Ipv6Addr::from(a).to_string()),
            _ => None,
        },
        _ => None,
    }
}

pub fn parse_der(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(san_label)
                .collect()
        })
        .unwrap_or_default();
    Some(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        sans,
        key: key_label(&cert),
        sig_alg: sig_label(&cert.signature_algorithm.algorithm),
        serial: cert.raw_serial_as_string(),
        is_ca: cert
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|b| b.value.ca),
    })
}

/// Certificates of a comma-joined list of DER hex strings; unparsable ones are skipped.
pub fn parse_chain(hex_list: &str) -> Vec<CertInfo> {
    hex_list
        .split(',')
        .filter_map(hex_to_bytes)
        .filter_map(|der| parse_der(&der))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decoding() {
        assert_eq!(hex_to_bytes("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(hex_to_bytes("abc"), None);
        assert_eq!(hex_to_bytes("zz"), None);
    }

    #[test]
    fn garbage_is_skipped() {
        assert!(parse_der(&[1, 2, 3]).is_none());
        assert!(parse_chain("0102,zz,").is_empty());
    }
}
