//! "Decode As": `-d tcp.port==8080,http` arguments and the list of bindable protocols.

use wl_model::{CaptureError, DecodeAs};

use crate::error::from_stderr;
use crate::process::{self, Tools};

/// Dissector tables the UI offers (and the only ones accepted on the command line).
pub const FIELDS: [&str; 2] = ["tcp.port", "udp.port"];

fn valid_protocol(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// A rule that is safe to hand to tshark.
pub fn is_valid(r: &DecodeAs) -> bool {
    FIELDS.contains(&r.field.as_str()) && r.value <= 65_535 && valid_protocol(&r.protocol)
}

/// `-d` arguments for `rules`. Invalid rules are skipped; a later rule for the same
/// field/value replaces an earlier one.
pub fn args(rules: &[DecodeAs]) -> Vec<String> {
    let mut kept: Vec<&DecodeAs> = Vec::new();
    for r in rules.iter().filter(|r| is_valid(r)) {
        kept.retain(|k| (&k.field, k.value) != (&r.field, r.value));
        kept.push(r);
    }
    kept.iter()
        .flat_map(|r| {
            [
                "-d".to_owned(),
                format!("{}=={},{}", r.field, r.value, r.protocol),
            ]
        })
        .collect()
}

/// Protocols registered in the `field` table, from `tshark -G decodes` (`table \t selector \t proto`).
pub fn parse_decodes(raw: &str, field: &str) -> Vec<String> {
    let mut out: Vec<String> = raw
        .lines()
        .filter_map(|l| {
            let mut c = l.split('\t');
            (c.next()? == field).then_some(())?;
            c.next()?;
            c.next().map(str::to_owned)
        })
        .filter(|p| valid_protocol(p))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

pub fn protocols(tools: &Tools, field: &str) -> Result<Vec<String>, CaptureError> {
    if !FIELDS.contains(&field) {
        return Ok(Vec::new());
    }
    let out = process::run(&tools.tshark, ["-G", "decodes"])?;
    if !out.status.success() {
        return Err(from_stderr(&String::from_utf8_lossy(&out.stderr)));
    }
    Ok(parse_decodes(&String::from_utf8_lossy(&out.stdout), field))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(f: &str, v: u32, p: &str) -> DecodeAs {
        DecodeAs {
            field: f.into(),
            value: v,
            protocol: p.into(),
        }
    }

    #[test]
    fn builds_d_arguments() {
        let a = args(&[
            rule("tcp.port", 8080, "http"),
            rule("udp.port", 5353, "mdns"),
        ]);
        assert_eq!(
            a,
            ["-d", "tcp.port==8080,http", "-d", "udp.port==5353,mdns"]
        );
    }

    #[test]
    fn rejects_injection_and_dedups() {
        let a = args(&[
            rule("tcp.port", 80, "http,evil"),
            rule("ip.proto", 6, "tcp"),
            rule("tcp.port", 70_000, "http"),
            rule("tcp.port", 8080, "http"),
            rule("tcp.port", 8080, "tls"),
        ]);
        assert_eq!(a, ["-d", "tcp.port==8080,tls"]);
    }

    #[test]
    fn parses_decodes_listing() {
        let raw =
            "tcp.port\t80\thttp\nudp.port\t53\tdns\ntcp.port\t8080\thttp\ntcp.port\t25\tsmtp\n";
        assert_eq!(parse_decodes(raw, "tcp.port"), ["http", "smtp"]);
        assert_eq!(parse_decodes(raw, "udp.port"), ["dns"]);
    }
}
