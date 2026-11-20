//! DNS query log: one streamed tshark pass over `dns`, query and response paired on the fly.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, DnsQuery, Rcode};

use crate::process::Tools;
use crate::tsv_pass::{Pass, columns, opt, run_pass_all};

/// Column order is part of the contract with `Builder::push`.
const FIELDS: [&str; 19] = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.qry.name",
    "dns.qry.type",
    "dns.response_to",
    "dns.time",
    "dns.cname",
    "dns.a",
    "dns.aaaa",
    "dns.ptr.domain_name",
    "dns.mx.mail_exchange",
    "dns.retransmission",
    "dns.retransmit_request_in",
];
/// Memory guard for huge captures.
const MAX_RECORDS: usize = 250_000;

pub fn dns_queries(
    tools: &Tools,
    file: &Path,
    opts: &[String],
) -> Result<Vec<DnsQuery>, CaptureError> {
    let pass = Pass {
        file,
        filter: "dns",
        fields: &FIELDS,
        opts,
    };
    let mut b = Builder::default();
    run_pass_all(tools, &pass, |line| {
        b.push(line);
        if b.out.len() >= MAX_RECORDS {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })?;
    Ok(b.out)
}

/// DNS record type number -> mnemonic (numeric text when unknown).
pub fn type_name(code: &str) -> String {
    match code {
        "1" => "A",
        "2" => "NS",
        "5" => "CNAME",
        "6" => "SOA",
        "12" => "PTR",
        "15" => "MX",
        "16" => "TXT",
        "28" => "AAAA",
        "33" => "SRV",
        "64" => "SVCB",
        "65" => "HTTPS",
        "255" => "ANY",
        other => other,
    }
    .to_owned()
}

#[derive(Default)]
struct Builder {
    out: Vec<DnsQuery>,
    by_frame: HashMap<u64, usize>,
}

fn addr<'a>(v4: &'a str, v6: &'a str) -> &'a str {
    opt(v4).or(opt(v6)).unwrap_or("")
}

impl Builder {
    fn push(&mut self, line: &str) {
        let f: [&str; FIELDS.len()] = columns(line);
        let Ok(frame) = f[0].parse::<u64>() else {
            return;
        };
        let rel = f[1].parse::<f64>().unwrap_or(0.0);
        let (src, dst) = (addr(f[2], f[3]), addr(f[4], f[5]));
        let rtt = f[11].parse::<f64>().ok().map(|s| s * 1000.0);
        if f[6].eq_ignore_ascii_case("true") || f[6] == "1" {
            self.response(frame, rel, (src, dst), rtt, &f);
        } else if let Some(orig) = f[18].parse::<u64>().ok().filter(|_| !f[17].is_empty()) {
            // A retransmitted query folds into the original row.
            if let Some(&i) = self.by_frame.get(&orig) {
                self.out[i].retransmission = true;
                self.by_frame.insert(frame, i);
                return;
            }
            self.query(frame, rel, (src, dst), &f, true);
        } else {
            self.query(frame, rel, (src, dst), &f, false);
        }
    }

    fn query(&mut self, frame: u64, rel: f64, (src, dst): (&str, &str), f: &[&str], retx: bool) {
        self.by_frame.insert(frame, self.out.len());
        self.out.push(DnsQuery {
            frame,
            response_frame: None,
            rel,
            client: src.to_owned(),
            server: dst.to_owned(),
            name: f[8].to_owned(),
            qtype: type_name(f[9]),
            rcode: None,
            answers: Vec::new(),
            rtt_ms: None,
            retransmission: retx,
        });
    }

    fn response(
        &mut self,
        frame: u64,
        rel: f64,
        (src, dst): (&str, &str),
        rtt: Option<f64>,
        f: &[&str],
    ) {
        let rcode = f[7].parse::<u8>().ok().map(Rcode::from_code);
        let answers: Vec<String> = f[12..17]
            .iter()
            .flat_map(|s| s.split(','))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let target = f[10]
            .parse::<u64>()
            .ok()
            .and_then(|q| self.by_frame.get(&q).copied());
        let i = target.unwrap_or_else(|| {
            // Response without its query (capture started mid-exchange).
            self.query(
                frame,
                rel - rtt.unwrap_or(0.0) / 1000.0,
                (dst, src),
                f,
                false,
            );
            self.out.len() - 1
        });
        let r = &mut self.out[i];
        r.response_frame = Some(frame);
        r.rcode = rcode;
        r.answers = answers;
        r.rtt_ms = rtt;
    }
}

#[cfg(test)]
#[path = "dns_scan_tests.rs"]
mod tests;
