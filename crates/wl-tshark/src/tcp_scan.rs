//! `tcp_samples`: ONE streaming pass collecting what the TCP stream graphs plot
//! (seq, ack, len, window, ack RTT, retransmission markers) for a single connection.

use std::ops::ControlFlow;
use std::path::Path;

use rustc_hash::FxHashSet;
use wl_model::{CaptureError, MAX_TCP_SAMPLES, TcpSample, TcpSamples};

use crate::flow_flags::{analysis_flags, tcp_flags};
use crate::process::Tools;
use crate::tsv_pass::{Pass, opt, run_pass};

const FIELDS: [&str; 14] = [
    "frame.number",
    "frame.time_relative",
    "_ws.col.def_src",
    "_ws.col.def_dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.window_size",
    "tcp.analysis.ack_rtt",
    "_ws.col.info",
    "tcp.stream",
];

fn parse(line: &str, out: &mut TcpSamples) -> Option<()> {
    let mut f = [""; FIELDS.len()];
    for (slot, v) in f.iter_mut().zip(line.splitn(FIELDS.len(), '\t')) {
        *slot = v;
    }
    let (src, dst) = (opt(f[2])?, opt(f[3])?);
    let (sp, dp) = (f[4].parse().ok(), f[5].parse().ok());
    let (frame, rel) = (f[0].parse().ok()?, f[1].parse().ok()?);
    if out.samples.is_empty() {
        out.a = src.into();
        out.b = dst.into();
        out.a_port = sp;
        out.b_port = dp;
    }
    out.samples.push(TcpSample {
        frame,
        rel,
        from_a: *out.a == *src && out.a_port == sp,
        seq: f[7].parse().unwrap_or(0),
        ack: f[8].parse().unwrap_or(0),
        len: f[9].parse().unwrap_or(0),
        window: f[10].parse().unwrap_or(0),
        rtt: f[11].parse().ok(),
        flags: tcp_flags(f[6]).with(analysis_flags(f[12])),
    });
    Some(())
}

pub fn tcp_samples(
    tools: &Tools,
    file: &Path,
    filter: &str,
    opts: &[String],
) -> Result<TcpSamples, CaptureError> {
    // Only sizes and TCP analysis matter: skip reassembly and application dissection.
    let mut all = opts.to_vec();
    all.extend(["-o".into(), "tcp.desegment_tcp_streams:FALSE".into()]);
    let filter = format!("tcp && ({filter})");
    let pass = Pass {
        file,
        filter: &filter,
        fields: &FIELDS,
        opts: &all,
    };
    let mut out = TcpSamples::default();
    let (mut first, mut others) = (None::<String>, FxHashSet::default());
    run_pass(tools, &pass, |line| {
        let stream = line.rsplit('\t').next().unwrap_or("");
        if first.get_or_insert_with(|| stream.to_owned()) != stream {
            others.insert(stream.to_owned());
            return ControlFlow::Continue(());
        }
        if out.samples.len() >= MAX_TCP_SAMPLES {
            out.truncated = true;
            return ControlFlow::Break(());
        }
        parse(line, &mut out);
        ControlFlow::Continue(())
    })?;
    out.other_streams = others.len() as u32;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sender_is_endpoint_a() {
        let mut out = TcpSamples::default();
        let l1 = "1\t0.0\t10.0.0.1\t10.0.0.2\t5000\t80\t0x0002\t0\t0\t0\t29200\t\t5000 \u{2192} 80 [SYN]";
        let l2 = "2\t0.1\t10.0.0.2\t10.0.0.1\t80\t5000\t0x0012\t0\t1\t0\t64240\t0.1\t80 \u{2192} 5000 [SYN, ACK]";
        parse(l1, &mut out);
        parse(l2, &mut out);
        assert_eq!(
            (&*out.a, out.a_port, out.samples.len()),
            ("10.0.0.1", Some(5000), 2)
        );
        assert!(out.samples[0].from_a && !out.samples[1].from_a);
        assert_eq!(out.samples[1].rtt, Some(0.1));
        assert_eq!(out.samples[1].window, 64240);
    }
}
