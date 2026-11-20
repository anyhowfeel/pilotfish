//! `flow_events`: ONE streaming `tshark -T fields` pass producing the sequence-diagram events.

use std::ops::ControlFlow;
use std::path::Path;

use wl_model::{CaptureError, FlowEvent, FlowEvents, MAX_FLOW_EVENTS};

use crate::flow_flags::{analysis_flags, drop_numbers, port, strip_ports, tcp_flags};
use crate::interner::Interner;
use crate::process::Tools;
use crate::tsv_pass::{Pass, opt, run_pass};

/// Info is last so a stray tab inside it cannot shift the other columns (`splitn`).
const FIELDS: [&str; 14] = [
    "frame.number",
    "frame.time_relative",
    "_ws.col.Source",
    "_ws.col.Destination",
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "_ws.col.Protocol",
    "tcp.flags",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "_ws.col.Info",
];

fn parse(line: &str, interner: &mut Interner) -> Option<FlowEvent> {
    let mut f = [""; FIELDS.len()];
    for (slot, v) in f.iter_mut().zip(line.splitn(FIELDS.len(), '\t')) {
        *slot = v;
    }
    let (frame, rel) = (f[0].parse().ok()?, f[1].parse().ok()?);
    let (src, dst) = (opt(f[2])?, opt(f[3])?);
    let info = f[13];
    Some(FlowEvent {
        frame,
        rel,
        src: interner.intern(src),
        dst: interner.intern(dst),
        src_port: port(f[4], f[5]),
        dst_port: port(f[6], f[7]),
        protocol: interner.intern(f[8]),
        label: drop_numbers(&strip_ports(info))
            .replace('\u{2192}', "->")
            .into(),
        flags: tcp_flags(f[9]).with(analysis_flags(info)),
        seq: f[10].parse().ok(),
        ack: f[11].parse().ok(),
        len: f[12].parse().unwrap_or(0),
    })
}

pub fn flow_events(
    tools: &Tools,
    file: &Path,
    filter: &str,
    opts: &[String],
) -> Result<FlowEvents, CaptureError> {
    let pass = Pass {
        file,
        filter,
        fields: &FIELDS,
        opts,
    };
    let (mut out, mut interner) = (FlowEvents::default(), Interner::default());
    run_pass(tools, &pass, |line| {
        if out.events.len() >= MAX_FLOW_EVENTS {
            out.truncated = true;
            return ControlFlow::Break(());
        }
        out.events.extend(parse(line, &mut interner));
        ControlFlow::Continue(())
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::FlowFlags;

    #[test]
    fn parses_a_syn_ack_line() {
        let line = "2\t0.086751\t72.30.35.9\t192.168.74.124\t443\t\t47985\t\tTCP\t0x0012\t0\t1\t0\t443 \u{2192} 47985 [SYN, ACK] Seq=0 Ack=1";
        let e = parse(line, &mut Interner::default()).unwrap();
        assert_eq!(
            (e.frame, e.src_port, e.dst_port),
            (2, Some(443), Some(47985))
        );
        assert_eq!(&*e.label, "[SYN, ACK]");
        assert!(e.flags.contains(FlowFlags::SYN.with(FlowFlags::ACK)));
        assert_eq!((e.seq, e.ack, e.len), (Some(0), Some(1), 0));
    }

    #[test]
    fn non_tcp_and_garbage_lines() {
        let udp = "5\t1.5\t10.0.0.1\t10.0.0.2\t\t5353\t\t5353\tMDNS\t\t\t\t\tStandard query";
        let e = parse(udp, &mut Interner::default()).unwrap();
        assert_eq!((e.seq, e.src_port), (None, Some(5353)));
        assert!(parse("garbage", &mut Interner::default()).is_none());
    }
}
