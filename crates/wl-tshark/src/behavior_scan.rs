//! One streamed pass reduced on the fly to per-channel timing summaries. Memory follows the
//! number of distinct channels, not packets, so there is no packet cap.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};
use wl_model::{CaptureError, Channel, ChannelKind, Proto};

use crate::process::Tools;
use crate::tsv_pass::{Pass, columns, opt, run_pass};

const FILTER: &str = "(tcp.flags.syn == 1 && tcp.flags.ack == 0) || tcp.len > 0 || udp \
                      || icmp.type == 8 || icmpv6.type == 128";
const FIELDS: [&str; 14] = [
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.len",
    "tcp.dstport",
    "tcp.stream",
    "udp.dstport",
    "udp.stream",
    "icmp.type",
    "icmpv6.type",
];
const MAX_CHANNELS: usize = 300_000;
/// Stream channels with fewer events cannot show a rhythm and are dropped from the output.
const MIN_STREAM_EVENTS: u32 = 4;

#[derive(Hash, PartialEq, Eq)]
struct Key {
    src: u32,
    dst: u32,
    stream: u32,
    dport: u16,
    proto: Proto,
    kind: u8,
}

/// Running count / mean / variance of the gaps between events (Welford).
#[derive(Default)]
struct Gaps {
    events: u32,
    last: f64,
    mean: f64,
    m2: f64,
}

impl Gaps {
    fn push(&mut self, t: f64) {
        if self.events > 0 {
            let gap = (t - self.last).max(0.0);
            let delta = gap - self.mean;
            self.mean += delta / f64::from(self.events);
            self.m2 += delta * (gap - self.mean);
        }
        self.last = t;
        self.events += 1;
    }

    fn jitter(&self) -> f64 {
        let gaps = self.events.saturating_sub(1);
        if gaps < 2 || self.mean <= 0.0 {
            return 0.0;
        }
        (self.m2 / f64::from(gaps)).sqrt() / self.mean
    }
}

#[derive(Default)]
struct Reducer {
    names: HashMap<Box<str>, u32>,
    by_id: Vec<Arc<str>>,
    channels: FxHashMap<Key, Gaps>,
    udp_seen: FxHashSet<u32>,
}

impl Reducer {
    fn id(&mut self, addr: &str) -> u32 {
        if let Some(&i) = self.names.get(addr) {
            return i;
        }
        let i = self.by_id.len() as u32;
        self.names.insert(addr.into(), i);
        self.by_id.push(Arc::from(addr));
        i
    }

    fn record(&mut self, key: Key, t: f64) {
        if self.channels.len() < MAX_CHANNELS || self.channels.contains_key(&key) {
            self.channels.entry(key).or_default().push(t);
        }
    }

    fn push_line(&mut self, line: &str) {
        let f: [&str; FIELDS.len()] = columns(line);
        let (Ok(t), Some(src), Some(dst)) = (
            f[0].trim().parse::<f64>(),
            opt(f[1]).or(opt(f[2])),
            opt(f[3]).or(opt(f[4])),
        ) else {
            return;
        };
        let (src, dst) = (self.id(src), self.id(dst));
        let key = |proto, kind: ChannelKind, dport, stream| Key {
            src,
            dst,
            stream,
            dport,
            proto,
            kind: kind as u8,
        };
        if !f[12].is_empty() || !f[13].is_empty() {
            if f[12] == "8" || f[13] == "128" {
                self.record(key(Proto::Icmp, ChannelKind::NewFlows, 0, 0), t);
            }
        } else if let (Ok(port), Ok(stream)) = (f[8].parse(), f[9].parse()) {
            if f[5] == "True" && f[6] != "True" {
                self.record(key(Proto::Tcp, ChannelKind::NewFlows, port, 0), t);
            } else if f[7].parse::<u32>().is_ok_and(|n| n > 0) {
                self.record(key(Proto::Tcp, ChannelKind::Stream, port, stream), t);
            }
        } else if let (Ok(port), Ok(stream)) = (f[10].parse(), f[11].parse())
            && self.udp_seen.insert(stream)
        {
            self.record(key(Proto::Udp, ChannelKind::NewFlows, port, 0), t);
        }
    }

    fn finish(self) -> Vec<Channel> {
        let names = self.by_id;
        self.channels
            .into_iter()
            .filter_map(|(k, g)| {
                let kind = if k.kind == ChannelKind::Stream as u8 {
                    ChannelKind::Stream
                } else {
                    ChannelKind::NewFlows
                };
                (kind == ChannelKind::NewFlows || g.events >= MIN_STREAM_EVENTS).then(|| Channel {
                    src: names[k.src as usize].clone(),
                    dst: names[k.dst as usize].clone(),
                    proto: k.proto,
                    kind,
                    dport: k.dport,
                    count: g.events,
                    gap_mean: g.mean,
                    gap_jitter: g.jitter(),
                })
            })
            .collect()
    }
}

pub fn behavior_channels(
    tools: &Tools,
    file: &Path,
    opts: &[String],
) -> Result<Vec<Channel>, CaptureError> {
    let mut all = opts.to_vec();
    all.extend(["-o".into(), "tcp.desegment_tcp_streams:FALSE".into()]);
    let pass = Pass {
        scope: None,
        file,
        filter: FILTER,
        fields: &FIELDS,
        opts: &all,
    };
    let mut reducer = Reducer::default();
    run_pass(tools, &pass, |line| {
        reducer.push_line(line);
        ControlFlow::Continue(())
    })?;
    Ok(reducer.finish())
}

#[cfg(test)]
#[path = "behavior_scan_tests.rs"]
mod tests;
