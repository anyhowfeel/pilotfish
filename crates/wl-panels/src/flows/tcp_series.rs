//! TCP stream graphs as plain point lists (pure: `TcpSamples` + direction -> series).
//! "Direction" is the data direction: `a_to_b` plots what A sends and what B answers.

use wl_model::{FlowFlags, TcpSample, TcpSamples};

/// What a series stands for; the view maps roles to colours and markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Main,
    Ack,
    Retransmission,
    DupAck,
    ZeroWindow,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pts {
    pub name: &'static str,
    pub role: Role,
    pub points: Vec<[f64; 2]>,
}

/// Number of throughput buckets across the stream.
const BUCKETS: f64 = 48.0;
const MIN_BUCKET_S: f64 = 0.01;

fn forward(s: &TcpSamples, a_to_b: bool) -> impl Iterator<Item = &TcpSample> {
    s.samples.iter().filter(move |x| x.from_a == a_to_b)
}

fn backward(s: &TcpSamples, a_to_b: bool) -> impl Iterator<Item = &TcpSample> {
    s.samples.iter().filter(move |x| x.from_a != a_to_b)
}

/// Direction that carries more payload (the interesting one for a download or upload).
pub fn busiest(s: &TcpSamples) -> bool {
    let bytes = |dir: bool| forward(s, dir).map(|x| u64::from(x.len)).sum::<u64>();
    bytes(true) >= bytes(false)
}

fn pts(name: &'static str, role: Role, points: Vec<[f64; 2]>) -> Pts {
    Pts { name, role, points }
}

/// Stevens time-sequence: end of every data segment, the ACK line of the peer and the marks.
pub fn time_sequence(s: &TcpSamples, a_to_b: bool) -> Vec<Pts> {
    let end = |x: &TcpSample| [x.rel, (x.seq + u64::from(x.len)) as f64];
    let data = || forward(s, a_to_b).filter(|x| x.len > 0);
    let acks = || backward(s, a_to_b).filter(|x| x.flags.contains(FlowFlags::ACK));
    vec![
        pts("Data (seq + len)", Role::Main, data().map(end).collect()),
        pts(
            "ACK (peer)",
            Role::Ack,
            acks().map(|x| [x.rel, x.ack as f64]).collect(),
        ),
        pts(
            "Retransmission",
            Role::Retransmission,
            data()
                .filter(|x| x.flags.contains(FlowFlags::RETRANS))
                .map(end)
                .collect(),
        ),
        pts(
            "Duplicate ACK",
            Role::DupAck,
            acks()
                .filter(|x| x.flags.contains(FlowFlags::DUP_ACK))
                .map(|x| [x.rel, x.ack as f64])
                .collect(),
        ),
    ]
}

/// Bucket width in seconds for a stream lasting `duration`.
pub fn bucket_width(duration: f64) -> f64 {
    (duration / BUCKETS).max(MIN_BUCKET_S)
}

/// Payload bytes per second in fixed buckets (all data, and the retransmitted part).
pub fn throughput(s: &TcpSamples, a_to_b: bool) -> Vec<Pts> {
    let data: Vec<&TcpSample> = forward(s, a_to_b).filter(|x| x.len > 0).collect();
    let (Some(first), Some(last)) = (s.samples.first(), s.samples.last()) else {
        return Vec::new();
    };
    let (t0, w) = (first.rel, bucket_width(last.rel - first.rel));
    let n = ((last.rel - t0) / w) as usize + 1;
    let (mut all, mut re) = (vec![0.0; n], vec![0.0; n]);
    for x in data {
        let i = (((x.rel - t0) / w) as usize).min(n - 1);
        all[i] += f64::from(x.len);
        if x.flags.contains(FlowFlags::RETRANS) {
            re[i] += f64::from(x.len);
        }
    }
    let line = |v: &[f64]| -> Vec<[f64; 2]> {
        v.iter()
            .enumerate()
            .map(|(i, b)| [t0 + (i as f64 + 0.5) * w, b / w])
            .collect()
    };
    let mut out = vec![pts("Throughput", Role::Main, line(&all))];
    if re.iter().any(|b| *b > 0.0) {
        out.push(pts("Retransmitted", Role::Retransmission, line(&re)));
    }
    out
}

/// ACK round-trip times (ms) measured on the peer's acknowledgements of our data.
pub fn rtt(s: &TcpSamples, a_to_b: bool) -> Vec<Pts> {
    let p = backward(s, a_to_b)
        .filter_map(|x| x.rtt.map(|r| [x.rel, r * 1000.0]))
        .collect();
    vec![pts("ACK RTT", Role::Main, p)]
}

/// Receive window advertised by the peer, zero-window events marked.
pub fn window(s: &TcpSamples, a_to_b: bool) -> Vec<Pts> {
    let adv = || backward(s, a_to_b).filter(|x| !x.flags.contains(FlowFlags::SYN));
    vec![
        pts(
            "Advertised window",
            Role::Main,
            adv().map(|x| [x.rel, x.window as f64]).collect(),
        ),
        pts(
            "Zero window",
            Role::ZeroWindow,
            adv()
                .filter(|x| x.flags.contains(FlowFlags::ZERO_WINDOW))
                .map(|x| [x.rel, 0.0])
                .collect(),
        ),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Summary {
    pub segments: usize,
    pub bytes: u64,
    pub retransmissions: usize,
    pub dup_acks: usize,
    pub rtt_mean_ms: Option<f64>,
    pub rtt_max_ms: Option<f64>,
}

pub fn summary(s: &TcpSamples, a_to_b: bool) -> Summary {
    let data = || forward(s, a_to_b).filter(|x| x.len > 0);
    let rtts: Vec<f64> = backward(s, a_to_b)
        .filter_map(|x| x.rtt.map(|r| r * 1000.0))
        .collect();
    Summary {
        segments: data().count(),
        bytes: data().map(|x| u64::from(x.len)).sum(),
        retransmissions: data()
            .filter(|x| x.flags.contains(FlowFlags::RETRANS))
            .count(),
        dup_acks: backward(s, a_to_b)
            .filter(|x| x.flags.contains(FlowFlags::DUP_ACK))
            .count(),
        rtt_mean_ms: (!rtts.is_empty()).then(|| rtts.iter().sum::<f64>() / rtts.len() as f64),
        rtt_max_ms: rtts.iter().copied().reduce(f64::max),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smp(rel: f64, from_a: bool, seq: u64, len: u32, flags: FlowFlags) -> TcpSample {
        TcpSample {
            frame: 1,
            rel,
            from_a,
            seq,
            ack: seq,
            len,
            window: 1000,
            rtt: None,
            flags,
        }
    }

    fn sample_set() -> TcpSamples {
        let ack = FlowFlags::ACK;
        let mut a_ack = smp(0.3, false, 0, 0, ack);
        a_ack.ack = 200;
        a_ack.rtt = Some(0.05);
        let mut dup = smp(0.4, false, 0, 0, ack.with(FlowFlags::DUP_ACK));
        dup.ack = 200;
        TcpSamples {
            samples: vec![
                smp(0.0, true, 0, 100, ack),
                smp(0.1, true, 100, 100, ack),
                a_ack,
                dup,
                smp(0.5, true, 100, 100, ack.with(FlowFlags::RETRANS)),
                smp(1.0, true, 200, 0, ack),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn busiest_direction_is_the_one_with_payload() {
        assert!(busiest(&sample_set()));
    }

    #[test]
    fn time_sequence_has_data_acks_and_marks() {
        let s = time_sequence(&sample_set(), true);
        assert_eq!(s[0].points, [[0.0, 100.0], [0.1, 200.0], [0.5, 200.0]]);
        assert_eq!(s[1].points, [[0.3, 200.0], [0.4, 200.0]]);
        assert_eq!(s[2].points, [[0.5, 200.0]]);
        assert_eq!(s[3].points, [[0.4, 200.0]]);
    }

    #[test]
    fn throughput_conserves_bytes() {
        let set = sample_set();
        let s = throughput(&set, true);
        let w = bucket_width(1.0);
        let total: f64 = s[0].points.iter().map(|p| p[1] * w).sum();
        assert!((total - 300.0).abs() < 1e-6, "{total}");
        assert_eq!(s[1].role, Role::Retransmission);
    }

    #[test]
    fn rtt_window_and_summary() {
        let set = sample_set();
        assert_eq!(rtt(&set, true)[0].points, [[0.3, 50.0]]);
        assert_eq!(window(&set, true)[0].points.len(), 2);
        let sum = summary(&set, true);
        assert_eq!((sum.segments, sum.bytes), (3, 300));
        assert_eq!((sum.retransmissions, sum.dup_acks), (1, 1));
        assert_eq!(sum.rtt_mean_ms, Some(50.0));
    }

    #[test]
    fn empty_stream_is_harmless() {
        let e = TcpSamples::default();
        assert!(throughput(&e, true).is_empty());
        assert_eq!(summary(&e, true), Summary::default());
    }
}
