//! Which packets the flow graph highlights: handshake, teardown, resets, retransmissions
//! and other TCP anomalies (pure classification, one mark per event).

use std::collections::HashSet;
use std::sync::Arc;

use wl_model::{FlowEvent, FlowFlags};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mark {
    #[default]
    None,
    Handshake,
    Teardown,
    Reset,
    Retransmission,
    /// Dup ACK, out-of-order, lost segment, zero window.
    Anomaly,
}

impl Mark {
    pub fn label(self) -> &'static str {
        match self {
            Mark::None => "",
            Mark::Handshake => "Handshake",
            Mark::Teardown => "Teardown",
            Mark::Reset => "Reset",
            Mark::Retransmission => "Retransmission",
            Mark::Anomaly => "Dup ACK / loss",
        }
    }
}

type Dir = (Arc<str>, Option<u16>, Arc<str>, Option<u16>);

fn dir(e: &FlowEvent) -> Dir {
    (e.src.clone(), e.src_port, e.dst.clone(), e.dst_port)
}

fn reversed(e: &FlowEvent) -> Dir {
    (e.dst.clone(), e.dst_port, e.src.clone(), e.src_port)
}

/// How many events carry each mark (marks that never occur are left out).
pub fn counts(marks: &[Mark]) -> Vec<(Mark, usize)> {
    [
        Mark::Handshake,
        Mark::Teardown,
        Mark::Reset,
        Mark::Retransmission,
        Mark::Anomaly,
    ]
    .into_iter()
    .map(|m| (m, marks.iter().filter(|x| **x == m).count()))
    .filter(|(_, n)| *n > 0)
    .collect()
}

const ANOMALY: FlowFlags = FlowFlags(
    FlowFlags::DUP_ACK.0 | FlowFlags::OUT_OF_ORDER.0 | FlowFlags::LOST.0 | FlowFlags::ZERO_WINDOW.0,
);

/// One mark per event. The ACK completing a three-way handshake counts as handshake too.
pub fn classify(events: &[FlowEvent]) -> Vec<Mark> {
    let mut third_ack: HashSet<Dir> = HashSet::new();
    events
        .iter()
        .map(|e| {
            let f = e.flags;
            if f.contains(FlowFlags::RETRANS) {
                Mark::Retransmission
            } else if f.intersects(ANOMALY) {
                Mark::Anomaly
            } else if f.contains(FlowFlags::RST) {
                Mark::Reset
            } else if f.contains(FlowFlags::FIN) {
                Mark::Teardown
            } else if f.contains(FlowFlags::SYN) {
                if f.contains(FlowFlags::ACK) {
                    third_ack.insert(reversed(e));
                }
                Mark::Handshake
            } else if f.contains(FlowFlags::ACK) && e.len == 0 && third_ack.remove(&dir(e)) {
                Mark::Handshake
            } else {
                Mark::None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(src: &str, dst: &str, flags: FlowFlags, len: u32) -> FlowEvent {
        FlowEvent {
            frame: 1,
            rel: 0.0,
            src: src.into(),
            dst: dst.into(),
            src_port: Some(if src == "c" { 1 } else { 2 }),
            dst_port: Some(if dst == "c" { 1 } else { 2 }),
            protocol: "TCP".into(),
            label: "".into(),
            flags,
            seq: None,
            ack: None,
            len,
        }
    }

    #[test]
    fn handshake_data_teardown() {
        let syn = FlowFlags::SYN;
        let synack = FlowFlags::SYN.with(FlowFlags::ACK);
        let fin = FlowFlags::FIN.with(FlowFlags::ACK);
        let marks = classify(&[
            ev("c", "s", syn, 0),
            ev("s", "c", synack, 0),
            ev("c", "s", FlowFlags::ACK, 0),
            ev("c", "s", FlowFlags::ACK, 0),
            ev("s", "c", fin, 0),
        ]);
        use Mark::*;
        assert_eq!(marks, [Handshake, Handshake, Handshake, None, Teardown]);
    }

    #[test]
    fn counts_skip_absent_marks() {
        let c = counts(&[Mark::None, Mark::Handshake, Mark::Handshake, Mark::Reset]);
        assert_eq!(c, [(Mark::Handshake, 2), (Mark::Reset, 1)]);
    }

    #[test]
    fn anomalies_take_priority() {
        let marks = classify(&[
            ev("c", "s", FlowFlags::ACK.with(FlowFlags::RETRANS), 100),
            ev("s", "c", FlowFlags::ACK.with(FlowFlags::DUP_ACK), 0),
            ev("s", "c", FlowFlags::RST, 0),
        ]);
        assert_eq!(marks, [Mark::Retransmission, Mark::Anomaly, Mark::Reset]);
    }
}
