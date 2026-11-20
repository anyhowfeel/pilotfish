//! Events -> lifelines: one lane per host in order of first appearance (initiator leftmost).

use std::collections::HashMap;
use std::sync::Arc;

use wl_model::FlowEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub addr: Arc<str>,
    /// The only port this host used (shown under its name), `None` when it used several.
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Lanes {
    pub hosts: Vec<Host>,
    /// Lane index of the sender / receiver of every event (same order as the events).
    pub from: Vec<u16>,
    pub to: Vec<u16>,
}

#[derive(Default)]
struct Slot {
    idx: u16,
    port: Option<u16>,
    multi: bool,
}

fn touch<'a>(
    map: &mut HashMap<&'a str, Slot>,
    hosts: &mut Vec<Host>,
    addr: &'a Arc<str>,
    port: Option<u16>,
) -> u16 {
    let next = hosts.len() as u16;
    let slot = map.entry(addr).or_insert_with(|| {
        hosts.push(Host {
            addr: addr.clone(),
            port: None,
        });
        Slot {
            idx: next,
            port,
            multi: false,
        }
    });
    if slot.port != port {
        slot.multi = true;
    }
    slot.idx
}

pub fn build(events: &[FlowEvent]) -> Lanes {
    let mut map: HashMap<&str, Slot> = HashMap::new();
    let mut lanes = Lanes {
        hosts: Vec::new(),
        from: Vec::with_capacity(events.len()),
        to: Vec::with_capacity(events.len()),
    };
    for e in events {
        let f = touch(&mut map, &mut lanes.hosts, &e.src, e.src_port);
        let t = touch(&mut map, &mut lanes.hosts, &e.dst, e.dst_port);
        lanes.from.push(f);
        lanes.to.push(t);
    }
    for (addr, slot) in &map {
        if !slot.multi {
            lanes.hosts[usize::from(slot.idx)].port = slot.port;
        }
        debug_assert_eq!(&*lanes.hosts[usize::from(slot.idx)].addr, *addr);
    }
    lanes
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::FlowFlags;

    pub(crate) fn ev(frame: u64, src: &str, sp: u16, dst: &str, dp: u16) -> FlowEvent {
        FlowEvent {
            frame,
            rel: frame as f64 * 0.01,
            src: src.into(),
            dst: dst.into(),
            src_port: Some(sp),
            dst_port: Some(dp),
            protocol: "TCP".into(),
            label: "[ACK]".into(),
            flags: FlowFlags::ACK,
            seq: Some(1),
            ack: Some(1),
            len: 0,
        }
    }

    #[test]
    fn lanes_follow_first_appearance() {
        let l = build(&[
            ev(1, "c", 5000, "s", 80),
            ev(2, "s", 80, "c", 5000),
            ev(3, "c", 5000, "x", 53),
        ]);
        let names: Vec<&str> = l.hosts.iter().map(|h| &*h.addr).collect();
        assert_eq!(names, ["c", "s", "x"]);
        assert_eq!(
            (l.from.as_slice(), l.to.as_slice()),
            (&[0, 1, 0][..], &[1, 0, 2][..])
        );
        assert_eq!(l.hosts[0].port, Some(5000));
    }

    #[test]
    fn a_host_with_several_ports_shows_none() {
        let l = build(&[ev(1, "c", 5000, "s", 80), ev(2, "c", 5001, "s", 80)]);
        assert_eq!((l.hosts[0].port, l.hosts[1].port), (None, Some(80)));
    }

    #[test]
    fn empty_input() {
        assert_eq!(build(&[]), Lanes::default());
    }
}
