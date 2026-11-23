//! Packet decoding: link, network and transport layers into the `PacketRow` the UI shows, plus
//! the facts the display filter needs.
//!
//! `src`, `dst`, ports, `len`, `epoch` and `stream` equal tshark's on the fixture captures (see
//! `tests/decode_vs_tshark.rs`). `transport` follows the row parser of `wl-tshark`: ports decide
//! TCP and UDP, otherwise the protocol field of the base IP header does, so an IPv6 packet with
//! extension headers and no ports is `Other` as it is there. An ICMP error takes ports,
//! transport and stream from the packet it quotes, as tshark does. MAC addresses print as plain
//! colon hex, not vendor names.
//!
//! `protocol` and `info` use Wireshark's wording for what [`label`] recognises. Known limits:
//! - Analysis that needs other packets is not reproduced: retransmission and duplicate ACK marks,
//!   "request in N" / "reply in N", checksum and malformed-packet notes.
//! - HTTP and TLS messages are followed across segments only by byte count (`Content-Length`,
//!   chunked end, connection close, TLS record length), not by parsing the reassembled content,
//!   so the last segment of a reassembled message shows its first line without Wireshark's
//!   content-type suffix. A response to a HEAD request is expected to have a body.
//! - IP fragments: the first fragment carries the ports and its datagram gets no stream number;
//!   Wireshark shows them on the last fragment, after reassembly.
//! - Only the application protocols named in [`label`] are recognised; the rest is TCP or UDP.

pub mod detail;
mod fmt;
mod label;
mod link;
mod net;
mod parse;
mod read;
mod streams;
mod transport;

use std::sync::Arc;

use wl_model::{Interner, PacketRow, Transport};

use self::parse::Packet;
use self::streams::{StreamTable, Tuple};
use self::transport::Segment;
use crate::reader::PacketMeta;

/// Layer facts of one packet that the filter evaluator reads. Fields a packet lacks stay `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub eth_src: Option<[u8; 6]>,
    pub eth_dst: Option<[u8; 6]>,
    pub ethertype: Option<u16>,
    /// Outermost VLAN id.
    pub vlan: Option<u16>,
    /// 4 or 6.
    pub ip_version: Option<u8>,
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6).
    pub ip_proto: Option<u8>,
    pub ttl: Option<u8>,
    pub tcp_flags: Option<u8>,
    /// `tcp.stream` or `udp.stream`.
    pub stream: Option<u32>,
    /// The IP header an ICMP error quotes. Wireshark shows it as a second IP layer, so its fields
    /// also answer `ip.addr`, `ip.ttl` and the like.
    pub inner: Option<InnerIp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerIp {
    pub version: u8,
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub proto: u8,
    pub ttl: u8,
    /// The flags byte of a quoted TCP header, when the quote reaches it.
    pub tcp_flags: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    pub row: PacketRow,
    pub facts: Facts,
}

/// Turns packets into rows. Holds the state that spans packets: stream numbering and the string
/// interner.
#[derive(Default)]
pub struct Decoder {
    interner: Interner,
    streams: StreamTable,
}

impl Decoder {
    /// Decodes one packet. Never fails: bytes it cannot read give a row with protocol "Ethernet",
    /// "Raw" or the deepest layer it understood, like Wireshark's malformed-packet fallback.
    pub fn decode(&mut self, meta: &PacketMeta, data: &[u8], first_epoch: f64) -> Decoded {
        let pkt = parse::packet(meta.link, data);
        let tracked = tuple(&pkt).map(|t| self.streams.track(&t));
        let stream = tracked.as_ref().map(|(s, _)| s.id);
        let label = label::describe(&pkt, tracked);
        let (src, dst) = self.endpoints(&pkt);
        let row = PacketRow {
            no: meta.no,
            epoch: meta.epoch,
            rel: meta.epoch - first_epoch,
            src,
            dst,
            src_ip: pkt.addrs().map(|a| a.0),
            dst_ip: pkt.addrs().map(|a| a.1),
            src_port: pkt.ports().map(|p| p.0),
            dst_port: pkt.ports().map(|p| p.1),
            transport: transport_of(&pkt),
            protocol: self.interner.intern(label.protocol),
            len: meta.orig_len,
            info: Arc::from(label.info),
            stream,
        };
        let facts = facts(&pkt, stream);
        Decoded { row, facts }
    }

    fn endpoints(&mut self, pkt: &Packet) -> (Arc<str>, Arc<str>) {
        let text = |ip: Option<std::net::IpAddr>, mac: Option<[u8; 6]>| {
            ip.map(|a| fmt::ip(&a))
                .or_else(|| mac.map(|m| fmt::mac(&m)))
                .unwrap_or_default()
        };
        let (s, d) = match pkt.addrs() {
            Some((s, d)) => (Some(s), Some(d)),
            None => (None, None),
        };
        let src = text(s, pkt.link.src);
        let dst = text(d, pkt.link.dst);
        (self.interner.intern(&src), self.interner.intern(&dst))
    }
}

/// Fragmented datagrams get no stream: only a reassembled one has a transport header to number.
fn tuple(pkt: &Packet) -> Option<Tuple> {
    let ip = pkt.ip().filter(|ip| ip.frag.is_none())?;
    let (udp, ports, syn_seq) = match &pkt.segment {
        Segment::Tcp(t) => {
            let syn = t.has(transport::Tcp::SYN) && !t.has(transport::Tcp::ACK);
            (false, (t.src, t.dst), syn.then_some(t.seq))
        }
        Segment::Udp(u) => (true, (u.src, u.dst), None),
        _ => {
            let numbered = |q: &Tuple| q.udp || pkt.quoted_tcp_flags().is_some();
            return pkt.quoted.clone().filter(numbered);
        }
    };
    Some(Tuple {
        udp,
        src: (ip.src, ports.0),
        dst: (ip.dst, ports.1),
        syn_seq,
    })
}

fn transport_of(pkt: &Packet) -> Transport {
    if let Some(q) = &pkt.quoted {
        return if q.udp {
            Transport::Udp
        } else {
            Transport::Tcp
        };
    }
    match (&pkt.segment, pkt.ip()) {
        (Segment::Tcp(_), _) => Transport::Tcp,
        (Segment::Udp(_), _) => Transport::Udp,
        (_, Some(ip)) => match ip.first_proto {
            transport::TCP => Transport::Tcp,
            transport::UDP => Transport::Udp,
            transport::ICMP | transport::ICMPV6 => Transport::Icmp,
            _ => Transport::Other,
        },
        _ => Transport::Other,
    }
}

fn facts(pkt: &Packet, stream: Option<u32>) -> Facts {
    let ip = pkt.ip();
    let eth = pkt.link.ethernet;
    Facts {
        eth_src: pkt.link.src.filter(|_| eth),
        eth_dst: pkt.link.dst.filter(|_| eth),
        ethertype: pkt.link.ethertype,
        vlan: pkt.link.vlan,
        ip_version: ip.map(|i| i.version),
        ip_proto: ip.map(|i| i.proto),
        ttl: ip.map(|i| i.ttl),
        tcp_flags: match &pkt.segment {
            Segment::Tcp(t) => Some(t.flags),
            _ => None,
        },
        stream,
        inner: pkt.inner.as_ref().map(|i| InnerIp {
            version: i.version,
            src: i.src,
            dst: i.dst,
            proto: i.proto,
            ttl: i.ttl,
            tcp_flags: pkt.quoted_tcp_flags(),
        }),
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod fuzz_tests;
