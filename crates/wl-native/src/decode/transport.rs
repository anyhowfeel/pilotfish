//! Transport layer: TCP, UDP and the ICMP headers, cut from an IP payload.

use etherparse::{TcpHeaderSlice, UdpHeaderSlice};

use super::net::Ip;
use super::read::tail;

pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const ICMPV6: u8 = 58;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcp<'a> {
    pub src: u16,
    pub dst: u16,
    pub seq: u32,
    pub ack: u32,
    /// Flag bits FIN..CWR, as in the TCP header.
    pub flags: u8,
    pub window: u16,
    pub options: &'a [u8],
    /// Frame offset of the header and its length.
    pub offset: usize,
    pub header_len: usize,
    /// Segment length the IP header declares.
    pub payload_len: usize,
    pub payload: &'a [u8],
}

impl Tcp<'_> {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const ACK: u8 = 0x10;

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp<'a> {
    pub src: u16,
    pub dst: u16,
    /// The length field, header included.
    pub length: u16,
    pub offset: usize,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp<'a> {
    pub v6: bool,
    pub kind: u8,
    pub code: u8,
    pub offset: usize,
    /// Everything after the 4 byte type / code / checksum header.
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment<'a> {
    Tcp(Tcp<'a>),
    Udp(Udp<'a>),
    Icmp(Icmp<'a>),
    /// A protocol this decoder does not read, a fragment after the first, or a cut header.
    None,
}

pub fn parse<'a>(ip: &Ip<'a>) -> Segment<'a> {
    if ip.frag.is_some_and(|f| f.offset != 0) {
        return Segment::None;
    }
    let at = ip.offset + ip.header_len;
    match ip.proto {
        TCP => tcp(ip, at).map_or(Segment::None, Segment::Tcp),
        UDP => udp(ip, at).map_or(Segment::None, Segment::Udp),
        ICMP | ICMPV6 => icmp(ip, at).map_or(Segment::None, Segment::Icmp),
        _ => Segment::None,
    }
}

fn tcp<'a>(ip: &Ip<'a>, at: usize) -> Option<Tcp<'a>> {
    let h = TcpHeaderSlice::from_slice(ip.payload).ok()?;
    let hl = h.slice().len();
    let payload_len = ip.payload_len.saturating_sub(hl);
    let end = (hl + payload_len).min(ip.payload.len());
    let flags = u8::from(h.fin())
        | u8::from(h.syn()) << 1
        | u8::from(h.rst()) << 2
        | u8::from(h.psh()) << 3
        | u8::from(h.ack()) << 4
        | u8::from(h.urg()) << 5
        | u8::from(h.ece()) << 6
        | u8::from(h.cwr()) << 7;
    Some(Tcp {
        src: h.source_port(),
        dst: h.destination_port(),
        seq: h.sequence_number(),
        ack: h.acknowledgment_number(),
        flags,
        window: h.window_size(),
        options: ip.payload.get(20..hl).unwrap_or(&[]),
        offset: at,
        header_len: hl,
        payload_len,
        payload: tail(&ip.payload[..end], hl),
    })
}

fn udp<'a>(ip: &Ip<'a>, at: usize) -> Option<Udp<'a>> {
    let h = UdpHeaderSlice::from_slice(ip.payload).ok()?;
    let length = h.length();
    let end = usize::from(length).clamp(8, ip.payload.len().max(8));
    Some(Udp {
        src: h.source_port(),
        dst: h.destination_port(),
        length,
        offset: at,
        payload: tail(&ip.payload[..end.min(ip.payload.len())], 8),
    })
}

fn icmp<'a>(ip: &Ip<'a>, at: usize) -> Option<Icmp<'a>> {
    let p = ip.payload;
    Some(Icmp {
        v6: ip.proto == ICMPV6,
        kind: *p.first()?,
        code: *p.get(1)?,
        offset: at,
        body: p.get(4..)?,
    })
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
