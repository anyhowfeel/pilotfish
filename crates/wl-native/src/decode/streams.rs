//! Stream numbering and the per-stream state the labels need.
//!
//! Numbers follow Wireshark's `tcp.stream` and `udp.stream`: one counter per transport, assigned
//! in order of first appearance of the direction-agnostic (address, port) pair and IP version.
//!
//! A TCP SYN (without ACK) on a stream that saw FIN or RST, or whose side already started at a
//! different sequence number, opens a new stream, as Wireshark's "port numbers reused" does.
//!
//! Limits: a datagram that arrives as IP fragments never gets a number, where Wireshark numbers
//! the reassembled datagram; the table holds at most [`MAX_STREAMS`] streams (about 150 bytes each,
//! so 150 MB at the cap) and forgets the oldest first, after which a late packet of a forgotten
//! stream starts a new number.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

pub const MAX_STREAMS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct End {
    addr: [u8; 16],
    port: u16,
}

impl End {
    fn new(ip: IpAddr, port: u16) -> Self {
        let mut addr = [0; 16];
        match ip {
            IpAddr::V4(v) => addr[..4].copy_from_slice(&v.octets()),
            IpAddr::V6(v) => addr = v.octets(),
        }
        End { addr, port }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    lo: End,
    hi: End,
    v6: bool,
    udp: bool,
}

/// What one side of a TCP stream has shown so far.
#[derive(Debug, Clone, Copy, Default)]
pub struct Half {
    /// Sequence number that relative numbers count from.
    pub base: Option<u32>,
    /// Window scale shift announced in this side's SYN.
    pub shift: Option<u8>,
    /// A ChangeCipherSpec went by, so later handshake records are encrypted.
    pub ccs: bool,
    /// Bytes of the current TLS record still to come in later segments.
    pub pending: u32,
    /// Content type of that record.
    pub pending_ct: u8,
    /// Record version of that record.
    pub pending_version: u16,
}

#[derive(Debug, Clone)]
pub struct Stream {
    pub id: u32,
    /// Index 0 is the side with the lower (address, port).
    pub half: [Half; 2],
    /// TLS version negotiated on this stream, from the hello messages.
    pub tls: Option<u16>,
    /// FIN or RST went by.
    pub closed: bool,
    /// First line of an HTTP message whose body is still arriving.
    pub http_line: Option<Box<str>>,
}

impl Stream {
    pub fn new(id: u32) -> Self {
        Stream {
            id,
            half: [Half::default(); 2],
            tls: None,
            closed: false,
            http_line: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuple {
    pub udp: bool,
    pub src: (IpAddr, u16),
    pub dst: (IpAddr, u16),
    /// Sequence number of a SYN without ACK, which may start a new connection on a used pair.
    pub syn_seq: Option<u32>,
}

pub struct StreamTable {
    map: HashMap<Key, Stream>,
    order: VecDeque<Key>,
    next: [u32; 2],
    cap: usize,
}

impl Default for StreamTable {
    fn default() -> Self {
        Self::with_capacity(MAX_STREAMS)
    }
}

impl StreamTable {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            next: [0; 2],
            cap: cap.max(1),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Finds or creates the stream of `t`. The second value is the side `t.src` is: 0 or 1.
    pub fn track(&mut self, t: &Tuple) -> (&mut Stream, usize) {
        let (a, b) = (End::new(t.src.0, t.src.1), End::new(t.dst.0, t.dst.1));
        let dir = usize::from(a > b);
        let key = Key {
            lo: a.min(b),
            hi: a.max(b),
            v6: t.src.0.is_ipv6(),
            udp: t.udp,
        };
        if self.map.len() >= self.cap
            && !self.map.contains_key(&key)
            && let Some(old) = self.order.pop_front()
        {
            self.map.remove(&old);
        }
        let next = &mut self.next[usize::from(t.udp)];
        let stream = match self.map.entry(key) {
            Entry::Occupied(e) => {
                let stream = e.into_mut();
                let reused = t.syn_seq.is_some_and(|seq| {
                    stream.closed || stream.half[dir].base.is_some_and(|b| b != seq)
                });
                if reused {
                    *stream = Stream::new(take(next));
                }
                stream
            }
            Entry::Vacant(v) => {
                self.order.push_back(key);
                v.insert(Stream::new(take(next)))
            }
        };
        (stream, dir)
    }
}

fn take(counter: &mut u32) -> u32 {
    let id = *counter;
    *counter = counter.wrapping_add(1);
    id
}

#[cfg(test)]
#[path = "streams_tests.rs"]
mod tests;
