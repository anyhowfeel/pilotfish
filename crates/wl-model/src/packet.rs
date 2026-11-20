use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Incoming,
    Outgoing,
    Unknown,
}

/// One line of the packet list. Cheap to clone (strings are interned `Arc<str>`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacketRow {
    /// 1-based frame number, identical to Wireshark's `frame.number`.
    pub no: u64,
    /// Seconds since the Unix epoch.
    pub epoch: f64,
    /// Seconds since the first packet of the session.
    pub rel: f64,
    /// Display source (IP, or MAC / protocol address when no IP layer).
    pub src: Arc<str>,
    pub dst: Arc<str>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub transport: Transport,
    /// Highest-layer protocol as shown by Wireshark (`_ws.col.protocol`).
    pub protocol: Arc<str>,
    /// Bytes on the wire (`frame.len`).
    pub len: u32,
    pub info: Arc<str>,
    /// `tcp.stream` / `udp.stream` when present.
    pub stream: Option<u32>,
}

/// Direction-agnostic identity of a conversation (A<->B).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowKey {
    pub a: Arc<str>,
    pub b: Arc<str>,
    pub transport: Transport,
    pub a_port: Option<u16>,
    pub b_port: Option<u16>,
}

/// True for protocols that carry encrypted payloads (TLS/SSL/DTLS, QUIC, SSH, IPsec, VPNs).
pub fn is_encrypted_protocol(protocol: &str) -> bool {
    let p = protocol.trim().to_ascii_uppercase();
    [
        "TLS",
        "SSL",
        "DTLS",
        "QUIC",
        "SSH",
        "ESP",
        "ISAKMP",
        "IKE",
        "WIREGUARD",
        "OPENVPN",
        "HTTPS",
    ]
    .iter()
    .any(|k| p.starts_with(k))
}

impl PacketRow {
    /// Canonical key: endpoints ordered so A->B and B->A map to the same key.
    pub fn flow_key(&self) -> FlowKey {
        let fwd = (&self.src, self.src_port) <= (&self.dst, self.dst_port);
        let (a, b, a_port, b_port) = if fwd {
            (&self.src, &self.dst, self.src_port, self.dst_port)
        } else {
            (&self.dst, &self.src, self.dst_port, self.src_port)
        };
        FlowKey {
            a: a.clone(),
            b: b.clone(),
            transport: self.transport,
            a_port,
            b_port,
        }
    }
}
