//! Layers assembled byte by byte, for cases etherparse cannot build: bad lengths, odd versions, TLS and DNS payloads.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::packets::dns_query_payload;
use super::{MAC_A, MAC_B};

/// Ethernet II frame with an arbitrary ethertype and payload.
pub fn eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.extend_from_slice(&MAC_B);
    out.extend_from_slice(&MAC_A);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Ethernet frame with `tags` 802.1Q / 802.1ad tags, each `(tag protocol id, vlan id)`, then
/// `ethertype` and `payload`.
pub fn eth_tagged(tags: &[(u16, u16)], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAC_B);
    out.extend_from_slice(&MAC_A);
    for (tpid, vid) in tags {
        out.extend_from_slice(&tpid.to_be_bytes());
        out.extend_from_slice(&vid.to_be_bytes());
    }
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// IPv4 header (20 bytes, checksum left zero) followed by `payload`. `frag` is the raw flags and
/// fragment offset field.
pub fn ip4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    ident: u16,
    frag: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = vec![0x45, 0];
    out.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    out.extend_from_slice(&ident.to_be_bytes());
    out.extend_from_slice(&frag.to_be_bytes());
    out.extend_from_slice(&[64, proto, 0, 0]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(payload);
    out
}

/// IPv6 header followed by `payload`, which may start with extension headers.
pub fn ip6_packet(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60, 0, 0, 0];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&[next, 64]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(payload);
    out
}

/// TCP header with raw `flags`, optional `options` (length a multiple of 4) and `payload`.
pub fn tcp_segment(
    ports: (u16, u16),
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ports.0.to_be_bytes());
    out.extend_from_slice(&ports.1.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ack.to_be_bytes());
    out.push((((20 + options.len()) / 4) as u8) << 4);
    out.push(flags);
    out.extend_from_slice(&window.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(options);
    out.extend_from_slice(payload);
    out
}

/// UDP header followed by `payload`.
pub fn udp_datagram(ports: (u16, u16), payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ports.0.to_be_bytes());
    out.extend_from_slice(&ports.1.to_be_bytes());
    out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

/// A TCP segment over IPv4 over Ethernet, built from raw header values.
pub fn tcp4_raw(
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    seq: u32,
    ack: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let tcp = tcp_segment((src.1, dst.1), seq, ack, flags, 64240, options, payload);
    eth_frame(0x0800, &ip4_packet(src.0, dst.0, 6, 1, 0, &tcp))
}

/// A DNS response for `name` (type A) with one answer, compressed by a pointer to the question.
pub fn dns_response_payload(id: u16, name: &str, answer: Ipv4Addr) -> Vec<u8> {
    let mut out = dns_query_payload(id, name);
    out[2] = 0x81;
    out[3] = 0x80;
    out[7] = 1;
    out.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    out.extend_from_slice(&answer.octets());
    out
}

/// A TLS record: content type, record version, body.
pub fn tls_record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type];
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A ClientHello handshake message offering `version`, with a server name and, when
/// `supported`, a `supported_versions` extension.
pub fn client_hello(version: u16, sni: &str, supported: &[u16]) -> Vec<u8> {
    let mut exts = Vec::new();
    let host = sni.as_bytes();
    let mut sn = vec![0];
    sn.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sn.extend_from_slice(host);
    let mut list = (sn.len() as u16).to_be_bytes().to_vec();
    list.extend(sn);
    exts.extend_from_slice(&[0, 0]);
    exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
    exts.extend(list);
    if !supported.is_empty() {
        exts.extend_from_slice(&[0, 0x2b]);
        exts.extend_from_slice(&((supported.len() * 2 + 1) as u16).to_be_bytes());
        exts.push((supported.len() * 2) as u8);
        for v in supported {
            exts.extend_from_slice(&v.to_be_bytes());
        }
    }
    let mut body = version.to_be_bytes().to_vec();
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend(exts);
    handshake_message(1, &body)
}

/// A ServerHello handshake message, with `supported_versions` when `selected` is given.
pub fn server_hello(version: u16, selected: Option<u16>) -> Vec<u8> {
    let mut body = version.to_be_bytes().to_vec();
    body.extend_from_slice(&[9; 32]);
    body.push(0);
    body.extend_from_slice(&[0x13, 0x01, 0]);
    let mut exts = Vec::new();
    if let Some(v) = selected {
        exts.extend_from_slice(&[0, 0x2b, 0, 2]);
        exts.extend_from_slice(&v.to_be_bytes());
    }
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend(exts);
    handshake_message(2, &body)
}

/// A handshake message header (type and 24 bit length) around `body`.
pub fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut out = vec![kind, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    out.extend_from_slice(body);
    out
}
