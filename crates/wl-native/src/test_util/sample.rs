//! A normal capture for tests that only need one.

use std::net::Ipv4Addr;

use super::files::Frame;
use super::packets::{
    ACK, FIN_ACK, PSH_ACK, SYN, SYN_ACK, dns_query_payload, icmp4_echo, tcp4, udp4,
};

/// A short, realistic conversation: TCP handshake, one request and reply, close, plus a DNS
/// lookup and a ping. Used where a test needs "a normal capture".
pub fn sample_frames() -> Vec<Frame> {
    let c = (Ipv4Addr::new(192, 168, 1, 10), 51000);
    let s = (Ipv4Addr::new(93, 184, 216, 34), 80);
    let dns = (Ipv4Addr::new(192, 168, 1, 1), 53);
    let t0 = 1_700_000_000.0;
    vec![
        Frame::new(
            t0,
            udp4((c.0, 40000), dns, &dns_query_payload(7, "example.com")),
        ),
        Frame::new(t0 + 0.010, tcp4(c, s, SYN, 100, 0, &[])),
        Frame::new(t0 + 0.030, tcp4(s, c, SYN_ACK, 500, 101, &[])),
        Frame::new(t0 + 0.031, tcp4(c, s, ACK, 101, 501, &[])),
        Frame::new(
            t0 + 0.032,
            tcp4(
                c,
                s,
                PSH_ACK,
                101,
                501,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ),
        ),
        Frame::new(
            t0 + 0.060,
            tcp4(s, c, PSH_ACK, 501, 140, b"HTTP/1.1 200 OK\r\n\r\n"),
        ),
        Frame::new(t0 + 0.061, tcp4(c, s, FIN_ACK, 140, 520, &[])),
        Frame::new(t0 + 0.500, icmp4_echo(c.0, dns.0, 1, 1)),
    ]
}
