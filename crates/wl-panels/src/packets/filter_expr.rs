//! Builds tshark display-filter expressions from a packet row (pure, tested).

use wl_model::{PacketRow, Transport};

fn ip_field(ip: &std::net::IpAddr, side: &str) -> String {
    let proto = if ip.is_ipv4() { "ip" } else { "ipv6" };
    format!("{proto}.{side} == {ip}")
}

fn looks_like_mac(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 17
        && b.iter().enumerate().all(|(i, c)| {
            if i % 3 == 2 {
                *c == b':'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn addr_filter(ip: Option<&std::net::IpAddr>, text: &str, side: &str) -> Option<String> {
    match ip {
        Some(ip) => Some(ip_field(ip, side)),
        None if looks_like_mac(text) => Some(format!("eth.{side} == {text}")),
        None => None,
    }
}

pub fn source(r: &PacketRow) -> Option<String> {
    addr_filter(r.src_ip.as_ref(), &r.src, "src")
}

pub fn destination(r: &PacketRow) -> Option<String> {
    addr_filter(r.dst_ip.as_ref(), &r.dst, "dst")
}

/// Wireshark filter name for a "Protocol" column value (`TLSv1.3` -> `tls`).
pub fn protocol(r: &PacketRow) -> String {
    protocol_name(&r.protocol)
}

pub fn protocol_name(p: &str) -> String {
    let p = p.trim();
    let base = if p.starts_with("TLS") {
        "TLS"
    } else if p.starts_with("DTLS") {
        "DTLS"
    } else if p.starts_with("SSHv") {
        "SSH"
    } else if let Some(i) = p.find('/') {
        &p[..i]
    } else {
        p
    };
    base.to_ascii_lowercase().replace(' ', "")
}

fn transport_name(t: Transport) -> Option<&'static str> {
    match t {
        Transport::Tcp => Some("tcp"),
        Transport::Udp => Some("udp"),
        _ => None,
    }
}

/// `tcp.port == N` for the source or destination port.
pub fn port(r: &PacketRow, dst: bool) -> Option<String> {
    let p = if dst { r.dst_port } else { r.src_port }?;
    Some(format!("{}.port == {p}", transport_name(r.transport)?))
}

pub fn summary(r: &PacketRow) -> String {
    format!(
        "{}\t{:.6}\t{}\t{}\t{}\t{}\t{}",
        r.no, r.rel, r.src, r.dst, r.protocol, r.len, r.info
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> PacketRow {
        PacketRow {
            no: 1,
            epoch: 0.0,
            rel: 0.5,
            src: "10.0.0.1".into(),
            dst: "fe80::1".into(),
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("fe80::1".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(443),
            transport: Transport::Tcp,
            protocol: "TLSv1.3".into(),
            len: 60,
            info: "Hello".into(),
            stream: Some(3),
        }
    }

    #[test]
    fn builds_expressions() {
        let r = row();
        assert_eq!(source(&r).unwrap(), "ip.src == 10.0.0.1");
        assert_eq!(destination(&r).unwrap(), "ipv6.dst == fe80::1");
        assert_eq!(protocol(&r), "tls");
        assert_eq!(port(&r, true).unwrap(), "tcp.port == 443");
    }

    #[test]
    fn mac_fallback_and_missing() {
        let mut r = row();
        r.src_ip = None;
        r.src = "aa:bb:cc:dd:ee:ff".into();
        assert_eq!(source(&r).unwrap(), "eth.src == aa:bb:cc:dd:ee:ff");
        r.src = "weird".into();
        assert!(source(&r).is_none());
        r.transport = Transport::Icmp;
        assert!(port(&r, false).is_none());
    }

    #[test]
    fn protocol_names_and_special_cases() {
        let mut r = row();
        for (input, expected) in [
            ("HTTP/JSON", "http"),
            ("DNS", "dns"),
            ("TLSv1.2", "tls"),
            ("DTLSv1.2", "dtls"),
            ("SSHv2", "ssh"),
            ("ICMPv6", "icmpv6"),
            ("DHCPv6", "dhcpv6"),
            (" SIP / SDP ", "sip"),
        ] {
            r.protocol = input.into();
            assert_eq!(protocol(&r), expected, "for {input}");
        }
        // Reject malformed 17-char strings with 5 colons that are not valid MACs.
        r.src_ip = None;
        r.src = "a:b:c:d:e:fffffff".into();
        assert!(source(&r).is_none());
        r.src = "zz:bb:cc:dd:ee:ff".into();
        assert!(source(&r).is_none());
        // IPv6 source and UDP ports.
        r.src_ip = Some("2001:db8::1".parse().unwrap());
        assert_eq!(source(&r).unwrap(), "ipv6.src == 2001:db8::1");
        r.transport = Transport::Udp;
        assert_eq!(port(&r, false).unwrap(), "udp.port == 1234");
        assert!(summary(&r).contains("\t1\t") || summary(&r).starts_with("1\t"));
    }
}
