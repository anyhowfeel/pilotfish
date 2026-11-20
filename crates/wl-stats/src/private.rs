//! Address-scope classification for host rows.

use std::net::{IpAddr, Ipv6Addr};

/// True for RFC1918, link-local, loopback and IPv6 ULA (fc00::/7) addresses.
/// `None` (non-IP endpoints such as MAC addresses) is never private.
pub fn is_private(ip: Option<IpAddr>) -> bool {
    match ip {
        None => false,
        Some(IpAddr::V4(v4)) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        Some(IpAddr::V6(v6)) => private_v6(v6),
    }
}

fn private_v6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_private(Some(IpAddr::V4(v4)));
    }
    v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> bool {
        is_private(Some(s.parse().unwrap()))
    }

    #[test]
    fn rfc1918_and_friends() {
        for a in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.1.1",
            "127.0.0.1",
        ] {
            assert!(p(a), "{a}");
        }
    }

    #[test]
    fn public_v4() {
        for a in [
            "8.8.8.8",
            "172.32.0.1",
            "172.15.0.1",
            "1.1.1.1",
            "192.169.0.1",
        ] {
            assert!(!p(a), "{a}");
        }
    }

    #[test]
    fn v6() {
        for a in ["::1", "fd00::1", "fc12::1", "fe80::1", "::ffff:192.168.0.1"] {
            assert!(p(a), "{a}");
        }
        for a in ["2001:4860:4860::8888", "2606:4700::1111"] {
            assert!(!p(a), "{a}");
        }
    }

    #[test]
    fn non_ip_is_false() {
        assert!(!is_private(None));
    }
}
