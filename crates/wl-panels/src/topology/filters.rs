//! Display-filter expressions for hosts and host pairs (pure).

use std::net::IpAddr;

fn clause(addr: &str) -> String {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => format!("ip.addr == {addr}"),
        Ok(IpAddr::V6(_)) => format!("ipv6.addr == {addr}"),
        Err(_) => format!("eth.addr == {addr}"),
    }
}

/// Every packet sent or received by `addr`.
pub fn host(addr: &str) -> String {
    clause(addr)
}

/// Every packet exchanged between `a` and `b` (either direction).
pub fn pair(a: &str, b: &str) -> String {
    format!("{} && {}", clause(a), clause(b))
}

/// Every packet exchanged by any of the pairs `(a, b)`.
pub fn any_pair<A: AsRef<str>, B: AsRef<str>>(pairs: &[(A, B)]) -> String {
    match pairs {
        [(a, b)] => pair(a.as_ref(), b.as_ref()),
        _ => pairs
            .iter()
            .map(|(a, b)| format!("({})", pair(a.as_ref(), b.as_ref())))
            .collect::<Vec<_>>()
            .join(" || "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn several_pairs_are_joined_with_or() {
        assert_eq!(
            any_pair(&[("10.0.0.1", "10.0.0.2")]),
            "ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2"
        );
        assert_eq!(
            any_pair(&[("10.0.0.1", "10.0.0.2"), ("10.0.0.3", "2001:db8::1")]),
            "(ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2) || (ip.addr == 10.0.0.3 && ipv6.addr == 2001:db8::1)"
        );
    }

    #[test]
    fn builds_per_address_family() {
        assert_eq!(host("10.0.0.1"), "ip.addr == 10.0.0.1");
        assert_eq!(host("2001:db8::1"), "ipv6.addr == 2001:db8::1");
        assert_eq!(host("aa:bb:cc:dd:ee:ff"), "eth.addr == aa:bb:cc:dd:ee:ff");
        assert_eq!(
            pair("72.30.35.9", "192.168.74.124"),
            "ip.addr == 72.30.35.9 && ip.addr == 192.168.74.124"
        );
    }
}
