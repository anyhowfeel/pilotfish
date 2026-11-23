use std::net::Ipv6Addr;

use super::*;

fn v6(s: &str) -> String {
    ipv6(&s.parse::<Ipv6Addr>().expect("valid address"))
}

#[test]
fn compresses_the_longest_zero_run() {
    assert_eq!(v6("::"), "::");
    assert_eq!(v6("::1"), "::1");
    assert_eq!(v6("fe80::1"), "fe80::1");
    assert_eq!(v6("2001:db8:0:0:1:0:0:1"), "2001:db8::1:0:0:1");
    assert_eq!(v6("1:0:0:2:0:0:0:3"), "1:0:0:2::3");
    assert_eq!(v6("2001:db8:0:1:1:1:1:1"), "2001:db8:0:1:1:1:1:1");
    assert_eq!(v6("ff02::fb"), "ff02::fb");
    assert_eq!(v6("1::"), "1::");
}

#[test]
fn mapped_and_compatible_addresses_end_in_dotted_decimal() {
    assert_eq!(v6("::ffff:1.2.3.4"), "::ffff:1.2.3.4");
    assert_eq!(v6("::1.2.3.4"), "::1.2.3.4");
    assert_eq!(v6("::ffff:0:1"), "::ffff:0.0.0.1");
    assert_eq!(v6("::1:2"), "::0.1.0.2");
    assert_eq!(v6("::2"), "::2");
    assert_eq!(v6("1::ffff:1.2.3.4"), "1::ffff:102:304");
}

#[test]
fn mac_and_hex_are_lowercase_colon_text() {
    assert_eq!(mac(&[0xaa, 0, 1, 0xff, 0x10, 0x0b]), "aa:00:01:ff:10:0b");
    assert_eq!(hex(&[0, 0xab]), "00ab");
}
