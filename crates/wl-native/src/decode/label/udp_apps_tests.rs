use super::*;

fn dhcp_packet(kind: u8) -> Vec<u8> {
    let mut p = vec![0; 240];
    p[0] = 1;
    p[4..8].copy_from_slice(&[0x39, 0x03, 0xf3, 0x26]);
    p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    p.extend_from_slice(&[0, 53, 1, kind, 61, 2, 1, 2, 255]);
    p
}

#[test]
fn dhcp_names_the_message_type_and_pads_it_like_wireshark() {
    assert_eq!(
        dhcp(&dhcp_packet(1)).expect("dhcp").info,
        "DHCP Discover - Transaction ID 0x3903f326"
    );
    assert_eq!(
        dhcp(&dhcp_packet(2)).expect("dhcp").info,
        "DHCP Offer    - Transaction ID 0x3903f326"
    );
    assert_eq!(
        dhcp(&dhcp_packet(5)).expect("dhcp").info,
        "DHCP ACK      - Transaction ID 0x3903f326"
    );
    assert_eq!(dhcp(&dhcp_packet(1)).expect("dhcp").protocol, "DHCP");
}

#[test]
fn dhcp_needs_the_cookie_and_a_known_type() {
    let mut p = dhcp_packet(1);
    p[236] = 0;
    assert!(dhcp(&p).is_none());
    assert!(dhcp(&dhcp_packet(99)).is_none());
    assert!(dhcp(&[0; 100]).is_none());
    let mut cut = dhcp_packet(1);
    cut.truncate(243);
    assert!(dhcp(&cut).is_none());
}

#[test]
fn ntp_modes() {
    let mut p = vec![0u8; 48];
    p[0] = 0x23;
    assert_eq!(ntp(&p).expect("ntp").info, "NTP Version 4, client");
    p[0] = 0x1c;
    assert_eq!(ntp(&p).expect("ntp").info, "NTP Version 3, server");
    assert!(ntp(&p[..47]).is_none());
    assert!(ntp(&[]).is_none());
}

#[test]
fn ssdp_shows_the_start_line() {
    let l = ssdp(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n").expect("ssdp");
    assert_eq!(
        (l.protocol, l.info.as_str()),
        ("SSDP", "M-SEARCH * HTTP/1.1 ")
    );
    assert_eq!(
        ssdp(b"NOTIFY * HTTP/1.1\r\n").expect("ssdp").info,
        "NOTIFY * HTTP/1.1 "
    );
    assert!(ssdp(b"random").is_none());
}

#[test]
fn quic_long_headers() {
    let mut p = vec![0xc3, 0, 0, 0, 1, 4, 0xde, 0xad, 0xbe, 0xef, 0];
    p.extend_from_slice(&[0; 20]);
    let l = quic(&p).expect("quic");
    assert_eq!(
        (l.protocol, l.info.as_str()),
        ("QUIC", "Initial, DCID=deadbeef")
    );
    p[0] = 0xe3;
    assert!(quic(&p).expect("quic").info.starts_with("Handshake"));
    p[4] = 0;
    assert!(
        quic(&p)
            .expect("quic")
            .info
            .starts_with("Version Negotiation")
    );
}

#[test]
fn quic_rejects_short_headers_and_cut_connection_ids() {
    assert!(quic(&[0x43, 0, 0, 0, 1, 4]).is_none());
    assert!(quic(&[0xc0, 0, 0, 0, 1, 20, 1, 2]).is_none());
    assert!(quic(&[]).is_none());
}
