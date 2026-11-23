use super::tests::props;
use crate::test_util::{
    OPT_COMMENT, multi_interface_pcapng, ng_epb, ng_idb, ng_opt, ng_shb, ng_shb_opts,
};

#[test]
fn pcapng_section_options_and_interfaces_are_listed() {
    let p = props(multi_interface_pcapng());
    assert_eq!(p.comments, vec!["first comment", "second comment"]);
    assert_eq!(
        (p.hardware.as_str(), p.os.as_str(), p.application.as_str()),
        ("Fancy HW", "MyOS 1", "MyApp 2")
    );
    assert_eq!(p.encapsulation, "per-packet");
    assert_eq!(p.interfaces.len(), 2);
    let (eth, any) = (&p.interfaces[0], &p.interfaces[1]);
    assert_eq!(
        (eth.name.as_str(), eth.description.as_str()),
        ("eth0", "the wire")
    );
    assert_eq!(
        (eth.capture_length.as_str(), eth.packets.as_str()),
        ("1000", "2")
    );
    assert_eq!(eth.encapsulation, "Ethernet (1 - ether)");
    assert_eq!(
        (any.name.as_str(), any.packets.as_str(), any.filter.as_str()),
        ("any", "1", "")
    );
    assert_eq!(
        any.encapsulation,
        "Linux cooked-mode capture v1 (25 - linux-sll)"
    );
}

#[test]
fn each_time_has_the_decimals_of_its_own_interface() {
    let p = props(multi_interface_pcapng());
    assert_eq!(p.strict_order, Some(false));
    assert_eq!(p.first_packet, "1970-01-01 00:00:00.100900");
    assert_eq!(p.last_packet, "1970-01-01 00:01:40.500");
    assert_eq!(p.data_size, 200);
}

#[test]
fn two_interfaces_of_one_type_keep_that_type() {
    let mut bytes = ng_shb(false);
    bytes.extend(ng_idb(false, 1, 0, None));
    bytes.extend(ng_idb(false, 1, 0, None));
    bytes.extend(ng_epb(false, 0, 5, &[0; 60], 60));
    let p = props(bytes);
    assert_eq!(p.encapsulation, "ether");
    assert_eq!(
        p.interfaces
            .iter()
            .map(|i| i.packets.as_str())
            .collect::<Vec<_>>(),
        ["1", "0"]
    );
}

#[test]
fn a_second_section_adds_its_interfaces_and_keeps_the_first_options() {
    let mut bytes = ng_shb_opts(&[ng_opt(OPT_COMMENT, b"one")]);
    bytes.extend(ng_idb(false, 1, 0, None));
    bytes.extend(ng_epb(false, 0, 5, &[0; 60], 60));
    bytes.extend(ng_shb_opts(&[ng_opt(OPT_COMMENT, b"two")]));
    bytes.extend(ng_idb(false, 1, 0, None));
    bytes.extend(ng_epb(false, 0, 9, &[0; 60], 60));
    let p = props(bytes);
    assert_eq!(p.comments, vec!["one"]);
    assert_eq!(
        p.interfaces
            .iter()
            .map(|i| i.packets.as_str())
            .collect::<Vec<_>>(),
        ["1", "1"]
    );
}

#[test]
fn a_pcapng_with_no_packets_is_valid() {
    let mut bytes = ng_shb(false);
    bytes.extend(ng_idb(false, 1, 0, None));
    let p = props(bytes);
    assert_eq!((p.packets, p.first_packet.as_str()), (0, "n/a"));
}
