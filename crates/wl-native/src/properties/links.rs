//! Wireshark's names for link-layer types, as `capinfos` prints them.

use crate::reader::LinkType;

/// Text of an interface's `Encapsulation` line and the short name `capinfos -M` gives the file.
pub struct Encap {
    pub long: &'static str,
    /// Wireshark's own number for the type, not the `LINKTYPE_*` code.
    pub wtap: u16,
    pub short: &'static str,
}

const fn encap(long: &'static str, wtap: u16, short: &'static str) -> Option<Encap> {
    Some(Encap { long, wtap, short })
}

/// `None` for types this table does not list; the Properties page then shows a dash.
pub fn encap_of(link: LinkType) -> Option<Encap> {
    match link {
        LinkType::Null => encap("NULL/Loopback", 15, "null"),
        LinkType::Ethernet => encap("Ethernet", 1, "ether"),
        LinkType::RawIp => encap("Raw IP", 7, "rawip"),
        LinkType::LinuxSll => encap("Linux cooked-mode capture v1", 25, "linux-sll"),
        LinkType::LinuxSll2 => encap("Linux cooked-mode capture v2", 210, "linux-sll2"),
        LinkType::Other(9 | 50) => encap("PPP", 4, "ppp"),
        LinkType::Other(10) => encap("FDDI with bit-swapped MAC addresses", 6, "fddi-swapped"),
        LinkType::Other(104) => encap("Cisco HDLC", 28, "chdlc"),
        LinkType::Other(105) => encap("IEEE 802.11 Wireless LAN", 20, "ieee-802-11"),
        LinkType::Other(107) => encap("Frame Relay", 26, "frelay"),
        LinkType::Other(108) => encap("OpenBSD loopback", 174, "loop"),
        LinkType::Other(127) => encap(
            "IEEE 802.11 plus radiotap radio header",
            23,
            "ieee-802-11-radiotap",
        ),
        LinkType::Other(147) => encap("USER 0", 45, "user0"),
        LinkType::Other(195) => encap("IEEE 802.15.4 Wireless PAN", 104, "wpan"),
        LinkType::Other(228) => encap("Raw IPv4", 129, "rawip4"),
        LinkType::Other(229) => encap("Raw IPv6", 130, "rawip6"),
        LinkType::Other(_) => None,
    }
}

/// `Ethernet (1 - ether)`.
pub fn interface_text(link: LinkType) -> String {
    encap_of(link)
        .map(|e| format!("{} ({} - {})", e.long, e.wtap, e.short))
        .unwrap_or_default()
}

/// The short name when every interface has the same type, `per-packet` otherwise.
pub fn file_text<I: IntoIterator<Item = LinkType>>(links: I) -> String {
    let mut names = links
        .into_iter()
        .map(|l| encap_of(l).map(|e| e.short).unwrap_or_default());
    let Some(first) = names.next() else {
        return String::new();
    };
    if names.all(|n| n == first) {
        first.to_owned()
    } else {
        "per-packet".to_owned()
    }
}
