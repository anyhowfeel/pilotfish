//! Calm, WCAG-AA, color-blind-safe protocol colors grouped by protocol family
//! (Okabe-Ito / Paul Tol categorical lineage tuned in OKLCH).

use eframe::egui::Color32;

use super::{Mode, mode};

/// Semantic protocol family grouping so tables remain calm (7 hues total instead of 20+).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtocolFamily {
    /// Reliable stream transport (TCP, SSH, SCTP, FTP).
    Stream,
    /// Datagram & multiplexed UDP transport (UDP, QUIC, RTP, STUN).
    Datagram,
    /// Web application & TLS security layer (HTTP, HTTP/2, TLS, SSL).
    WebTls,
    /// Name resolution, discovery & host configuration (DNS, mDNS, DHCP, NTP).
    Naming,
    /// Control, routing & diagnostics (ICMP, ICMPv6, IGMP, BGP, OSPF).
    Control,
    /// Link-layer & L2 discovery (ARP, STP, LLDP, EAPOL).
    Link,
    /// Unclassified or miscellaneous protocols (calm neutral grey).
    Other,
}

impl ProtocolFamily {
    #[cfg(test)]
    pub(crate) const ALL: [ProtocolFamily; 7] = [
        ProtocolFamily::Stream,
        ProtocolFamily::Datagram,
        ProtocolFamily::WebTls,
        ProtocolFamily::Naming,
        ProtocolFamily::Control,
        ProtocolFamily::Link,
        ProtocolFamily::Other,
    ];

    /// `(dark_hex, light_hex)` OKLCH-tuned Okabe-Ito / Tol pair.
    pub(crate) const fn hex(self) -> (u32, u32) {
        match self {
            ProtocolFamily::Stream => (0x5B99E6, 0x1F3F9E),
            ProtocolFamily::Datagram => (0x80CEF6, 0x0C6783),
            ProtocolFamily::WebTls => (0x7AD0A0, 0x1B6B45),
            ProtocolFamily::Naming => (0xDD93CB, 0x7B2E6C),
            ProtocolFamily::Control => (0xE4706B, 0x851A1F),
            ProtocolFamily::Link => (0xF4A467, 0x944809),
            ProtocolFamily::Other => (0x989CA0, 0x3E4145),
        }
    }

    pub(crate) const fn color(self, m: Mode) -> Color32 {
        let (dark, light) = self.hex();
        rgb(match m {
            Mode::Dark => dark,
            Mode::Light => light,
        })
    }
}

pub(crate) fn classify_protocol(name: &str) -> ProtocolFamily {
    let up = name.trim().to_ascii_uppercase();
    let head = up.split_once('/').map_or(up.as_str(), |(h, _)| h);
    match head {
        "TCP" | "SSH" | "SSHV2" | "SCTP" | "FTP" | "FTP-DATA" | "TELNET" | "SMTP" | "IMAP"
        | "SMB" | "SMB2" => ProtocolFamily::Stream,
        "UDP" | "QUIC" | "RTP" | "RTCP" | "STUN" | "WIREGUARD" | "DTLS" => ProtocolFamily::Datagram,
        "HTTP" | "HTTP2" | "HTTP3" | "TLS" | "TLSV1" | "TLSV1.1" | "TLSV1.2" | "TLSV1.3"
        | "SSL" | "OCSP" | "OCSP-OVER-HTTP" | "WEBSOCKET" | "GRPC" => ProtocolFamily::WebTls,
        "DNS" | "MDNS" | "DHCP" | "DHCPV6" | "BOOTP" | "NTP" | "NBNS" | "LLMNR" | "SSDP"
        | "BROWSER" => ProtocolFamily::Naming,
        "ICMP" | "ICMPV6" | "IGMP" | "BGP" | "OSPF" | "RIP" => ProtocolFamily::Control,
        "ARP" | "RARP" | "STP" | "RSTP" | "LLDP" | "CDP" | "EAPOL" | "ETH" | "VLAN" => {
            ProtocolFamily::Link
        }
        _ => ProtocolFamily::Other,
    }
}

pub(crate) const fn rgb(v: u32) -> Color32 {
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

/// Protocol color for a specific theme `Mode`, assigned by protocol family.
pub fn protocol_color_for(name: &str, m: Mode) -> Color32 {
    classify_protocol(name).color(m)
}

/// Stable color for a protocol name (case-insensitive), grouped by semantic family.
pub fn protocol_color(name: &str) -> Color32 {
    protocol_color_for(name, mode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_case_insensitive() {
        assert_eq!(protocol_color("tcp"), protocol_color("TCP"));
        assert_eq!(protocol_color("Foo"), protocol_color("Foo"));
        assert_ne!(protocol_color("TCP"), protocol_color("UDP"));
        assert_eq!(protocol_color("HTTP"), protocol_color("TLSv1.3"));
        assert_eq!(protocol_color("DNS"), protocol_color("mDNS"));
        assert_eq!(protocol_color("UnknownProto"), protocol_color("OTHER"));
        assert_ne!(
            protocol_color_for("TCP", Mode::Dark),
            protocol_color_for("TCP", Mode::Light)
        );
    }
}
