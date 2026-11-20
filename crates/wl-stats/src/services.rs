//! Well-known port -> service name lookup.

use wl_model::Transport;

/// Name of the well-known service on `port`, if any. UDP-only / TCP-only
/// services only match their own transport; the rest match TCP and UDP.
pub fn service_name(port: u16, transport: Transport) -> Option<&'static str> {
    use Transport::{Tcp, Udp};
    let both = matches!(transport, Tcp | Udp);
    Some(match port {
        20 | 21 if transport == Tcp => "ftp",
        22 if both => "ssh",
        23 if transport == Tcp => "telnet",
        25 if transport == Tcp => "smtp",
        53 if both => "dns",
        67 | 68 if transport == Udp => "dhcp",
        69 if transport == Udp => "tftp",
        80 if both => "http",
        88 if both => "kerberos",
        110 if transport == Tcp => "pop3",
        111 if both => "rpcbind",
        119 if transport == Tcp => "nntp",
        123 if transport == Udp => "ntp",
        135 if transport == Tcp => "msrpc",
        137 | 138 if transport == Udp => "netbios",
        139 if transport == Tcp => "netbios-ssn",
        143 if transport == Tcp => "imap",
        161 | 162 if transport == Udp => "snmp",
        179 if transport == Tcp => "bgp",
        389 if both => "ldap",
        443 if both => "https",
        445 if transport == Tcp => "smb",
        465 if transport == Tcp => "smtps",
        500 if transport == Udp => "isakmp",
        514 if both => "syslog",
        515 if transport == Tcp => "lpd",
        587 if transport == Tcp => "submission",
        631 if both => "ipp",
        636 if transport == Tcp => "ldaps",
        853 if both => "dns-over-tls",
        873 if transport == Tcp => "rsync",
        993 if transport == Tcp => "imaps",
        995 if transport == Tcp => "pop3s",
        1080 if transport == Tcp => "socks",
        1194 if both => "openvpn",
        1433 if transport == Tcp => "mssql",
        1521 if transport == Tcp => "oracle",
        1701 if transport == Udp => "l2tp",
        1723 if transport == Tcp => "pptp",
        1883 if transport == Tcp => "mqtt",
        1900 if transport == Udp => "ssdp",
        2049 if both => "nfs",
        3000 | 8000 | 8080 if transport == Tcp => "http-alt",
        3306 if transport == Tcp => "mysql",
        3389 if both => "rdp",
        3478 if both => "stun",
        4500 if transport == Udp => "ipsec-nat-t",
        5060 if both => "sip",
        5061 if transport == Tcp => "sips",
        5222 if transport == Tcp => "xmpp",
        5353 if transport == Udp => "mdns",
        5355 if both => "llmnr",
        5432 if transport == Tcp => "postgresql",
        5672 if transport == Tcp => "amqp",
        5900 if transport == Tcp => "vnc",
        6379 if transport == Tcp => "redis",
        6667 if transport == Tcp => "irc",
        8443 if transport == Tcp => "https-alt",
        8883 if transport == Tcp => "mqtts",
        9092 if transport == Tcp => "kafka",
        9200 if transport == Tcp => "elasticsearch",
        27017 if transport == Tcp => "mongodb",
        51820 if transport == Udp => "wireguard",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use Transport::*;

    #[test]
    fn common_ports() {
        assert_eq!(service_name(22, Tcp), Some("ssh"));
        assert_eq!(service_name(53, Udp), Some("dns"));
        assert_eq!(service_name(53, Tcp), Some("dns"));
        assert_eq!(service_name(443, Tcp), Some("https"));
        assert_eq!(service_name(5353, Udp), Some("mdns"));
        assert_eq!(service_name(67, Udp), Some("dhcp"));
        assert_eq!(service_name(68, Udp), Some("dhcp"));
        assert_eq!(service_name(123, Udp), Some("ntp"));
    }

    #[test]
    fn transport_specific_and_unknown() {
        assert_eq!(service_name(123, Tcp), None);
        assert_eq!(service_name(5353, Tcp), None);
        assert_eq!(service_name(22, Icmp), None);
        assert_eq!(service_name(40000, Tcp), None);
    }
}
