//! The fields the native evaluator knows. A field outside this table sends the filter to tshark.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Only tested for presence.
    Proto,
    /// A TCP flag: `1`, `0`, `true`, `false`.
    Bool,
    /// An unsigned number up to the given maximum.
    Int(u64),
    Ipv4,
    Ipv6,
    Mac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Eth,
    Ip,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Arp,
    Dns,
    Http,
    Tls,
    EthAddr,
    EthSrc,
    EthDst,
    IpAddr,
    IpSrc,
    IpDst,
    IpTtl,
    IpProto,
    Ipv6Addr,
    Ipv6Src,
    Ipv6Dst,
    TcpPort,
    TcpSrcPort,
    TcpDstPort,
    TcpStream,
    UdpPort,
    UdpSrcPort,
    UdpDstPort,
    UdpStream,
    FrameNumber,
    FrameLen,
    Syn,
    Ack,
    Fin,
    Reset,
    Push,
}

const U16: Kind = Kind::Int(0xffff);
const U32: Kind = Kind::Int(0xffff_ffff);

const TABLE: &[(&str, Field, Kind)] = &[
    ("eth", Field::Eth, Kind::Proto),
    ("ip", Field::Ip, Kind::Proto),
    ("ipv6", Field::Ipv6, Kind::Proto),
    ("tcp", Field::Tcp, Kind::Proto),
    ("udp", Field::Udp, Kind::Proto),
    ("icmp", Field::Icmp, Kind::Proto),
    ("icmpv6", Field::Icmpv6, Kind::Proto),
    ("arp", Field::Arp, Kind::Proto),
    ("dns", Field::Dns, Kind::Proto),
    ("http", Field::Http, Kind::Proto),
    ("tls", Field::Tls, Kind::Proto),
    ("eth.addr", Field::EthAddr, Kind::Mac),
    ("eth.src", Field::EthSrc, Kind::Mac),
    ("eth.dst", Field::EthDst, Kind::Mac),
    ("ip.addr", Field::IpAddr, Kind::Ipv4),
    ("ip.src", Field::IpSrc, Kind::Ipv4),
    ("ip.dst", Field::IpDst, Kind::Ipv4),
    ("ip.ttl", Field::IpTtl, Kind::Int(0xff)),
    ("ip.proto", Field::IpProto, Kind::Int(0xff)),
    ("ipv6.addr", Field::Ipv6Addr, Kind::Ipv6),
    ("ipv6.src", Field::Ipv6Src, Kind::Ipv6),
    ("ipv6.dst", Field::Ipv6Dst, Kind::Ipv6),
    ("tcp.port", Field::TcpPort, U16),
    ("tcp.srcport", Field::TcpSrcPort, U16),
    ("tcp.dstport", Field::TcpDstPort, U16),
    ("tcp.stream", Field::TcpStream, U32),
    ("udp.port", Field::UdpPort, U16),
    ("udp.srcport", Field::UdpSrcPort, U16),
    ("udp.dstport", Field::UdpDstPort, U16),
    ("udp.stream", Field::UdpStream, U32),
    ("frame.number", Field::FrameNumber, U32),
    ("frame.len", Field::FrameLen, U32),
    ("tcp.flags.syn", Field::Syn, Kind::Bool),
    ("tcp.flags.ack", Field::Ack, Kind::Bool),
    ("tcp.flags.fin", Field::Fin, Kind::Bool),
    ("tcp.flags.reset", Field::Reset, Kind::Bool),
    ("tcp.flags.push", Field::Push, Kind::Bool),
];

impl Field {
    pub fn lookup(name: &str) -> Option<(Field, Kind)> {
        TABLE
            .iter()
            .find(|(n, ..)| *n == name)
            .map(|(_, f, k)| (*f, *k))
    }
}
