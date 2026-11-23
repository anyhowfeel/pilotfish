//! What a decoded packet holds for each field. Wireshark tests every occurrence of a field, and
//! an ICMP error holds a second IP layer: the header of the packet it quotes.

use std::net::IpAddr;

use super::field::Field;
use super::literal::Val;
use crate::decode::Decoded;
use wl_model::Transport;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;
const ETHERTYPE_ARP: u16 = 0x0806;
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// The occurrences of a field in one packet: outer layer first, then the quoted one.
pub type Vals = [Option<Val>; 4];

struct Layer {
    src: IpAddr,
    dst: IpAddr,
    ttl: u8,
    proto: u8,
}

/// The IP layers of version `version`: the packet's own and the one an ICMP error quotes.
fn layers(d: &Decoded, version: u8) -> [Option<Layer>; 2] {
    let (f, r) = (&d.facts, &d.row);
    let outer = match (f.ip_version, r.src_ip, r.dst_ip, f.ttl, f.ip_proto) {
        (Some(v), Some(src), Some(dst), Some(ttl), Some(proto)) if v == version => Some(Layer {
            src,
            dst,
            ttl,
            proto,
        }),
        _ => None,
    };
    let inner = f
        .inner
        .as_ref()
        .filter(|i| i.version == version)
        .map(|i| Layer {
            src: i.src,
            dst: i.dst,
            ttl: i.ttl,
            proto: i.proto,
        });
    [outer, inner]
}

fn num(n: impl Into<u64>) -> Option<Val> {
    Some(Val::Num(n.into()))
}

fn mac(m: Option<[u8; 6]>) -> Option<Val> {
    m.map(Val::Mac)
}

fn from_layers(d: &Decoded, version: u8, pick: impl Fn(&Layer) -> [Option<Val>; 2]) -> Vals {
    let [outer, inner] = layers(d, version);
    let [a, b] = outer.as_ref().map_or([None, None], &pick);
    let [c, e] = inner.as_ref().map_or([None, None], &pick);
    [a, b, c, e]
}

fn addrs(d: &Decoded, version: u8, src: bool, dst: bool) -> Vals {
    from_layers(d, version, |l| {
        [src.then_some(Val::Ip(l.src)), dst.then_some(Val::Ip(l.dst))]
    })
}

fn is_quoting(d: &Decoded, proto: u8) -> bool {
    d.facts.inner.as_ref().is_some_and(|i| i.proto == proto) && d.row.src_port.is_some()
}

fn is_tcp(d: &Decoded) -> bool {
    d.facts.tcp_flags.is_some() || is_quoting(d, TCP)
}

fn is_udp(d: &Decoded) -> bool {
    let own = d.row.transport == Transport::Udp && d.facts.ip_proto == Some(UDP);
    own || is_quoting(d, UDP)
}

fn ports(d: &Decoded, on: bool, src: bool, dst: bool) -> Vals {
    let pick = |want: bool, p: Option<u16>| p.filter(|_| on && want).and_then(num);
    [
        pick(src, d.row.src_port),
        pick(dst, d.row.dst_port),
        None,
        None,
    ]
}

fn first(v: Option<Val>) -> Vals {
    [v, None, None, None]
}

fn flag(d: &Decoded, bit: u8) -> Vals {
    let quoted = d.facts.inner.as_ref().and_then(|i| i.tcp_flags);
    let test = |f: Option<u8>| f.and_then(|f| num(u8::from(f & bit != 0)));
    [test(d.facts.tcp_flags), test(quoted), None, None]
}

fn tcp_stream(d: &Decoded) -> Option<Val> {
    d.row.stream.filter(|_| is_tcp(d)).and_then(num)
}

fn has_proto(d: &Decoded, version: u8, proto: u8) -> bool {
    layers(d, version)
        .iter()
        .flatten()
        .any(|l| l.proto == proto)
}

impl Field {
    /// Whether the packet has the protocol or field at all.
    pub fn present(self, d: &Decoded) -> bool {
        let f = &d.facts;
        match self {
            Field::Eth => f.eth_src.is_some(),
            Field::Ip => layers(d, 4).iter().any(Option::is_some),
            Field::Ipv6 => layers(d, 6).iter().any(Option::is_some),
            Field::Tcp => is_tcp(d),
            Field::Udp => is_udp(d),
            Field::Icmp => has_proto(d, 4, ICMP),
            Field::Icmpv6 => has_proto(d, 6, ICMPV6),
            Field::Arp => f.ethertype == Some(ETHERTYPE_ARP),
            Field::Dns => &*d.row.protocol == "DNS",
            Field::Http => d.row.protocol.starts_with("HTTP"),
            Field::Tls => d.row.protocol.starts_with("TLS"),
            _ => self.values(d).iter().any(Option::is_some),
        }
    }

    pub fn values(self, d: &Decoded) -> Vals {
        let (f, r) = (&d.facts, &d.row);
        match self {
            Field::EthAddr => [mac(f.eth_src), mac(f.eth_dst), None, None],
            Field::EthSrc => first(mac(f.eth_src)),
            Field::EthDst => first(mac(f.eth_dst)),
            Field::IpAddr => addrs(d, 4, true, true),
            Field::IpSrc => addrs(d, 4, true, false),
            Field::IpDst => addrs(d, 4, false, true),
            Field::IpTtl => from_layers(d, 4, |l| [num(l.ttl), None]),
            Field::IpProto => from_layers(d, 4, |l| [num(l.proto), None]),
            Field::Ipv6Addr => addrs(d, 6, true, true),
            Field::Ipv6Src => addrs(d, 6, true, false),
            Field::Ipv6Dst => addrs(d, 6, false, true),
            Field::TcpPort => ports(d, is_tcp(d), true, true),
            Field::TcpSrcPort => ports(d, is_tcp(d), true, false),
            Field::TcpDstPort => ports(d, is_tcp(d), false, true),
            Field::TcpStream => first(tcp_stream(d)),
            Field::UdpPort => ports(d, is_udp(d), true, true),
            Field::UdpSrcPort => ports(d, is_udp(d), true, false),
            Field::UdpDstPort => ports(d, is_udp(d), false, true),
            Field::UdpStream => first(r.stream.filter(|_| is_udp(d)).and_then(num)),
            Field::FrameNumber => first(num(r.no)),
            Field::FrameLen => first(num(r.len)),
            Field::Syn => flag(d, SYN),
            Field::Ack => flag(d, ACK),
            Field::Fin => flag(d, FIN),
            Field::Reset => flag(d, RST),
            Field::Push => flag(d, PSH),
            _ => [None; 4],
        }
    }
}
