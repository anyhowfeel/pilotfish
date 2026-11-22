//! Socket-to-process attribution: parsers for `/proc/net/{tcp,tcp6,udp,udp6}` text and the
//! lookup tables built from them. No I/O: callers supply the text and the inode owners.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crate::{FlowKey, Transport};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: Arc<str>,
}

impl ProcessInfo {
    pub fn label(&self) -> String {
        format!("{} ({})", self.name, self.pid)
    }
}

/// "firefox (1234)", plus " +N" when more processes match.
pub fn summarize(list: &[ProcessInfo]) -> String {
    match list {
        [] => String::new(),
        [one] => one.label(),
        [first, rest @ ..] => format!("{} +{}", first.label(), rest.len()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SockProto {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketEntry {
    pub proto: SockProto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub inode: u64,
}

// The kernel prints each 32-bit address word in host byte order; little-endian hosts only.
fn parse_ip(hex: &str) -> Option<IpAddr> {
    let word = |s: &str| u32::from_str_radix(s, 16).ok().map(u32::to_le_bytes);
    match hex.len() {
        8 => Some(Ipv4Addr::from(word(hex)?).into()),
        32 => {
            let mut octets = [0u8; 16];
            for (i, chunk) in octets.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(&word(hex.get(i * 8..i * 8 + 8)?)?);
            }
            Some(Ipv6Addr::from(octets).into())
        }
        _ => None,
    }
}

fn parse_endpoint(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    Some(SocketAddr::new(
        parse_ip(ip)?,
        u16::from_str_radix(port, 16).ok()?,
    ))
}

/// Rows of one `/proc/net/{tcp,tcp6,udp,udp6}` file. Sockets without an inode (TIME_WAIT) and
/// malformed lines are skipped.
pub fn parse_proc_net(text: &str, proto: SockProto) -> Vec<SocketEntry> {
    text.lines()
        .skip(1)
        .filter_map(|l| parse_row(l, proto))
        .collect()
}

fn parse_row(line: &str, proto: SockProto) -> Option<SocketEntry> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let inode: u64 = f.get(9)?.parse().ok().filter(|&i| i != 0)?;
    Some(SocketEntry {
        proto,
        local: parse_endpoint(f.get(1)?)?,
        remote: parse_endpoint(f.get(2)?)?,
        inode,
    })
}

/// Inode of a `/proc/<pid>/fd/<n>` link target such as `socket:[48213]`.
pub fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

type Pair = (SockProto, SocketAddr, SocketAddr);

#[derive(Default, Debug)]
pub struct ProcessMap {
    connected: HashMap<Pair, ProcessInfo>,
    bound: HashMap<(SockProto, u16), Vec<(IpAddr, ProcessInfo)>>,
    by_remote: HashMap<IpAddr, Vec<ProcessInfo>>,
}

impl ProcessMap {
    pub fn build(sockets: &[SocketEntry], owners: &HashMap<u64, ProcessInfo>) -> Self {
        let mut m = Self::default();
        for s in sockets {
            let Some(p) = owners.get(&s.inode) else {
                continue;
            };
            if s.remote.port() == 0 {
                m.bound
                    .entry((s.proto, s.local.port()))
                    .or_default()
                    .push((s.local.ip(), p.clone()));
                continue;
            }
            m.connected.insert((s.proto, s.local, s.remote), p.clone());
            let list = m.by_remote.entry(s.remote.ip()).or_default();
            if !list.contains(p) {
                list.push(p.clone());
            }
        }
        m.by_remote.values_mut().for_each(|l| l.sort());
        m
    }

    pub fn is_empty(&self) -> bool {
        self.connected.is_empty() && self.bound.is_empty()
    }

    /// Processes holding a connection to `addr`.
    pub fn for_host(&self, addr: &str) -> &[ProcessInfo] {
        addr.parse::<IpAddr>()
            .ok()
            .and_then(|ip| self.by_remote.get(&ip))
            .map_or(&[], Vec::as_slice)
    }

    pub fn for_flow(&self, key: &FlowKey) -> Option<&ProcessInfo> {
        let proto = match key.transport {
            Transport::Tcp => SockProto::Tcp,
            Transport::Udp => SockProto::Udp,
            _ => return None,
        };
        let a = SocketAddr::new(key.a.parse().ok()?, key.a_port?);
        let b = SocketAddr::new(key.b.parse().ok()?, key.b_port?);
        self.connected
            .get(&(proto, a, b))
            .or_else(|| self.connected.get(&(proto, b, a)))
            .or_else(|| self.bound_to(proto, a))
            .or_else(|| self.bound_to(proto, b))
    }

    fn bound_to(&self, proto: SockProto, at: SocketAddr) -> Option<&ProcessInfo> {
        self.bound
            .get(&(proto, at.port()))?
            .iter()
            .find(|(ip, _)| *ip == at.ip() || ip.is_unspecified())
            .map(|(_, p)| p)
    }
}

#[cfg(test)]
#[path = "procmap_tests.rs"]
mod tests;
