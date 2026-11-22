//! Socket-to-process attribution: parsers for `/proc/net/{tcp,tcp6,udp,udp6}` text and the
//! lookup tables built from them. No I/O: callers supply the text and the inode owners.

use std::collections::{HashMap, HashSet};
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

// The kernel prints each 32-bit address word as a host-order integer, so its in-memory bytes
// (`to_ne_bytes`) are the network-order octets on any endianness.
fn parse_ip(hex: &str) -> Option<IpAddr> {
    let word = |s: &str| u32::from_str_radix(s, 16).ok().map(u32::to_ne_bytes);
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
        parse_ip(ip)?.to_canonical(),
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

/// Scans a closed connection stays attributable for, so short-lived flows still get a label.
const KEEP_SCANS: u8 = 3;

#[derive(Debug)]
struct Seen {
    process: ProcessInfo,
    age: u8,
}

#[derive(Default, Debug)]
pub struct ProcessMap {
    connected: HashMap<Pair, Seen>,
    bound: HashMap<(SockProto, u16), Vec<(IpAddr, ProcessInfo)>>,
    by_remote: HashMap<IpAddr, Vec<ProcessInfo>>,
    local: HashSet<IpAddr>,
}

impl ProcessMap {
    pub fn build(sockets: &[SocketEntry], owners: &HashMap<u64, ProcessInfo>) -> Self {
        let mut m = Self {
            local: sockets
                .iter()
                .map(|s| s.local.ip())
                .filter(|ip| !ip.is_unspecified())
                .collect(),
            ..Self::default()
        };
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
            let seen = Seen {
                process: p.clone(),
                age: 0,
            };
            m.connected.insert((s.proto, s.local, s.remote), seen);
        }
        m.reindex();
        m
    }

    /// `scanned` plus the connections of `self` that vanished less than `KEEP_SCANS` scans ago.
    pub fn refreshed(self, mut scanned: ProcessMap) -> ProcessMap {
        for (pair, seen) in self.connected {
            if seen.age + 1 < KEEP_SCANS {
                scanned.connected.entry(pair).or_insert(Seen {
                    process: seen.process,
                    age: seen.age + 1,
                });
            }
        }
        scanned.reindex();
        scanned
    }

    fn reindex(&mut self) {
        self.by_remote.clear();
        for ((_, _, remote), seen) in &self.connected {
            let list = self.by_remote.entry(remote.ip()).or_default();
            if !list.contains(&seen.process) {
                list.push(seen.process.clone());
            }
        }
        self.by_remote.values_mut().for_each(|l| l.sort());
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
        let endpoint = |ip: &str, port: Option<u16>| {
            Some(SocketAddr::new(
                ip.parse::<IpAddr>().ok()?.to_canonical(),
                port?,
            ))
        };
        let a = endpoint(&key.a, key.a_port)?;
        let b = endpoint(&key.b, key.b_port)?;
        self.connected
            .get(&(proto, a, b))
            .or_else(|| self.connected.get(&(proto, b, a)))
            .map(|s| &s.process)
            .or_else(|| self.bound_to(proto, a))
            .or_else(|| self.bound_to(proto, b))
    }

    fn bound_to(&self, proto: SockProto, at: SocketAddr) -> Option<&ProcessInfo> {
        self.bound
            .get(&(proto, at.port()))?
            .iter()
            .find(|(ip, _)| *ip == at.ip() || (ip.is_unspecified() && self.is_local(at.ip())))
            .map(|(_, p)| p)
    }

    fn is_local(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.local.contains(&ip)
    }
}

#[cfg(test)]
#[path = "procmap_tests.rs"]
mod tests;
