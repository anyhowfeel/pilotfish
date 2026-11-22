//! Reads the socket tables and per-process fd links under `/proc` into a `ProcessMap`.
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use wl_model::{ProcessInfo, ProcessMap, SockProto, SocketEntry, parse_proc_net, socket_inode};

const TABLES: [(&str, SockProto); 4] = [
    ("net/tcp", SockProto::Tcp),
    ("net/tcp6", SockProto::Tcp),
    ("net/udp", SockProto::Udp),
    ("net/udp6", SockProto::Udp),
];

fn sockets(root: &Path) -> Vec<SocketEntry> {
    TABLES
        .iter()
        .filter_map(|(file, proto)| {
            Some(parse_proc_net(
                &fs::read_to_string(root.join(file)).ok()?,
                *proto,
            ))
        })
        .flatten()
        .collect()
}

/// Socket inode -> owning process. Processes whose fd directory cannot be read (other users)
/// are skipped.
fn owners(root: &Path) -> HashMap<u64, ProcessInfo> {
    let mut out = HashMap::new();
    let Ok(dir) = fs::read_dir(root) else {
        return out;
    };
    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        let info = ProcessInfo {
            pid,
            name: comm.trim().into(),
        };
        for fd in fds.flatten() {
            let inode = fs::read_link(fd.path())
                .ok()
                .and_then(|l| socket_inode(&l.to_string_lossy()));
            if let Some(inode) = inode {
                out.insert(inode, info.clone());
            }
        }
    }
    out
}

pub fn scan(root: &Path) -> ProcessMap {
    ProcessMap::build(&sockets(root), &owners(root))
}

#[cfg(test)]
#[path = "proc_scan_tests.rs"]
mod tests;
