use std::collections::HashMap;
use std::sync::Arc;

use wl_model::{HostStat, PacketRow};

use crate::private::is_private;
use crate::top::top_n_by;

/// Hard cap on tracked hosts; later unseen hosts are ignored (totals still count them).
pub const MAX_HOSTS: usize = 500_000;

#[derive(Debug, Default)]
pub struct HostTable(HashMap<Arc<str>, HostStat>);

impl HostTable {
    /// Source counts as outgoing, destination as incoming.
    pub fn add(&mut self, row: &PacketRow) {
        let bytes = u64::from(row.len);
        if let Some(s) = self.entry(&row.src, row.src_ip) {
            s.packets_out += 1;
            s.bytes_out += bytes;
        }
        if let Some(d) = self.entry(&row.dst, row.dst_ip) {
            d.packets_in += 1;
            d.bytes_in += bytes;
        }
    }

    /// `None` once the table is full and `addr` is new (memory stays bounded under scans).
    fn entry(&mut self, addr: &Arc<str>, ip: Option<std::net::IpAddr>) -> Option<&mut HostStat> {
        if !self.0.contains_key(&**addr) && self.0.len() >= MAX_HOSTS {
            return None;
        }
        Some(self.0.entry(addr.clone()).or_insert_with(|| HostStat {
            addr: addr.clone(),
            is_private: is_private(ip),
            ..Default::default()
        }))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn top(&self, n: usize) -> Vec<HostStat> {
        let total = |h: &HostStat| h.bytes_in + h.bytes_out;
        top_n_by(self.0.values(), n, |a, b| {
            total(b).cmp(&total(a)).then_with(|| a.addr.cmp(&b.addr))
        })
        .into_iter()
        .cloned()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_capped_but_known_hosts_keep_counting() {
        let mut t = HostTable::default();
        let mk = |a: &str| PacketRow {
            no: 1,
            epoch: 0.0,
            rel: 0.0,
            src: Arc::from(a),
            dst: Arc::from("10.9.9.9"),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            transport: wl_model::Transport::Other,
            protocol: Arc::from("X"),
            len: 10,
            info: Arc::from(""),
            stream: None,
        };
        for i in 0..(MAX_HOSTS + 100) {
            t.add(&mk(&format!("h{i}")));
        }
        assert_eq!(t.0.len(), MAX_HOSTS);
        t.add(&mk("h0"));
        assert_eq!(t.0["h0"].packets_out, 2);
    }
}
