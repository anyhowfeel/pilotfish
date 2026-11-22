//! Offline country / ASN lookup from local `.mmdb` files.
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use maxminddb::{Reader, geoip2};
use wl_panels::overview::GeoInfo;

const MAX_CACHE: usize = 8192;

pub struct GeoDb {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
    cache: Mutex<HashMap<IpAddr, Option<GeoInfo>>>,
}

impl GeoDb {
    pub fn search_dirs() -> Vec<PathBuf> {
        let mut v = Vec::new();
        if let Some(d) = crate::app_paths::env_override("GEO_DIR") {
            v.push(PathBuf::from(d));
        }
        if let Some(d) = dirs::data_dir() {
            v.push(d.join("pilotfish").join("geo"));
            v.push(d.join("qBittorrent").join("GeoDB"));
        }
        if let Some(d) = dirs::config_dir() {
            v.push(d.join("pilotfish").join("geo"));
        }
        for d in [
            "/usr/share/GeoIP",
            "/var/lib/GeoIP",
            "/usr/local/share/GeoIP",
        ] {
            v.push(PathBuf::from(d));
        }
        v
    }

    /// Where to put a database so that `discover` finds it.
    pub fn primary_dir() -> PathBuf {
        Self::search_dirs()
            .into_iter()
            .find(|d| d.ends_with("pilotfish/geo"))
            .unwrap_or_default()
    }

    pub fn discover() -> Option<Arc<Self>> {
        Self::from_dirs(&Self::search_dirs())
    }

    pub fn from_dirs(dirs: &[PathBuf]) -> Option<Arc<Self>> {
        let (mut country, mut asn) = (None, None);
        for dir in dirs {
            let Ok(rd) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut files: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "mmdb"))
                .collect();
            files.sort();
            for f in files {
                let Ok(r) = Reader::open_readfile(&f) else {
                    continue;
                };
                let kind = r.metadata().database_type.to_ascii_lowercase();
                let name = file_stem(&f);
                if kind.contains("asn") || name.contains("asn") {
                    asn.get_or_insert(r);
                } else if kind.contains("country") || kind.contains("city") {
                    country.get_or_insert(r);
                }
            }
        }
        (country.is_some() || asn.is_some()).then(|| {
            Arc::new(Self {
                country,
                asn,
                cache: Mutex::new(HashMap::new()),
            })
        })
    }

    pub fn lookup(&self, addr: &str) -> Option<GeoInfo> {
        let ip: IpAddr = addr.parse().ok()?;
        if let Some(hit) = self.cache.lock().ok()?.get(&ip) {
            return hit.clone();
        }
        let info = self.lookup_ip(ip);
        if let Ok(mut c) = self.cache.lock()
            && c.len() < MAX_CACHE
        {
            c.insert(ip, info.clone());
        }
        info
    }

    fn lookup_ip(&self, ip: IpAddr) -> Option<GeoInfo> {
        if is_local(ip) {
            return None;
        }
        let mut g = GeoInfo {
            country_code: None,
            country: None,
            asn: None,
            org: None,
        };
        if let Some(r) = &self.country
            && let Ok(res) = r.lookup(ip)
            && let Ok(Some(c)) = res.decode::<geoip2::Country>()
        {
            g.country_code = c.country.iso_code.map(Arc::from);
            g.country = c.country.names.english.map(Arc::from);
        }
        if let Some(r) = &self.asn
            && let Ok(res) = r.lookup(ip)
            && let Ok(Some(a)) = res.decode::<geoip2::Asn>()
        {
            g.asn = a.autonomous_system_number;
            g.org = a.autonomous_system_organization.map(Arc::from);
        }
        (g.country_code.is_some() || g.asn.is_some()).then_some(g)
    }
}

fn file_stem(p: &Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_multicast()
                || v.is_unspecified()
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_multicast()
                || v.is_unspecified()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_addresses_are_skipped() {
        for a in [
            "10.0.0.1",
            "127.0.0.1",
            "192.168.1.5",
            "fe80::1",
            "fd00::1",
            "::1",
        ] {
            assert!(is_local(a.parse().unwrap()), "{a}");
        }
        assert!(!is_local("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn no_dirs_means_no_db() {
        assert!(GeoDb::from_dirs(&[PathBuf::from("/nonexistent/wl")]).is_none());
    }
}
