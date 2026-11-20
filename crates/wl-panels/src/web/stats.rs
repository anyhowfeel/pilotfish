//! Summary aggregation over the whole capture (not just the filtered rows).

use std::collections::HashSet;

use wl_model::{HttpExchange, StatusClass, TlsSession};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WebStats {
    pub requests: usize,
    pub hosts: usize,
    pub errors: usize,
    /// 4xx + 5xx share of requests that got a response (0..=1).
    pub error_rate: f64,
    pub avg_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    /// Slowest request, the scale of the inline latency bars.
    pub max_ms: f64,
    pub tls: usize,
    /// TLS sessions / (TLS sessions + HTTP exchanges), 0..=1.
    pub https_share: f64,
}

/// Nearest-rank percentile of an ascending slice (`p` in 0..=1).
pub fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (p * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted.get(rank - 1).copied()
}

pub fn aggregate(ex: &[HttpExchange], tls: &[TlsSession]) -> WebStats {
    let mut hosts: HashSet<&str> = HashSet::new();
    let (mut errors, mut answered) = (0usize, 0usize);
    let mut times: Vec<f64> = Vec::new();
    for e in ex {
        if !e.host.is_empty() {
            hosts.insert(&e.host);
        }
        match e.status_class() {
            StatusClass::ClientError | StatusClass::ServerError => {
                errors += 1;
                answered += 1;
            }
            StatusClass::Unknown => {}
            _ => answered += 1,
        }
        if let Some(t) = e.time_ms {
            times.push(t);
        }
    }
    for t in tls {
        if !t.server_name.is_empty() {
            hosts.insert(&t.server_name);
        }
    }
    times.sort_by(f64::total_cmp);
    let total = ex.len() + tls.len();
    WebStats {
        requests: ex.len(),
        hosts: hosts.len(),
        errors,
        error_rate: if answered == 0 {
            0.0
        } else {
            errors as f64 / answered as f64
        },
        avg_ms: (!times.is_empty()).then(|| times.iter().sum::<f64>() / times.len() as f64),
        p95_ms: percentile(&times, 0.95),
        max_ms: times.last().copied().unwrap_or(0.0),
        tls: tls.len(),
        https_share: if total == 0 {
            0.0
        } else {
            tls.len() as f64 / total as f64
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::demo::{exchange, session};

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(percentile(&v, 0.95), Some(19.0));
        assert_eq!(percentile(&v, 0.5), Some(10.0));
        assert_eq!(percentile(&[], 0.95), None);
    }

    #[test]
    fn aggregates() {
        let ex = vec![
            exchange(1, "GET", "a.com", "/", Some(200), 10.0),
            exchange(2, "GET", "a.com", "/x", Some(404), 30.0),
            exchange(3, "POST", "b.com", "/y", Some(500), 50.0),
            exchange(4, "GET", "b.com", "/z", Some(301), 10.0),
        ];
        let tls = vec![session(1, "c.com"), session(2, "a.com")];
        let s = aggregate(&ex, &tls);
        assert_eq!((s.requests, s.hosts, s.errors, s.tls), (4, 3, 2, 2));
        assert!((s.error_rate - 0.5).abs() < 1e-9);
        assert_eq!(s.avg_ms, Some(25.0));
        assert_eq!(s.max_ms, 50.0);
        assert!((s.https_share - 2.0 / 6.0).abs() < 1e-9);
        assert_eq!(aggregate(&[], &[]), WebStats::default());
    }
}
