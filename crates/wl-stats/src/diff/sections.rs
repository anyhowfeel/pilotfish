use wl_model::{FlowKey, Transport};

use super::join::{Side, tally};
use super::model::{CaptureData, Micros, Traffic};

pub fn hosts(d: &CaptureData) -> Side<Traffic> {
    tally::<_, Traffic>(
        &d.stats.hosts,
        |h| Some(h.addr.to_string()),
        |t, h| t.add(h.packets_in + h.packets_out, h.bytes_in + h.bytes_out),
    )
}

fn service_label(k: &FlowKey) -> String {
    let (proto, port) = match k.transport {
        Transport::Tcp | Transport::Udp => {
            let port = k.a_port.into_iter().chain(k.b_port).min();
            (format!("{:?}", k.transport).to_uppercase(), port)
        }
        other => (format!("{other:?}").to_uppercase(), None),
    };
    match port {
        Some(p) => format!("{} \u{2194} {} {proto}/{p}", k.a, k.b),
        None => format!("{} \u{2194} {} {proto}", k.a, k.b),
    }
}

pub fn services(d: &CaptureData) -> Side<Traffic> {
    tally::<_, Traffic>(
        &d.stats.conversations,
        |c| Some(service_label(&c.key)),
        |t, c| t.add(c.packets, c.bytes),
    )
}

fn mean_micros(sums: Side<(f64, u64)>) -> Side<Micros> {
    sums.into_iter()
        .map(|(k, (sum, n))| (k, Micros((sum / n as f64 * 1000.0).round() as u64)))
        .collect()
}

pub fn latency(d: &CaptureData) -> Side<Micros> {
    let mut sums = tally::<_, (f64, u64)>(
        &d.http,
        |e| {
            let host = (!e.host.is_empty()).then_some(&e.host)?;
            e.time_ms.map(|_| format!("HTTP {host}"))
        },
        |s, e| {
            s.0 += e.time_ms.unwrap_or_default();
            s.1 += 1;
        },
    );
    let dns = tally::<_, (f64, u64)>(
        &d.dns,
        |q| q.rtt_ms.map(|_| format!("DNS {}", q.name)),
        |s, q| {
            s.0 += q.rtt_ms.unwrap_or_default();
            s.1 += 1;
        },
    );
    sums.extend(dns);
    mean_micros(sums)
}

fn count<T>(items: &[T], mut key: impl FnMut(&T) -> Option<String>) -> Side<u64> {
    tally::<_, u64>(items, |i| key(i), |n, _| *n += 1)
}

pub fn http_hosts(d: &CaptureData) -> Side<u64> {
    count(&d.http, |e| {
        (!e.host.is_empty()).then(|| e.host.to_string())
    })
}

pub fn statuses(d: &CaptureData) -> Side<u64> {
    count(&d.http, |e| e.status.map(|s| s.to_string()))
}

pub fn tls_names(d: &CaptureData) -> Side<u64> {
    count(&d.tls, |t| {
        (!t.server_name.is_empty()).then(|| t.server_name.to_string())
    })
}
