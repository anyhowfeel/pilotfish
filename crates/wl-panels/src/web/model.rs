//! Pure master-list logic: unified HTTP + TLS rows, filtering and sorting.

use std::cmp::Ordering;

use wl_model::{HttpExchange, StatusClass, TlsSession};

use super::cells::{ci_contains, short_type};
use crate::overview::SortState;

/// Index into the exchange or session slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowRef {
    Http(u32),
    Tls(u32),
}

/// Stable selection identity (survives re-sorting and data refreshes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sel {
    Http(u64),
    Tls(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KindFilter {
    #[default]
    All,
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortCol {
    Time,
    Method,
    Host,
    Path,
    Status,
    Type,
    Size,
    Latency,
}

/// Status-class chips: 2xx, 3xx, 4xx, 5xx.
pub const CLASS_LABELS: [&str; 4] = ["2xx", "3xx", "4xx", "5xx"];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filter {
    pub kind: KindFilter,
    pub query: String,
    pub classes: [bool; 4],
}

#[derive(Clone, Copy)]
pub struct Data<'a> {
    pub ex: &'a [HttpExchange],
    pub tls: &'a [TlsSession],
}

fn class_slot(c: StatusClass) -> Option<usize> {
    match c {
        StatusClass::Success => Some(0),
        StatusClass::Redirect => Some(1),
        StatusClass::ClientError => Some(2),
        StatusClass::ServerError => Some(3),
        _ => None,
    }
}

impl Filter {
    fn any_class(&self) -> bool {
        self.classes.iter().any(|c| *c)
    }

    fn http_ok(&self, e: &HttpExchange) -> bool {
        if self.kind == KindFilter::Https {
            return false;
        }
        if self.any_class() && !class_slot(e.status_class()).is_some_and(|i| self.classes[i]) {
            return false;
        }
        let q = self.query.trim().to_lowercase();
        q.is_empty()
            || ci_contains(&e.host, &q)
            || ci_contains(&e.uri, &q)
            || ci_contains(&e.method, &q)
            || e.status.is_some_and(|s| s.to_string().contains(&q))
    }

    fn tls_ok(&self, t: &TlsSession) -> bool {
        if self.kind == KindFilter::Http || self.any_class() {
            return false;
        }
        let q = self.query.trim().to_lowercase();
        q.is_empty()
            || ci_contains(&t.server_name, &q)
            || ci_contains(&t.version, &q)
            || t.alpn.as_deref().is_some_and(|a| ci_contains(a, &q))
            || "tls https".contains(&q)
    }
}

fn start(d: &Data, r: RowRef) -> f64 {
    match r {
        RowRef::Http(i) => d.ex[i as usize].start_rel,
        RowRef::Tls(i) => d.tls[i as usize].start_rel,
    }
}

fn size(d: &Data, r: RowRef) -> u64 {
    match r {
        RowRef::Http(i) => d.ex[i as usize].resp_bytes + d.ex[i as usize].req_bytes,
        RowRef::Tls(i) => d.tls[i as usize].bytes,
    }
}

fn host<'a>(d: &Data<'a>, r: RowRef) -> &'a str {
    match r {
        RowRef::Http(i) => &d.ex[i as usize].host,
        RowRef::Tls(i) => &d.tls[i as usize].server_name,
    }
}

fn compare(d: &Data, col: SortCol, a: RowRef, b: RowRef) -> Ordering {
    let http = |r| match r {
        RowRef::Http(i) => Some(&d.ex[i as usize]),
        RowRef::Tls(_) => None,
    };
    let (ha, hb) = (http(a), http(b));
    let text = |h: Option<&HttpExchange>, f: fn(&HttpExchange) -> &str| h.map_or("", f).to_owned();
    match col {
        SortCol::Time => start(d, a).total_cmp(&start(d, b)),
        SortCol::Size => size(d, a).cmp(&size(d, b)),
        SortCol::Host => host(d, a).to_lowercase().cmp(&host(d, b).to_lowercase()),
        SortCol::Method => text(ha, |e| &e.method).cmp(&text(hb, |e| &e.method)),
        SortCol::Path => text(ha, |e| &e.uri).cmp(&text(hb, |e| &e.uri)),
        SortCol::Status => ha.and_then(|e| e.status).cmp(&hb.and_then(|e| e.status)),
        SortCol::Type => {
            let t = |h: Option<&HttpExchange>| {
                h.map_or("tls", |e| short_type(e.content_type.as_deref()))
            };
            t(ha).cmp(t(hb))
        }
        SortCol::Latency => {
            let l = |h: Option<&HttpExchange>| h.and_then(|e| e.time_ms).unwrap_or(-1.0);
            l(ha).total_cmp(&l(hb))
        }
    }
}

/// Visible rows in display order.
pub fn build(d: Data, f: &Filter, sort: SortState<SortCol>) -> Vec<RowRef> {
    let mut rows: Vec<RowRef> = (0..d.ex.len())
        .filter(|&i| f.http_ok(&d.ex[i]))
        .map(|i| RowRef::Http(i as u32))
        .chain(
            (0..d.tls.len())
                .filter(|&i| f.tls_ok(&d.tls[i]))
                .map(|i| RowRef::Tls(i as u32)),
        )
        .collect();
    rows.sort_by(|&a, &b| {
        let o = compare(&d, sort.col, a, b).then_with(|| start(&d, a).total_cmp(&start(&d, b)));
        if sort.desc { o.reverse() } else { o }
    });
    rows
}

pub fn sel_of(d: &Data, r: RowRef) -> Sel {
    match r {
        RowRef::Http(i) => Sel::Http(d.ex[i as usize].id),
        RowRef::Tls(i) => Sel::Tls(d.tls[i as usize].first_frame),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::demo::{exchange, session};

    fn data() -> (Vec<HttpExchange>, Vec<TlsSession>) {
        (
            vec![
                exchange(1, "GET", "a.com", "/index", Some(200), 30.0),
                exchange(2, "POST", "b.com", "/api", Some(500), 10.0),
                exchange(3, "GET", "a.com", "/missing", Some(404), 20.0),
            ],
            vec![session(10, "secure.org")],
        )
    }

    fn ids(d: Data, rows: &[RowRef]) -> Vec<Sel> {
        rows.iter().map(|r| sel_of(&d, *r)).collect()
    }

    #[test]
    fn kind_query_and_class_filters() {
        let (ex, tls) = data();
        let d = Data { ex: &ex, tls: &tls };
        let s = SortState::new(SortCol::Time, false);
        assert_eq!(build(d, &Filter::default(), s).len(), 4);
        let f = Filter {
            kind: KindFilter::Https,
            ..Default::default()
        };
        assert_eq!(ids(d, &build(d, &f, s)), [Sel::Tls(10)]);
        let f = Filter {
            query: "A.COM".into(),
            ..Default::default()
        };
        assert_eq!(build(d, &f, s).len(), 2);
        let f = Filter {
            query: "404".into(),
            ..Default::default()
        };
        assert_eq!(ids(d, &build(d, &f, s)), [Sel::Http(3)]);
        let mut f = Filter::default();
        f.classes[3] = true;
        f.classes[2] = true;
        assert_eq!(ids(d, &build(d, &f, s)), [Sel::Http(2), Sel::Http(3)]);
    }

    #[test]
    fn sorting_by_latency_and_host() {
        let (ex, tls) = data();
        let d = Data { ex: &ex, tls: &tls };
        let f = Filter::default();
        let rows = build(d, &f, SortState::new(SortCol::Latency, true));
        assert_eq!(
            ids(d, &rows),
            [Sel::Http(1), Sel::Http(3), Sel::Http(2), Sel::Tls(10)]
        );
        let rows = build(d, &f, SortState::new(SortCol::Host, false));
        assert_eq!(sel_of(&d, rows[0]), Sel::Http(1));
        assert_eq!(sel_of(&d, *rows.last().unwrap()), Sel::Tls(10));
    }
}
