//! Streaming request/response pairing. Requests are appended as they arrive; a response attaches
//! through `http.request_in` (exact), the HTTP/2 stream id, or — pipelining fallback — the oldest
//! unanswered request of the same TCP stream.

use std::collections::{HashMap, VecDeque};
use std::ops::ControlFlow;

use wl_model::HttpExchange;

use crate::http_row::{HttpRec, Kind};

/// Hard cap on exchanges kept for one capture (UI and memory protection).
pub const MAX_EXCHANGES: usize = 200_000;

/// Bytes seen on the wire for a message: the frame itself, or the announced body if larger
/// (reassembled bodies sit in their last small segment).
fn wire_bytes(r: &HttpRec) -> u64 {
    r.frame_len.max(r.content_len)
}

fn new_exchange(r: &HttpRec) -> HttpExchange {
    let request = r.kind == Kind::Request;
    HttpExchange {
        id: r.frame,
        stream: r.stream,
        req_frame: request.then_some(r.frame),
        resp_frame: None,
        method: r.method.clone(),
        host: r.host.clone(),
        uri: r.uri.clone(),
        version: r.version.clone(),
        status: None,
        reason: None,
        content_type: None,
        req_bytes: if request { wire_bytes(r) } else { 0 },
        resp_bytes: 0,
        start_rel: r.rel,
        time_ms: None,
    }
}

fn attach_response(ex: &mut HttpExchange, r: &HttpRec) {
    ex.resp_frame = Some(r.frame);
    ex.status = r.status;
    ex.reason = r.reason.clone();
    ex.content_type = r.content_type.clone();
    ex.resp_bytes = wire_bytes(r);
    if ex.version.is_empty() {
        ex.version = r.version.clone();
    }
    ex.time_ms = r.time_ms.or_else(|| {
        ex.req_frame
            .map(|_| ((r.rel - ex.start_rel) * 1000.0).max(0.0))
    });
}

#[derive(Default)]
pub struct Pairer {
    out: Vec<HttpExchange>,
    by_req_frame: HashMap<u64, usize>,
    unanswered: HashMap<Option<u32>, VecDeque<usize>>,
    h2_open: HashMap<(u32, u32), usize>,
    pub truncated: bool,
}

impl Pairer {
    pub fn push(&mut self, r: HttpRec) -> ControlFlow<()> {
        if self.out.len() >= MAX_EXCHANGES {
            self.truncated = true;
            return ControlFlow::Break(());
        }
        match r.kind {
            Kind::Request => self.request(&r),
            Kind::Response => self.response(&r),
        }
        ControlFlow::Continue(())
    }

    fn request(&mut self, r: &HttpRec) {
        let idx = self.out.len();
        self.out.push(new_exchange(r));
        self.by_req_frame.insert(r.frame, idx);
        self.unanswered.entry(r.stream).or_default().push_back(idx);
        if let (Some(s), Some(h)) = (r.stream, r.h2_stream) {
            self.h2_open.insert((s, h), idx);
        }
    }

    fn find_request(&mut self, r: &HttpRec) -> Option<usize> {
        let exact = r
            .request_in
            .and_then(|f| self.by_req_frame.get(&f).copied())
            .or_else(|| {
                let key = (r.stream?, r.h2_stream?);
                self.h2_open.get(&key).copied()
            });
        let idx = exact.or_else(|| self.unanswered.get_mut(&r.stream)?.pop_front())?;
        if let Some(q) = self.unanswered.get_mut(&r.stream) {
            if q.front() == Some(&idx) {
                q.pop_front();
            } else {
                q.retain(|&i| i != idx);
            }
        }
        Some(idx)
    }

    fn response(&mut self, r: &HttpRec) {
        let open = self.find_request(r).filter(|&i| {
            // A second response (after `100 Continue`) may replace an informational one only.
            let ex = &self.out[i];
            ex.resp_frame.is_none() || matches!(ex.status, Some(100..=199))
        });
        match open {
            Some(i) => attach_response(&mut self.out[i], r),
            None => {
                let mut ex = new_exchange(r);
                attach_response(&mut ex, r);
                self.out.push(ex);
            }
        }
    }

    pub fn finish(self) -> Vec<HttpExchange> {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn rec(kind: Kind, frame: u64, stream: u32) -> HttpRec {
        let s: Arc<str> = Arc::from("");
        HttpRec {
            kind,
            frame,
            rel: frame as f64 / 10.0,
            stream: Some(stream),
            h2_stream: None,
            method: if kind == Kind::Request {
                "GET".into()
            } else {
                s.clone()
            },
            host: "h".into(),
            uri: format!("/{frame}").into(),
            version: "HTTP/1.1".into(),
            status: (kind == Kind::Response).then_some(200),
            reason: None,
            content_type: None,
            content_len: 0,
            frame_len: 100,
            request_in: None,
            time_ms: None,
        }
    }

    fn run(recs: Vec<HttpRec>) -> Vec<HttpExchange> {
        let mut p = Pairer::default();
        for r in recs {
            let _ = p.push(r);
        }
        p.finish()
    }

    #[test]
    fn pairs_by_request_in_even_out_of_order() {
        let mut a = rec(Kind::Response, 9, 0);
        a.request_in = Some(2);
        let mut b = rec(Kind::Response, 8, 0);
        b.request_in = Some(1);
        let v = run(vec![
            rec(Kind::Request, 1, 0),
            rec(Kind::Request, 2, 0),
            a,
            b,
        ]);
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].resp_frame, v[1].resp_frame), (Some(8), Some(9)));
        assert!(v[0].time_ms.is_some());
    }

    #[test]
    fn pipelining_fallback_is_fifo_per_stream() {
        let v = run(vec![
            rec(Kind::Request, 1, 0),
            rec(Kind::Request, 2, 0),
            rec(Kind::Request, 3, 1),
            rec(Kind::Response, 4, 1),
            rec(Kind::Response, 5, 0),
            rec(Kind::Response, 6, 0),
        ]);
        let pairs: Vec<_> = v.iter().map(|e| (e.id, e.resp_frame)).collect();
        assert_eq!(pairs, [(1, Some(5)), (2, Some(6)), (3, Some(4))]);
    }

    #[test]
    fn unpaired_messages_are_kept() {
        let v = run(vec![rec(Kind::Response, 3, 5), rec(Kind::Request, 4, 6)]);
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].req_frame, v[0].status), (None, Some(200)));
        assert_eq!((v[1].req_frame, v[1].resp_frame), (Some(4), None));
    }

    #[test]
    fn h2_pairs_by_stream_id() {
        let mut q1 = rec(Kind::Request, 1, 0);
        q1.h2_stream = Some(1);
        let mut q2 = rec(Kind::Request, 2, 0);
        q2.h2_stream = Some(3);
        let mut r2 = rec(Kind::Response, 3, 0);
        r2.h2_stream = Some(3);
        let v = run(vec![q1, q2, r2]);
        assert_eq!((v[0].resp_frame, v[1].resp_frame), (None, Some(3)));
    }

    #[test]
    fn caps_and_flags_truncation() {
        let mut p = Pairer::default();
        for i in 0..=MAX_EXCHANGES as u64 {
            if p.push(rec(Kind::Request, i + 1, 0)).is_break() {
                break;
            }
        }
        assert!(p.truncated);
        assert_eq!(p.finish().len(), MAX_EXCHANGES);
    }
}
