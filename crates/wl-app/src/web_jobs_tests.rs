//! Refresh policy and job plumbing of the Web page, with a stub backend and the real fixtures.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use wl_model::{
    CaptureBackend, CaptureError, CaptureSource, FrameDetail, HttpDetail, HttpExchange, Interface,
    Session, TlsSession,
};

use super::*;
use crate::worker::Controller;

#[derive(Default)]
struct Stub {
    scans: AtomicUsize,
}

fn exchange(id: u64) -> HttpExchange {
    HttpExchange {
        id,
        stream: Some(0),
        req_frame: Some(id),
        resp_frame: None,
        method: "GET".into(),
        host: "h".into(),
        uri: "/".into(),
        version: "HTTP/1.1".into(),
        status: None,
        reason: None,
        content_type: None,
        req_bytes: 0,
        resp_bytes: 0,
        start_rel: 0.0,
        time_ms: None,
    }
}

impl CaptureBackend for Stub {
    fn interfaces(&self) -> Result<Vec<Interface>, CaptureError> {
        Ok(vec![])
    }
    fn start(&self, _: CaptureSource, _: Option<String>) -> Result<Session, CaptureError> {
        Err(CaptureError::Other("stub".into()))
    }
    fn frame_detail(&self, _: &Path, _: u64) -> Result<FrameDetail, CaptureError> {
        Err(CaptureError::Other("stub".into()))
    }
    fn check_filter(&self, _: &str) -> Result<(), CaptureError> {
        Ok(())
    }
    fn export(&self, _: &Path, _: Option<&[u64]>, _: &Path) -> Result<(), CaptureError> {
        Ok(())
    }
    fn http_exchanges(&self, _: &Path) -> Result<Vec<HttpExchange>, CaptureError> {
        let n = self.scans.fetch_add(1, Ordering::SeqCst) as u64;
        Ok(vec![exchange(n + 1)])
    }
    fn tls_sessions(&self, _: &Path) -> Result<Vec<TlsSession>, CaptureError> {
        Ok(vec![])
    }
    fn http_detail(&self, _: &Path, ex: &HttpExchange) -> Result<HttpDetail, CaptureError> {
        Ok(HttpDetail {
            request: Some(wl_model::HttpMessage {
                start_line: format!("GET /{}", ex.id),
                ..Default::default()
            }),
            response: None,
        })
    }
}

fn wait_for<T>(mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end {
        if let Some(v) = f() {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

fn wait_idle(s: &WebState) {
    assert!(wait_for(|| (!s.jobs.in_flight()).then_some(())).is_some());
}

#[test]
fn scans_only_when_active_and_once_for_files() {
    let stub = Arc::new(Stub::default());
    let mut s = WebState::new(stub.clone());
    let (file, t0) = (Some(PathBuf::from("a.pcapng")), Instant::now());
    s.tick(file.clone(), false, t0);
    assert_eq!(
        stub.scans.load(Ordering::SeqCst),
        0,
        "inactive page never scans"
    );
    s.set_active(true, false);
    s.tick(file.clone(), false, t0);
    wait_idle(&s);
    s.tick(file.clone(), false, t0 + Duration::from_secs(60));
    wait_idle(&s);
    assert_eq!(
        stub.scans.load(Ordering::SeqCst),
        1,
        "finished file: one scan"
    );
    s.jobs.drain();
    let (ex, tls) = s.jobs.take_web().expect("result");
    assert_eq!((ex.len(), tls.len()), (1, 0));
    assert!(s.jobs.take_web().is_none(), "result is handed out once");
    s.on_new_capture();
    s.tick(file, false, t0);
    wait_idle(&s);
    assert_eq!(stub.scans.load(Ordering::SeqCst), 2, "new capture rescans");
}

#[test]
fn live_capture_refreshes_every_three_seconds() {
    let stub = Arc::new(Stub::default());
    let mut s = WebState::new(stub.clone());
    let (file, t0) = (Some(PathBuf::from("live.pcapng")), Instant::now());
    s.set_active(true, true);
    s.tick(file.clone(), true, t0);
    wait_idle(&s);
    s.tick(file.clone(), true, t0 + Duration::from_secs(1));
    wait_idle(&s);
    assert_eq!(stub.scans.load(Ordering::SeqCst), 1);
    s.tick(file.clone(), true, t0 + LIVE_REFRESH);
    wait_idle(&s);
    assert_eq!(stub.scans.load(Ordering::SeqCst), 2);
    s.on_stop(true);
    s.tick(file, false, t0 + Duration::from_secs(4));
    wait_idle(&s);
    assert_eq!(
        stub.scans.load(Ordering::SeqCst),
        3,
        "final scan after stop"
    );
}

#[test]
fn stale_results_are_dropped_and_detail_latest_wins() {
    let stub = Arc::new(Stub::default());
    let jobs = WebJobs::new(stub);
    jobs.request_detail(PathBuf::from("f"), exchange(1));
    jobs.request_detail(PathBuf::from("f"), exchange(2));
    let line = wait_for(|| {
        jobs.drain();
        jobs.take_detail()
    })
    .and_then(|d| d.request)
    .map(|m| m.start_line);
    assert_eq!(line.as_deref(), Some("GET /2"));
    jobs.request(PathBuf::from("f"));
    jobs.invalidate();
    std::thread::sleep(Duration::from_millis(100));
    jobs.drain();
    assert!(
        jobs.take_web().is_none(),
        "invalidated scan must not surface"
    );
}

#[test]
fn controller_serves_real_exchanges_and_detail() {
    let Ok(b) = wl_tshark::TsharkBackend::new() else {
        return;
    };
    b.set_tls_keylog(None);
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/web-http.pcapng");
    let mut c = Controller::new(Arc::new(b));
    c.set_web_active(true);
    c.start(CaptureSource::File(fixture), None);
    let (ex, tls) = wait_for(|| {
        c.poll();
        c.poll_web()
    })
    .unwrap_or_else(|| panic!("web scan result (err={:?})", c.error()));
    assert_eq!((ex.len(), tls.len()), (6, 0));
    c.request_http_detail(&ex[0]);
    let d = wait_for(|| {
        c.poll();
        c.poll_http_detail()
    })
    .expect("detail");
    assert_eq!(
        d.request.map(|m| m.start_line),
        Some(format!("GET {} HTTP/1.1", ex[0].uri))
    );
    assert!(c.error().is_none());
}
