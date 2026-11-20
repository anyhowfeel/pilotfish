//! Headless controller tests against the sample capture and a deterministic mock backend.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::bounded;
use wl_model::{
    CaptureBackend, CaptureError, CaptureEvent, CaptureSource, DetailNode, FrameDetail, Interface,
    PacketRow, Session, Transport,
};

use super::Controller;
use crate::state::RunState;

fn sample() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sample.pcapng")
}

fn controller() -> Option<Controller> {
    wl_tshark::TsharkBackend::new()
        .ok()
        .map(|b| Controller::new(Arc::new(b)))
}

fn run_to_end(c: &mut Controller) -> Vec<PacketRow> {
    let (mut rows, t) = (Vec::new(), Instant::now());
    while t.elapsed() < Duration::from_secs(30) {
        rows.extend(c.poll().rows);
        if !c.is_busy() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    rows
}

fn dummy_row(no: u64) -> PacketRow {
    PacketRow {
        no,
        epoch: no as f64,
        rel: no as f64 * 0.01,
        src: "10.0.0.1".into(),
        dst: "10.0.0.2".into(),
        src_ip: None,
        dst_ip: None,
        src_port: Some(1234),
        dst_port: Some(443),
        transport: Transport::Tcp,
        protocol: "TCP".into(),
        len: 64,
        info: "ACK".into(),
        stream: Some(0),
    }
}

struct MockBackend {
    batches: usize,
    detail_calls: AtomicUsize,
    stopped: Arc<AtomicBool>,
}

impl MockBackend {
    fn new(batches: usize) -> Self {
        Self {
            batches,
            detail_calls: AtomicUsize::new(0),
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl CaptureBackend for MockBackend {
    fn interfaces(&self) -> Result<Vec<Interface>, CaptureError> {
        Ok(vec![])
    }

    fn start(&self, src: CaptureSource, _: Option<String>) -> Result<Session, CaptureError> {
        let (tx, rx) = bounded(16);
        let (batches, stopped) = (self.batches, self.stopped.clone());
        std::thread::spawn(move || {
            for b in 0..batches {
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                let rows = (1..=5).map(|i| dummy_row((b * 5 + i) as u64)).collect();
                if tx.send(CaptureEvent::Rows(rows)).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = tx.send(CaptureEvent::Finished);
        });
        let backing_file = match src {
            CaptureSource::File(p) => p,
            CaptureSource::Live { .. } | CaptureSource::Capture(_) => {
                PathBuf::from("/tmp/mock-live.pcapng")
            }
        };
        let sf = self.stopped.clone();
        Ok(Session {
            events: rx,
            backing_file,
            stop: Box::new(move || sf.store(true, Ordering::SeqCst)),
        })
    }

    fn frame_detail(&self, _: &Path, frame_no: u64) -> Result<FrameDetail, CaptureError> {
        self.detail_calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(25));
        let node = DetailNode {
            label: format!("Frame {frame_no}"),
            range: Some((0, 4)),
            children: vec![],
        };
        Ok(FrameDetail {
            frame_no,
            layers: vec![node],
            bytes: vec![1, 2, 3, 4],
        })
    }

    fn check_filter(&self, filter: &str) -> Result<(), CaptureError> {
        if filter == "slow_bad" {
            std::thread::sleep(Duration::from_millis(40));
            return Err(CaptureError::BadFilter("bad".into()));
        }
        Ok(())
    }

    fn export(&self, _: &Path, _: Option<&[u64]>, _: &Path) -> Result<(), CaptureError> {
        Ok(())
    }
}

fn wait_for<T>(secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if let Some(v) = f() {
            return v;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for async controller result");
}

#[test]
fn sample_stats_filter_detail_and_errors() {
    let Some(mut c) = controller() else { return };
    c.start(CaptureSource::File(sample()), None);
    let rows = run_to_end(&mut c);
    assert!(rows.len() > 250 && c.status().state == RunState::Finished);
    assert_eq!(c.snapshot().total_packets, rows.len() as u64);
    assert!(
        c.snapshot()
            .protocols
            .iter()
            .any(|p| &*p.name == "TCP" || &*p.name == "HTTP")
    );
    assert!(!c.snapshot().hosts.is_empty() && !c.snapshot().conversations.is_empty());

    c.request_detail(1);
    let no = wait_for(10, || {
        c.poll();
        c.detail().map(|d| d.frame_no)
    });
    assert_eq!(no, 1);

    assert!(c.apply_filter(Some("icmp".into())));
    let icmp = run_to_end(&mut c).len();
    assert!(icmp > 0 && icmp < rows.len() && c.snapshot().total_packets == icmp as u64);

    c.validate_filter("tcp.port ==== ".into());
    let (_, res) = wait_for(10, || {
        c.poll();
        c.take_filter_result()
    });
    assert!(res.is_err());

    c.start(CaptureSource::File("/nonexistent/x.pcap".into()), None);
    run_to_end(&mut c);
    assert!(c.status().state == RunState::Failed && c.error().is_some());
}

#[test]
fn pause_resume_and_stop_from_paused() {
    let mut c = Controller::new(Arc::new(MockBackend::new(6)));
    c.start(CaptureSource::File("/tmp/a.pcap".into()), None);
    c.toggle_pause();
    assert!(c.is_paused() && c.status().state == RunState::Paused);
    std::thread::sleep(Duration::from_millis(60));
    assert!(c.poll().rows.is_empty(), "paused poll must not drain rows");
    c.toggle_pause();
    assert!(!c.is_paused() && c.status().state == RunState::Running);
    assert_eq!(run_to_end(&mut c).len(), 30);
    assert_eq!(c.status().state, RunState::Finished);

    let mut c2 = Controller::new(Arc::new(MockBackend::new(50)));
    c2.start(
        CaptureSource::Live {
            interface: "lo".into(),
            capture_filter: None,
        },
        None,
    );
    c2.toggle_pause();
    c2.stop();
    assert!(!c2.is_paused() && c2.status().state == RunState::Finished);
    assert!(c2.apply_filter(Some("tcp".into())));
}

#[test]
fn rapid_detail_coalesces_and_filter_race_ignores_stale() {
    let mock = Arc::new(MockBackend::new(1));
    let mut c = Controller::new(mock.clone());
    c.start(CaptureSource::File("/tmp/a.pcap".into()), None);
    run_to_end(&mut c);
    for n in 1..=20 {
        c.request_detail(n);
    }
    wait_for(3, || {
        c.poll();
        (c.detail().map(|d| d.frame_no) == Some(20)).then_some(())
    });
    assert!(mock.detail_calls.load(Ordering::SeqCst) <= 3);

    c.validate_filter("slow_bad".into());
    std::thread::sleep(Duration::from_millis(5));
    c.validate_filter("tcp".into());
    let (expr, status) = wait_for(3, || {
        c.poll();
        c.take_filter_result()
    });
    assert_eq!(expr, "tcp");
    assert!(status.is_ok());
}
