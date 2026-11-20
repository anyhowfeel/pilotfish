//! The link computes only what is missing, caches per interval and file, and never blocks.
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use super::*;
use wl_model::{CaptureSource, FrameDetail, Interface, Session};

/// Backend whose `io_series` records each call and answers with one bucket per spec.
#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<(usize, f64)>>,
}

impl CaptureBackend for Fake {
    fn interfaces(&self) -> Result<Vec<Interface>, CaptureError> {
        Ok(Vec::new())
    }
    fn start(&self, _: CaptureSource, _: Option<String>) -> Result<Session, CaptureError> {
        Err(CaptureError::Other("unused".into()))
    }
    fn frame_detail(&self, _: &Path, _: u64) -> Result<FrameDetail, CaptureError> {
        Err(CaptureError::Other("unused".into()))
    }
    fn check_filter(&self, _: &str) -> Result<(), CaptureError> {
        Ok(())
    }
    fn export(&self, _: &Path, _: Option<&[u64]>, _: &Path) -> Result<(), CaptureError> {
        Ok(())
    }
    fn io_series(
        &self,
        _: &Path,
        specs: &[IoSpec],
        interval: f64,
    ) -> Result<IoGraph, CaptureError> {
        self.calls.lock().unwrap().push((specs.len(), interval));
        Ok(IoGraph {
            interval,
            duration: 10.0,
            series: specs
                .iter()
                .map(|_| IoSeries {
                    packets: vec![1],
                    bytes: vec![100],
                    ..IoSeries::default()
                })
                .collect(),
        })
    }
}

fn spec(f: &str) -> IoSpec {
    IoSpec {
        filter: f.into(),
        delta: None,
    }
}

fn req(interval: f64, filters: &[&str]) -> GraphsRequest {
    GraphsRequest {
        interval,
        specs: filters.iter().map(|f| spec(f)).collect(),
    }
}

/// Ticks until the in-flight pass has been stored (at most ~2 s).
fn settle(link: &mut GraphsLink, file: &Path, r: &GraphsRequest) {
    for _ in 0..200 {
        link.tick(Some(file.to_owned()), r, false);
        if !link.view(r).loading {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("pass never finished");
}

fn setup() -> (Arc<Fake>, GraphsLink, PathBuf) {
    let fake = Arc::new(Fake::default());
    let link = GraphsLink::new(fake.clone(), egui::Context::default());
    (fake, link, PathBuf::from("/tmp/a.pcapng"))
}

#[test]
fn computes_once_then_serves_from_cache() {
    let (fake, mut link, file) = setup();
    let r = req(1.0, &["", "tcp"]);
    assert!(link.view(&r).series.is_empty());
    settle(&mut link, &file, &r);
    settle(&mut link, &file, &r);
    assert_eq!(*fake.calls.lock().unwrap(), vec![(2, 1.0)]);
    let v = link.view(&r);
    assert_eq!(v.series.len(), 2);
    assert!(!v.loading && v.duration == 10.0);
}

#[test]
fn only_missing_specs_and_new_intervals_are_computed() {
    let (fake, mut link, file) = setup();
    settle(&mut link, &file, &req(1.0, &["tcp"]));
    settle(&mut link, &file, &req(1.0, &["tcp", "udp"]));
    settle(&mut link, &file, &req(10.0, &["tcp"]));
    assert_eq!(
        *fake.calls.lock().unwrap(),
        vec![(1, 1.0), (1, 1.0), (1, 10.0)]
    );
}

#[test]
fn old_data_stays_visible_while_a_new_interval_loads() {
    let (_, mut link, file) = setup();
    settle(&mut link, &file, &req(1.0, &["tcp"]));
    let wanted = req(0.5, &["tcp"]);
    let v = link.view(&wanted);
    assert_eq!((v.interval, v.series.len(), v.loading), (1.0, 1, true));
}

#[test]
fn a_different_file_starts_from_scratch() {
    let (fake, mut link, file) = setup();
    let r = req(1.0, &["tcp"]);
    settle(&mut link, &file, &r);
    settle(&mut link, Path::new("/tmp/b.pcapng"), &r);
    assert_eq!(fake.calls.lock().unwrap().len(), 2);
}

#[test]
fn backend_without_data_becomes_a_series_error_not_a_loop() {
    struct Mute;
    impl CaptureBackend for Mute {
        fn interfaces(&self) -> Result<Vec<Interface>, CaptureError> {
            Ok(Vec::new())
        }
        fn start(&self, _: CaptureSource, _: Option<String>) -> Result<Session, CaptureError> {
            Err(CaptureError::Other("x".into()))
        }
        fn frame_detail(&self, _: &Path, _: u64) -> Result<FrameDetail, CaptureError> {
            Err(CaptureError::Other("x".into()))
        }
        fn check_filter(&self, _: &str) -> Result<(), CaptureError> {
            Ok(())
        }
        fn export(&self, _: &Path, _: Option<&[u64]>, _: &Path) -> Result<(), CaptureError> {
            Ok(())
        }
    }
    let mut link = GraphsLink::new(Arc::new(Mute), egui::Context::default());
    let (file, r) = (PathBuf::from("/tmp/c.pcapng"), req(1.0, &["tcp"]));
    settle(&mut link, &file, &r);
    let v = link.view(&r);
    assert!(v.series.values().all(|s| s.error.is_some()));
}
