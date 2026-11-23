//! Changing the time zone reaches the backend once and refreshes an open dialog only.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use wl_model::{CaptureError, CaptureSource, FrameDetail, Interface, Session};

/// Records the zone it was given and the zone in force at each `capture_properties` call.
#[derive(Default)]
struct Recorder {
    zone: Mutex<ClockZone>,
    set: Mutex<Vec<ClockZone>>,
    read_in: Mutex<Vec<ClockZone>>,
}

impl CaptureBackend for Recorder {
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
    fn set_clock_zone(&self, zone: ClockZone) {
        *self.zone.lock().unwrap() = zone;
        self.set.lock().unwrap().push(zone);
    }
    fn capture_properties(&self, _: &Path) -> Result<CaptureProperties, CaptureError> {
        self.read_in
            .lock()
            .unwrap()
            .push(*self.zone.lock().unwrap());
        Ok(CaptureProperties::default())
    }
    fn file_sha256(&self, _: &Path) -> Result<String, CaptureError> {
        Ok("00".into())
    }
}

fn hub() -> (PropsHub, Arc<Recorder>) {
    let backend = Arc::new(Recorder::default());
    let hub = PropsHub::new(backend.clone(), egui::Context::default());
    (hub, backend)
}

fn file() -> PathBuf {
    PathBuf::from("a.pcap")
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn the_default_zone_is_not_sent_to_the_backend() {
    let (mut hub, backend) = hub();
    hub.set_clock_zone(ClockZone::Local);
    assert!(backend.set.lock().unwrap().is_empty());
}

#[test]
fn a_new_zone_reaches_the_backend_once() {
    let (mut hub, backend) = hub();
    hub.set_clock_zone(ClockZone::Utc);
    hub.set_clock_zone(ClockZone::Utc);
    assert_eq!(*backend.set.lock().unwrap(), [ClockZone::Utc]);
}

#[test]
fn a_closed_dialog_is_not_reloaded() {
    let (mut hub, backend) = hub();
    hub.open(file());
    wait_for("the first read", || {
        backend.read_in.lock().unwrap().len() == 1
    });
    hub.dialog.close();
    hub.set_clock_zone(ClockZone::Utc);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(backend.read_in.lock().unwrap().len(), 1);
}

#[test]
fn an_open_dialog_reads_again_in_the_new_zone() {
    let (mut hub, backend) = hub();
    hub.open(file());
    wait_for("the first read", || {
        backend.read_in.lock().unwrap().len() == 1
    });
    hub.set_clock_zone(ClockZone::Utc);
    wait_for("the second read", || {
        backend.read_in.lock().unwrap().len() == 2
    });
    assert_eq!(
        *backend.read_in.lock().unwrap(),
        [ClockZone::Local, ClockZone::Utc]
    );
}

#[test]
fn switching_back_reads_in_local_time_again() {
    let (mut hub, backend) = hub();
    hub.open(file());
    hub.set_clock_zone(ClockZone::Utc);
    hub.set_clock_zone(ClockZone::Local);
    wait_for("three reads", || backend.read_in.lock().unwrap().len() >= 3);
    assert_eq!(
        *backend.set.lock().unwrap(),
        [ClockZone::Utc, ClockZone::Local]
    );
    assert_eq!(
        backend.read_in.lock().unwrap().last(),
        Some(&ClockZone::Local)
    );
}
