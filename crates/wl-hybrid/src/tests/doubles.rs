use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wl_model::{
    CaptureBackend, CaptureError, CaptureProperties, CaptureSource, ClockZone, DecodeAs,
    FrameDetail, Interface, IoGraph, IoSpec, Session,
};

use crate::{FastPath, HybridBackend};

pub fn session(tag: &str) -> Session {
    let (_tx, events) = crossbeam_channel::unbounded();
    Session {
        events,
        backing_file: PathBuf::from(tag),
        stop: Box::new(|| {}),
    }
}

pub fn missing() -> CaptureError {
    CaptureError::ToolMissing("no wireshark".into())
}

/// Records every call as `name` and keeps the decode-as rules it was given.
#[derive(Default)]
pub struct MockDeep {
    pub calls: Mutex<Vec<String>>,
    pub rules: Mutex<Vec<DecodeAs>>,
    pub zone: Mutex<Option<ClockZone>>,
}

impl MockDeep {
    fn note(&self, what: &str) {
        self.calls.lock().unwrap().push(what.into());
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl CaptureBackend for MockDeep {
    fn interfaces(&self) -> Result<Vec<Interface>, CaptureError> {
        self.note("interfaces");
        Ok(vec![Interface {
            name: "eth0".into(),
            description: None,
            is_loopback: false,
            is_up: true,
            sys: Default::default(),
        }])
    }

    fn start(&self, _: CaptureSource, _: Option<String>) -> Result<Session, CaptureError> {
        self.note("start");
        Ok(session("deep"))
    }

    fn frame_detail(&self, _: &Path, n: u64) -> Result<FrameDetail, CaptureError> {
        self.note("frame_detail");
        Ok(FrameDetail {
            frame_no: n,
            ..Default::default()
        })
    }

    fn check_filter(&self, f: &str) -> Result<(), CaptureError> {
        self.note("check_filter");
        if f == "bad" {
            Err(CaptureError::BadFilter("bad".into()))
        } else {
            Ok(())
        }
    }

    fn export(&self, _: &Path, _: Option<&[u64]>, _: &Path) -> Result<(), CaptureError> {
        self.note("export");
        Ok(())
    }

    fn io_series(&self, _: &Path, _: &[IoSpec], _: f64) -> Result<IoGraph, CaptureError> {
        self.note("io_series");
        Ok(IoGraph::default())
    }

    fn set_clock_zone(&self, zone: ClockZone) {
        self.note("set_clock_zone");
        *self.zone.lock().unwrap() = Some(zone);
    }

    fn set_decode_as(&self, rules: Vec<DecodeAs>) {
        self.note("set_decode_as");
        *self.rules.lock().unwrap() = rules;
    }
}

/// Native stand-in: accepts only the filter `tcp` and records what it was asked.
#[derive(Default)]
pub struct FakeFast {
    pub calls: Mutex<Vec<String>>,
}

impl FakeFast {
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn note(&self, what: &str) {
        self.calls.lock().unwrap().push(what.into());
    }
}

impl FastPath for Arc<FakeFast> {
    fn supports_filter(&self, filter: &str) -> bool {
        filter.trim().is_empty() || filter == "tcp"
    }

    fn start_file(&self, _: &Path, filter: Option<&str>) -> Result<Session, CaptureError> {
        self.note(&format!("start_file:{}", filter.unwrap_or("-")));
        Ok(session("native"))
    }

    fn capture_properties(
        &self,
        _: &Path,
        zone: ClockZone,
    ) -> Result<CaptureProperties, CaptureError> {
        self.note(&format!("capture_properties:{zone:?}"));
        Ok(CaptureProperties::default())
    }

    fn file_sha256(&self, _: &Path) -> Result<String, CaptureError> {
        self.note("file_sha256");
        Ok("abc".into())
    }

    fn io_series(
        &self,
        _: &Path,
        specs: &[IoSpec],
        _: f64,
    ) -> Option<Result<IoGraph, CaptureError>> {
        self.note("io_series");
        specs
            .iter()
            .all(|s| self.supports_filter(&s.filter))
            .then(|| Ok(IoGraph::default()))
    }

    fn frame_detail(&self, _: &Path, n: u64) -> Result<FrameDetail, CaptureError> {
        self.note("native_frame_detail");
        Ok(FrameDetail {
            frame_no: n + 1000,
            ..Default::default()
        })
    }
}

pub struct Rig {
    pub hybrid: HybridBackend<Arc<FakeFast>>,
    pub fast: Arc<FakeFast>,
    pub deep: Arc<MockDeep>,
    pub builds: Arc<AtomicUsize>,
}

impl Rig {
    pub fn working() -> Self {
        Self::with(true)
    }

    pub fn broken() -> Self {
        Self::with(false)
    }

    fn with(ok: bool) -> Self {
        let (fast, deep) = (Arc::new(FakeFast::default()), Arc::new(MockDeep::default()));
        let builds = Arc::new(AtomicUsize::new(0));
        let (b, d) = (builds.clone(), deep.clone());
        let hybrid = HybridBackend::new(fast.clone(), move || {
            b.fetch_add(1, Ordering::SeqCst);
            if ok {
                Ok(d.clone() as Arc<dyn CaptureBackend>)
            } else {
                Err(missing())
            }
        });
        Self {
            hybrid,
            fast,
            deep,
            builds,
        }
    }

    pub fn builds(&self) -> usize {
        self.builds.load(Ordering::SeqCst)
    }
}
