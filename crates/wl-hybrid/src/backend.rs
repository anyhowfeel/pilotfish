use std::path::Path;

use wl_model::{
    CaptureBackend, CaptureError, CaptureProperties, CaptureSource, Channel, ClockZone, Credential,
    DecodeAs, DnsQuery, FlowEvents, FrameDetail, FrameFields, HttpDetail, HttpExchange, Interface,
    IoGraph, IoSpec, MessageStream, ObjectSet, PacketBookmark, Session, TcpSamples, TlsSession,
};

use crate::route::{self, Route};
use crate::{FastPath, HybridBackend, lock};

impl<F: FastPath> CaptureBackend for HybridBackend<F> {
    /// Empty without the deep backend, so the capture page still opens.
    fn interfaces(&self) -> Result<Vec<Interface>, CaptureError> {
        match self.deep() {
            Ok(d) => d.interfaces(),
            Err(_) => Ok(Vec::new()),
        }
    }

    fn start(
        &self,
        source: CaptureSource,
        display_filter: Option<String>,
    ) -> Result<Session, CaptureError> {
        let supports = |f: &str| self.fast.supports_filter(f);
        let routed = route::start_route(
            &source,
            display_filter.as_deref(),
            self.decode_as_active(),
            supports,
        );
        match (routed, &source) {
            (Route::Native, CaptureSource::File(path)) => {
                let filter = display_filter.as_deref().filter(|f| !f.trim().is_empty());
                self.fast.start_file(path, filter)
            }
            _ => self.deep()?.start(source, display_filter),
        }
    }

    fn check_capture_filter(&self, interface: &str, filter: &str) -> Result<(), CaptureError> {
        self.deep()?.check_capture_filter(interface, filter)
    }

    fn frame_detail(&self, file: &Path, frame_no: u64) -> Result<FrameDetail, CaptureError> {
        match self.deep() {
            Ok(d) => d.frame_detail(file, frame_no),
            Err(_) => self.fast.frame_detail(file, frame_no),
        }
    }

    fn check_filter(&self, filter: &str) -> Result<(), CaptureError> {
        match route::filter_route(filter, |f| self.fast.supports_filter(f)) {
            Route::Native => Ok(()),
            Route::Deep => self.deep()?.check_filter(filter),
        }
    }

    fn export(&self, file: &Path, frames: Option<&[u64]>, dest: &Path) -> Result<(), CaptureError> {
        self.deep()?.export(file, frames, dest)
    }

    fn http_exchanges(&self, file: &Path) -> Result<Vec<HttpExchange>, CaptureError> {
        self.deep()?.http_exchanges(file)
    }

    fn http_exchanges_scoped(
        &self,
        file: &Path,
        scope: Option<&str>,
    ) -> Result<Vec<HttpExchange>, CaptureError> {
        self.deep()?.http_exchanges_scoped(file, scope)
    }

    fn tls_sessions(&self, file: &Path) -> Result<Vec<TlsSession>, CaptureError> {
        self.deep()?.tls_sessions(file)
    }

    fn tls_sessions_scoped(
        &self,
        file: &Path,
        scope: Option<&str>,
    ) -> Result<Vec<TlsSession>, CaptureError> {
        self.deep()?.tls_sessions_scoped(file, scope)
    }

    fn packet_comments(&self, file: &Path) -> Result<Vec<PacketBookmark>, CaptureError> {
        self.deep()?.packet_comments(file)
    }

    fn save_with_comments(
        &self,
        file: &Path,
        comments: &[PacketBookmark],
        dest: &Path,
    ) -> Result<(), CaptureError> {
        self.deep()?.save_with_comments(file, comments, dest)
    }

    fn message_streams(&self, file: &Path) -> Result<Vec<MessageStream>, CaptureError> {
        self.deep()?.message_streams(file)
    }

    fn message_streams_scoped(
        &self,
        file: &Path,
        scope: Option<&str>,
    ) -> Result<Vec<MessageStream>, CaptureError> {
        self.deep()?.message_streams_scoped(file, scope)
    }

    fn http_detail(&self, file: &Path, ex: &HttpExchange) -> Result<HttpDetail, CaptureError> {
        self.deep()?.http_detail(file, ex)
    }

    fn flow_events(&self, file: &Path, filter: &str) -> Result<FlowEvents, CaptureError> {
        self.deep()?.flow_events(file, filter)
    }

    fn tcp_samples(&self, file: &Path, filter: &str) -> Result<TcpSamples, CaptureError> {
        self.deep()?.tcp_samples(file, filter)
    }

    fn frame_fields(
        &self,
        file: &Path,
        filter: &str,
        fields: &[String],
    ) -> Result<Vec<FrameFields>, CaptureError> {
        self.deep()?.frame_fields(file, filter, fields)
    }

    fn io_series(
        &self,
        file: &Path,
        specs: &[IoSpec],
        interval: f64,
    ) -> Result<IoGraph, CaptureError> {
        if route::io_route(specs, |f| self.fast.supports_filter(f)) == Route::Native
            && let Some(graph) = self.fast.io_series(file, specs, interval)
        {
            return graph;
        }
        self.deep()?.io_series(file, specs, interval)
    }

    fn capture_properties(&self, file: &Path) -> Result<CaptureProperties, CaptureError> {
        let zone = lock(&self.settings).zone;
        self.fast.capture_properties(file, zone)
    }

    fn file_sha256(&self, file: &Path) -> Result<String, CaptureError> {
        self.fast.file_sha256(file)
    }

    fn set_decode_as(&self, rules: Vec<DecodeAs>) {
        let mut stored = lock(&self.settings);
        stored.rules = rules.clone();
        if let Some(d) = self.deep.built() {
            d.set_decode_as(rules);
        }
    }

    fn set_clock_zone(&self, zone: ClockZone) {
        let mut stored = lock(&self.settings);
        stored.zone = zone;
        if let Some(d) = self.deep.built() {
            d.set_clock_zone(zone);
        }
    }

    fn decode_protocols(&self, field: &str) -> Result<Vec<String>, CaptureError> {
        self.deep()?.decode_protocols(field)
    }

    fn export_objects(&self, file: &Path, protocol: &str) -> Result<ObjectSet, CaptureError> {
        self.deep()?.export_objects(file, protocol)
    }

    fn behavior_channels(&self, file: &Path) -> Result<Vec<Channel>, CaptureError> {
        self.deep()?.behavior_channels(file)
    }

    fn credentials(&self, file: &Path) -> Result<Vec<Credential>, CaptureError> {
        self.deep()?.credentials(file)
    }

    fn dns_queries(&self, file: &Path) -> Result<Vec<DnsQuery>, CaptureError> {
        self.deep()?.dns_queries(file)
    }
}
