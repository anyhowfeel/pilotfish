//! `CaptureBackend` implementation on top of tshark / dumpcap / editcap.
//! tshark does all dissection; this crate only orchestrates processes and parses their output.

pub mod analysis;
mod backend_core;
mod behavior_scan;
mod capinfos;
mod capture_args;
mod cert_parse;
mod cert_scan;
mod comments;
mod control;
mod cred_parse;
mod cred_scan;
mod decode_as;
mod dns_scan;
mod error;
pub mod expert;
mod export;
mod export_chunked;
pub mod fields;
mod file_source;
mod finish;
mod flow_flags;
mod flow_scan;
pub mod follow;
mod frame;
mod frame_cache;
mod frame_fields;
mod hexdump;
mod http_detail;
mod http_message;
mod http_pair;
mod http_row;
mod http_scan;
mod interfaces;
mod interner;
mod io_stat;
mod io_stat_parse;
mod json_ordered;
pub mod keylog;
mod keys_embed;
mod live;
mod msg_group;
mod msg_preview;
mod msg_rows;
mod msg_scan;
pub mod netinfo;
mod object_names;
pub mod objects;
pub mod objects_save;
#[cfg(test)]
mod parse_bench;
mod pdml;
pub mod phs;
mod process;
mod pump;
mod remote_args;
mod ring;
mod row_parser;
mod scan_memo;
mod sse;
mod tcp_scan;
mod tls_merge;
mod tls_names;
mod tls_scan;
mod tsv_pass;
mod validate;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::TempDir;
use wl_model::{
    CaptureBackend, CaptureError, CaptureOptions, CaptureProperties, CaptureSource, Channel,
    Credential, DecodeAs, DnsQuery, FlowEvents, FrameDetail, FrameFields, HttpDetail, HttpExchange,
    Interface, IoGraph, IoSpec, MessageStream, ObjectSet, PacketBookmark, Session, TcpSamples,
    TlsSession,
};

use process::Tools;
pub use process::{kill_all_children, spawned as processes_spawned};

pub struct TsharkBackend {
    pub(crate) tools: Tools,
    /// Holds live capture files and the empty pcap used for filter checks; removed on drop.
    scratch: TempDir,
    empty_pcap: PathBuf,
    counter: AtomicU64,
    frame_cache: frame_cache::FrameCache,
    http_cache: http_detail::DetailCache,
    keylog: Mutex<Option<PathBuf>>,
    decode_as: Mutex<Vec<DecodeAs>>,
    scans: Scans,
}

#[derive(Default)]
struct Scans {
    http: scan_memo::ScanMemo<HttpExchange>,
    tls: scan_memo::ScanMemo<TlsSession>,
    dns: scan_memo::ScanMemo<DnsQuery>,
    credentials: scan_memo::ScanMemo<Credential>,
    certs: cert_scan::CertCache,
}

impl Scans {
    fn clear(&self) {
        self.http.clear();
        self.tls.clear();
        self.dns.clear();
        self.credentials.clear();
        self.certs.clear();
    }
}

impl CaptureBackend for TsharkBackend {
    fn interfaces(&self) -> Result<Vec<Interface>, CaptureError> {
        interfaces::list(&self.tools)
    }

    fn start(
        &self,
        source: CaptureSource,
        display_filter: Option<String>,
    ) -> Result<Session, CaptureError> {
        let display = display_filter.as_deref();
        let opts = self.dissect_opts();
        match source {
            CaptureSource::File(path) => {
                file_source::start(&self.tools, &self.empty_pcap, &path, display, &opts)
            }
            CaptureSource::Live {
                interface,
                capture_filter,
            } => self.start_live(
                &CaptureOptions::single(&interface, capture_filter.as_deref()),
                display,
                &opts,
            ),
            CaptureSource::Capture(options) => self.start_live(&options, display, &opts),
        }
    }

    fn frame_detail(&self, file: &Path, frame_no: u64) -> Result<FrameDetail, CaptureError> {
        frame::frame_detail(
            &self.tools,
            &self.frame_cache,
            file,
            frame_no,
            &self.dissect_opts(),
        )
    }

    fn check_capture_filter(&self, interface: &str, filter: &str) -> Result<(), CaptureError> {
        validate::capture_filter(&self.tools, interface, filter)
    }

    fn check_filter(&self, filter: &str) -> Result<(), CaptureError> {
        validate::display_filter(&self.tools, &self.empty_pcap, filter)
    }

    fn export(&self, file: &Path, frames: Option<&[u64]>, dest: &Path) -> Result<(), CaptureError> {
        export::export(&self.tools, file, frames, dest)
    }

    fn frame_fields(
        &self,
        file: &Path,
        filter: &str,
        fields: &[String],
    ) -> Result<Vec<FrameFields>, CaptureError> {
        frame_fields::frame_fields(&self.tools, file, filter, fields, &self.dissect_opts())
    }

    fn http_exchanges(&self, file: &Path) -> Result<Vec<HttpExchange>, CaptureError> {
        self.scans.http.get_or_scan(file, || {
            http_scan::http_exchanges(&self.tools, file, &self.dissect_opts())
        })
    }

    fn tls_sessions(&self, file: &Path) -> Result<Vec<TlsSession>, CaptureError> {
        self.scans.tls.get_or_scan(file, || {
            tls_scan::tls_sessions(&self.tools, &self.scans.certs, file, &self.dissect_opts())
        })
    }

    fn http_detail(&self, file: &Path, ex: &HttpExchange) -> Result<HttpDetail, CaptureError> {
        http_detail::http_detail(
            &self.tools,
            &self.http_cache,
            file,
            ex,
            &self.dissect_opts(),
        )
    }

    fn packet_comments(&self, file: &Path) -> Result<Vec<PacketBookmark>, CaptureError> {
        comments::read(&self.tools, file, &self.dissect_opts())
    }

    fn save_with_comments(
        &self,
        file: &Path,
        comments: &[PacketBookmark],
        dest: &Path,
    ) -> Result<(), CaptureError> {
        comments::write(&self.tools, file, comments, dest)
    }

    fn message_streams(&self, file: &Path) -> Result<Vec<MessageStream>, CaptureError> {
        msg_scan::message_streams(&self.tools, file, &self.dissect_opts())
    }

    fn flow_events(&self, file: &Path, filter: &str) -> Result<FlowEvents, CaptureError> {
        flow_scan::flow_events(&self.tools, file, filter, &self.dissect_opts())
    }

    fn tcp_samples(&self, file: &Path, filter: &str) -> Result<TcpSamples, CaptureError> {
        tcp_scan::tcp_samples(&self.tools, file, filter, &self.dissect_opts())
    }
    fn io_series(
        &self,
        file: &Path,
        specs: &[IoSpec],
        interval: f64,
    ) -> Result<IoGraph, CaptureError> {
        io_stat::io_series(&self.tools, file, specs, interval, &self.dissect_opts())
    }

    fn capture_properties(&self, file: &Path) -> Result<CaptureProperties, CaptureError> {
        capinfos::properties(&self.tools, file)
    }

    fn file_sha256(&self, file: &Path) -> Result<String, CaptureError> {
        capinfos::sha256(&self.tools, file)
    }
    fn set_decode_as(&self, rules: Vec<DecodeAs>) {
        *self.decode_as.lock().unwrap_or_else(|e| e.into_inner()) = rules;
        self.frame_cache.clear();
        self.http_cache.clear();
        self.scans.clear();
    }

    fn decode_protocols(&self, field: &str) -> Result<Vec<String>, CaptureError> {
        decode_as::protocols(&self.tools, field)
    }

    fn export_objects(&self, file: &Path, protocol: &str) -> Result<ObjectSet, CaptureError> {
        let opts = self.dissect_opts();
        let req = objects::Request {
            tools: &self.tools,
            file,
            protocol,
            dir: self.scratch.path().join(format!("objects-{protocol}")),
            opts: &opts,
            cap: objects::SIZE_CAP,
        };
        objects::export(&req, || {
            http_scan::http_exchanges(&self.tools, file, &opts).unwrap_or_default()
        })
    }

    fn behavior_channels(&self, file: &Path) -> Result<Vec<Channel>, CaptureError> {
        behavior_scan::behavior_channels(&self.tools, file, &self.dissect_opts())
    }

    fn credentials(&self, file: &Path) -> Result<Vec<Credential>, CaptureError> {
        self.scans.credentials.get_or_scan(file, || {
            cred_scan::credentials(&self.tools, file, &self.dissect_opts())
        })
    }

    fn dns_queries(&self, file: &Path) -> Result<Vec<DnsQuery>, CaptureError> {
        self.scans.dns.get_or_scan(file, || {
            dns_scan::dns_queries(&self.tools, file, &self.dissect_opts())
        })
    }
}
