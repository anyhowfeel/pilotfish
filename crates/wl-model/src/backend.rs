use std::path::{Path, PathBuf};

use crossbeam_channel::Receiver;
use thiserror::Error;

use crate::{
    CaptureOptions, CaptureProperties, Channel, ClockZone, Credential, DecodeAs, DnsQuery,
    FlowEvents, FrameDetail, HttpDetail, HttpExchange, IoGraph, IoSpec, MessageStream, ObjectSet,
    PacketBookmark, PacketRow, SysInfo, TcpSamples, TlsSession,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// Name passed to the capture tool (e.g. `eth0`).
    pub name: String,
    /// Friendly description, if any.
    pub description: Option<String>,
    pub is_loopback: bool,
    pub is_up: bool,
    /// sysfs facts used to group and tag the interface.
    pub sys: SysInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureSource {
    Live {
        interface: String,
        capture_filter: Option<String>,
    },
    /// Live capture with the full Capture > Options set.
    Capture(CaptureOptions),
    File(PathBuf),
}

impl CaptureSource {
    pub fn is_remote(&self) -> bool {
        matches!(self, CaptureSource::Capture(o) if o.remote.enabled)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CaptureError {
    #[error("{}", crate::host_os::missing_text(.0))]
    ToolMissing(String),
    #[error("permission denied: {0}")]
    Permission(String),
    #[error("invalid filter: {0}")]
    BadFilter(String),
    #[error("{0}")]
    Other(String),
}

impl CaptureError {
    pub fn is_tool_missing(&self) -> bool {
        matches!(self, CaptureError::ToolMissing(_))
    }
}

/// Messages flowing from the capture thread to the UI. Rows are batched for performance.
#[derive(Debug, Clone)]
pub enum CaptureEvent {
    Rows(Vec<PacketRow>),
    /// Capture finished normally (file fully read or live stopped).
    Finished,
    Failed(CaptureError),
}

/// A running capture. Dropping it stops the underlying processes.
pub struct Session {
    pub events: Receiver<CaptureEvent>,
    /// Pcapng file backing every frame of this session (temp file for live captures).
    pub backing_file: PathBuf,
    pub stop: Box<dyn FnMut() + Send>,
}

/// `frame.number` plus the requested field values (empty string when a field is absent).
pub type FrameFields = (u64, Vec<String>);

/// Port implemented by `wl-tshark`; UI and app only see this trait (dependency inversion).
pub trait CaptureBackend: Send + Sync {
    fn interfaces(&self) -> Result<Vec<Interface>, CaptureError>;
    /// `display_filter` is applied to the packet list (tshark `-Y`).
    fn start(
        &self,
        source: CaptureSource,
        display_filter: Option<String>,
    ) -> Result<Session, CaptureError>;
    /// Validates a capture (BPF) filter against an interface without capturing.
    fn check_capture_filter(&self, _interface: &str, _filter: &str) -> Result<(), CaptureError> {
        Ok(())
    }
    /// Full dissection + raw bytes of one frame of a backing file.
    fn frame_detail(&self, file: &Path, frame_no: u64) -> Result<FrameDetail, CaptureError>;
    /// Validates a display filter without capturing.
    fn check_filter(&self, filter: &str) -> Result<(), CaptureError>;
    /// Save frames (all when `frames` is None) to a pcapng/pcap file.
    fn export(&self, file: &Path, frames: Option<&[u64]>, dest: &Path) -> Result<(), CaptureError>;
    /// HTTP request/response exchanges found in a backing file (empty if the backend can't).
    fn http_exchanges(&self, _file: &Path) -> Result<Vec<HttpExchange>, CaptureError> {
        Ok(Vec::new())
    }
    /// TLS sessions (SNI, version, cipher, ALPN, cert subject) found in a backing file.
    fn tls_sessions(&self, _file: &Path) -> Result<Vec<TlsSession>, CaptureError> {
        Ok(Vec::new())
    }
    /// Comments stored in the capture file itself (pcapng `opt_comment` of packets).
    fn packet_comments(&self, _file: &Path) -> Result<Vec<PacketBookmark>, CaptureError> {
        Ok(Vec::new())
    }
    /// Writes a new pcapng file whose packet comments are exactly `comments`.
    fn save_with_comments(
        &self,
        _file: &Path,
        _comments: &[PacketBookmark],
        _dest: &Path,
    ) -> Result<(), CaptureError> {
        Err(CaptureError::Other(
            "this backend cannot write comments".into(),
        ))
    }
    /// WebSocket, Server-Sent Events and gRPC streams with their messages.
    fn message_streams(&self, _file: &Path) -> Result<Vec<MessageStream>, CaptureError> {
        Ok(Vec::new())
    }
    /// Start line, headers and body preview of one exchange.
    fn http_detail(&self, _file: &Path, _ex: &HttpExchange) -> Result<HttpDetail, CaptureError> {
        Ok(HttpDetail::default())
    }
    /// Packets matching `filter` as sequence-diagram events (one streaming pass, capped).
    fn flow_events(&self, _file: &Path, _filter: &str) -> Result<FlowEvents, CaptureError> {
        Ok(FlowEvents::default())
    }
    /// TCP segments matching `filter` (one connection) for the stream graphs.
    fn tcp_samples(&self, _file: &Path, _filter: &str) -> Result<TcpSamples, CaptureError> {
        Ok(TcpSamples::default())
    }
    /// Frames of `file` matching display filter `filter` (empty = every frame), each with the
    /// first value of every tshark field in `fields` (`-e`). Used by Find Packet and custom columns.
    fn frame_fields(
        &self,
        _file: &Path,
        _filter: &str,
        _fields: &[String],
    ) -> Result<Vec<FrameFields>, CaptureError> {
        Err(CaptureError::Other(
            "this backend cannot extract frame fields".into(),
        ))
    }
    /// Per-interval packet/byte (and frame-time-delta) series for each spec in ONE pass over the
    /// file (Wireshark I/O graph). Empty when the backend can't.
    fn io_series(
        &self,
        _file: &Path,
        _specs: &[IoSpec],
        _interval: f64,
    ) -> Result<IoGraph, CaptureError> {
        Ok(IoGraph::default())
    }
    /// Capture file summary (`capinfos`), without the (slow) file hash.
    fn capture_properties(&self, _file: &Path) -> Result<CaptureProperties, CaptureError> {
        Ok(CaptureProperties::default())
    }
    /// SHA256 of the file as lowercase hex, computed on demand.
    fn file_sha256(&self, _file: &Path) -> Result<String, CaptureError> {
        Err(CaptureError::Other("hashing is not supported".into()))
    }
    /// Replaces the "Decode As" rules (`-d tcp.port==8080,http`) used by every later dissection
    /// and drops cached dissections. The caller re-reads the current file afterwards.
    fn set_decode_as(&self, _rules: Vec<DecodeAs>) {}
    /// Zone of the times in `capture_properties`. The caller reads the properties again.
    fn set_clock_zone(&self, _zone: ClockZone) {}
    /// Short names of the protocols that can be bound to `field` (e.g. `tcp.port`).
    fn decode_protocols(&self, _field: &str) -> Result<Vec<String>, CaptureError> {
        Ok(Vec::new())
    }
    /// Files carried in the capture for `protocol` (http, smb, tftp, imf, dicom), extracted into a
    /// backend-owned temporary directory (`tshark --export-objects`).
    fn export_objects(&self, _file: &Path, _protocol: &str) -> Result<ObjectSet, CaptureError> {
        Ok(ObjectSet::default())
    }
    /// Timing summary of connection attempts and TCP streams found in a backing file.
    fn behavior_channels(&self, _file: &Path) -> Result<Vec<Channel>, CaptureError> {
        Ok(Vec::new())
    }
    /// Cleartext logins and tokens (HTTP, FTP, SMTP, POP3, NTLM) found in a backing file.
    fn credentials(&self, _file: &Path) -> Result<Vec<Credential>, CaptureError> {
        Ok(Vec::new())
    }
    /// One entry per DNS transaction (query + response) found in a backing file.
    fn dns_queries(&self, _file: &Path) -> Result<Vec<DnsQuery>, CaptureError> {
        Ok(Vec::new())
    }
}
