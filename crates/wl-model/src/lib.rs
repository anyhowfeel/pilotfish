//! Shared contract: plain data types and traits. No I/O, no UI.
//! Every other crate depends on this one and on nothing "sideways".

mod analysis;
mod backend;
mod behavior;
mod capture_options;
mod cert;
mod detail;
mod extras;
mod flow;
mod io_graph;
mod packet;
mod stats;
mod sysinfo;
mod tcp_graph;
mod web;

pub use analysis::*;
pub use backend::{
    CaptureBackend, CaptureError, CaptureEvent, CaptureSource, FrameFields, Interface, Session,
};
pub use behavior::{BehaviorData, Channel, ChannelKind, Proto};
pub use capture_options::{AutoStop, CaptureOptions, RingBuffer, SNAPLEN_MAX};
pub use cert::{CertFinding, CertInfo, CertWarning, date_label, evaluate as evaluate_chain};
pub use detail::{DetailNode, FrameDetail};
pub use extras::{DecodeAs, DnsQuery, ExportObject, ObjectSet, Rcode, sanitize_filename};
pub use flow::{FlowEvent, FlowEvents, FlowFlags, FlowSel, MAX_FLOW_EVENTS};
pub use io_graph::{CaptureProperties, DeltaStat, InterfaceInfo, IoGraph, IoSeries, IoSpec};
pub use packet::{Direction, FlowKey, PacketRow, Transport, is_encrypted_protocol};
pub use stats::{
    ConversationStat, HostEdge, HostStat, ProtocolStat, RatePoint, StatsSnapshot, rebin,
};
pub use sysinfo::{ARPHRD_ETHER, SysInfo};
pub use tcp_graph::{MAX_TCP_SAMPLES, TcpSample, TcpSamples};
pub use web::{HttpDetail, HttpExchange, HttpMessage, StatusClass, TlsSession};
