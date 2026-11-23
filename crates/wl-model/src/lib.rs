//! Shared contract: plain data types and traits. No I/O, no UI.
//! Every other crate depends on this one and on nothing "sideways".

mod analysis;
mod analysis_state;
mod backend;
mod behavior;
mod capture_options;
mod cert;
mod clock;
mod credential;
mod detail;
mod extras;
mod flow;
mod intel;
mod interner;
mod io_graph;
mod msg_stream;
mod packet;
mod procmap;
mod remote_target;
mod stats;
mod sysinfo;
mod tcp_graph;
mod web;
mod wireshark;

pub use analysis::*;
pub use analysis_state::{Analyses, Analysis};
pub use backend::{
    CaptureBackend, CaptureError, CaptureEvent, CaptureSource, FrameFields, Interface, Session,
};
pub use behavior::{BehaviorData, Channel, ChannelKind, Proto};
pub use capture_options::{AutoStop, CaptureOptions, RingBuffer, SNAPLEN_MAX};
pub use cert::{
    Assessment, CertFinding, CertInfo, CertWarning, assess as assess_chain, date_label,
    evaluate as evaluate_chain,
};
pub use clock::ClockZone;
pub use credential::{CredKind, Credential, SecurityData, mask};
pub use detail::{DetailNode, FrameDetail};
pub use extras::{DecodeAs, DnsQuery, ExportObject, ObjectSet, Rcode, sanitize_filename};
pub use flow::{FlowEvent, FlowEvents, FlowFlags, FlowSel, MAX_FLOW_EVENTS};
pub use intel::{Fingerprint, Indicator, ThreatIntel};
pub use interner::Interner;
pub use io_graph::{CaptureProperties, DeltaStat, InterfaceInfo, IoGraph, IoSeries, IoSpec};
pub use msg_stream::{
    MessageStream, MsgDir, StreamKind, StreamMessage, grpc_status_name, is_control_label,
};
pub use packet::{Direction, FlowKey, PacketRow, Transport, is_encrypted_protocol};
pub use procmap::{
    ProcessInfo, ProcessMap, SockProto, SocketEntry, parse_proc_net, socket_inode, summarize,
};
pub use remote_target::RemoteTarget;
pub use stats::{
    ConversationStat, HostEdge, HostStat, ProtocolStat, RatePoint, StatsSnapshot, rebin,
};
pub use sysinfo::{ARPHRD_ETHER, SysInfo};
pub use tcp_graph::{MAX_TCP_SAMPLES, TcpSample, TcpSamples};
pub use web::{HttpDetail, HttpExchange, HttpMessage, StatusClass, TlsSession};
pub use wireshark::{NEEDS_HINT, Wireshark, needs_message, needs_title};
