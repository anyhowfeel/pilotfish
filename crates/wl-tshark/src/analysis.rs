//! High-level tshark analysis entry points on `TsharkBackend` (follow, expert, PHS, fields).

use std::path::Path;

use wl_model::{
    CaptureError, ExpertReport, FilterField, ProtocolHierarchy, StreamConversation, StreamFormat,
    StreamProtocol,
};

use crate::{TsharkBackend, expert, fields, follow, phs};

impl TsharkBackend {
    /// Follows a TCP or UDP stream (`-q -z follow,<proto>,<fmt>,<id>`).
    pub fn follow_stream(
        &self,
        file: &Path,
        protocol: StreamProtocol,
        stream_id: u32,
        format: StreamFormat,
    ) -> Result<StreamConversation, CaptureError> {
        follow::follow_stream(&self.tools, file, protocol, stream_id, format)
    }

    /// Runs Wireshark Expert Info analysis (`-q -z expert`).
    pub fn expert_info(
        &self,
        file: &Path,
        display_filter: Option<&str>,
    ) -> Result<ExpertReport, CaptureError> {
        expert::expert_info(&self.tools, file, display_filter)
    }

    /// Computes Protocol Hierarchy Statistics (`-q -z io,phs`).
    pub fn protocol_hierarchy(
        &self,
        file: &Path,
        display_filter: Option<&str>,
    ) -> Result<ProtocolHierarchy, CaptureError> {
        phs::protocol_hierarchy(&self.tools, file, display_filter)
    }

    /// Loads display filter field definitions from `tshark -G fields`.
    pub fn filter_fields(&self, limit: Option<usize>) -> Result<Vec<FilterField>, CaptureError> {
        fields::load_fields(&self.tools, limit)
    }
}
