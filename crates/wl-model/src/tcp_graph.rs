//! Samples of one TCP connection for the stream graphs (time-sequence, throughput, RTT, window).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::FlowFlags;

/// Cap of samples one TCP pass returns.
pub const MAX_TCP_SAMPLES: usize = 200_000;

/// One TCP segment.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TcpSample {
    pub frame: u64,
    pub rel: f64,
    /// Sent by endpoint A (the one that sent the first captured packet).
    pub from_a: bool,
    /// Relative sequence / acknowledgement numbers.
    pub seq: u64,
    pub ack: u64,
    /// Payload bytes.
    pub len: u32,
    /// Scaled advertised receive window.
    pub window: u64,
    /// `tcp.analysis.ack_rtt` of this (acknowledging) segment, in seconds.
    pub rtt: Option<f64>,
    pub flags: FlowFlags,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct TcpSamples {
    pub a: Arc<str>,
    pub b: Arc<str>,
    pub a_port: Option<u16>,
    pub b_port: Option<u16>,
    pub samples: Vec<TcpSample>,
    pub truncated: bool,
}
