//! I/O graph and capture-properties data (Wireshark `io,stat` and `capinfos`), plain data only.

/// Extra per-bucket statistic of the frame time delta (`frame.time_delta`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeltaStat {
    Max,
    Min,
}

/// One graph series to compute: the packets matching `filter` (empty = every packet), plus an
/// optional time-delta statistic. Hashable: it is part of the result cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IoSpec {
    pub filter: String,
    pub delta: Option<DeltaStat>,
}

/// Per-interval values of one series. Bucket `i` covers `[i * interval, (i + 1) * interval)`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IoSeries {
    pub packets: Vec<u64>,
    pub bytes: Vec<u64>,
    /// Max/min frame time delta in seconds (empty unless the spec asked for it).
    pub delta: Vec<f64>,
    /// Set when this series' filter could not be evaluated (the other series are still valid).
    pub error: Option<String>,
}

/// Result of one `io_series` call: one series per requested spec, in order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IoGraph {
    pub interval: f64,
    /// Capture duration in seconds.
    pub duration: f64,
    pub series: Vec<IoSeries>,
}

/// One interface description block of a capture file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub encapsulation: String,
    pub capture_length: String,
    pub filter: String,
    pub packets: String,
}

/// `capinfos -M` summary of a capture file (Wireshark: Capture File Properties).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CaptureProperties {
    pub file_name: String,
    pub file_type: String,
    pub encapsulation: String,
    pub file_size: u64,
    pub data_size: u64,
    pub packets: u64,
    pub duration: f64,
    pub first_packet: String,
    pub last_packet: String,
    pub bytes_per_sec: f64,
    pub bits_per_sec: f64,
    pub avg_packet_size: f64,
    pub avg_packets_per_sec: f64,
    pub strict_order: Option<bool>,
    pub application: String,
    pub hardware: String,
    pub os: String,
    pub comments: Vec<String>,
    pub interfaces: Vec<InterfaceInfo>,
}
