use serde::{Deserialize, Serialize};

/// A node of the dissection tree (layer -> field -> sub-field).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DetailNode {
    /// Human text, e.g. "Source Port: 443".
    pub label: String,
    /// Byte range `(start, end_exclusive)` inside `FrameDetail::bytes`, for hex highlight.
    pub range: Option<(usize, usize)>,
    pub children: Vec<DetailNode>,
}

/// Everything needed by the detail + hex panes for one frame.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct FrameDetail {
    pub frame_no: u64,
    pub layers: Vec<DetailNode>,
    pub bytes: Vec<u8>,
}
