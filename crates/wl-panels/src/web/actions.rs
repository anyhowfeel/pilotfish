//! Panel input (`WebData`) and output (`WebAction`).

use wl_model::{HttpDetail, HttpExchange, MessageStream, TlsSession, Wireshark};

/// What the panel asks the app to do.
#[derive(Debug, Clone, PartialEq)]
pub enum WebAction {
    /// Fetch headers/body of this exchange (answered through `WebData::detail`).
    LoadDetail(HttpExchange),
    /// Select this frame in Packets and switch to that page.
    ShowInPackets(u64),
    ApplyFilter(String),
    /// Request of the Files tab (extraction, preview, save).
    Objects(super::ObjectsAction),
    PickKeylog,
    ClearKeylog,
    /// Save a copy of the capture with the key log embedded.
    EmbedKeys,
}

/// State of the TLS key log, shown above the tabs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeysInfo {
    /// File name of the active key log, if any.
    pub file: Option<String>,
    pub can_embed: bool,
}

/// Loading state of the exchange list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WebStatus<'a> {
    #[default]
    Ready,
    Loading,
    Error(&'a str),
}

/// Everything the panel needs for one frame.
#[derive(Clone, Copy)]
pub struct WebData<'a> {
    /// Bumped by the owner whenever `exchanges` / `tls` change (cheap change detection).
    pub rev: u64,
    pub exchanges: &'a [HttpExchange],
    pub tls: &'a [TlsSession],
    pub streams: &'a [MessageStream],
    /// Detail of the currently selected exchange, once loaded.
    pub detail: Option<&'a HttpDetail>,
    pub status: WebStatus<'a>,
    pub keys: &'a KeysInfo,
    pub wireshark: Wireshark,
}
