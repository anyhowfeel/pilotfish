//! Panel input (`WebData`) and output (`WebAction`).

use wl_model::{HttpDetail, HttpExchange, TlsSession};

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
    /// Detail of the currently selected exchange, once loaded.
    pub detail: Option<&'a HttpDetail>,
    pub status: WebStatus<'a>,
}
