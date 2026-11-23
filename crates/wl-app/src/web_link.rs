//! Glue between the controller and the Web page: polling, detail requests, demo feed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use wl_model::{HttpDetail, HttpExchange, MessageStream, ThreatIntel, TlsSession, Wireshark};
use wl_panels::web::{
    KeysInfo, WebAction, WebData, WebStatus, demo_data, demo_detail, demo_streams,
};

use crate::app::App;
use crate::dispatch::Command;
use crate::page::Page;
use crate::worker::Controller;

/// Minimum time between two refreshes of a growing capture while the page is open.
const REFRESH_EVERY: Duration = Duration::from_millis(1500);

/// What the Web page needs from the capture controller.
pub trait WebBackend {
    fn request_web(&mut self);
    fn poll_web(&mut self) -> Option<(Vec<HttpExchange>, Vec<TlsSession>, Vec<MessageStream>)>;
    fn request_http_detail(&mut self, ex: &HttpExchange);
    fn poll_http_detail(&mut self) -> Option<HttpDetail>;
    fn set_web_active(&mut self, active: bool);
    /// Packets seen so far (progress key: refresh when it changes).
    fn packets(&self) -> u64;
    fn ready(&self) -> bool;
}

pub struct WebLink {
    exchanges: Vec<HttpExchange>,
    tls: Vec<TlsSession>,
    streams: Vec<MessageStream>,
    detail: Option<HttpDetail>,
    rev: u64,
    demo: bool,
    loading: bool,
    was_active: bool,
    last_packets: u64,
    last_request: Option<Instant>,
    unavailable: bool,
    intel: Arc<ThreatIntel>,
}

impl WebLink {
    pub fn new(demo: bool) -> Self {
        let (exchanges, tls) = if demo {
            demo_data()
        } else {
            (Vec::new(), Vec::new())
        };
        Self {
            exchanges,
            tls,
            streams: if demo { demo_streams() } else { Vec::new() },
            detail: None,
            rev: 1,
            demo,
            loading: false,
            was_active: false,
            last_packets: 0,
            last_request: None,
            unavailable: false,
            intel: Arc::default(),
        }
    }

    /// Marks the TLS sessions with the offline lists, now and for every later scan.
    pub fn set_intel(&mut self, intel: Arc<ThreatIntel>) {
        self.intel = intel;
        self.intel.annotate_tls(&mut self.tls);
        self.rev += 1;
    }

    pub fn data<'a>(&'a self, keys: &'a KeysInfo, wireshark: Wireshark) -> WebData<'a> {
        let status = if self.unavailable {
            WebStatus::Error("Web analysis is not available in this build.")
        } else if self.loading && self.exchanges.is_empty() && self.tls.is_empty() {
            WebStatus::Loading
        } else {
            WebStatus::Ready
        };
        WebData {
            rev: self.rev,
            exchanges: &self.exchanges,
            tls: &self.tls,
            streams: &self.streams,
            detail: self.detail.as_ref(),
            status,
            keys,
            wireshark,
        }
    }

    fn request(&mut self, b: &mut impl WebBackend) {
        b.request_web();
        self.loading = true;
        self.last_packets = b.packets();
        self.last_request = Some(Instant::now());
    }

    fn clear_data(&mut self) {
        self.exchanges.clear();
        self.tls.clear();
        self.streams.clear();
        self.detail = None;
        self.rev += 1;
    }

    pub fn clear(&mut self) {
        if self.demo {
            return;
        }
        self.clear_data();
        self.loading = false;
        self.last_packets = 0;
        self.last_request = None;
    }

    /// Call every frame; true when new data arrived (repaint).
    pub fn tick(&mut self, b: &mut impl WebBackend, active: bool) -> bool {
        if self.demo {
            return false;
        }
        self.unavailable = !b.ready();
        if active != self.was_active {
            self.was_active = active;
            b.set_web_active(active);
            if active && !self.unavailable && b.packets() > 0 {
                self.request(b);
            }
        }
        if !active || self.unavailable {
            return false;
        }
        let packets = b.packets();
        if packets == 0 && (!self.exchanges.is_empty() || !self.tls.is_empty()) {
            self.clear_data();
        }
        let stale = self
            .last_request
            .is_none_or(|t| t.elapsed() > REFRESH_EVERY);
        if packets != self.last_packets && packets > 0 && stale {
            self.request(b);
        }
        let mut changed = false;
        if let Some((ex, tls, streams)) = b.poll_web() {
            self.exchanges = ex;
            self.tls = tls;
            self.intel.annotate_tls(&mut self.tls);
            self.streams = streams;
            self.rev += 1;
            self.loading = false;
            changed = true;
        }
        if let Some(d) = b.poll_http_detail() {
            self.detail = Some(d);
            changed = true;
        }
        changed
    }

    /// Drops the previous detail and asks for the one of `ex`.
    pub fn request_detail(&mut self, b: &mut impl WebBackend, ex: &HttpExchange) {
        self.detail = None;
        if self.demo {
            self.detail = Some(demo_detail(ex));
        } else {
            b.request_http_detail(ex);
        }
    }
}

impl App {
    /// Executes what the Web page asked for.
    pub(crate) fn web_action(
        &mut self,
        a: WebAction,
        cmds: &mut Vec<Command>,
        ctx: &egui::Context,
    ) {
        match a {
            WebAction::LoadDetail(ex) => self.web_link.request_detail(&mut self.ctrl, &ex),
            WebAction::ShowInPackets(n) => {
                if self.packets.select_frame(n) {
                    cmds.push(Command::Select(n));
                }
                self.page = Page::Packets;
            }
            WebAction::Objects(a) => self.objects_action(a, cmds),
            WebAction::ApplyFilter(f) => {
                cmds.push(Command::ApplyFilter(f));
                self.page = Page::Packets;
            }
            keys @ (WebAction::PickKeylog | WebAction::ClearKeylog | WebAction::EmbedKeys) => {
                self.keys_action(keys, ctx);
            }
        }
    }
}

impl WebBackend for Controller {
    fn request_web(&mut self) {
        Controller::request_web(self);
    }
    fn poll_web(&mut self) -> Option<(Vec<HttpExchange>, Vec<TlsSession>, Vec<MessageStream>)> {
        Controller::poll_web(self)
    }
    fn request_http_detail(&mut self, ex: &HttpExchange) {
        Controller::request_http_detail(self, ex);
    }
    fn poll_http_detail(&mut self) -> Option<HttpDetail> {
        Controller::poll_http_detail(self)
    }
    fn set_web_active(&mut self, active: bool) {
        Controller::set_web_active(self, active);
    }
    fn packets(&self) -> u64 {
        self.status().packets
    }
    fn ready(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[path = "web_link_tests.rs"]
mod tests;
