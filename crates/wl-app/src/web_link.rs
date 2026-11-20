//! Glue between the controller and the Web page: polling, detail requests, demo feed.

use std::time::{Duration, Instant};

use wl_model::{HttpDetail, HttpExchange, TlsSession};
use wl_panels::web::{WebAction, WebData, WebStatus, demo_data, demo_detail};

use crate::app::App;
use crate::dispatch::Command;
use crate::page::Page;
use crate::worker::Controller;

/// Minimum time between two refreshes of a growing capture while the page is open.
const REFRESH_EVERY: Duration = Duration::from_millis(1500);

/// What the Web page needs from the capture controller.
pub trait WebBackend {
    fn request_web(&mut self);
    fn poll_web(&mut self) -> Option<(Vec<HttpExchange>, Vec<TlsSession>)>;
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
    detail: Option<HttpDetail>,
    rev: u64,
    demo: bool,
    loading: bool,
    was_active: bool,
    last_packets: u64,
    last_request: Option<Instant>,
    unavailable: bool,
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
            detail: None,
            rev: 1,
            demo,
            loading: false,
            was_active: false,
            last_packets: 0,
            last_request: None,
            unavailable: false,
        }
    }

    pub fn data(&self) -> WebData<'_> {
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
            detail: self.detail.as_ref(),
            status,
        }
    }

    fn request(&mut self, b: &mut impl WebBackend) {
        b.request_web();
        self.loading = true;
        self.last_packets = b.packets();
        self.last_request = Some(Instant::now());
    }

    pub fn clear(&mut self) {
        if self.demo {
            return;
        }
        self.exchanges.clear();
        self.tls.clear();
        self.detail = None;
        self.rev += 1;
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
            self.exchanges.clear();
            self.tls.clear();
            self.detail = None;
            self.rev += 1;
        }
        let stale = self
            .last_request
            .is_none_or(|t| t.elapsed() > REFRESH_EVERY);
        if packets != self.last_packets && packets > 0 && stale {
            self.request(b);
        }
        let mut changed = false;
        if let Some((ex, tls)) = b.poll_web() {
            self.exchanges = ex;
            self.tls = tls;
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
    pub(crate) fn web_action(&mut self, a: WebAction, cmds: &mut Vec<Command>) {
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
        }
    }
}

impl WebBackend for Controller {
    fn request_web(&mut self) {
        Controller::request_web(self);
    }
    fn poll_web(&mut self) -> Option<(Vec<HttpExchange>, Vec<TlsSession>)> {
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
