//! Web page API of the `Controller` (HTTP exchanges, TLS sessions, exchange detail).
//! Child module of `worker` so it can reach the controller's private state.

use std::time::Instant;

use wl_model::{HttpDetail, HttpExchange, MessageStream, TlsSession};

use super::Controller;

impl Controller {
    /// Scans the current backing file for HTTP exchanges and TLS sessions on helper threads.
    /// Automatic refreshes (new capture, live ticks) only run while `set_web_active(true)`.
    pub fn request_web(&mut self) {
        let (backing, scope) = (self.backing(), self.display_filter().map(str::to_owned));
        self.web.request_now(backing, scope, Instant::now());
    }

    /// Finished scan, once per result: `(exchanges, tls sessions)`.
    pub fn poll_web(&mut self) -> Option<(Vec<HttpExchange>, Vec<TlsSession>, Vec<MessageStream>)> {
        self.poll_web_jobs();
        self.web.jobs.take_web()
    }

    /// Loads headers/body of one exchange; the latest request wins.
    pub fn request_http_detail(&mut self, ex: &HttpExchange) {
        if let Some(file) = self.backing() {
            self.web.jobs.request_detail(file, ex.clone());
        }
    }

    pub fn poll_http_detail(&mut self) -> Option<HttpDetail> {
        self.poll_web_jobs();
        self.web.jobs.take_detail()
    }

    /// Tell the controller whether the Web page is visible: live captures are re-scanned about
    /// every 3 s while it is.
    pub fn set_web_active(&mut self, active: bool) {
        let live = self.live_running();
        self.web.set_active(active, live);
    }

    /// A live capture still writing its backing file.
    fn live_running(&self) -> bool {
        self.is_live() && self.session.is_some()
    }

    /// Drains finished web jobs and starts a due refresh. Web errors of a live capture (file still
    /// empty or being written) are expected and ignored, and so is a missing Wireshark: the page
    /// says so itself.
    pub(super) fn poll_web_jobs(&mut self) {
        let (live, backing) = (self.live_running(), self.backing());
        let scope = self.display_filter().map(str::to_owned);
        self.web.tick(backing, scope, live, Instant::now());
        if let Some(e) = self.web.jobs.drain()
            && !live
            && !e.is_tool_missing()
        {
            self.error = Some(e);
        }
    }
}
