//! Tests for the Web page glue (fake backend).
use super::*;
use wl_panels::web::KeysInfo;

#[derive(Default)]
struct Fake {
    packets: u64,
    reply: Option<(Vec<HttpExchange>, Vec<TlsSession>, Vec<MessageStream>)>,
    requests: u32,
    active: Vec<bool>,
}

impl WebBackend for Fake {
    fn request_web(&mut self) {
        self.requests += 1;
    }
    fn poll_web(&mut self) -> Option<(Vec<HttpExchange>, Vec<TlsSession>, Vec<MessageStream>)> {
        self.reply.take()
    }
    fn request_http_detail(&mut self, _: &HttpExchange) {}
    fn poll_http_detail(&mut self) -> Option<HttpDetail> {
        None
    }
    fn set_web_active(&mut self, a: bool) {
        self.active.push(a);
    }
    fn packets(&self) -> u64 {
        self.packets
    }
    fn ready(&self) -> bool {
        true
    }
}

#[test]
fn requests_on_activation_and_loads_reply() {
    let mut link = WebLink::new(false);
    let mut fake = Fake {
        packets: 10,
        ..Default::default()
    };
    assert!(!link.tick(&mut fake, false));
    link.tick(&mut fake, true);
    assert_eq!((fake.requests, fake.active.clone()), (1, vec![true]));
    assert!(matches!(
        link.data(&KeysInfo::default()).status,
        WebStatus::Loading
    ));
    let (ex, tls) = demo_data();
    fake.reply = Some((ex, tls, Vec::new()));
    assert!(link.tick(&mut fake, true));
    assert_eq!(link.data(&KeysInfo::default()).exchanges.len(), 40);
    assert!(matches!(
        link.data(&KeysInfo::default()).status,
        WebStatus::Ready
    ));
}

#[test]
fn demo_feeds_without_backend() {
    let link = WebLink::new(true);
    assert_eq!(link.data(&KeysInfo::default()).tls.len(), 10);
}
