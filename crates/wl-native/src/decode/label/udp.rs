//! UDP datagrams: application protocol by port and payload, else the generic Info text.

use super::{Label, dns, udp_apps};
use crate::decode::transport::Udp;

pub fn label(u: &Udp) -> Label {
    let on = |port: u16| u.src == port || u.dst == port;
    let p = u.payload;
    let app = if on(5353) {
        dns::info(p, true).map(|i| Label::new("MDNS", i))
    } else if on(53) {
        dns::info(p, false).map(|i| Label::new("DNS", i))
    } else if on(67) || on(68) {
        udp_apps::dhcp(p)
    } else if on(123) {
        udp_apps::ntp(p)
    } else if on(1900) {
        udp_apps::ssdp(p)
    } else if on(443) {
        udp_apps::quic(p)
    } else {
        None
    };
    app.unwrap_or_else(|| {
        let len = usize::from(u.length).saturating_sub(8);
        Label::new("UDP", format!("{} \u{2192} {} Len={len}", u.src, u.dst))
    })
}
