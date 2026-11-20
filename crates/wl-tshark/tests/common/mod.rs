//! Helpers shared by the tshark integration tests (they skip when the tools are missing).
#![allow(dead_code)]
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use wl_model::{CaptureError, CaptureEvent, PacketRow, Session};
use wl_tshark::TsharkBackend;

pub fn backend() -> Option<TsharkBackend> {
    TsharkBackend::new().ok()
}

pub fn send_udp(port: u16, n: usize) {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    for i in 0..n {
        let _ = s.send_to(format!("hello {i}").as_bytes(), ("127.0.0.1", port));
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub fn collect(session: &Session) -> (Vec<PacketRow>, Option<CaptureError>) {
    let mut rows = Vec::new();
    let end = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end {
        match session.events.recv_timeout(Duration::from_millis(200)) {
            Ok(CaptureEvent::Rows(r)) => rows.extend(r),
            Ok(CaptureEvent::Finished) => return (rows, None),
            Ok(CaptureEvent::Failed(e)) => return (rows, Some(e)),
            Err(_) => {}
        }
    }
    (rows, Some(CaptureError::Other("timeout".into())))
}
