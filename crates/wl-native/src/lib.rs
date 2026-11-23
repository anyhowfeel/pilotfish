//! Pure-Rust capture file backend: reads pcap and pcapng files, decodes the link, network and
//! transport layers, and serves the pages that only need packet rows (Overview, Hosts, Map,
//! packet list, I/O graphs, file properties) without Wireshark.
//!
//! It does not implement `CaptureBackend`. `wl-hybrid` decides per request whether this crate can
//! answer or whether tshark has to.

mod backend;
pub mod decode;
pub mod filter;
mod hash;
mod io_series;
mod properties;
pub mod reader;
mod session;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use backend::NativeBackend;
