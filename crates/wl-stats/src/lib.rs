//! Incremental packet statistics: `PacketRow` stream -> `StatsSnapshot`.

mod diff;
mod edges;
mod engine;
mod flows;
mod hosts;
mod private;
mod protocols;
mod series;
mod server_port;
mod services;
mod top;

pub use diff::{CaptureData, CaptureDiff, Metric, Micros, Presence, Row, Traffic};
pub use engine::StatsEngine;
pub use private::is_private;
pub use series::TimeSeries;
pub use server_port::ServerPorts;
pub use services::service_name;
