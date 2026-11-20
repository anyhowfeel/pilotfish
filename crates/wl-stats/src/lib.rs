//! Incremental packet statistics: `PacketRow` stream -> `StatsSnapshot`.

mod edges;
mod engine;
mod flows;
mod hosts;
mod private;
mod protocols;
mod series;
mod services;
mod top;

pub use engine::StatsEngine;
pub use private::is_private;
pub use series::TimeSeries;
pub use services::service_name;
