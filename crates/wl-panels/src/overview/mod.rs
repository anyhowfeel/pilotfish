//! Overview panels: dashboard, hosts, conversations and capture setup.
//! All panels are plain structs: `ui(&mut self, ui, data) -> Vec<OverviewAction>`; no I/O besides
//! the file dialog opened by `CaptureSetup`.

mod actions;
mod activity;
mod cards;
mod conversations;
pub(crate) mod conversations_sort;
mod dashboard;
mod dashboard_data;
mod endpoint_cell;
mod grid;
mod hosts;
mod hosts_sort;
mod iface_class;
mod interface_card;
mod recent;
mod recent_ui;
mod resolver;
mod services;
mod setup;
mod setup_actions;
mod setup_bar;
mod setup_interfaces;
mod setup_logic;
mod sort;
mod table_cells;
mod window_scope;

#[cfg(test)]
mod harness;
#[cfg(test)]
mod iface_class_tests;
#[cfg(test)]
mod layout_tests;
#[cfg(test)]
mod setup_tests;

pub use actions::OverviewAction;
pub use activity::{Activity, ActivityMap};
pub use conversations::ConversationsPanel;
pub use dashboard::Dashboard;
pub use hosts::HostsPanel;
pub use resolver::{GeoInfo, NameResolver, NoNames, StreamLookup, process_lines};
pub use setup::{CaptureSetup, SetupData};
pub use setup_bar::FilterStatus;
pub(crate) use sort::SortState;
pub(crate) use table_cells::{filter_box, sort_header};
