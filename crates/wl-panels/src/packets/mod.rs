//! Packet inspection panels (list, filter bar, dissection tree, hex view).
//! Pure logic lives in `*_state` / `*_model` / `filter_*` files; drawing files stay thin.

mod actions;
mod column_set;
mod columns;
mod columns_menu;
mod context_menu;
mod custom_cols;
mod demo;
mod detail_row;
mod detail_tree;
mod filter_bar;
mod filter_expr;
mod filter_history;
pub mod filter_presets;
mod find_bar;
mod find_local;
mod find_query;
mod find_state;
mod hex_model;
mod hex_view;
mod http_row;
mod kit;
#[cfg(test)]
mod layout_tests;
mod order;
mod presets_menu;
mod quick_bar;
pub(crate) mod quick_filter;
pub(crate) mod split;
mod table;
mod table_cells;
mod table_follow;
mod table_state;
#[cfg(test)]
mod table_state_tests;
mod table_toolbar;
mod time_format;
mod tree_menu;
mod tree_model;
mod view;

pub use actions::PacketsAction;
pub use column_set::{ColumnSet, TablePrefs};
pub use columns::Col;
pub use context_menu::decode_target;
pub use detail_tree::DetailTree;
pub use filter_bar::{FilterBar, FilterStatus};
pub use filter_presets::SavedFilter;
pub use hex_view::HexView;
pub use split::Layout;
pub use table::PacketTable;
pub use time_format::TimeFormat;
pub use view::PacketsView;
