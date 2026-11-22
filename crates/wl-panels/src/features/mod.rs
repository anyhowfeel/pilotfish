//! Feature panels and helpers:
//! - Follow TCP/UDP stream modal (`stream_view`)
//! - Plain-language Network Health insights + Expert Info + Protocol Hierarchy (`health`, `insights`)
//! - Display filter autocomplete (`autocomplete`)
//! - Keyboard-first command palette (`command_palette`)
//! - Click-to-filter on dissected detail nodes (`detail_filter`)
//! - Packet bookmarks & comments (`bookmarks`)

pub mod autocomplete;
mod autocomplete_catalog;
mod autocomplete_context;
mod autocomplete_names;
#[cfg(test)]
mod autocomplete_tests;
mod autocomplete_values;
mod behavior;
pub mod bookmarks;
mod bookmarks_json;
pub mod command_palette;
pub mod detail_filter;
pub mod health;
#[cfg(test)]
mod health_tests;
mod palette_items;
mod stream_text;
pub mod stream_view;

pub use crate::insights::{InsightsAction, InsightsPanel};
pub use autocomplete::{FieldCatalog, FilterAutocomplete, ValueIndex};
pub use autocomplete_names::NameBook;
pub use bookmarks::{BookmarkBarAction, BookmarkStore, bookmark_toolbar_ui};
pub use command_palette::{CommandPalette, PaletteAction, PalettePage};
pub use detail_filter::{
    FieldFilterCandidate, FilterCombine, build_expression, detail_filter_menu,
    extract_filter_candidate,
};
pub use health::synthesize_insights;
pub use stream_view::{StreamView, StreamViewAction};
