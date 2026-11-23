//! Panels. `packets` (list/detail/hex/filter) and `overview` (dashboard/hosts/flows/setup) are owned by different agents.
pub mod capture_form;
pub mod decode_as;
pub mod diff;
pub mod dns;
pub mod features;
pub mod flows;
pub mod graphs;
pub mod insights;
mod needs;
pub mod overview;
pub mod packets;
pub mod properties;
pub mod settings;
pub mod topology;
pub mod web;

#[cfg(test)]
mod test_util;
