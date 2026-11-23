//! The states of an analysis that has no result to show: not run, running, failed.

use wl_kit::egui::Ui;
use wl_kit::widgets::empty_state;
use wl_model::Analysis;

/// Shows the state when there is no result and returns the result when there is one.
pub fn ready_or_explain<'a, T>(
    ui: &mut Ui,
    what: &str,
    analysis: &'a Analysis<T>,
) -> Option<&'a T> {
    match analysis {
        Analysis::Ready(data) => return Some(data),
        Analysis::Idle => empty_state(
            ui,
            "i",
            &format!("{what} not loaded"),
            "Use Re-analyse to run it.",
        ),
        Analysis::Pending => empty_state(
            ui,
            "i",
            &format!("Analysing {}", what.to_lowercase()),
            "The result appears when it finishes.",
        ),
        Analysis::Failed(reason) => empty_state(
            ui,
            "!",
            &format!("{what} failed"),
            &format!(
                "{}. Use Re-analyse to try again.",
                reason.trim_end_matches('.')
            ),
        ),
    }
    None
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
