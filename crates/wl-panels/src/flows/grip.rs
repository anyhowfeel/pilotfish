//! Drag handle between the conversation list and the detail pane.
use wl_kit::egui::{CursorIcon, Rect, Sense, Stroke, Ui, pos2};
use wl_kit::theme::{Palette, spacing};

/// Interacts with the gap right of `list` (the layout spacing); returns the new list width while
/// it is being dragged.
pub fn list_grip(ui: &mut Ui, list: Rect, width: f32, avail: f32, min: f32) -> Option<f32> {
    let grip = Rect::from_min_max(
        pos2(list.right(), list.top()),
        pos2(list.right() + spacing::LG, list.bottom()),
    );
    let resp = ui
        .interact(grip, ui.scope_id().with("flows_grip"), Sense::drag())
        .on_hover_cursor(CursorIcon::ResizeHorizontal);
    if resp.hovered() || resp.dragged() {
        let x = grip.center().x;
        ui.painter().line_segment(
            [pos2(x, grip.top() + 8.0), pos2(x, grip.bottom() - 8.0)],
            Stroke::new(2.0, Palette::accent()),
        );
    }
    resp.dragged()
        .then(|| (width + resp.drag_delta().x).clamp(min, (avail * 0.6).max(min)))
}
