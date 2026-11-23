//! Pointer and keyboard handling of the canvas (pan, zoom, drag, select, shortcuts).

use wl_kit::egui::{self, CursorIcon, Rect, Response, Ui};

use super::frame::Drag;
use super::model::Filters;
use super::state::{Resolved, Selection};
use super::{TopologyView, controls, hit};

impl TopologyView {
    pub(super) fn input(&mut self, ui: &Ui, resp: &Response, rect: Rect, hover: Resolved) {
        let g = &self.graph;
        if resp.drag_started() {
            let at = ui.input(|i| i.pointer.press_origin());
            self.drag = Some(
                match at.and_then(|p| hit::node_at(&self.buf.discs, p, 3.0)) {
                    Some(i) => Drag::Node(i),
                    None => Drag::Pan,
                },
            );
        }
        if resp.dragged() {
            match (self.drag, resp.interact_pointer_pos()) {
                (Some(Drag::Node(i)), Some(p)) => self.layout.drag(i, self.vp.to_world(rect, p), g),
                (Some(Drag::Pan), _) => {
                    self.vp.pan_by_screen(resp.drag_delta());
                    self.auto_fit = false;
                }
                _ => {}
            }
            ui.ctx().set_cursor_icon(CursorIcon::Grabbing);
        } else if hover != Resolved::None {
            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
        }
        if resp.drag_stopped() {
            self.drag = None;
        }
        if resp.double_clicked() {
            match hover {
                Resolved::Node(i) => self.layout.unpin(i, g),
                _ => self.auto_fit = true,
            }
        } else if resp.clicked() {
            self.sel = match hover {
                Resolved::Node(i) => Selection::Node(g.nodes[i].addr.clone()),
                Resolved::Link(l) => Selection::of_link(g, l),
                Resolved::None => Selection::None,
            };
        }
        let (scroll, zoom) = ui.input(|i| (i.smooth_scroll_delta.y, i.zoom_delta()));
        let factor = zoom * (scroll * 0.0015).exp();
        if let (true, Some(p)) = (
            resp.hovered() && (factor - 1.0).abs() > 1e-4,
            resp.hover_pos(),
        ) {
            self.vp.zoom_at(rect, p, factor);
            self.auto_fit = false;
        }
        self.keys(ui, rect);
    }

    fn keys(&mut self, ui: &Ui, rect: Rect) {
        use egui::Key;
        let ctx = ui.ctx();
        let (esc, plus, minus, zero, reset) = ctx.input(|i| {
            let free = !i.modifiers.command;
            (
                i.key_pressed(Key::Escape),
                free && (i.key_pressed(Key::Plus) || i.key_pressed(Key::Equals)),
                free && i.key_pressed(Key::Minus),
                free && i.key_pressed(Key::Num0),
                free && i.key_pressed(Key::R),
            )
        });
        if esc {
            self.sel = Selection::None;
            self.search.clear();
        }
        if ctx.egui_wants_keyboard_input() {
            return;
        }
        let step = controls::ZOOM_STEP;
        if plus || minus {
            self.vp
                .zoom_at(rect, rect.center(), if plus { step } else { 1.0 / step });
            self.auto_fit = false;
        }
        if zero {
            self.auto_fit = true;
        }
        if reset {
            self.reset_view();
        }
    }

    /// Back to the starting view: fitted, every host free, nothing selected, searched or filtered. The
    /// layout mode and the display switches (labels, directions, encrypted) are preferences and stay.
    pub(super) fn reset_view(&mut self) {
        self.sel = Selection::None;
        self.search.clear();
        self.drag = None;
        self.opts.filters = Filters::default();
        self.layout.forget();
        // The graph is built again with the default filters, and laid out from scratch.
        self.key = None;
        self.auto_fit = true;
    }

    pub(super) fn apply(&mut self, cmd: controls::Cmd, rect: Rect) {
        if let Some(f) = cmd.zoom {
            self.vp.zoom_at(rect, rect.center(), f);
            self.auto_fit = false;
        }
        self.auto_fit |= cmd.fit;
        if cmd.reset {
            self.reset_view();
        }
        if cmd.search_enter
            && let Some(&i) = self.buf.matches.first()
        {
            self.sel = Selection::Node(self.graph.nodes[i].addr.clone());
            self.vp.center = self.layout.pos[i];
            self.vp.zoom = self.vp.zoom.max(1.0);
            self.auto_fit = false;
        }
        if self.opts.mode != self.layout.mode() {
            self.layout.set_mode(self.opts.mode, &self.graph);
            self.auto_fit = true;
        }
    }
}
