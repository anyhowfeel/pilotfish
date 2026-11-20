//! The flow graph body: sticky host header over a virtualised, scrolling list of arrows.

use wl_kit::egui::{
    self, Key, Label, RichText, ScrollArea, Sense, Ui, pos2, scroll_area::ScrollBarVisibility, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, mono, spacing};
use wl_model::{FlowEvent, FlowEvents};

use super::actions::FlowsAction;
use super::geom::{self, HEAD_H, ROW_H};
use super::lanes::{self, Lanes};
use super::marks::{self, Mark};
use super::{paint, virt};

#[derive(Default)]
pub struct FlowGraph {
    rev: Option<u64>,
    lanes: Lanes,
    marks: Vec<Mark>,
    counts: Vec<(Mark, usize)>,
    selected: Option<usize>,
    pending_frame: Option<u64>,
    reveal: Option<usize>,
    menu_row: Option<usize>,
    offset: f32,
    view_h: f32,
}

impl FlowGraph {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Selects the event of this frame as soon as the events are known (screenshots, links).
    pub fn select_frame(&mut self, frame: u64) {
        self.pending_frame = Some(frame);
    }

    pub fn selected_frame(&self, ev: &FlowEvents) -> Option<u64> {
        self.selected
            .and_then(|i| ev.events.get(i))
            .map(|e| e.frame)
    }

    pub fn lanes(&self) -> &Lanes {
        &self.lanes
    }

    pub fn counts(&self) -> &[(Mark, usize)] {
        &self.counts
    }

    fn sync(&mut self, rev: u64, ev: &FlowEvents) {
        if self.rev != Some(rev) {
            self.rev = Some(rev);
            self.lanes = lanes::build(&ev.events);
            self.marks = marks::classify(&ev.events);
            self.counts = marks::counts(&self.marks);
            self.selected = None;
        }
        if let Some(f) = self.pending_frame.take() {
            self.selected = ev.events.iter().position(|e| e.frame == f);
            self.reveal = self.selected;
        }
    }

    fn keyboard(&mut self, ui: &Ui, n: usize, out: &mut Vec<FlowsAction>, ev: &FlowEvents) {
        if n == 0 || ui.memory(|m| m.focused().is_some()) {
            return;
        }
        let page = ((self.view_h / ROW_H) as usize).max(1);
        let (dy, home, end, enter) = ui.input(|i| {
            let k = |key| i.key_pressed(key);
            let dy = match () {
                _ if k(Key::ArrowDown) => 1isize,
                _ if k(Key::ArrowUp) => -1,
                _ if k(Key::PageDown) => page as isize,
                _ if k(Key::PageUp) => -(page as isize),
                _ => 0,
            };
            (dy, k(Key::Home), k(Key::End), k(Key::Enter))
        });
        let cur = self.selected;
        let next = match (dy, home, end) {
            (_, true, _) => Some(0),
            (_, _, true) => Some(n - 1),
            (0, _, _) => None,
            (d, _, _) => Some(cur.map_or(0, |c| c.saturating_add_signed(d).min(n - 1))),
        };
        if let Some(i) = next {
            self.selected = Some(i);
            self.reveal = Some(i);
        }
        if enter && let Some(f) = self.selected_frame(ev) {
            out.push(FlowsAction::ShowInPackets(f));
        }
    }

    pub fn ui(&mut self, ui: &mut Ui, ev: &FlowEvents, rev: u64, out: &mut Vec<FlowsAction>) {
        self.sync(rev, ev);
        self.keyboard(ui, ev.events.len(), out, ev);
        let bar = ui.spacing().scroll.allocated_width();
        let (avail_w, avail_h) = (ui.available_width(), ui.available_height());
        let cols = geom::cols(avail_w - bar, self.lanes.hosts.len());
        ScrollArea::horizontal()
            .id_salt("flow_h")
            .auto_shrink([false, false])
            .scroll_bar_visibility(ScrollBarVisibility::VisibleWhenNeeded)
            .show(ui, |ui| {
                ui.set_width(cols.width + bar);
                let (head, _) = ui.allocate_exact_size(vec2(cols.width, HEAD_H), Sense::hover());
                paint::header(ui.painter(), head.min, &cols, &self.lanes);
                ui.add_space(spacing::XS);
                let body_h = (avail_h - HEAD_H - spacing::XS - bar).max(ROW_H);
                self.rows(ui, ev, &cols, body_h, out);
            });
    }

    fn rows(
        &mut self,
        ui: &mut Ui,
        ev: &FlowEvents,
        cols: &geom::Cols,
        h: f32,
        out: &mut Vec<FlowsAction>,
    ) {
        let n = ev.events.len();
        let mut area = ScrollArea::vertical()
            .id_salt("flow_v")
            .max_height(h)
            .auto_shrink([false, false]);
        let view_h = if self.view_h > 0.0 { self.view_h } else { h };
        if let Some(i) = self.reveal.take()
            && let Some(off) = virt::reveal(i, self.offset, view_h, ROW_H)
        {
            area = area.vertical_scroll_offset(off);
        }
        let shown = area.show_viewport(ui, |ui, viewport| {
            let (rect, resp) =
                ui.allocate_exact_size(vec2(cols.width, n as f32 * ROW_H), Sense::click());
            let p = ui.painter().clone();
            let hover = resp
                .hover_pos()
                .and_then(|pos| virt::row_at(pos.y - rect.top(), ROW_H, n));
            let range = virt::visible_range(viewport.min.y, viewport.height(), ROW_H, n);
            let top = |i: usize| pos2(rect.left(), rect.top() + i as f32 * ROW_H);
            let (y0, y1) = (viewport.min.y + rect.top(), viewport.max.y + rect.top());
            paint::lifelines(&p, rect.left(), y0, y1, cols, self.lanes.hosts.len());
            for i in range {
                let st = paint::RowState {
                    selected: self.selected == Some(i),
                    hovered: hover == Some(i),
                };
                let lane = (
                    usize::from(self.lanes.from[i]),
                    usize::from(self.lanes.to[i]),
                );
                paint::row(&p, top(i), cols, &ev.events[i], lane, self.marks[i], st);
            }
            self.interact(&resp, rect.top(), n, ev, out);
            if let Some(i) = hover {
                let e = &ev.events[i];
                resp.on_hover_ui_at_pointer(|ui| tooltip(ui, e));
            }
        });
        self.offset = shown.state.clamped_offset().y;
        self.view_h = shown.inner_rect.height();
    }

    fn interact(
        &mut self,
        resp: &egui::Response,
        top: f32,
        n: usize,
        ev: &FlowEvents,
        out: &mut Vec<FlowsAction>,
    ) {
        let row_of = |pos: egui::Pos2| virt::row_at(pos.y - top, ROW_H, n);
        if resp.clicked() || resp.secondary_clicked() {
            self.selected = resp
                .interact_pointer_pos()
                .and_then(row_of)
                .or(self.selected);
            self.menu_row = if resp.secondary_clicked() {
                self.selected
            } else {
                None
            };
        }
        if resp.double_clicked()
            && let Some(f) = self.selected_frame(ev)
        {
            out.push(FlowsAction::ShowInPackets(f));
        }
        resp.context_menu(|ui| {
            let Some(e) = self.menu_row.and_then(|i| ev.events.get(i)) else {
                ui.close();
                return;
            };
            if ui.button("Show in Packets").clicked() {
                out.push(FlowsAction::ShowInPackets(e.frame));
                ui.close();
            }
            if ui.button("Copy label").clicked() {
                ui.ctx().copy_text(e.label.to_string());
                ui.close();
            }
        });
    }
}

fn endpoint(addr: &str, port: Option<u16>) -> String {
    match port {
        Some(p) if addr.contains(':') => format!("[{addr}]:{p}"),
        Some(p) => format!("{addr}:{p}"),
        None => addr.to_owned(),
    }
}

fn tooltip(ui: &mut Ui, e: &FlowEvent) {
    ui.set_max_width(420.0);
    let head = format!("#{}   {} s", e.frame, format::time_rel(e.rel));
    ui.label(mono(head).color(Palette::muted()));
    let path = format!(
        "{}  ->  {}",
        endpoint(&e.src, e.src_port),
        endpoint(&e.dst, e.dst_port)
    );
    ui.label(RichText::new(path).strong());
    ui.add(Label::new(format!("{}  {}", e.protocol, e.label)).wrap());
    ui.label(mono(paint::note(e)).color(Palette::muted()));
}
