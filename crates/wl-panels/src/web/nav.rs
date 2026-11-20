//! Web panel data refresh, selection, keyboard navigation and detail requests.
use super::*;

impl WebPanel {
    pub(super) fn refresh(&mut self, d: &WebData) {
        let key = (d.rev, self.filter.clone(), self.sort);
        if self.key.as_ref() == Some(&key) {
            return;
        }
        if self.key.as_ref().is_none_or(|k| k.0 != d.rev) {
            self.stats = aggregate(d.exchanges, d.tls);
        }
        let data = Data {
            ex: d.exchanges,
            tls: d.tls,
        };
        self.order = build(data, &self.filter, self.sort);
        self.key = Some(key);
    }

    pub(super) fn select(&mut self, i: usize, data: Data) {
        if let Some(r) = self.order.get(i) {
            self.selected = Some(sel_of(&data, *r));
            self.scroll_to = Some(i);
        }
    }

    /// Up/Down move the selection, Enter shows it in Packets, Esc clears it.
    pub(super) fn keyboard(&mut self, ui: &Ui, data: Data, out: &mut Vec<WebAction>) {
        if ui.memory(|m| m.focused().is_some()) || self.order.is_empty() {
            return;
        }
        let cur = self
            .selected
            .and_then(|s| self.order.iter().position(|r| sel_of(&data, *r) == s));
        let (down, up, enter, esc) = ui.input(|i| {
            (
                i.key_pressed(Key::ArrowDown),
                i.key_pressed(Key::ArrowUp),
                i.key_pressed(Key::Enter),
                i.key_pressed(Key::Escape),
            )
        });
        let last = self.order.len() - 1;
        if down {
            self.select(cur.map_or(0, |c| (c + 1).min(last)), data);
        } else if up {
            self.select(cur.map_or(0, |c| c.saturating_sub(1)), data);
        } else if esc {
            self.selected = None;
        } else if enter && let Some(f) = self.selected.and_then(|s| frame_of(&data, s)) {
            out.push(WebAction::ShowInPackets(f));
        }
    }

    /// Requests the detail when the selected HTTP row changed; caches pretty bodies once loaded.
    pub(super) fn sync_detail(&mut self, d: &WebData, out: &mut Vec<WebAction>) {
        let Some(sel @ Sel::Http(id)) = self.selected else {
            self.requested = None;
            return;
        };
        if self.requested != Some(sel) {
            self.requested = Some(sel);
            self.shown_for = None;
            if let Some(e) = d.exchanges.iter().find(|e| e.id == id) {
                out.push(WebAction::LoadDetail(e.clone()));
            }
        }
        if self.shown_for != Some(sel)
            && let Some(det) = d.detail
        {
            let pretty = |m: &Option<wl_model::HttpMessage>| {
                m.as_ref()
                    .and_then(|m| m.body_preview.as_deref())
                    .map(body::display_text)
            };
            self.shown = [pretty(&det.request), pretty(&det.response)];
            self.shown_for = Some(sel);
        }
    }
}
