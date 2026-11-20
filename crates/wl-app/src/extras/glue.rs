//! `App` side of the extras: panel actions in, background results out.

use eframe::egui;
use wl_model::DecodeAs;
use wl_panels::decode_as::DecodeAsAction;
use wl_panels::dns::DnsState;
use wl_panels::features::InsightsAction;
use wl_panels::packets::decode_target;
use wl_panels::web::ObjectsAction;

use super::Msg;
use crate::app::App;
use crate::dispatch::Command;
use crate::page::Page;

impl App {
    /// Forgets everything derived from the previous capture or dissection rules.
    pub(crate) fn reset_extras(&mut self) {
        self.extras.reset();
        self.web.objects_mut().invalidate();
        self.hub.insights.dns_mut().invalidate();
    }

    /// Selects `n` in Packets and switches to that page.
    fn show_frame(&mut self, n: u64, cmds: &mut Vec<Command>) {
        if self.packets.select_frame(n) {
            cmds.push(Command::Select(n));
        }
        self.page = Page::Packets;
    }

    /// Requests of the Web page's Files tab.
    pub(crate) fn objects_action(&mut self, a: ObjectsAction, cmds: &mut Vec<Command>) {
        let set = self.web.objects_mut().set().cloned();
        match a {
            ObjectsAction::Load(p) => match self.ctrl.backing() {
                Some(file) => self.extras.load_objects(file, p),
                None => self
                    .web
                    .objects_mut()
                    .set_result(&p, Err("Open a capture to list its files.".into())),
            },
            ObjectsAction::Preview(id) => {
                if let Some(set) = set {
                    self.extras.load_preview(set, id);
                }
            }
            ObjectsAction::Save(id) => {
                if let Some(set) = set
                    && let Some(o) = set.objects.get(id as usize).cloned()
                {
                    self.extras.save_one(set, o);
                }
            }
            ObjectsAction::SaveAll => {
                if let Some(set) = set {
                    self.extras.save_all(set);
                }
            }
            ObjectsAction::ShowInPackets(n) => self.show_frame(n, cmds),
        }
    }

    /// Insights actions that belong to the DNS tab; false for the others.
    pub(crate) fn dns_action(&mut self, a: &InsightsAction, cmds: &mut Vec<Command>) -> bool {
        match a {
            InsightsAction::LoadDns => {
                let dns = self.hub.insights.dns_mut();
                match self.ctrl.backing() {
                    Some(file) => {
                        dns.set_state(DnsState::Loading);
                        self.extras.load_dns(file);
                    }
                    None => {
                        dns.set_state(DnsState::Error("Open a capture to read its DNS.".into()))
                    }
                }
            }
            InsightsAction::ShowInPackets(n) => self.show_frame(*n, cmds),
            InsightsAction::Refresh => self.hub.insights.dns_mut().invalidate(),
            _ => return false,
        }
        true
    }

    /// Applies finished background jobs to the panels. Called every frame.
    pub(crate) fn pump_extras(&mut self) {
        for m in self.extras.poll() {
            match m {
                Msg::Objects(p, r) => self.web.objects_mut().set_result(&p, r),
                Msg::Preview(d) => self.web.objects_mut().set_preview(d),
                Msg::Dns(Ok(q)) => self.hub.insights.dns_mut().set_state(DnsState::Ready(q)),
                Msg::Dns(Err(e)) => self.hub.insights.dns_mut().set_state(DnsState::Error(e)),
                Msg::Protocols(f, Ok(list)) => self.extras.decode.set_protocols(&f, list),
                Msg::Protocols(f, Err(e)) => {
                    self.extras.decode.set_protocols(&f, Vec::new());
                    self.hub.error = Some(e);
                }
                Msg::Done(Ok(s)) if !s.is_empty() => self.hub.notice = Some(s),
                Msg::Done(Ok(_)) => {}
                Msg::Done(Err(e)) => self.hub.error = Some(e),
            }
        }
    }

    /// Opens Decode As, pre-filled from the selected packet when it has a TCP/UDP port.
    pub(crate) fn open_decode_as(&mut self) {
        let state = &self.packets.table.state;
        let target = state
            .selected_pos()
            .and_then(|p| state.row_at(p))
            .and_then(decode_target);
        match target {
            Some((field, port)) => self.extras.decode.open_for(field, port),
            None => self.extras.decode.open(),
        }
    }

    pub(crate) fn open_decode_as_for(&mut self, field: &str, port: u16) {
        self.extras.decode.open_for(field, port);
    }

    /// Draws the Decode As dialog and applies what it asks for.
    pub(crate) fn decode_as_ui(&mut self, ctx: &egui::Context) {
        if !self.extras.decode.is_open() {
            return;
        }
        let rules = self.extras.rules.clone();
        for a in self.extras.decode.ui(ctx, &rules) {
            match a {
                DecodeAsAction::Add(rule) => {
                    let mut next = rules.clone();
                    next.retain(|r| (&r.field, r.value) != (&rule.field, rule.value));
                    next.push(rule);
                    self.apply_decode_rules(next, ctx);
                }
                DecodeAsAction::Remove(i) if i < rules.len() => {
                    let mut next = rules.clone();
                    next.remove(i);
                    self.apply_decode_rules(next, ctx);
                }
                DecodeAsAction::Remove(_) => {}
                DecodeAsAction::LoadProtocols(f) => self.extras.load_protocols(f),
            }
        }
    }

    /// Activates `rules`, stores them in the preferences and dissects the capture again.
    pub(crate) fn apply_decode_rules(&mut self, rules: Vec<DecodeAs>, ctx: &egui::Context) {
        self.extras.set_rules(rules.clone());
        self.prefs.decode_as = rules;
        self.prefs.save();
        self.web_link.clear();
        self.web.objects_mut().invalidate();
        self.hub.insights.dns_mut().invalidate();
        if self.ctrl.backing().is_some() {
            let (page, filter) = (self.page, self.packets.filter_bar.text().to_owned());
            self.execute(Command::ApplyFilter(filter), ctx);
            self.page = page;
        }
    }
}
