//! Application state machine: owns the controller, panels, and `FeaturesHub`, pumps events.
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use crossbeam_channel::{Receiver, unbounded};
use eframe::egui;
use wl_kit::scale;
use wl_model::{CaptureBackend, FlowKey, Interface};
use wl_panels::flows::{FlowsPanel, Tab as FlowTab};
use wl_panels::overview::{CaptureSetup, ConversationsPanel, Dashboard, HostsPanel};
use wl_panels::packets::{Layout, PacketsView};
use wl_panels::settings::{SettingsDialog, ThemeChoice};
use wl_panels::topology::{TopologyView, demo::demo_snapshot};
use wl_panels::web::WebPanel;

use crate::bench::Bench;
use crate::cli::Cli;
use crate::dialogs::FileDialogs;
use crate::dispatch::Command;
use crate::dns::AsyncResolver;
use crate::extras::Extras;
use crate::features_hub::FeaturesHub;
use crate::flows_link::FlowsLink;
use crate::graphs_hub::GraphsHub;
use crate::missing::Missing;
use crate::page::Page;
use crate::prefs::Prefs;
use crate::props_hub::PropsHub;
use crate::setup_io::SetupIo;
use crate::shot::Shot;
use crate::web_link::WebLink;
use crate::worker::Controller;

pub struct App {
    pub(crate) page: Page,
    pub(crate) prefs: Prefs,
    pub(crate) ctrl: Controller,
    pub(crate) packets: PacketsView,
    pub(crate) dashboard: Dashboard,
    pub(crate) hosts: HostsPanel,
    pub(crate) convs: ConversationsPanel,
    pub(crate) map: TopologyView,
    pub(crate) demo_map: Option<wl_model::StatsSnapshot>,
    /// Size of the stats the filter value suggestions were last built from.
    pub(crate) values_key: Option<(usize, usize)>,
    pub(crate) diff: crate::diff_hub::DiffHub,
    pub(crate) web: WebPanel,
    pub(crate) web_link: WebLink,
    pub(crate) flows: FlowsPanel,
    pub(crate) flows_link: FlowsLink,
    pub(crate) setup: CaptureSetup,
    pub(crate) setup_io: SetupIo,
    pub(crate) hub: FeaturesHub,
    pub(crate) gh: GraphsHub,
    pub(crate) props: PropsHub,
    pub(crate) extras: Extras,
    pub(crate) settings: SettingsDialog,
    pub(crate) interfaces: Vec<Interface>,
    pub(crate) iface_rx: Receiver<Vec<Interface>>,
    pub(crate) dialogs: FileDialogs,
    pub(crate) resolver: AsyncResolver,
    pub(crate) geo_store: crate::geo_store::GeoStore,
    pub(crate) startup_error: Option<String>,
    pub(crate) shot: Option<Shot>,
    pub(crate) last_scale: f32,
    pub(crate) was_running: bool,
    pub(crate) bench: Option<Bench>,
    pub(crate) script: Option<crate::bench_script::Script>,
    pub(crate) select: Option<u64>,
    pub(crate) fields: crate::fields_jobs::FieldJobs,
    pub(crate) streams: Rc<RefCell<HashMap<FlowKey, u32>>>,
    /// Pages opened in their own window (opt-in: Shift+click in the sidebar).
    pub(crate) detached: Vec<Page>,
    pub(crate) last_layout: Option<Layout>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, cli: Cli, prefs: Prefs) -> App {
        let mut visuals = prefs.settings.clone();
        if cli.light {
            visuals.theme = ThemeChoice::Light;
        }
        if let Some(s) = cli.scale {
            visuals.ui_scale = s;
        }
        crate::app_settings::apply_visuals(&cc.egui_ctx, &visuals.clamped());
        let scale = scale::ui_scale(&cc.egui_ctx);
        crate::tools_info::warm();
        send_min_size(&cc.egui_ctx, scale);
        let (backend, tshark, startup_error): (Arc<dyn CaptureBackend>, _, _) =
            match wl_tshark::TsharkBackend::new() {
                Ok(b) => {
                    let arc = Arc::new(b);
                    (arc.clone(), Some(arc), None)
                }
                Err(e) => (Arc::new(Missing(e.clone())), None, Some(e.to_string())),
            };
        let (itx, iface_rx) = unbounded();
        let (b, ctx) = (backend.clone(), cc.egui_ctx.clone());
        std::thread::spawn(move || {
            let _ = itx.send(b.interfaces().unwrap_or_default());
            ctx.request_repaint();
        });
        let resolver = AsyncResolver::spawn(cc.egui_ctx.clone());
        let mut hosts = HostsPanel::default();
        hosts.set_resolver(Box::new(resolver.clone()));
        let mut map = TopologyView::default();
        map.set_resolver(Box::new(resolver.clone()));
        let setup_io = SetupIo::new(backend.clone(), cc.egui_ctx.clone());
        let mut rules = prefs.decode_as.clone();
        for r in cli.decode_rules() {
            rules.retain(|x| (&x.field, x.value) != (&r.field, r.value));
            rules.push(r);
        }
        let extras = Extras::new(backend.clone(), cc.egui_ctx.clone(), rules);
        let mut app = App {
            page: cli.page().unwrap_or_default(),
            prefs,
            ctrl: Controller::new(backend.clone()),
            gh: GraphsHub::new(backend.clone(), cc.egui_ctx.clone()),
            props: PropsHub::new(backend.clone(), cc.egui_ctx.clone()),
            packets: PacketsView::default(),
            dashboard: Dashboard::default(),
            hosts,
            convs: ConversationsPanel::default(),
            map,
            demo_map: cli.demo_map.then(|| demo_snapshot(40, 120)),
            values_key: None,
            diff: crate::diff_hub::DiffHub::new(backend.clone()),
            web: WebPanel::default(),
            web_link: WebLink::new(cli.demo_web),
            flows: FlowsPanel::default(),
            flows_link: FlowsLink::new(backend.clone(), cc.egui_ctx.clone()),
            setup: CaptureSetup::default(),
            setup_io,
            hub: FeaturesHub::new(tshark, cc.egui_ctx.clone()),
            extras,
            settings: SettingsDialog::default(),
            interfaces: Vec::new(),
            iface_rx,
            dialogs: FileDialogs::default(),
            resolver,
            geo_store: Default::default(),
            startup_error,
            shot: cli.screenshot.clone().map(|p| Shot::new(p, cli.wait_ms)),
            last_scale: scale,
            was_running: false,
            detached: Vec::new(),
            select: cli.select,
            fields: crate::fields_jobs::FieldJobs::new(backend.clone()),
            streams: Rc::default(),
            last_layout: None,
            bench: cli.bench_frames.map(Bench::new),
            script: cli.bench_script.then(crate::bench_script::Script::new),
        };
        if let Some(l) = app.prefs.layout {
            app.packets.set_layout(l);
        }
        app.last_layout = Some(app.packets.layout());
        app.apply_capture_defaults();
        app.apply_runtime_settings();
        if let Some(spec) = &cli.setup_expand {
            app.setup.expand(spec);
        }
        app.packets.set_table_prefs(app.prefs.table.clone());
        app.packets
            .set_filter_history(app.prefs.filter_history.clone());
        app.packets
            .set_filter_presets(app.prefs.filter_presets.clone());
        let lookup = app.streams.clone();
        app.convs
            .set_stream_lookup(Box::new(move |k| lookup.borrow().get(k).copied()));
        if let Some(v) = &cli.map_view {
            app.map.apply_spec(v);
        }
        if let Some(a) = &cli.map_select {
            app.map.select_host(a);
        }
        if let Some(f) = &cli.diff {
            app.diff.set_other(f.clone());
        }
        if let Some(f) = cli.file() {
            app.execute(Command::OpenFile(f.clone()), &cc.egui_ctx);
            if let Some(flt) = &cli.filter {
                app.execute(Command::ApplyFilter(flt.clone()), &cc.egui_ctx);
            }
            app.page = cli.page().unwrap_or(Page::Packets);
        } else if let Some(i) = &cli.live {
            let options = wl_model::CaptureOptions::single(i, None);
            app.execute(Command::StartLive(options), &cc.egui_ctx);
            app.page = cli.page().unwrap_or(Page::Packets);
        }
        app.detached
            .extend(cli.detach.iter().filter_map(|p| Page::parse(p)));
        if let Some(sel) = cli
            .flow_select
            .as_deref()
            .and_then(wl_model::FlowSel::parse)
        {
            app.flows.open(sel);
        }
        if let Some(t) = cli.flow_tab.as_deref().and_then(FlowTab::parse) {
            app.flows.set_tab(t);
        }
        if let Some(f) = cli.flow_frame {
            app.flows.select_frame(f);
        }
        if let Some(d) = &cli.packets_demo {
            app.packets.apply_demo(d);
        }
        if let Some(v) = &cli.graph_view {
            app.gh.panel.apply_spec(v);
        }
        if let Some(spec) = &cli.window {
            app.preselect_window(spec);
        }
        if let Some(s) = &cli.web_select {
            app.web.preselect(s);
        }
        if let Some(t) = &cli.web_tab {
            let (kind, proto) = t.split_once(':').unwrap_or((t, ""));
            if kind == "files" {
                app.web.show_files(Some(proto).filter(|p| !p.is_empty()));
            }
        }
        if cli.insights_tab.as_deref() == Some("dns") {
            app.hub.insights.show_dns();
        }
        if let Some(o) = &cli.overlay {
            app.open_overlay(o, cli.file().cloned(), &cc.egui_ctx);
        }
        app
    }
}

pub(crate) fn send_min_size(ctx: &egui::Context, scale: f32) {
    let s = scale.max(0.5);
    ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(egui::vec2(
        1000.0 / s,
        640.0 / s,
    )));
}
