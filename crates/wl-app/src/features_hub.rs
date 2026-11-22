//! Coordinates the secondary features: command palette, stream view, insights, autocomplete, bookmarks and exports.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, bounded};
use eframe::egui;
use wl_model::{
    BehaviorData, CaptureBackend, CaptureError, ExpertReport, HealthInsight, PacketBookmark,
    PacketRow, ProtocolHierarchy, StatsSnapshot, StreamConversation, StreamFormat, StreamProtocol,
};
use wl_panels::features::{
    BookmarkStore, CommandPalette, FieldCatalog, InsightsAction, InsightsPanel, PaletteAction,
    PalettePage, StreamView, StreamViewAction, synthesize_insights,
};

use crate::export_data::{write_html_report, write_packets_csv, write_stats_json};
use crate::page::Page;

enum Msg {
    Fields(Arc<FieldCatalog>),
    Stream(Result<StreamConversation, CaptureError>),
    Insights(Option<ExpertReport>, Option<ProtocolHierarchy>),
    Behavior(BehaviorData),
    Comments(Vec<PacketBookmark>),
    ExportDone(Result<String, String>),
}

pub enum HubCommand {
    Page(Page),
    JumpToFrame(u64),
    ApplyFilter(String),
    ToggleTheme,
    OpenSettings,
    OpenFileDialog,
    FileProperties,
    TogglePause,
    Stop,
    ExportCsv,
    ExportJson,
    ExportHtml,
    ExportObjects,
    DecodeAs,
    DnsLog,
}

#[path = "features_hub_export.rs"]
mod export;

pub struct FeaturesHub {
    tshark: Option<Arc<wl_tshark::TsharkBackend>>,
    pub palette: CommandPalette,
    pub stream_view: StreamView,
    pub insights: InsightsPanel,
    pub bookmarks: BookmarkStore,
    pub bookmark_comment: String,
    pub bookmark_frame: Option<u64>,
    pub expert: Option<ExpertReport>,
    pub phs: Option<ProtocolHierarchy>,
    pub behavior: Option<BehaviorData>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    pub notice: Option<String>,
    pub error: Option<String>,
}

impl FeaturesHub {
    pub fn new(tshark: Option<Arc<wl_tshark::TsharkBackend>>, ctx: egui::Context) -> Self {
        let (tx, rx) = bounded(16);
        if let Some(b) = tshark.clone() {
            let tx2 = tx.clone();
            std::thread::spawn(move || {
                if let Ok(fields) = b.filter_fields(None) {
                    let catalog = Arc::new(FieldCatalog::from_fields(fields));
                    let _ = tx2.try_send(Msg::Fields(catalog));
                    ctx.request_repaint();
                }
            });
        }
        Self {
            tshark,
            palette: CommandPalette::default(),
            stream_view: StreamView::default(),
            insights: InsightsPanel::default(),
            bookmarks: BookmarkStore::default(),
            bookmark_comment: String::new(),
            bookmark_frame: None,
            expert: None,
            phs: None,
            behavior: None,
            tx,
            rx,
            notice: None,
            error: None,
        }
    }

    pub(crate) fn insights_for(&self, stats: &StatsSnapshot) -> Vec<HealthInsight> {
        synthesize_insights(
            self.expert.as_ref(),
            self.phs.as_ref(),
            self.behavior.as_ref(),
            stats,
        )
    }

    pub fn clear_capture(&mut self) {
        self.expert = None;
        self.phs = None;
        self.behavior = None;
        self.stream_view.close();
    }

    fn spawn_job<F>(&self, file: &Arc<PathBuf>, ctx: &egui::Context, job: F)
    where
        F: FnOnce(&wl_tshark::TsharkBackend, &Path) -> Msg + Send + 'static,
    {
        let Some(b) = self.tshark.clone() else { return };
        let (file, tx, ctx) = (file.clone(), self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.try_send(job(&b, &file));
            ctx.request_repaint();
        });
    }

    /// Expert info + protocol hierarchy, channel summaries and DNS names run in parallel; each
    /// result is delivered as soon as it is ready.
    pub fn refresh_insights(&mut self, file: PathBuf, ctx: egui::Context) {
        let file = Arc::new(file);
        self.spawn_job(&file, &ctx, |b, f| {
            Msg::Insights(
                b.expert_info(f, None).ok(),
                b.protocol_hierarchy(f, None).ok(),
            )
        });
        self.spawn_job(&file, &ctx, |b, f| {
            Msg::Comments(b.packet_comments(f).unwrap_or_default())
        });
        self.spawn_job(&file, &ctx, |b, f| {
            let (channels, dns) = std::thread::scope(|s| {
                let c = s.spawn(|| b.behavior_channels(f).unwrap_or_default());
                let d = b.dns_queries(f).unwrap_or_default();
                (c.join().unwrap_or_default(), d)
            });
            Msg::Behavior(BehaviorData { channels, dns })
        });
    }

    pub fn open_stream(
        &mut self,
        file: PathBuf,
        protocol: StreamProtocol,
        stream_id: u32,
        format: StreamFormat,
        ctx: egui::Context,
    ) {
        self.stream_view.begin_load(protocol, stream_id, format);
        let Some(b) = self.tshark.clone() else {
            self.stream_view
                .set_error("tshark backend unavailable".into());
            return;
        };
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let _ = tx.try_send(Msg::Stream(
                b.follow_stream(&file, protocol, stream_id, format),
            ));
            ctx.request_repaint();
        });
    }

    pub fn poll(&mut self) -> (Option<Arc<FieldCatalog>>, bool) {
        let (mut fields, mut changed) = (None, false);
        while let Ok(msg) = self.rx.try_recv() {
            changed = true;
            match msg {
                Msg::Fields(f) => fields = Some(f),
                Msg::Stream(Ok(c)) => self.stream_view.set_conversation(c),
                Msg::Stream(Err(e)) => self.stream_view.set_error(e.to_string()),
                Msg::Insights(e, p) => {
                    self.expert = e;
                    self.phs = p;
                }
                Msg::Behavior(b) => self.behavior = Some(b),
                Msg::Comments(list) => {
                    for c in list {
                        self.bookmarks.set(c.frame_no, c.comment);
                    }
                }
                Msg::ExportDone(Ok(n)) => self.notice = Some(n),
                Msg::ExportDone(Err(e)) => self.error = Some(e),
            }
        }
        (fields, changed)
    }

    pub fn overlay_ui(
        &mut self,
        ctx: &egui::Context,
        backing: Option<PathBuf>,
    ) -> Option<HubCommand> {
        if let Some(act) = self.stream_view.ui(ctx) {
            match act {
                StreamViewAction::Close => {}
                StreamViewAction::ApplyFilter(f) => return Some(HubCommand::ApplyFilter(f)),
                StreamViewAction::ReloadFormat {
                    protocol,
                    stream_id,
                    format,
                } => {
                    if let Some(file) = backing {
                        self.open_stream(file, protocol, stream_id, format, ctx.clone());
                    }
                }
            }
        }
        self.palette.ui(ctx).map(|act| match act {
            PaletteAction::GoToPage(p) => HubCommand::Page(map_page(p)),
            PaletteAction::JumpToFrame(n) => HubCommand::JumpToFrame(n),
            PaletteAction::ApplyFilter(f) => HubCommand::ApplyFilter(f),
            PaletteAction::ToggleTheme => HubCommand::ToggleTheme,
            PaletteAction::OpenSettings => HubCommand::OpenSettings,
            PaletteAction::ExportCsv => HubCommand::ExportCsv,
            PaletteAction::ExportStatsJson => HubCommand::ExportJson,
            PaletteAction::ExportHtmlReport => HubCommand::ExportHtml,
            PaletteAction::OpenPcap => HubCommand::OpenFileDialog,
            PaletteAction::FileProperties => HubCommand::FileProperties,
            PaletteAction::TogglePause => HubCommand::TogglePause,
            PaletteAction::StopCapture => HubCommand::Stop,
            PaletteAction::ExportObjects => HubCommand::ExportObjects,
            PaletteAction::DecodeAs => HubCommand::DecodeAs,
            PaletteAction::DnsLog => HubCommand::DnsLog,
        })
    }

    pub fn insights_ui(&mut self, ui: &mut egui::Ui, stats: &StatsSnapshot) -> Vec<InsightsAction> {
        self.insights.ui(
            ui,
            stats,
            self.expert.as_ref(),
            self.phs.as_ref(),
            self.behavior.as_ref(),
        )
    }
}

fn map_page(p: PalettePage) -> Page {
    match p {
        PalettePage::Setup => Page::Setup,
        PalettePage::Overview => Page::Overview,
        PalettePage::Graphs => Page::Graphs,
        PalettePage::Packets => Page::Packets,
        PalettePage::Hosts => Page::Hosts,
        PalettePage::Conversations => Page::Conversations,
        PalettePage::Web => Page::Web,
        PalettePage::Insights => Page::Insights,
    }
}
