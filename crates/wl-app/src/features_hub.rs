//! Coordinates the secondary features: command palette, stream view, insights, autocomplete, bookmarks and exports.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, bounded};
use eframe::egui;
use wl_model::{
    Analyses, Analysis, BehaviorData, CaptureBackend, CaptureError, ExpertReport, PacketBookmark,
    PacketRow, ProtocolHierarchy, SecurityData, StatsSnapshot, StreamConversation, StreamFormat,
    StreamProtocol, ThreatIntel, Wireshark, needs_message,
};
use wl_panels::features::{
    BookmarkStore, CommandPalette, FieldCatalog, InsightsPanel, NameBook, PaletteAction,
    PalettePage, StreamView, StreamViewAction,
};
use wl_panels::insights::InsightRules;

use crate::export_data::{write_html_report, write_packets_csv, write_stats_json};
use crate::page::Page;
use crate::wireshark::LazyTshark;

/// Results of scans that belong to one capture carry its generation: `None` means valid for any.
type Tagged = (Option<u64>, Msg);

enum Msg {
    Fields(Arc<FieldCatalog>),
    Stream(Result<StreamConversation, CaptureError>),
    Insights(Analysis<ExpertReport>, Analysis<ProtocolHierarchy>),
    Behavior(Analysis<BehaviorData>, NameBook),
    Security(Analysis<SecurityData>),
    /// tshark could not be started for a reason other than being absent.
    Unavailable(String),
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
#[path = "features_hub_insights.rs"]
mod insights_job;
#[path = "features_hub_jobs.rs"]
mod jobs;

pub struct FeaturesHub {
    pub(crate) tshark: LazyTshark,
    pub(crate) wireshark: Wireshark,
    pub palette: CommandPalette,
    pub stream_view: StreamView,
    pub insights: InsightsPanel,
    pub bookmarks: BookmarkStore,
    pub bookmark_comment: String,
    pub bookmark_frame: Option<u64>,
    pub analyses: Analyses,
    pub intel: Arc<ThreatIntel>,
    pub rules: InsightRules,
    /// Names for the filter suggestions and how many times they were rebuilt.
    pub names: (Arc<NameBook>, u64),
    generation: u64,
    tx: Sender<Tagged>,
    rx: Receiver<Tagged>,
    pub notice: Option<String>,
    pub error: Option<String>,
}

impl FeaturesHub {
    pub fn new(tshark: LazyTshark, wireshark: Wireshark, ctx: egui::Context) -> Self {
        let (tx, rx) = bounded(16);
        {
            let (tx2, tshark) = (tx.clone(), tshark.clone());
            std::thread::spawn(move || {
                let Ok(b) = tshark.get() else { return };
                if let Ok(fields) = b.filter_fields(None) {
                    let catalog = Arc::new(FieldCatalog::from_fields(fields));
                    let _ = tx2.try_send((None, Msg::Fields(catalog)));
                    ctx.request_repaint();
                }
            });
        }
        Self {
            tshark,
            wireshark,
            palette: CommandPalette::default(),
            stream_view: StreamView::default(),
            insights: InsightsPanel::default(),
            bookmarks: BookmarkStore::default(),
            bookmark_comment: String::new(),
            bookmark_frame: None,
            analyses: Analyses::default(),
            intel: Arc::default(),
            rules: InsightRules::default(),
            names: (Arc::default(), 0),
            generation: 0,
            tx,
            rx,
            notice: None,
            error: None,
        }
    }

    pub fn clear_capture(&mut self) {
        self.analyses = Analyses::default();
        self.names = (Arc::default(), self.names.1 + 1);
        self.bookmarks.clear();
        self.bookmark_comment.clear();
        self.bookmark_frame = None;
        self.stream_view.close();
        self.generation += 1;
    }

    fn spawn_job<F>(&self, file: &Arc<PathBuf>, ctx: &egui::Context, job: F)
    where
        F: FnOnce(&wl_tshark::TsharkBackend, &Path) -> Msg + Send + 'static,
    {
        let (tshark, file, tx, ctx) = (
            self.tshark.clone(),
            file.clone(),
            self.tx.clone(),
            ctx.clone(),
        );
        let generation = Some(self.generation);
        std::thread::spawn(move || {
            // Without Wireshark the pages say so themselves, so there is nothing to report.
            let msg = match tshark.get() {
                Ok(b) => job(&b, &file),
                Err(e) if e.is_tool_missing() => return,
                Err(e) => Msg::Unavailable(e.to_string()),
            };
            let _ = tx.try_send((generation, msg));
            ctx.request_repaint();
        });
    }

    /// Expert info + protocol hierarchy, channel summaries and DNS names run in parallel; each
    /// result is delivered as soon as it is ready.
    pub fn refresh_insights(&mut self, file: PathBuf, ctx: egui::Context) {
        let file = Arc::new(file);
        self.analyses.start();
        self.spawn_job(&file, &ctx, |b, f| {
            jobs::insights(b.expert_info(f, None), b.protocol_hierarchy(f, None))
        });
        self.spawn_job(&file, &ctx, |b, f| {
            Msg::Comments(b.packet_comments(f).unwrap_or_default())
        });
        self.spawn_job(&file, &ctx, |b, f| {
            std::thread::scope(|s| {
                let channels = s.spawn(|| b.behavior_channels(f));
                let tls = s.spawn(|| b.tls_sessions(f));
                let http = s.spawn(|| b.http_exchanges(f));
                let dns = b.dns_queries(f);
                jobs::behavior(jobs::join(channels), dns, jobs::join(tls), jobs::join(http))
            })
        });
        self.spawn_security(&file, &ctx);
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
        let (tshark, tx, generation) =
            (self.tshark.clone(), self.tx.clone(), Some(self.generation));
        std::thread::spawn(move || {
            let stream = match tshark.get() {
                Ok(b) => b.follow_stream(&file, protocol, stream_id, format),
                Err(_) => Err(CaptureError::Other(needs_message("Follow stream"))),
            };
            let _ = tx.try_send((generation, Msg::Stream(stream)));
            ctx.request_repaint();
        });
    }

    pub fn poll(&mut self) -> (Option<Arc<FieldCatalog>>, bool) {
        let (mut fields, mut changed) = (None, false);
        while let Ok((generation, msg)) = self.rx.try_recv() {
            if generation.is_some_and(|g| g != self.generation) {
                continue;
            }
            changed = true;
            match msg {
                Msg::Fields(f) => fields = Some(f),
                Msg::Stream(Ok(c)) => self.stream_view.set_conversation(c),
                Msg::Stream(Err(e)) => self.stream_view.set_error(e.to_string()),
                Msg::Insights(e, p) => {
                    self.analyses.expert = e;
                    self.analyses.hierarchy = p;
                }
                Msg::Security(s) => self.analyses.security = s,
                Msg::Behavior(b, names) => {
                    self.analyses.behavior = b;
                    self.names = (Arc::new(names), self.names.1 + 1);
                }
                Msg::Unavailable(reason) => self.analyses.fail_pending(&reason),
                Msg::Comments(list) => {
                    for c in list {
                        if self.bookmarks.comment(c.frame_no).is_none_or(str::is_empty) {
                            self.bookmarks.set(c.frame_no, c.comment);
                        }
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

#[cfg(test)]
#[path = "features_hub_tests.rs"]
mod tests;
