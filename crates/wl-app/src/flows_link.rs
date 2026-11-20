//! Glue between the Flows page and the backend: two "latest wins" tshark jobs (flow events,
//! TCP samples) whose results are matched to the selection they were asked for.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender, unbounded};
use wl_kit::egui;
use wl_model::{CaptureBackend, CaptureError, FlowEvents, FlowSel, TcpSamples};
use wl_panels::flows::{FlowsAction, FlowsData};

use crate::app::App;
use crate::bg::LatestSlot;
use crate::dispatch::Command;
use crate::page::Page;

struct Job {
    file: PathBuf,
    sel: FlowSel,
}

enum Done {
    Flow(FlowSel, Result<FlowEvents, CaptureError>),
    Tcp(FlowSel, Result<TcpSamples, CaptureError>),
}

type Slot = Arc<LatestSlot<Job>>;

pub struct FlowsLink {
    flow_slot: Slot,
    tcp_slot: Slot,
    rx: Receiver<Done>,
    want_flow: Option<FlowSel>,
    want_tcp: Option<FlowSel>,
    flow: Option<(FlowSel, FlowEvents)>,
    tcp: Option<(FlowSel, TcpSamples)>,
    flow_err: Option<String>,
    tcp_err: Option<String>,
    rev: u64,
}

fn worker(
    slot: Slot,
    tx: Sender<Done>,
    ctx: egui::Context,
    run: impl Fn(Job) -> Done + Send + 'static,
) {
    thread::spawn(move || {
        while let Some(job) = slot.take() {
            if tx.send(run(job)).is_err() {
                break;
            }
            ctx.request_repaint();
        }
    });
}

impl FlowsLink {
    pub fn new(backend: Arc<dyn CaptureBackend>, ctx: egui::Context) -> Self {
        let (tx, rx) = unbounded();
        let (flow_slot, tcp_slot) = (Arc::new(LatestSlot::new()), Arc::new(LatestSlot::new()));
        let b = backend.clone();
        worker(flow_slot.clone(), tx.clone(), ctx.clone(), move |j| {
            Done::Flow(j.sel.clone(), b.flow_events(&j.file, &j.sel.filter()))
        });
        worker(tcp_slot.clone(), tx, ctx, move |j| {
            Done::Tcp(j.sel.clone(), backend.tcp_samples(&j.file, &j.sel.filter()))
        });
        Self {
            flow_slot,
            tcp_slot,
            rx,
            want_flow: None,
            want_tcp: None,
            flow: None,
            tcp: None,
            flow_err: None,
            tcp_err: None,
            rev: 1,
        }
    }

    pub fn request_flow(&mut self, file: PathBuf, sel: FlowSel) {
        self.flow = None;
        self.flow_err = None;
        self.want_flow = Some(sel.clone());
        self.flow_slot.put(Job { file, sel });
        self.rev += 1;
    }

    pub fn request_tcp(&mut self, file: PathBuf, sel: FlowSel) {
        self.tcp = None;
        self.tcp_err = None;
        self.want_tcp = Some(sel.clone());
        self.tcp_slot.put(Job { file, sel });
        self.rev += 1;
    }

    pub fn fail(&mut self, msg: &str) {
        self.flow_err = Some(msg.to_owned());
        self.tcp_err = Some(msg.to_owned());
    }

    /// Forgets every result (a new capture was opened).
    pub fn clear(&mut self) {
        self.flow_slot.clear();
        self.tcp_slot.clear();
        (self.want_flow, self.want_tcp) = (None, None);
        (self.flow, self.tcp) = (None, None);
        (self.flow_err, self.tcp_err) = (None, None);
        self.rev += 1;
    }

    /// Takes finished jobs; true when something changed.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        while let Ok(done) = self.rx.try_recv() {
            match done {
                Done::Flow(s, r) if self.want_flow.as_ref() == Some(&s) => {
                    changed = true;
                    match r {
                        Ok(e) => self.flow = Some((s, e)),
                        Err(e) => self.flow_err = Some(e.to_string()),
                    }
                }
                Done::Tcp(s, r) if self.want_tcp.as_ref() == Some(&s) => {
                    changed = true;
                    match r {
                        Ok(t) => self.tcp = Some((s, t)),
                        Err(e) => self.tcp_err = Some(e.to_string()),
                    }
                }
                _ => {}
            }
        }
        self.rev += u64::from(changed);
        changed
    }

    pub fn data<'a>(&'a self, stats: &'a wl_model::StatsSnapshot) -> FlowsData<'a> {
        FlowsData {
            stats,
            flow: self.flow.as_ref().map(|(s, e)| (s, e)),
            tcp: self.tcp.as_ref().map(|(s, t)| (s, t)),
            rev: self.rev,
            flow_error: self.flow_err.as_deref(),
            tcp_error: self.tcp_err.as_deref(),
        }
    }
}

impl Drop for FlowsLink {
    fn drop(&mut self) {
        self.flow_slot.close();
        self.tcp_slot.close();
    }
}

impl App {
    /// Executes what the Flows page asked for.
    pub(crate) fn flows_action(&mut self, a: FlowsAction, cmds: &mut Vec<Command>) {
        match a {
            FlowsAction::LoadFlow(sel) => match self.ctrl.backing() {
                Some(file) => self.flows_link.request_flow(file, sel),
                None => self.flows_link.fail("Open a capture first."),
            },
            FlowsAction::LoadTcp(sel) => match self.ctrl.backing() {
                Some(file) => self.flows_link.request_tcp(file, sel),
                None => self.flows_link.fail("Open a capture first."),
            },
            FlowsAction::ShowInPackets(n) => {
                if self.packets.select_frame(n) {
                    cmds.push(Command::Select(n));
                }
                self.page = Page::Packets;
            }
            FlowsAction::ApplyFilter(f) => cmds.push(Command::ApplyFilter(f)),
        }
    }
}
