//! `--bench-script`: drives a fixed UI scenario (pages, scroll, keys, sort, search, resize, scale)
//! and prints per-phase frame statistics plus RSS. Developer tooling, not part of the product UI.
use std::time::Instant;

use eframe::egui::{self, Event, Key, Modifiers, MouseWheelUnit, PointerButton, pos2, vec2};
use wl_panels::packets::Col;

use crate::app::App;
use crate::dispatch::Command;
use crate::page::Page;

#[derive(Clone, Copy)]
enum Act {
    None,
    Page(Page),
    Sort(Col),
    Quick(&'static str),
    Size(f32, f32),
    Scale(f32),
    Clear,
    Reopen,
}

#[derive(Clone, Copy)]
enum Input {
    None,
    Scroll,
    Keys,
}

struct Phase(&'static str, u32, Act, Input);

const PHASES: &[Phase] = &[
    Phase("packets-idle", 120, Act::Page(Page::Packets), Input::None),
    Phase("scroll", 150, Act::None, Input::Scroll),
    Phase("keys-held", 150, Act::None, Input::Keys),
    Phase("sort-info", 30, Act::Sort(Col::Info), Input::None),
    Phase("sort-len", 30, Act::Sort(Col::Length), Input::None),
    Phase("sort-len-desc", 30, Act::Sort(Col::Length), Input::None),
    Phase("sort-off", 30, Act::Sort(Col::Length), Input::None),
    Phase("quick-tcp", 30, Act::Quick("tcp"), Input::None),
    Phase("quick-clear", 30, Act::Quick(""), Input::None),
    Phase("resize", 60, Act::Size(1000.0, 700.0), Input::None),
    Phase("resize2", 60, Act::Size(1900.0, 1000.0), Input::None),
    Phase("scale1.5", 90, Act::Scale(1.5), Input::Scroll),
    Phase("scale1.0", 30, Act::Scale(1.0), Input::None),
    Phase("overview", 90, Act::Page(Page::Overview), Input::None),
    Phase("hosts", 90, Act::Page(Page::Hosts), Input::None),
    Phase("convs", 90, Act::Page(Page::Conversations), Input::None),
    Phase("insights", 60, Act::Page(Page::Insights), Input::None),
    Phase("setup", 60, Act::Page(Page::Setup), Input::None),
    Phase("clear", 30, Act::Clear, Input::None),
    Phase("reopen1", 5, Act::Reopen, Input::None),
    Phase("clear1", 60, Act::Clear, Input::None),
    Phase("reopen2", 5, Act::Reopen, Input::None),
    Phase("clear2", 60, Act::Clear, Input::None),
];

pub struct Script {
    idx: usize,
    frame: u32,
    t0: Instant,
    last: Instant,
    ui: Vec<f32>,
    gap: Vec<f32>,
    rows_seen: bool,
}

fn rss_mb() -> f64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let kb = s
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<f64>().ok());
    kb.unwrap_or(0.0) / 1024.0
}

fn pct(v: &mut [f32], p: f32) -> f32 {
    v.sort_by(f32::total_cmp);
    v.get(((v.len() as f32 * p) as usize).min(v.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0.0)
}

impl Script {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            idx: 0,
            frame: 0,
            t0: now,
            last: now,
            ui: Vec::new(),
            gap: Vec::new(),
            rows_seen: false,
        }
    }

    fn report(&mut self, name: &str) {
        let n = self.ui.len().max(1) as f32;
        let avg_ui = self.ui.iter().sum::<f32>() / n;
        let avg_gap = self.gap.iter().sum::<f32>() / n;
        let (u95, u99) = (pct(&mut self.ui, 0.95), pct(&mut self.ui, 0.99));
        let (g95, gmax) = (pct(&mut self.gap, 0.95), pct(&mut self.gap, 1.0));
        let umax = pct(&mut self.ui, 1.0);
        println!(
            "{name:<13} ui avg/p95/p99/max {avg_ui:6.2} {u95:6.2} {u99:6.2} {umax:7.2} | gap avg/p95/max {avg_gap:6.2} {g95:6.2} {gmax:7.2} | rss {:.0} MB",
            rss_mb()
        );
        self.ui.clear();
        self.gap.clear();
    }

    /// Inject synthetic input before the frame's egui pass.
    pub fn inject(&mut self, raw: &mut egui::RawInput) {
        let Some(Phase(_, _, _, input)) = PHASES.get(self.idx) else {
            return;
        };
        let at = pos2(600.0, 250.0);
        let m = Modifiers::NONE;
        match input {
            Input::None => {}
            Input::Scroll => raw.events.extend([
                Event::PointerMoved(at),
                Event::MouseWheel {
                    unit: MouseWheelUnit::Point,
                    delta: vec2(0.0, if self.frame % 40 < 20 { -240.0 } else { 240.0 }),
                    phase: egui::TouchPhase::Move,
                    source: egui::MouseWheelSource::Unknown,
                    modifiers: m,
                },
            ]),
            Input::Keys => {
                if self.frame == 0 {
                    raw.events.push(Event::PointerMoved(at));
                    for pressed in [true, false] {
                        raw.events.push(Event::PointerButton {
                            pos: at,
                            button: PointerButton::Primary,
                            pressed,
                            modifiers: m,
                        });
                    }
                }
                raw.events.push(Event::Key {
                    key: Key::ArrowDown,
                    physical_key: Some(Key::ArrowDown),
                    pressed: true,
                    repeat: self.frame > 0,
                    modifiers: m,
                });
            }
        }
    }
}

impl App {
    pub(crate) fn script_frame(&mut self, ctx: &egui::Context, start: Instant) {
        let Some(mut s) = self.script.take() else {
            return;
        };
        ctx.request_repaint();
        let live_ready = self.ctrl.is_live() && s.t0.elapsed().as_secs() >= 10;
        let loaded = (live_ready || !self.ctrl.is_busy()) && self.packets.table.state.total() > 0;
        if !s.rows_seen {
            if s.ui.is_empty() && std::env::var_os("WL_BENCH_SORT_STREAM").is_some() {
                self.packets.table.state.cycle_sort(Col::Info);
            }
            if loaded && s.t0.elapsed().as_secs_f32() > 1.0 {
                s.rows_seen = true;
                s.report("streaming");
                println!(
                    "loaded {} rows in {:.1}s, rss {:.0} MB",
                    self.packets.table.state.total(),
                    s.t0.elapsed().as_secs_f32(),
                    rss_mb()
                );
                self.run_act(Act::Page(Page::Packets), ctx);
            }
            s.ui.push(start.elapsed().as_secs_f32() * 1000.0);
            s.gap.push(s.last.elapsed().as_secs_f32() * 1000.0);
            s.last = Instant::now();
            self.script = Some(s);
            return;
        }
        if s.frame == 0 {
            if matches!(PHASES[s.idx].2, Act::Reopen) {
                s.rows_seen = false;
                s.t0 = Instant::now();
            }
            self.run_act(PHASES[s.idx].2, ctx);
        }
        s.ui.push(start.elapsed().as_secs_f32() * 1000.0);
        s.gap.push(s.last.elapsed().as_secs_f32() * 1000.0);
        s.last = Instant::now();
        s.frame += 1;
        if s.frame > PHASES[s.idx].1 {
            s.report(PHASES[s.idx].0);
            s.idx += 1;
            s.frame = 0;
            if s.idx >= PHASES.len() {
                std::process::exit(0);
            }
        }
        self.script = Some(s);
    }

    fn run_act(&mut self, act: Act, ctx: &egui::Context) {
        match act {
            Act::None => {}
            Act::Page(p) => self.page = p,
            Act::Sort(c) => self.packets.table.state.cycle_sort(c),
            Act::Quick(q) => self.packets.table.state.set_quick(q),
            Act::Size(w, h) => ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(vec2(w, h))),
            Act::Scale(f) => wl_kit::scale::set_ui_scale(ctx, f),
            Act::Clear => self.execute(Command::ClearAll, ctx),
            Act::Reopen => {
                if let Some(p) = std::env::var_os("WL_BENCH_FILE") {
                    self.execute(Command::OpenFile(p.into()), ctx);
                }
            }
        }
    }
}
