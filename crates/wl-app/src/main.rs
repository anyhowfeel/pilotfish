//! wirelens desktop entry point.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod app;
mod app_banner;
mod app_cmd;
mod app_demo;
mod app_panes;
mod app_pump;
mod app_settings;
mod app_ui;
mod bench;
mod bench_script;
mod bg;
mod cli;
mod clock;
mod dialogs;
mod dispatch;
mod dns;
#[allow(dead_code)]
mod export_data;
#[allow(dead_code)]
mod export_html;
mod extras;
#[allow(dead_code)]
mod features;
mod features_hub;
mod fields_jobs;
mod flows_link;
mod graphs_hub;
mod graphs_link;
mod icons;
mod metrics;
mod missing;
mod page;
mod prefs;
mod props_hub;
mod setup_io;
mod shell;
mod shot;
mod sidebar_brand;
mod sidebar_stop;
mod signals;
mod state;
mod tools_info;
mod web_jobs;
mod web_link;
mod window_job;
mod worker;

/// mimalloc: faster for millions of small `Arc<str>` rows and returns memory after Clear/reopen
/// (glibc malloc fragments badly under this pattern).
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::Parser;
use eframe::egui;

fn main() -> eframe::Result {
    signals::install();
    let cli = cli::Cli::parse();
    let prefs = prefs::Prefs::load();
    let [w, h] = cli.size().unwrap_or([1280.0, 800.0]);
    let viewport = egui::ViewportBuilder::default()
        .with_title("wirelens")
        .with_app_id("wirelens")
        .with_inner_size([w, h])
        .with_min_inner_size([1000.0, 640.0]);
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "wirelens",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, cli, prefs)))),
    )
}
