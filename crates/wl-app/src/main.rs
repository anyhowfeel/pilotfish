//! pilotfish desktop entry point.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod app;
mod app_banner;
mod app_cmd;
mod app_demo;
mod app_icon;
mod app_panes;
mod app_paths;
mod app_pump;
mod app_settings;
mod app_ui;
mod bench;
mod bench_script;
mod bg;
mod cli;
mod clock;
mod dialogs;
mod diff_hub;
mod diff_scan;
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
mod geo;
mod geo_store;
mod graphs_hub;
mod graphs_link;
mod icons;
mod intel_store;
mod keys_link;
mod metrics;
mod page;
mod prefs;
mod proc_scan;
mod proc_watch;
mod props_hub;
mod report_bookmarks;
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
mod wireshark;
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
    app_paths::migrate_legacy_dirs();
    let prefs = prefs::Prefs::load();
    let [w, h] = cli.size().unwrap_or([1280.0, 800.0]);
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("pilotfish")
        .with_app_id("pilotfish")
        .with_inner_size([w, h])
        .with_min_inner_size([1000.0, 640.0]);
    if let Some(icon) = app_icon::window_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "pilotfish",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, cli, prefs)))),
    )
}
