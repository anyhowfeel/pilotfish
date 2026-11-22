//! Settings integration for `App`: open dialog, live preview, apply/revert, persistence.
use eframe::egui;
use wl_kit::widgets::{PillLookKind, set_pill_look, toast};
use wl_kit::{scale, theme};
use wl_panels::settings::{
    AboutInfo, Category, Density, GeoAction, IntelAction, PillLook, Settings, SettingsAction,
    ThemeChoice,
};

use crate::app::App;
use crate::prefs::Prefs;

/// Concrete mode for a theme choice (System follows the OS, falling back to dark).
pub fn resolve_mode(ctx: &egui::Context, choice: ThemeChoice) -> theme::Mode {
    match choice {
        ThemeChoice::Dark => theme::Mode::Dark,
        ThemeChoice::Light => theme::Mode::Light,
        ThemeChoice::System => match ctx.system_theme() {
            Some(egui::Theme::Light) => theme::Mode::Light,
            _ => theme::Mode::Dark,
        },
    }
}

/// Applies the visual parts of `s` (theme + scale) without persisting anything.
pub fn apply_visuals(ctx: &egui::Context, s: &Settings) {
    theme::set_compact(s.density == Density::Compact);
    set_pill_look(match s.pill_look {
        PillLook::Tinted => PillLookKind::Tinted,
        PillLook::Solid => PillLookKind::Solid,
        PillLook::Dot => PillLookKind::Dot,
    });
    theme::apply_mode(ctx, resolve_mode(ctx, s.theme));
    scale::set_ui_scale(ctx, s.ui_scale);
}

impl App {
    pub(crate) fn open_settings(&mut self) {
        self.open_settings_at(None);
    }

    pub(crate) fn open_settings_at(&mut self, cat: Option<Category>) {
        let about = self.about_info();
        self.settings.open(self.prefs.settings.clone(), about, cat);
    }

    fn about_info(&self) -> AboutInfo {
        let (tshark, dumpcap) = crate::tools_info::get();
        AboutInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            tshark,
            dumpcap,
            config_dir: Prefs::path()
                .and_then(|p| p.parent().map(|d| d.display().to_string()))
                .unwrap_or_else(|| "unavailable".into()),
        }
    }

    /// Settings that act on running services rather than on the look: name resolution and the
    /// statistics refresh rate.
    pub(crate) fn apply_runtime_settings(&mut self) {
        let s = &self.prefs.settings;
        self.resolver.set_enabled(s.resolve_dns);
        self.ctrl.set_stats_hz(s.stats_hz);
        self.hub.rules = s.insights.clone();
    }

    /// Pushes the saved Capture > Options into the Setup page.
    pub(crate) fn apply_capture_defaults(&mut self) {
        let s = &self.prefs.settings;
        self.setup.set_defaults(&s.capture, &s.default_interface);
    }

    /// Remembers the packet count of a capture file once it has been read completely.
    pub(crate) fn record_finished_file(&mut self) {
        use wl_model::CaptureSource;
        let done = self.ctrl.status().state == crate::state::RunState::Finished;
        if let (true, Some(CaptureSource::File(p))) = (done, self.ctrl.source().cloned()) {
            let n = self.ctrl.status().packets;
            if n > 0 && self.prefs.record_packets(&p, n) {
                self.prefs.save();
            }
        }
    }

    /// Draws the dialog (when open) and handles its actions. Call after the main UI.
    pub(crate) fn settings_ui(&mut self, ctx: &egui::Context) {
        let comma = ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Comma));
        if comma && !self.settings.is_open() {
            self.open_settings();
        }
        if self.settings.is_open() {
            let about = self.about_info();
            self.settings.set_about(about);
            self.settings.set_geo(self.geo_store.info());
            self.settings.set_intel(self.intel_store.info());
        }
        if self.geo_store.poll() {
            self.resolver.reload_geo();
            self.hosts.invalidate();
            self.map.invalidate();
        }
        if self.intel_store.poll(ctx) {
            self.on_intel_changed(ctx);
        }
        match self.settings.ui(ctx) {
            Some(SettingsAction::Preview(s)) => apply_visuals(ctx, &s),
            Some(SettingsAction::Apply(s)) => {
                apply_visuals(ctx, &s);
                self.prefs.settings = s;
                self.prefs.save();
                self.apply_capture_defaults();
                self.apply_runtime_settings();
            }
            Some(SettingsAction::Cancel(orig)) => apply_visuals(ctx, &orig),
            Some(SettingsAction::OpenConfigDir) => self.open_config_dir(),
            Some(SettingsAction::Geo(action)) => self.run_geo_action(action, ctx),
            Some(SettingsAction::Intel(action)) => self.run_intel_action(action, ctx),
            None => {}
        }
    }

    fn run_geo_action(&mut self, action: GeoAction, ctx: &egui::Context) {
        match action {
            GeoAction::Download(id) => self.geo_store.download(&id, ctx),
            GeoAction::AddFile => self.geo_store.pick_file(ctx),
            GeoAction::Remove(id) => {
                self.geo_store.remove(&id);
                self.resolver.reload_geo();
                self.hosts.invalidate();
                self.map.invalidate();
            }
            GeoAction::OpenFolder => {
                if let Err(e) = self.geo_store.open_folder() {
                    self.startup_error = Some(e);
                }
            }
        }
    }

    fn run_intel_action(&mut self, action: IntelAction, ctx: &egui::Context) {
        match action {
            IntelAction::AddFile => self.intel_store.pick_file(ctx),
            IntelAction::Reload => self.intel_store.reload(ctx),
            IntelAction::OpenFolder => {
                if let Err(e) = self.intel_store.open_folder() {
                    self.startup_error = Some(e);
                }
            }
        }
    }

    fn on_intel_changed(&mut self, ctx: &egui::Context) {
        let intel = self.intel_store.current();
        self.web_link.set_intel(intel.clone());
        self.hub.set_intel(intel, self.ctrl.backing(), ctx);
        self.hosts.invalidate();
    }

    fn open_config_dir(&mut self) {
        let Some(dir) = Prefs::path().and_then(|p| p.parent().map(|d| d.to_path_buf())) else {
            return;
        };
        if let Err(e) = std::fs::create_dir_all(&dir).and_then(|()| {
            std::process::Command::new("xdg-open")
                .arg(&dir)
                .spawn()
                .map(drop)
        }) {
            self.startup_error = Some(format!("Could not open {}: {e}", dir.display()));
        }
    }

    /// Hides the findings matching `pattern` from now on (undone in Settings > Insights).
    pub(crate) fn mute_finding(&mut self, pattern: &str, ctx: &egui::Context) {
        if self.prefs.settings.insights.mute(pattern) {
            self.hub.rules = self.prefs.settings.insights.clone();
            self.prefs.save();
            toast::push(ctx, format!("Muted {pattern}"));
        }
    }

    /// Ctrl+K palette / shortcut theme flip: dark <-> light, persisted, with a brief toast.
    pub(crate) fn toggle_theme(&mut self, ctx: &egui::Context) {
        let next = match theme::mode() {
            theme::Mode::Dark => ThemeChoice::Light,
            theme::Mode::Light => ThemeChoice::Dark,
        };
        self.prefs.settings.theme = next;
        apply_visuals(ctx, &self.prefs.settings);
        self.prefs.save();
        toast::push(ctx, format!("{next:?} theme"));
    }
}
