use wl_kit::egui::{Grid, RichText, Ui};
use wl_kit::theme::{Palette, mono, spacing};
use wl_kit::widgets::{badge, section_header};
use wl_stats::{Metric, Presence, Row};

/// Rows drawn per section, to keep frames short on huge diffs.
const MAX_ROWS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Show {
    #[default]
    All,
    Added,
    Removed,
    Changed,
}

impl Show {
    pub fn admits(self, p: Presence) -> bool {
        match self {
            Show::All => true,
            Show::Added => p == Presence::Added,
            Show::Removed => p == Presence::Removed,
            Show::Changed => p == Presence::Changed,
        }
    }
}

fn tag(p: Presence) -> (&'static str, wl_kit::egui::Color32) {
    match p {
        Presence::Added => ("new", Palette::ok()),
        Presence::Removed => ("gone", Palette::danger()),
        Presence::Changed => ("diff", Palette::warn()),
    }
}

pub fn section<V: Metric>(
    ui: &mut Ui,
    title: &str,
    rows: &[Row<V>],
    fmt: fn(&V) -> String,
    show: Show,
) {
    let shown: Vec<&Row<V>> = rows.iter().filter(|r| show.admits(r.presence())).collect();
    if shown.is_empty() {
        return;
    }
    ui.add_space(spacing::SM);
    section_header(ui, &format!("{title} ({})", shown.len()));
    Grid::new(title)
        .num_columns(4)
        .striped(true)
        .show(ui, |ui| {
            for r in shown.iter().take(MAX_ROWS) {
                let (label, color) = tag(r.presence());
                badge(ui, label, color);
                ui.label(mono(&r.label));
                let cell = |v: &Option<V>| v.as_ref().map_or("-".to_owned(), fmt);
                ui.label(RichText::new(cell(&r.before)).color(Palette::muted()));
                ui.label(cell(&r.after));
                ui.end_row();
            }
        });
    if shown.len() > MAX_ROWS {
        let more = shown.len() - MAX_ROWS;
        ui.label(RichText::new(format!("{more} more not shown")).color(Palette::muted()));
    }
}
