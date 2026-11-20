//! TCP stream graph tabs: direction picker, summary chips and the XY chart of one graph.

use wl_kit::charts::{Marker, SeriesStyle, XySeries, xy_chart};
use wl_kit::egui::{RichText, Ui};
use wl_kit::format;
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{chip_dot, empty_state, segmented_w};
use wl_model::TcpSamples;

use super::tabs::Tab;
use super::tcp_series::{self as series, Pts, Role, Summary};

/// Width from which the direction picker sits beside its label instead of below it.
const DIR_INLINE_W: f32 = 430.0;
/// Smallest chart; when the controls leave less, the view scrolls.
const MIN_CHART_H: f32 = 160.0;

#[derive(Default)]
pub struct TcpView {
    /// Data direction (`true` = A to B); `None` until the busiest one is picked.
    dir: Option<bool>,
    cache: Option<((u64, Tab, bool), Vec<XySeries>)>,
}

fn style_of(role: Role, tab: Tab) -> (wl_kit::egui::Color32, SeriesStyle) {
    match role {
        Role::Main if matches!(tab, Tab::Rtt | Tab::Sequence) => {
            (Palette::accent(), SeriesStyle::Scatter(Marker::Circle))
        }
        Role::Main => (Palette::accent(), SeriesStyle::Line),
        Role::Ack => (Palette::series(1), SeriesStyle::Line),
        Role::Retransmission if tab == Tab::Throughput => (Palette::danger(), SeriesStyle::Line),
        Role::Retransmission => (Palette::danger(), SeriesStyle::Scatter(Marker::Diamond)),
        Role::DupAck => (Palette::warn(), SeriesStyle::Scatter(Marker::Up)),
        Role::ZeroWindow => (Palette::danger(), SeriesStyle::Scatter(Marker::Cross)),
    }
}

fn to_series(tab: Tab, parts: Vec<Pts>) -> Vec<XySeries> {
    parts
        .into_iter()
        .map(|p| {
            let (color, style) = style_of(p.role, tab);
            XySeries::new(p.name, color, style, p.points)
        })
        .collect()
}

/// Milliseconds as "850 \u{b5}s", "12.4 ms" or "1.20 s".
pub fn fmt_ms(ms: f64) -> String {
    match ms {
        m if m < 1.0 => format!("{:.0} \u{b5}s", m * 1000.0),
        m if m < 100.0 => format!("{m:.1} ms"),
        m if m < 1000.0 => format!("{m:.0} ms"),
        m => format!("{:.2} s", m / 1000.0),
    }
}

fn y_formatter(tab: Tab) -> fn(f64) -> String {
    match tab {
        Tab::Throughput => format::rate,
        Tab::Rtt => fmt_ms,
        _ => |v| format::bytes(v.max(0.0) as u64),
    }
}

fn summary_chips(ui: &mut Ui, s: &Summary) {
    let danger = |n: usize| (n > 0).then(Palette::danger);
    let warn = |n: usize| (n > 0).then(Palette::warn);
    let mut chips = vec![
        (
            format!("{} data segments", format::count(s.segments as u64)),
            None,
        ),
        (format::bytes(s.bytes), None),
        (
            format!("{} retransmissions", s.retransmissions),
            danger(s.retransmissions),
        ),
        (format!("{} dup ACKs", s.dup_acks), warn(s.dup_acks)),
    ];
    if let (Some(avg), Some(max)) = (s.rtt_mean_ms, s.rtt_max_ms) {
        chips.push((
            format!("RTT avg {}  max {}", fmt_ms(avg), fmt_ms(max)),
            None,
        ));
    }
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = wl_kit::egui::vec2(spacing::SM, spacing::SM);
        for (text, dot) in chips {
            chip_dot(ui, &text, false, dot);
        }
    });
}

impl TcpView {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// `page_h` is the height the whole view may use; the chart takes what the controls leave.
    pub fn ui(&mut self, ui: &mut Ui, tab: Tab, s: &TcpSamples, rev: u64, id: &str, page_h: f32) {
        let top = ui.cursor().min.y;
        if s.samples.is_empty() {
            empty_state(
                ui,
                "~",
                "No TCP packets",
                "This selection has no TCP segments to plot.",
            );
            return;
        }
        let dir = *self.dir.get_or_insert_with(|| series::busiest(s));
        let mut d = dir;
        let long = |addr: &str, port: Option<u16>| match port {
            Some(p) => format!("{addr}:{p}"),
            None => addr.to_owned(),
        };
        let (a, b) = (long(&s.a, s.a_port), long(&s.b, s.b_port));
        let options = [
            (true, format!("{a}  ->  {b}")),
            (false, format!("{b}  ->  {a}")),
        ];
        let opts: Vec<(bool, &str)> = options.iter().map(|(v, t)| (*v, t.as_str())).collect();
        let label = RichText::new("Data direction").color(Palette::muted());
        let inline = ui.available_width() >= DIR_INLINE_W;
        let mut picker = |ui: &mut Ui| {
            let w = ui.available_width().min(560.0);
            ui.push_id("tcp_dir", |ui| segmented_w(ui, &mut d, &opts, w));
        };
        if inline {
            // The label and the 28 pt control share one centred row (a plain `horizontal` leaves
            // the label above the control's middle).
            wl_kit::widgets::centered_row(ui, 28.0, |ui| {
                ui.label(label);
                picker(ui);
            });
        } else {
            ui.label(label);
            picker(ui);
        }
        self.dir = Some(d);
        ui.add_space(spacing::SM);
        summary_chips(ui, &series::summary(s, d));
        ui.add_space(spacing::SM);
        let key = (rev, tab, d);
        if self.cache.as_ref().map(|c| c.0) != Some(key) {
            let parts = match tab {
                Tab::Sequence => series::time_sequence(s, d),
                Tab::Throughput => series::throughput(s, d),
                Tab::Rtt => series::rtt(s, d),
                _ => series::window(s, d),
            };
            self.cache = Some((key, to_series(tab, parts)));
        }
        let Some((_, plot)) = &self.cache else { return };
        if plot.iter().all(XySeries::is_empty) {
            let hint = "No samples for this graph in the chosen direction.";
            empty_state(ui, "~", "Nothing to plot", hint);
            return;
        }
        let hint_h = ui.text_style_height(&wl_kit::egui::TextStyle::Small);
        let reserve = spacing::XS + hint_h + 2.0 * ui.spacing().item_spacing.y;
        let used = ui.cursor().min.y - top;
        let h = (page_h - used - reserve).max(MIN_CHART_H);
        let plot_id = format!("{id}-{tab:?}-{d}");
        xy_chart(ui, &plot_id, plot, &y_formatter(tab), h);
        ui.add_space(spacing::XS);
        ui.label(
            RichText::new("Drag a box to zoom, double-click to reset.")
                .small()
                .color(Palette::muted()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn milliseconds_scale() {
        assert_eq!(fmt_ms(0.25), "250 \u{b5}s");
        assert_eq!(fmt_ms(12.34), "12.3 ms");
        assert_eq!(fmt_ms(250.0), "250 ms");
        assert_eq!(fmt_ms(1500.0), "1.50 s");
    }
}
