//! "A -> B" endpoints cell: both addresses on their own half of the column (ports muted), an
//! arrow between them, so the addresses line up from one row to the next.

use wl_kit::egui::text::{LayoutJob, TextFormat};
use wl_kit::egui::{self, Align, FontId, Layout, Sense, Stroke, TextStyle, Ui, pos2, vec2};
use wl_kit::table::cell_pad;
use wl_kit::theme::{Palette, row_h};
use wl_model::ConversationStat;

const ARROW_W: f32 = 28.0;
/// Cap per address so the arrow stays close to the first one on a very wide column.
const SIDE_MAX: f32 = 230.0;

fn endpoint(font: &FontId, addr: &str, port: Option<u16>) -> LayoutJob {
    let mut job = LayoutJob::default();
    let fmt = |c| TextFormat::simple(font.clone(), c);
    let host = if addr.contains(':') && port.is_some() {
        format!("[{addr}]")
    } else {
        addr.to_owned()
    };
    job.append(&host, 0.0, fmt(Palette::text()));
    if let Some(p) = port {
        job.append(&format!(":{p}"), 0.0, fmt(Palette::muted()));
    }
    job
}

fn half(ui: &mut Ui, w: f32, job: LayoutJob) {
    ui.allocate_ui_with_layout(
        vec2(w, row_h()),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.set_width(w);
            ui.add(egui::Label::new(job).truncate().selectable(false));
        },
    );
}

/// Draws the cell for one conversation.
pub fn endpoints_cell(ui: &mut Ui, c: &ConversationStat) {
    cell_pad(ui);
    let font = TextStyle::Body.resolve(ui.style());
    let free = (ui.available_width() - ARROW_W).max(80.0);
    let side = (free / 2.0).floor().min(SIDE_MAX);
    half(ui, side, endpoint(&font, &c.key.a, c.key.a_port));
    let (r, _) = ui.allocate_exact_size(vec2(ARROW_W, row_h()), Sense::hover());
    let (y, x0, x1) = (r.center().y, r.left() + 6.0, r.right() - 6.0);
    let s = Stroke::new(1.3, Palette::muted());
    let p = ui.painter();
    p.line_segment([pos2(x0, y), pos2(x1, y)], s);
    // A conversation goes both ways: a head at each end.
    for (tip, back) in [(x1, -4.5), (x0, 4.5)] {
        p.line_segment([pos2(tip, y), pos2(tip + back, y - 3.5)], s);
        p.line_segment([pos2(tip, y), pos2(tip + back, y + 3.5)], s);
    }
    half(ui, side, endpoint(&font, &c.key.b, c.key.b_port));
}
