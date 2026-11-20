//! Capture > Options form, shared by the Setup page and the Settings dialog (one code path).
//! Interface selection and the capture filter live on the Setup page; everything else is here.

use wl_kit::egui::Ui;
use wl_kit::widgets::{number_row, settings_card, text_row, toggle_row};
use wl_model::{CaptureOptions, SNAPLEN_MAX};

/// Draws the option cards. Returns true when anything changed.
pub fn capture_options(ui: &mut Ui, o: &mut CaptureOptions) -> bool {
    let mut changed = false;
    settings_card(ui, "Interface", |ui| {
        changed |= toggle_row(
            ui,
            true,
            "Promiscuous mode",
            "Capture traffic not addressed to this machine.",
            &mut o.promiscuous,
        );
        changed |= toggle_row(
            ui,
            false,
            "Monitor mode",
            "Wi-Fi only (dumpcap -I). Needs a capable adapter and root or CAP_NET_ADMIN.",
            &mut o.monitor,
        );
        changed |= number_row(
            ui,
            false,
            "Snap length",
            "Bytes kept per packet.",
            &mut o.snaplen,
            64..=SNAPLEN_MAX,
            " B",
        );
        changed |= number_row(
            ui,
            false,
            "Buffer size",
            "Kernel capture buffer. 0 = driver default.",
            &mut o.buffer_mb,
            0..=4096,
            " MB",
        );
    });
    settings_card(ui, "Output", |ui| {
        changed |= text_row(
            ui,
            true,
            "Save to",
            "Keep the capture at this path. Empty = temporary file.",
            &mut o.save_to,
            "/home/me/captures/run.pcapng",
        );
        changed |= toggle_row(
            ui,
            false,
            "Ring buffer",
            "Rotate over several files; the oldest is deleted first.",
            &mut o.ring.enabled,
        );
        if o.ring.enabled {
            changed |= ring_rows(ui, o);
        }
    });
    settings_card(ui, "Auto-stop (0 = never)", |ui| {
        changed |= number_row(
            ui,
            true,
            "After packets",
            "",
            &mut o.stop.packets,
            0..=100_000_000,
            "",
        );
        changed |= number_row(
            ui,
            false,
            "After size",
            "",
            &mut o.stop.mb,
            0..=100_000,
            " MB",
        );
        changed |= number_row(
            ui,
            false,
            "After duration",
            "",
            &mut o.stop.secs,
            0..=864_000,
            " s",
        );
    });
    changed
}

fn ring_rows(ui: &mut Ui, o: &mut CaptureOptions) -> bool {
    let r = &mut o.ring;
    let mut changed = number_row(
        ui,
        false,
        "File size",
        "Start a new file after this much data. 0 = no limit.",
        &mut r.file_mb,
        0..=100_000,
        " MB",
    );
    changed |= number_row(
        ui,
        false,
        "File duration",
        "Start a new file after this long. 0 = no limit.",
        &mut r.secs,
        0..=864_000,
        " s",
    );
    changed |= number_row(ui, false, "Files kept", "", &mut r.files, 2..=10_000, "");
    changed
}

/// One-line summary of the non-default choices ("promisc off \u{b7} ring 10x100 MB").
pub fn summary(o: &CaptureOptions) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(if o.promiscuous {
        "promiscuous".into()
    } else {
        "non-promiscuous".into()
    });
    if o.monitor {
        parts.push("monitor".into());
    }
    if o.snaplen < SNAPLEN_MAX {
        parts.push(format!("snaplen {}", o.snaplen));
    }
    if o.ring.enabled {
        parts.push(format!("ring {}x{} MB", o.ring.files, o.ring.file_mb));
    }
    if o.stop.packets + o.stop.mb + o.stop.secs > 0 {
        parts.push("auto-stop".into());
    }
    parts.join(" \u{b7} ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_lists_only_what_differs() {
        let mut o = CaptureOptions::default();
        assert_eq!(summary(&o), "promiscuous");
        o.promiscuous = false;
        o.monitor = true;
        o.snaplen = 96;
        o.ring.enabled = true;
        o.stop.secs = 5;
        assert_eq!(
            summary(&o),
            "non-promiscuous \u{b7} monitor \u{b7} snaplen 96 \u{b7} ring 10x100 MB \u{b7} auto-stop"
        );
    }
}
