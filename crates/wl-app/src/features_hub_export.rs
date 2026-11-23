//! File exports (CSV / JSON / HTML) of `FeaturesHub`, run off the UI thread.
use super::*;

impl FeaturesHub {
    fn spawn_save(
        &self,
        name: &'static str,
        ext: &'static str,
        ctx: egui::Context,
        write_fn: impl FnOnce(&PathBuf) -> Result<String, String> + Send + 'static,
    ) {
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            if let Some(p) = rfd::FileDialog::new()
                .set_file_name(name)
                .add_filter(ext, &[ext])
                .save_file()
            {
                let _ = tx.try_send((None, Msg::ExportDone(write_fn(&p))));
                ctx.request_repaint();
            }
        });
    }

    pub fn export_csv(&self, rows: Vec<PacketRow>, ctx: egui::Context) {
        self.spawn_save("packets.csv", "csv", ctx, move |p| {
            write_packets_csv(p, &rows)
                .map(|()| format!("Exported CSV to {}", p.display()))
                .map_err(|e| e.to_string())
        });
    }

    pub fn export_json(&self, stats: Arc<StatsSnapshot>, ctx: egui::Context) {
        let insights = self.insights_for(&stats);
        self.spawn_save("stats.json", "json", ctx, move |p| {
            write_stats_json(p, &stats, &insights)
                .map(|()| format!("Exported JSON to {}", p.display()))
                .map_err(|e| e.to_string())
        });
    }

    pub fn export_html(
        &self,
        title: String,
        stats: Arc<StatsSnapshot>,
        file: Option<PathBuf>,
        ctx: egui::Context,
    ) {
        let insights = self.insights_for(&stats);
        let (phs, expert, bms) = (
            self.analyses.hierarchy.ready().cloned(),
            self.analyses.expert.ready().cloned(),
            self.bookmarks.all(),
        );
        let tshark = self.tshark.clone();
        self.spawn_save("report.html", "html", ctx, move |p| {
            let bms = match tshark.get() {
                Ok(b) => crate::report_bookmarks::load(&*b, file.as_deref(), &bms),
                Err(_) => crate::report_bookmarks::join(&bms, &[]),
            };
            write_html_report(
                p,
                &title,
                &stats,
                &insights,
                phs.as_ref(),
                expert.as_ref(),
                &bms,
            )
            .map(|()| format!("Saved report to {}", p.display()))
            .map_err(|e| e.to_string())
        });
    }

    /// Saves a copy of `file` whose packet comments are the bookmark comments.
    pub fn save_comments(&self, file: PathBuf, ctx: egui::Context) {
        let (tshark, bms) = (self.tshark.clone(), self.bookmarks.all());
        self.spawn_save("annotated.pcapng", "pcapng", ctx, move |p| {
            let b = crate::wireshark::require(&tshark, "Saving comments")?;
            b.save_with_comments(&file, &bms, p)
                .map(|()| format!("Saved annotated capture to {}", p.display()))
                .map_err(|e| e.to_string())
        });
    }
}
