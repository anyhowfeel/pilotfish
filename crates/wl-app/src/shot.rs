//! Screenshot harness: wait, grab the framebuffer via eframe, write a PNG, exit.
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;

pub struct Shot {
    path: PathBuf,
    due: Instant,
    requested: bool,
}

impl Shot {
    pub fn new(path: PathBuf, wait_ms: u64) -> Shot {
        Shot {
            path,
            due: Instant::now() + Duration::from_millis(wait_ms),
            requested: false,
        }
    }

    /// Call once per frame.
    pub fn tick(&mut self, ctx: &egui::Context) {
        if Instant::now() < self.due {
            ctx.request_repaint_after(Duration::from_millis(50));
            return;
        }
        if !self.requested {
            self.requested = true;
            let path = self.path.clone();
            ctx.request_screenshot(move |img| {
                let code = save_png(&path, &img).map(|()| 0).unwrap_or_else(|e| {
                    eprintln!("screenshot failed: {e}");
                    1
                });
                std::process::exit(code);
            });
        }
        ctx.request_repaint_after(Duration::from_millis(50));
    }
}

fn save_png(path: &PathBuf, img: &egui::ColorImage) -> Result<(), image::ImageError> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    image::save_buffer(
        path,
        img.as_raw(),
        img.width() as u32,
        img.height() as u32,
        image::ColorType::Rgba8,
    )
}
