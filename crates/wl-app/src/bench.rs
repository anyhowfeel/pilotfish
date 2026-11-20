//! `--bench-frames`: records frame times, prints summary statistics, and exits.
use std::time::Instant;

pub struct Bench {
    target: u32,
    last: Instant,
    times: Vec<f32>,
}

impl Bench {
    pub fn new(target: u32) -> Self {
        Self {
            target,
            last: Instant::now(),
            times: Vec::new(),
        }
    }

    pub fn tick(&mut self) {
        let now = Instant::now();
        self.times
            .push(now.duration_since(self.last).as_secs_f32() * 1000.0);
        self.last = now;
        if self.times.len() as u32 >= self.target {
            report(&self.times);
        }
    }
}

pub fn report(times: &[f32]) {
    // Skip the first frames (startup, font atlas).
    let mut t: Vec<f32> = times.iter().skip(5).copied().collect();
    if t.is_empty() {
        t = times.to_vec();
    }
    t.sort_by(f32::total_cmp);
    let avg = t.iter().sum::<f32>() / t.len() as f32;
    let p95 = t[(t.len() as f32 * 0.95) as usize % t.len()];
    println!(
        "frames={} avg_ms={avg:.2} p95_ms={p95:.2} max_ms={:.2}",
        t.len(),
        t[t.len() - 1]
    );
    std::process::exit(0);
}
