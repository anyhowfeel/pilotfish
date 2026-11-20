//! SIGTERM / SIGINT / SIGHUP: reap capture children before dying so none is orphaned.
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

/// Spawns a watcher thread; on a termination signal it kills every tshark/dumpcap child and
/// exits with the conventional `128 + signo` status. Failure to install is non-fatal.
pub fn install() {
    let Ok(mut signals) = Signals::new([SIGTERM, SIGINT, SIGHUP]) else {
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("wl-signals".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                wl_tshark::kill_all_children();
                std::process::exit(128 + sig);
            }
        });
    drop(spawned);
}
