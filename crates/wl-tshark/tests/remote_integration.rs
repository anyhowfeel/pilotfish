//! Remote capture through a fake `ssh` that replays a fixture pcap (needs tshark; no network).
//! The scenarios run in a re-executed copy of this test binary because `PATH` cannot be changed
//! in-process without `unsafe`.
mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::{backend, collect};
use wl_model::{CaptureBackend, CaptureError, CaptureEvent, CaptureOptions, CaptureSource};

const CHILD: &str = "scenario_child";
const FIXTURE_PACKETS: usize = 75;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/behavior.pcap")
}

fn fake_ssh(dir: &Path, body: &str) {
    let path = dir.join("ssh");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write ssh");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn run_scenario(name: &str, ssh_body: &str) -> (PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tmp");
    fake_ssh(dir.path(), ssh_body);
    let path = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", CHILD, "--nocapture", "--test-threads=1"])
        .env("PATH", path)
        .env("WL_REMOTE_SCENARIO", name)
        .env("WL_REMOTE_DIR", dir.path())
        .output()
        .expect("spawn child");
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (dir.path().join("args"), dir)
}

fn options() -> CaptureOptions {
    let mut o = CaptureOptions::single("ignored", Some("port 53; id"));
    o.remote.enabled = true;
    o.remote.host = "198.51.100.7".into();
    o.remote.user = "ops".into();
    o.remote.port = 2222;
    o.remote.interface = "eth0".into();
    o.remote.sudo = true;
    o
}

#[test]
fn replayed_capture_reaches_the_model() {
    if backend().is_none() {
        return;
    }
    let body = format!(
        "printf '%s\\n' \"$@\" > \"$WL_REMOTE_DIR/args\"\ncat {}\nsleep 1",
        fixture().display()
    );
    let (args, _dir) = run_scenario("replay", &body);
    let args = std::fs::read_to_string(args).expect("args");
    assert!(args.contains("BatchMode=yes"), "{args}");
    assert!(args.contains("2222\n--\nops@198.51.100.7\n"), "{args}");
    assert!(
        args.contains("sudo -n tcpdump -U -n -i 'eth0' -w - -- 'port 53; id'"),
        "{args}"
    );
}

#[test]
fn ssh_auth_failure_is_reported() {
    if backend().is_none() {
        return;
    }
    run_scenario(
        "auth",
        "echo 'ops@198.51.100.7: Permission denied (publickey).' >&2\nsleep 1\nexit 255",
    );
}

#[test]
fn missing_tcpdump_is_reported() {
    if backend().is_none() {
        return;
    }
    run_scenario(
        "no-tcpdump",
        "echo 'bash: tcpdump: command not found' >&2\nsleep 1\nexit 127",
    );
}

#[test]
fn stop_terminates_a_hanging_ssh() {
    if backend().is_none() {
        return;
    }
    let body = format!("cat {}\nexec sleep 60", fixture().display());
    run_scenario("stop", &body);
}

fn stop_scenario(b: &impl CaptureBackend) {
    let mut session = b
        .start(CaptureSource::Capture(options()), None)
        .expect("start");
    let first = session
        .events
        .recv_timeout(Duration::from_secs(10))
        .expect("rows before stop");
    assert!(matches!(first, CaptureEvent::Rows(_)));
    let t = Instant::now();
    (session.stop)();
    assert!(t.elapsed() < Duration::from_secs(5), "stop hung");
}

#[test]
fn scenario_child() {
    let (Ok(name), Some(b)) = (std::env::var("WL_REMOTE_SCENARIO"), backend()) else {
        return;
    };
    if name == "stop" {
        return stop_scenario(&b);
    }
    let session = b
        .start(CaptureSource::Capture(options()), None)
        .expect("start");
    let (rows, err) = collect(&session);
    match name.as_str() {
        "replay" => {
            assert!(err.is_none(), "{err:?}");
            assert_eq!(rows.len(), FIXTURE_PACKETS);
            assert_eq!(rows[0].no, 1);
        }
        "auth" => assert!(
            matches!(err, Some(CaptureError::Permission(m)) if m.contains("authentication"))
        ),
        "no-tcpdump" => {
            assert!(matches!(err, Some(CaptureError::Other(m)) if m.contains("not installed")))
        }
        other => panic!("unknown scenario {other}"),
    }
}
