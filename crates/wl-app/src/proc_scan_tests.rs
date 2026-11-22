use std::os::unix::fs::symlink;
use std::path::Path;

use wl_model::{FlowKey, Transport};

use super::scan;

const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0F02A8C0:C350 22D8B85D:01BB 01 00000000:00000000 02:000A1B2C 00000000  1000        0 33003 2 0000000000000000 20 4 30 10 -1
   1: 0F02A8C0:C351 5DB8D822:0050 01 00000000:00000000 02:000A1B2C 00000000     0        0 44004 2 0000000000000000 20 4 30 10 -1
";

fn process(root: &Path, pid: &str, comm: &str, fds: &[(&str, &str)]) {
    let dir = root.join(pid);
    std::fs::create_dir_all(dir.join("fd")).expect("fd dir");
    std::fs::write(dir.join("comm"), format!("{comm}\n")).expect("comm");
    for (n, target) in fds {
        symlink(target, dir.join("fd").join(n)).expect("link");
    }
}

fn flow(local_port: u16, remote: &str, remote_port: u16) -> FlowKey {
    FlowKey {
        a: "192.168.2.15".into(),
        b: remote.into(),
        transport: Transport::Tcp,
        a_port: Some(local_port),
        b_port: Some(remote_port),
    }
}

#[test]
fn joins_sockets_with_fd_links_and_comm() {
    let root = tempfile::tempdir().expect("tmp");
    let p = root.path();
    std::fs::create_dir_all(p.join("net")).expect("net");
    std::fs::write(p.join("net/tcp"), TCP).expect("tcp");
    process(
        p,
        "1234",
        "firefox",
        &[
            ("3", "socket:[33003]"),
            ("4", "/dev/null"),
            ("5", "pipe:[9]"),
        ],
    );
    let map = scan(p);
    let hit = map.for_flow(&flow(50000, "93.184.216.34", 443));
    assert_eq!(hit.map(|i| (i.pid, &*i.name)), Some((1234, "firefox")));
    assert_eq!(map.for_host("93.184.216.34").len(), 1);
}

#[test]
fn unreadable_or_foreign_processes_are_skipped_without_failing() {
    let root = tempfile::tempdir().expect("tmp");
    let p = root.path();
    std::fs::create_dir_all(p.join("net")).expect("net");
    std::fs::write(p.join("net/tcp"), TCP).expect("tcp");
    std::fs::create_dir_all(p.join("1")).expect("pid without fd dir");
    std::fs::create_dir_all(p.join("self")).expect("non-numeric entry");
    process(p, "77", "curl", &[("3", "socket:[44004]")]);
    let map = scan(p);
    assert!(map.for_flow(&flow(50000, "93.184.216.34", 443)).is_none());
    assert_eq!(
        map.for_flow(&flow(50001, "34.216.184.93", 80))
            .map(|i| i.pid),
        Some(77)
    );
}

#[test]
fn missing_proc_yields_an_empty_map() {
    assert!(scan(Path::new("/nonexistent-proc-root")).is_empty());
}
