//! Headless layout tests of the Setup page with a realistic ~30 interface machine.

use std::collections::HashMap;
use std::path::PathBuf;

use wl_kit::theme::Mode;
use wl_model::{Interface, SysInfo};

use super::activity::{Activity, ActivityMap};
use super::harness::run_extent;
use super::{CaptureSetup, SetupData};

fn iface(name: &str, desc: Option<&str>, sys: SysInfo, up: bool) -> Interface {
    Interface {
        name: name.into(),
        description: desc.map(Into::into),
        is_loopback: name == "lo",
        is_up: up,
        sys,
    }
}

fn sys(devtype: &str, physical: bool, wireless: bool, default_route: bool) -> SysInfo {
    SysInfo {
        present: true,
        devtype: devtype.into(),
        physical,
        wireless,
        arphrd: 1,
        speed_mbps: physical.then_some(1000),
        default_route,
    }
}

fn machine() -> Vec<Interface> {
    let mut v = vec![
        iface("wlan0", None, sys("wlan", true, true, true), true),
        iface("eth0", None, sys("", true, false, false), false),
        iface(
            "docker0",
            Some("Docker Bridge"),
            sys("bridge", false, false, false),
            true,
        ),
        iface("lo", Some("Loopback"), sys("", false, false, false), true),
        iface("any", None, SysInfo::default(), true),
    ];
    for i in 0..4 {
        let h = format!("br-{i:012x}");
        v.push(iface(
            &h,
            Some("Bridge"),
            sys("bridge", false, false, false),
            true,
        ));
        v.push(iface(
            &format!("veth{i}a1b2c3"),
            Some("Virtual Ethernet"),
            sys("veth", false, false, false),
            true,
        ));
        v.push(iface(
            &format!("tap-e165d89647{i}"),
            None,
            sys("", false, false, false),
            false,
        ));
    }
    for n in [
        "sshdump",
        "ciscodump",
        "udpdump",
        "wifidump",
        "randpkt",
        "dpauxmon",
        "bluetooth0",
        "nflog",
        "nfqueue",
        "dbus-system",
        "dbus-session",
    ] {
        v.push(iface(n, Some("remote capture"), SysInfo::default(), false));
    }
    v
}

fn activity() -> ActivityMap {
    let mut a = Activity::default();
    for i in 0..30 {
        a.push(f64::from(i % 7) * 12_345.0);
    }
    HashMap::from([("wlan0".to_string(), a.clone()), ("docker0".to_string(), a)])
}

#[test]
fn setup_page_fits_every_size_and_selects_the_default_route() {
    let ifs = machine();
    let act = activity();
    let tmp = std::env::temp_dir().join(format!("wl-setup-{}.pcapng", std::process::id()));
    std::fs::write(&tmp, vec![0u8; 4096]).expect("tmp file");
    let counts = HashMap::from([(std::fs::canonicalize(&tmp).expect("canon"), 1234)]);
    let recent = vec![
        tmp.clone(),
        tmp.clone(),
        PathBuf::from("/does/not/exist.pcap"),
    ];
    let mut setup = CaptureSetup::default();
    for mode in [Mode::Dark, Mode::Light] {
        for (w, h) in [(1000.0_f32, 640.0_f32), (1440.0, 900.0), (2560.0, 1440.0)] {
            for scale in [1.0_f32, 1.5] {
                setup.open_options_for_test();
                let right = run_extent(w, h, scale, mode, |ui| {
                    let data = SetupData {
                        interfaces: &ifs,
                        activity: &act,
                        recent: &recent,
                        pinned: &[],
                        packet_counts: &counts,
                        filter_status: None,
                        running: false,
                        paused: false,
                    };
                    setup.ui(ui, &data);
                });
                assert!(
                    right <= w / scale + 1.0,
                    "{mode:?} {w}x{h}@{scale}: painted up to x={right}"
                );
            }
        }
    }
    assert_eq!(setup.selected_interfaces(), ["wlan0"]);
    let _ = std::fs::remove_file(tmp);
}
