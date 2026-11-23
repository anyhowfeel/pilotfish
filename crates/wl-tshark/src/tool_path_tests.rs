use std::collections::HashSet;

use super::*;

fn files(list: &[&str]) -> HashSet<PathBuf> {
    list.iter().map(PathBuf::from).collect()
}

fn lookup<'a>(
    os: HostOs,
    dir: Option<&'a Path>,
    path_var: &str,
    present: &'a HashSet<PathBuf>,
    login: &'a dyn Fn() -> Vec<PathBuf>,
) -> Lookup<'a> {
    Lookup {
        os,
        dir,
        path_var: Some(path_var.into()),
        fallbacks: fallback_dirs(os, Some(Path::new("/Users/me")), &|_| None),
        login_path: login,
        exists: Box::new(move |p: &Path| present.contains(p)),
    }
}

fn no_login() -> Vec<PathBuf> {
    Vec::new()
}

#[test]
fn macos_fallbacks_start_with_the_app_bundle() {
    let d = fallback_dirs(HostOs::Mac, Some(Path::new("/Users/me")), &|_| None);
    let want: Vec<PathBuf> = [
        "/Applications/Wireshark.app/Contents/MacOS",
        "/Users/me/Applications/Wireshark.app/Contents/MacOS",
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/opt/local/bin",
    ]
    .map(PathBuf::from)
    .to_vec();
    assert_eq!(d, want);
}

#[test]
fn windows_fallbacks_come_from_the_environment() {
    let env = |v: &str| match v {
        "ProgramFiles" => Some("/pf".to_owned()),
        "LOCALAPPDATA" => Some("/lad".to_owned()),
        _ => None,
    };
    let d = fallback_dirs(HostOs::Windows, None, &env);
    assert_eq!(
        d,
        [
            Path::new("/pf").join("Wireshark"),
            Path::new("/lad").join("Programs").join("Wireshark")
        ]
    );
    assert_eq!(exe_name(HostOs::Windows, "tshark"), "tshark.exe");
    assert_eq!(exe_name(HostOs::Mac, "tshark"), "tshark");
}

#[test]
fn linux_fallbacks_are_the_system_folders() {
    let d = fallback_dirs(HostOs::Linux, None, &|_| None);
    assert_eq!(d.len(), 4);
    assert!(d.contains(&PathBuf::from("/usr/sbin")));
}

#[test]
fn path_wins_over_the_fallbacks() {
    let present = files(&["/p/tshark", "/opt/homebrew/bin/tshark"]);
    let l = lookup(HostOs::Mac, None, "/p", &present, &no_login);
    assert_eq!(l.find("tshark"), Some(PathBuf::from("/p/tshark")));
}

#[test]
fn the_fallbacks_are_used_when_path_is_minimal() {
    let present = files(&["/Applications/Wireshark.app/Contents/MacOS/tshark"]);
    let l = lookup(HostOs::Mac, None, "/usr/bin:/bin", &present, &no_login);
    assert_eq!(
        l.find("tshark"),
        Some(PathBuf::from(
            "/Applications/Wireshark.app/Contents/MacOS/tshark"
        ))
    );
}

#[test]
fn the_chosen_folder_wins_over_path() {
    let present = files(&["/p/tshark", "/mine/tshark"]);
    let l = lookup(
        HostOs::Linux,
        Some(Path::new("/mine")),
        "/p",
        &present,
        &no_login,
    );
    assert_eq!(l.find("tshark"), Some(PathBuf::from("/mine/tshark")));
}

#[test]
fn a_chosen_folder_without_the_tool_falls_through() {
    let present = files(&["/p/tshark"]);
    let l = lookup(
        HostOs::Linux,
        Some(Path::new("/mine")),
        "/p",
        &present,
        &no_login,
    );
    assert_eq!(l.find("tshark"), Some(PathBuf::from("/p/tshark")));
}

#[test]
fn relative_entries_are_never_searched() {
    let present = files(&["bin/tshark", "./tshark"]);
    let l = lookup(
        HostOs::Linux,
        Some(Path::new("rel")),
        "bin:.",
        &present,
        &no_login,
    );
    assert_eq!(l.find("tshark"), None);
}

#[test]
fn the_login_shell_is_asked_last_and_only_on_macos() {
    let present = files(&["/Users/me/bin/tshark"]);
    let login = || vec![PathBuf::from("/Users/me/bin")];
    let mac = lookup(HostOs::Mac, None, "/usr/bin", &present, &login);
    assert_eq!(
        mac.find("tshark"),
        Some(PathBuf::from("/Users/me/bin/tshark"))
    );
    let linux = lookup(HostOs::Linux, None, "/usr/bin", &present, &login);
    assert_eq!(linux.find("tshark"), None);

    let asked = std::cell::Cell::new(false);
    let spy = || {
        asked.set(true);
        Vec::new()
    };
    let found = files(&["/p/tshark"]);
    lookup(HostOs::Mac, None, "/p", &found, &spy).find("tshark");
    assert!(!asked.get(), "a match on PATH must not start a shell");
}

#[test]
fn windows_looks_for_exe_names() {
    let present = files(&["/pf/Wireshark/tshark.exe"]);
    let mut l = lookup(HostOs::Windows, None, "", &present, &no_login);
    l.fallbacks = vec![PathBuf::from("/pf/Wireshark")];
    assert_eq!(
        l.find("tshark"),
        Some(PathBuf::from("/pf/Wireshark/tshark.exe"))
    );
}

#[test]
fn the_wrapper_finds_a_file_in_a_chosen_folder() {
    let dir = tempfile::tempdir().expect("tempdir");
    let name = exe_name(HostOs::current(), "tshark");
    std::fs::write(dir.path().join(&name), "").expect("write");
    assert_eq!(
        find_tool(Some(dir.path()), "tshark"),
        Some(dir.path().join(name))
    );
}
