//! Where Wireshark's command-line tools are looked for. The search is pure (OS, environment and
//! file existence are parameters) so every OS is tested on any host; `find_tool` reads the real ones.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use wl_model::HostOs;

use crate::login_path::login_shell_path;

/// Folders the official installers and package managers use, for when PATH lacks them.
pub(crate) fn fallback_dirs(
    os: HostOs,
    home: Option<&Path>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Vec<PathBuf> {
    let bundle = "Wireshark.app/Contents/MacOS";
    let mut dirs: Vec<PathBuf> = Vec::new();
    match os {
        HostOs::Mac => {
            dirs.push(Path::new("/Applications").join(bundle));
            dirs.extend(home.map(|h| h.join("Applications").join(bundle)));
            dirs.extend(
                ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"].map(PathBuf::from),
            );
        }
        HostOs::Windows => {
            let vars = ["ProgramFiles", "ProgramFiles(x86)"];
            dirs.extend(
                vars.iter()
                    .filter_map(|v| env(v))
                    .map(|d| Path::new(&d).join("Wireshark")),
            );
            dirs.extend(
                env("LOCALAPPDATA").map(|d| Path::new(&d).join("Programs").join("Wireshark")),
            );
        }
        HostOs::Linux => {
            dirs.extend(["/usr/bin", "/usr/local/bin", "/usr/sbin", "/sbin"].map(PathBuf::from));
        }
    }
    dirs
}

pub(crate) fn exe_name(os: HostOs, name: &str) -> String {
    if os == HostOs::Windows {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

/// First existing `name` in `order`. Relative entries are skipped: they would resolve against
/// whatever folder the app was started in.
pub(crate) fn search(
    order: &[PathBuf],
    name: &str,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    order
        .iter()
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| exists(p))
}

/// Everything the lookup depends on, so tests can fake any of it.
pub(crate) struct Lookup<'a> {
    pub os: HostOs,
    pub dir: Option<&'a Path>,
    pub path_var: Option<OsString>,
    pub fallbacks: Vec<PathBuf>,
    pub login_path: &'a dyn Fn() -> Vec<PathBuf>,
    pub exists: Box<dyn Fn(&Path) -> bool + 'a>,
}

impl Lookup<'_> {
    /// Chosen folder, then PATH, then the OS folders, then (macOS only, and only when nothing
    /// else matched, since it starts a shell) the login shell PATH.
    pub(crate) fn find(&self, name: &str) -> Option<PathBuf> {
        let file = exe_name(self.os, name);
        let path: Vec<PathBuf> = self
            .path_var
            .iter()
            .flat_map(std::env::split_paths)
            .collect();
        let order: Vec<PathBuf> = self
            .dir
            .map(Path::to_path_buf)
            .into_iter()
            .chain(path)
            .chain(self.fallbacks.iter().cloned())
            .collect();
        search(&order, &file, &self.exists).or_else(|| {
            (self.os == HostOs::Mac)
                .then(|| search(&(self.login_path)(), &file, &self.exists))
                .flatten()
        })
    }
}

/// Looks `name` up on this machine. `dir` is the user's Wireshark folder, if any.
pub fn find_tool(dir: Option<&Path>, name: &str) -> Option<PathBuf> {
    let os = HostOs::current();
    let env = |v: &str| std::env::var(v).ok();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    Lookup {
        os,
        dir,
        path_var: std::env::var_os("PATH"),
        fallbacks: fallback_dirs(os, home.as_deref(), &env),
        login_path: &|| login_shell_path().to_vec(),
        exists: Box::new(|p| p.is_file()),
    }
    .find(name)
}

#[cfg(test)]
#[path = "tool_path_tests.rs"]
mod tests;
