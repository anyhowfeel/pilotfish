use std::ffi::OsString;
use std::path::Path;

const LEGACY_NAME: &str = "wirelens";
const LEGACY_PREFIX: &str = "WIRELENS_";

/// Value of `PILOTFISH_<name>`, falling back to the variable of the former name.
pub fn env_override(name: &str) -> Option<OsString> {
    std::env::var_os(format!("PILOTFISH_{name}"))
        .or_else(|| std::env::var_os(format!("{LEGACY_PREFIX}{name}")))
}

/// Moves the per-user folders of the former name to the new one, unless the new one exists.
pub fn migrate_legacy_dirs() {
    for base in [dirs::config_dir(), dirs::data_dir()].into_iter().flatten() {
        move_dir(&base.join(LEGACY_NAME), &base.join("pilotfish"));
    }
}

fn move_dir(old: &Path, new: &Path) {
    if old.is_dir() && !new.exists() {
        let _ = std::fs::rename(old, new);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_folder_moves_once_and_never_over_a_new_one() {
        let base = tempfile::tempdir().expect("tempdir");
        let (old, new) = (base.path().join(LEGACY_NAME), base.path().join("pilotfish"));
        std::fs::create_dir(&old).expect("old");
        std::fs::write(old.join("prefs.json"), "{}").expect("file");
        move_dir(&old, &new);
        assert!(new.join("prefs.json").exists() && !old.exists());

        std::fs::create_dir(&old).expect("old again");
        move_dir(&old, &new);
        assert!(old.exists(), "an existing new folder is left alone");
    }
}
