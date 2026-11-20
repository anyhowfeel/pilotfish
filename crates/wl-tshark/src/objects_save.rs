//! Saving extracted objects. Writes never leave the chosen directory: names are sanitised again
//! here, collisions get a numeric suffix and existing files are never overwritten.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use wl_model::{ExportObject, ObjectSet, sanitize_filename};

/// Reads at most `max` bytes of an extracted object (previews).
pub fn read_head(set: &ObjectSet, o: &ExportObject, max: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    open_inside(&set.dir, &o.path)?
        .take(max as u64)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// Opens `path` only when it is a regular file directly inside `dir` (no symlink games).
fn open_inside(dir: &Path, path: &Path) -> io::Result<fs::File> {
    if path.parent() != Some(dir) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "object is outside its directory",
        ));
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    fs::File::open(path)
}

/// `name`, `name(1)`, `name(2)` ... the first one that does not exist in `dir`.
fn free_name(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    (1..)
        .map(|n| dir.join(format!("{name}({n})")))
        .find(|p| !p.exists())
        .unwrap_or(first)
}

/// Copies one object to exactly `dest` (a path the user picked in a save dialog).
pub fn save_as(set: &ObjectSet, o: &ExportObject, dest: &Path) -> io::Result<()> {
    let mut src = open_inside(&set.dir, &o.path)?;
    let mut out = fs::File::create(dest)?;
    io::copy(&mut src, &mut out).map(|_| ())
}

/// Copies every object into `dir` under its sanitised name; returns how many were written.
pub fn save_all(set: &ObjectSet, dir: &Path) -> io::Result<usize> {
    let mut n = 0;
    for o in &set.objects {
        let mut src = open_inside(&set.dir, &o.path)?;
        let target = free_name(dir, &sanitize_filename(&o.save_name));
        debug_assert_eq!(target.parent(), Some(dir));
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        io::copy(&mut src, &mut out)?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_with(dir: &Path, names: &[(&str, &str)]) -> ObjectSet {
        let objects = names
            .iter()
            .enumerate()
            .map(|(i, (file, save))| {
                fs::write(dir.join(file), format!("data{i}")).expect("w");
                ExportObject {
                    id: i as u32,
                    name: (*save).into(),
                    save_name: (*save).into(),
                    content_type: String::new(),
                    size: 5,
                    host: String::new(),
                    packet: None,
                    path: dir.join(file),
                }
            })
            .collect();
        ObjectSet {
            protocol: "http".into(),
            dir: dir.to_path_buf(),
            objects,
            truncated: false,
        }
    }

    #[test]
    fn save_all_stays_inside_and_never_overwrites() {
        let src = tempfile::tempdir().expect("s");
        let dst = tempfile::tempdir().expect("d");
        let set = set_with(
            src.path(),
            &[("a", "../../evil"), ("b", "same.txt"), ("c", "same.txt")],
        );
        assert_eq!(save_all(&set, dst.path()).expect("save"), 3);
        let mut names: Vec<String> = fs::read_dir(dst.path())
            .expect("ls")
            .map(|e| e.expect("e").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["_.._evil", "same.txt", "same.txt(1)"]);
        assert!(!dst.path().join("..").join("evil").exists());
    }

    #[test]
    fn refuses_objects_outside_their_directory_and_symlinks() {
        let src = tempfile::tempdir().expect("s");
        let other = tempfile::tempdir().expect("o");
        fs::write(other.path().join("secret"), "x").expect("w");
        let mut set = set_with(src.path(), &[("a", "a")]);
        set.objects[0].path = other.path().join("secret");
        assert!(read_head(&set, &set.objects[0], 10).is_err());
        let link = src.path().join("link");
        std::os::unix::fs::symlink(other.path().join("secret"), &link).expect("ln");
        set.objects[0].path = link;
        assert!(read_head(&set, &set.objects[0], 10).is_err());
    }

    #[test]
    fn read_head_is_bounded() {
        let src = tempfile::tempdir().expect("s");
        let set = set_with(src.path(), &[("a", "a")]);
        assert_eq!(read_head(&set, &set.objects[0], 2).expect("r"), b"da");
    }
}
