//! Files the commands read and write, and the paths they resolve: absolute and normalized without touching the disk,
//! so that a name leading out of a directory is recognised before anything is read or written.

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use crate::errors::{CommandFailure, UsageError};

/// The content of the file at `path`.
pub fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>, CommandFailure> {
    let path = path.as_ref();
    std::fs::read(path).map_err(|error| file_failure(path, &error))
}

/// Writes `content` to the file at `path`, replacing it.
pub fn write_file(path: impl AsRef<Path>, content: &[u8]) -> Result<(), CommandFailure> {
    let path = path.as_ref();
    std::fs::write(path, content).map_err(|error| file_failure(path, &error))
}

/// Creates `directory` and its parents.
pub fn create_directory(directory: &Path) -> Result<(), CommandFailure> {
    std::fs::create_dir_all(directory).map_err(|error| file_failure(directory, &error))
}

/// Refuses to replace an existing file unless `is_forced`.
pub fn check_writable(path: &str, is_forced: bool) -> Result<(), UsageError> {
    if Path::new(path).is_file() && !is_forced {
        return Err(UsageError::FileExists { path: path.to_owned() });
    }
    Ok(())
}

/// `path` made absolute against the current directory, with "." and ".." resolved by name (symbolic links are not
/// followed).
pub fn full_path(path: impl AsRef<Path>) -> Result<PathBuf, CommandFailure> {
    let path = path.as_ref();
    let absolute = std::path::absolute(path).map_err(|error| file_failure(path, &error))?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other),
        }
    }
    Ok(normalized)
}

/// True when `path` lies strictly inside `directory` (both full paths).
pub fn is_inside(path: &Path, directory: &Path) -> bool {
    path != directory && path.starts_with(directory)
}

/// The last component of `path`, or the whole text when there is none.
pub fn file_name(path: &str) -> String {
    match Path::new(path).file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => String::new(),
    }
}

/// The last component of `path` without its last extension.
pub fn file_stem(path: &str) -> String {
    match Path::new(path).file_stem() {
        Some(stem) => stem.to_string_lossy().into_owned(),
        None => String::new(),
    }
}

fn file_failure(path: &Path, error: &std::io::Error) -> CommandFailure {
    let shown = match std::path::absolute(path) {
        Ok(absolute) => absolute,
        Err(_) => path.to_path_buf(),
    };
    match error.kind() {
        ErrorKind::NotFound => CommandFailure::FileNotFound {
            path: shown.display().to_string(),
        },
        ErrorKind::PermissionDenied => CommandFailure::FileAccessDenied {
            path: shown.display().to_string(),
        },
        _ => CommandFailure::File {
            path: path.display().to_string(),
            reason: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_paths_resolve_parent_directories_by_name() {
        assert_eq!(full_path("/a/b/../c/./d").unwrap(), PathBuf::from("/a/c/d"));
        assert!(!is_inside(&full_path("/a/b/../../x").unwrap(), Path::new("/a/b")));
        assert!(is_inside(&full_path("/a/b/c/x").unwrap(), Path::new("/a/b")));
        assert!(!is_inside(Path::new("/a/b"), Path::new("/a/b")));
        assert!(!is_inside(Path::new("/a/bc"), Path::new("/a/b")));
    }

    #[test]
    fn names_and_stems_are_taken_from_the_last_component() {
        assert_eq!(file_name("/dir/doc.txt.p7s"), "doc.txt.p7s");
        assert_eq!(file_stem("/dir/doc.txt.p7s"), "doc.txt");
        assert_eq!(file_name("../outside.txt"), "outside.txt");
    }
}
