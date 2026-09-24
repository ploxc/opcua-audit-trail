//! Writing files that must survive a crash or power cut in one piece.

use std::io::Write;
use std::path::Path;

/// Writes `bytes` to `path` atomically and durably: into a temporary file in
/// the same directory, flushed to disk, renamed over `path`, and the
/// directory flushed. A crash leaves either the old or the new file.
///
/// On Unix, `mode` sets the file's permissions; without it the existing
/// file's permissions are kept (0600 for a new file).
pub fn write_atomic(path: &Path, bytes: &[u8], mode: Option<u32>) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mode = mode.unwrap_or_else(|| {
            std::fs::metadata(path)
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0o600)
        });
        options.mode(mode);
        let _ = std::fs::remove_file(&tmp);
        let mut file = options.open(&tmp)?;
        // `mode` is filtered by the umask on creation; set it exactly.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_the_file_and_keeps_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_atomic(&path, b"one", None).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        #[cfg(unix)]
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        #[cfg(unix)]
        {
            assert_eq!(mode(&path), 0o600, "new files are private");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        write_atomic(&path, b"two", None).unwrap();
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o640, "an existing mode is kept");
        write_atomic(&path, b"three", Some(0o600)).unwrap();
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"three");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temporary file left"
        );
    }
}
