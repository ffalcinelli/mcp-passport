//! # Log directory setup
//!
//! Log files can contain session ids and request metadata, so the directory must
//! be private to the current user. On Unix it is created with mode `0o700`, and
//! an existing directory is accepted only if it is not a symlink and we can
//! restrict it to `0o700` (which fails unless we own it). This defeats a
//! pre-created or symlinked directory planted by another local user.

use crate::Result;
use anyhow::{bail, Context};
use std::path::Path;

/// Creates `dir` if needed and makes sure only the current user can access it.
pub fn prepare_log_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("Failed to create log directory {}", dir.display()))?;

        let meta = std::fs::symlink_metadata(dir)
            .with_context(|| format!("Failed to inspect log directory {}", dir.display()))?;
        if meta.file_type().is_symlink() {
            bail!(
                "Log directory {} is a symlink; refusing to use it",
                dir.display()
            );
        }
        if !meta.is_dir() {
            bail!("Log directory {} is not a directory", dir.display());
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "Log directory {} is not owned by the current user",
                    dir.display()
                )
            },
        )?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create log directory {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mcp-passport-logtest-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_creates_private_directory() {
        let base = scratch();
        let dir = base.join("a/b/logs");
        prepare_log_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn test_tightens_existing_directory() {
        let base = scratch();
        let dir = base.join("logs");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        prepare_log_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn test_rejects_symlink() {
        let base = scratch();
        let target = base.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let link = base.join("logs");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = prepare_log_dir(&link).unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn test_rejects_file() {
        let base = scratch();
        let file = base.join("logs");
        std::fs::write(&file, b"").unwrap();
        assert!(prepare_log_dir(&file).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }
}
