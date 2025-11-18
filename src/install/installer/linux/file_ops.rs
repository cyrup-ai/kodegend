//! Atomic file operations for Linux systemd configuration.
//!
//! This module provides safe, atomic file writing operations to prevent
//! configuration corruption during installation.

use std::fs;
use std::io::Write;
use std::path::Path;

use super::InstallerError;

/// Write file atomically to prevent corruption
pub(super) fn write_file_atomic(path: &Path, content: &str) -> Result<(), InstallerError> {
    let temp_path = path.with_extension("tmp");

    {
        let mut file = fs::File::create(&temp_path).map_err(|e| {
            InstallerError::System(format!("Failed to create temp file: {}", e))
        })?;

        file.write_all(content.as_bytes())
            .map_err(|e| InstallerError::System(format!("Failed to write temp file: {}", e)))?;

        file.sync_all()
            .map_err(|e| InstallerError::System(format!("Failed to sync temp file: {}", e)))?;
    }

    fs::rename(&temp_path, path)
        .map_err(|e| InstallerError::System(format!("Failed to rename temp file: {}", e)))?;

    Ok(())
}
