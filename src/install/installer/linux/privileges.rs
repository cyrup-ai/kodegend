//! Privilege checking for Linux systemd operations.
//!
//! This module validates that the current process has sufficient privileges
//! to perform systemd service installation and management operations.

use std::path::PathBuf;

use super::InstallerError;

/// Check if we have sufficient privileges for systemd operations
pub(super) fn check_privileges() -> Result<(), InstallerError> {
    // Check if we're running as root or have CAP_SYS_ADMIN
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        // Check for systemd user service support
        let home_dir = std::env::var("HOME").map_err(|_| InstallerError::PermissionDenied)?;
        let user_systemd_dir = PathBuf::from(home_dir).join(".config/systemd/user");

        if !user_systemd_dir.exists() {
            return Err(InstallerError::PermissionDenied);
        }
    }

    Ok(())
}
