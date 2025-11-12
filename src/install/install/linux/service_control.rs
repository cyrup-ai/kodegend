//! Systemd service control operations.
//!
//! This module provides functions to enable, disable, start, stop, and reload
//! systemd services for both system and user-level services.

use std::process::Command;

use super::InstallerError;

/// Enable the systemd service
pub(super) fn enable_systemd_service(service_name: &str) -> Result<(), InstallerError> {
    let output = if unsafe { libc::getuid() } == 0 {
        Command::new("systemctl")
            .args(["enable", &format!("{}.service", service_name)])
            .output()
    } else {
        Command::new("systemctl")
            .args(["--user", "enable", &format!("{}.service", service_name)])
            .output()
    };

    let output = output.map_err(|e| {
        InstallerError::System(format!("Failed to execute systemctl enable: {}", e))
    })?;

    if !output.status.success() {
        return Err(InstallerError::System(format!(
            "Failed to enable systemd service: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Start the systemd service
pub(super) fn start_systemd_service(service_name: &str) -> Result<(), InstallerError> {
    let output = if unsafe { libc::getuid() } == 0 {
        Command::new("systemctl")
            .args(["start", &format!("{}.service", service_name)])
            .output()
    } else {
        Command::new("systemctl")
            .args(["--user", "start", &format!("{}.service", service_name)])
            .output()
    };

    let output = output.map_err(|e| {
        InstallerError::System(format!("Failed to execute systemctl start: {}", e))
    })?;

    if !output.status.success() {
        return Err(InstallerError::System(format!(
            "Failed to start systemd service: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Stop the systemd service
pub(super) fn stop_systemd_service(service_name: &str) -> Result<(), InstallerError> {
    let output = if unsafe { libc::getuid() } == 0 {
        Command::new("systemctl")
            .args(["stop", &format!("{}.service", service_name)])
            .output()
    } else {
        Command::new("systemctl")
            .args(["--user", "stop", &format!("{}.service", service_name)])
            .output()
    };

    let output = output.map_err(|e| {
        InstallerError::System(format!("Failed to execute systemctl stop: {}", e))
    })?;

    if !output.status.success() {
        return Err(InstallerError::System(format!(
            "Failed to stop systemd service: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Disable the systemd service
pub(super) fn disable_systemd_service(service_name: &str) -> Result<(), InstallerError> {
    let output = if unsafe { libc::getuid() } == 0 {
        Command::new("systemctl")
            .args(["disable", &format!("{}.service", service_name)])
            .output()
    } else {
        Command::new("systemctl")
            .args(["--user", "disable", &format!("{}.service", service_name)])
            .output()
    };

    let output = output.map_err(|e| {
        InstallerError::System(format!("Failed to execute systemctl disable: {}", e))
    })?;

    if !output.status.success() {
        return Err(InstallerError::System(format!(
            "Failed to disable systemd service: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Enable user-level systemd service
pub(super) fn enable_user_systemd_service(service_name: &str) -> Result<(), InstallerError> {
    let output = Command::new("systemctl")
        .args(["--user", "enable", &format!("{}.service", service_name)])
        .output()
        .map_err(|e| {
            InstallerError::System(format!("Failed to execute systemctl --user enable: {}", e))
        })?;

    if !output.status.success() {
        return Err(InstallerError::System(format!(
            "Failed to enable user systemd service: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Start user-level systemd service
pub(super) fn start_user_systemd_service(service_name: &str) -> Result<(), InstallerError> {
    let output = Command::new("systemctl")
        .args(["--user", "start", &format!("{}.service", service_name)])
        .output()
        .map_err(|e| {
            InstallerError::System(format!("Failed to execute systemctl --user start: {}", e))
        })?;

    if !output.status.success() {
        return Err(InstallerError::System(format!(
            "Failed to start user systemd service: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Reload systemd daemon to pick up changes
pub(super) fn reload_systemd_daemon() -> Result<(), InstallerError> {
    let output = if unsafe { libc::getuid() } == 0 {
        Command::new("systemctl").args(["daemon-reload"]).output()
    } else {
        Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output()
    };

    let output = output.map_err(|e| {
        InstallerError::System(format!("Failed to execute systemctl daemon-reload: {}", e))
    })?;

    if !output.status.success() {
        return Err(InstallerError::System(format!(
            "Failed to reload systemd daemon: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}
