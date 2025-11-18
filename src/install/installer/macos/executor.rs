//! Privileged script execution using signed helper app or osascript.

use std::{io::Write, process::Command};

use anyhow::Context;

use super::{CommandBuilder, InstallerError};

use super::helper::{verify_code_signature, HELPER_PATH};

/// Execute script using the signed helper app with elevated privileges
pub(super) fn run_helper(script: &str) -> Result<(), InstallerError> {
    // Get the helper path
    let helper_path = HELPER_PATH
        .get()
        .ok_or_else(|| InstallerError::System("Helper app not initialized".to_string()))?;

    // CRITICAL: Re-verify signature immediately before execution
    verify_code_signature(helper_path).map_err(|e| {
        InstallerError::System(format!(
            "Helper signature verification failed before execution: {}",
            e
        ))
    })?;

    let helper_exe = helper_path.join("Contents/MacOS/KodegenHelper");

    // Launch helper with elevated privileges using osascript
    // The helper itself is what gets elevated, not the script
    let escaped_helper = helper_exe
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");

    let applescript =
        format!(r#"do shell script "\"{escaped_helper}\"" with administrator privileges"#);

    // Start the helper process with admin privileges
    let mut child = Command::new("osascript")
        .arg("-e")
        .arg(&applescript)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| InstallerError::System(format!("Failed to launch helper: {e}")))?;

    // Write the script to the helper's stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).map_err(|e| {
            InstallerError::System(format!("Failed to send script to helper: {e}"))
        })?;
        stdin.flush().map_err(|e| {
            InstallerError::System(format!("Failed to flush script to helper: {e}"))
        })?;
    }

    // Wait for the helper to complete
    let output = child
        .wait_with_output()
        .map_err(|e| InstallerError::System(format!("Failed to wait for helper: {e}")))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check for user cancellation
        if stderr.contains("User canceled")
            || stderr.contains("-128")
            || stdout.contains("User canceled")
            || stdout.contains("-128")
        {
            Err(InstallerError::Cancelled)
        } else if stderr.contains("Unauthorized parent process") {
            Err(InstallerError::System(
                "Helper security check failed".to_string(),
            ))
        } else if stderr.contains("Script execution timed out") {
            Err(InstallerError::System(
                "Installation script timed out".to_string(),
            ))
        } else {
            // Include both stdout and stderr for debugging
            let full_error = format!("Helper failed: stdout={stdout}, stderr={stderr}");
            Err(InstallerError::System(full_error))
        }
    }
}

/// Execute script using osascript with administrator privileges (legacy method, unused)
#[allow(dead_code)]
pub(super) fn run_osascript(script: &str) -> Result<(), InstallerError> {
    // Escape the script for AppleScript
    let escaped_script = script.replace('\\', "\\\\").replace('"', "\\\"");

    let applescript =
        format!(r#"do shell script "{escaped_script}" with administrator privileges"#);

    let output = Command::new("osascript")
        .arg("-e")
        .arg(&applescript)
        .output()
        .context("failed to invoke osascript")?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("User canceled") || stderr.contains("-128") {
            Err(InstallerError::Cancelled)
        } else if stderr.contains("authorization") || stderr.contains("privileges") {
            Err(InstallerError::PermissionDenied)
        } else {
            Err(InstallerError::System(stderr.into_owned()))
        }
    }
}

/// Convert a CommandBuilder into a shell script fragment
pub(super) fn command_to_script(cmd: &CommandBuilder) -> String {
    let mut parts = vec![cmd.program.to_string_lossy().to_string()];
    parts.extend(cmd.args.iter().cloned());
    parts.join(" ")
}
