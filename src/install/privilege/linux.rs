//! Linux privilege escalation using PolicyKit (pkexec).
//!
//! This module uses `pkexec` to show native desktop authentication dialogs
//! on GNOME, KDE, XFCE, and other desktop environments.
//!
//! # References
//! - https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html
//! - https://wiki.archlinux.org/title/Polkit
//!
//! # Exit Codes
//! - 0: Success
//! - 126: User dismissed the authentication dialog
//! - 127: Authorization denied or authentication failed

use std::process::Stdio;
use tokio::process::Command;

/// Execute a shell script with PolicyKit elevation (single auth prompt for all commands).
///
/// Uses `pkexec sh -c 'script'` to run the entire script with ONE authentication prompt.
/// This is important because pkexec does NOT cache credentials by default.
///
/// # Arguments
/// * `script` - Shell script to execute with root privileges
///
/// # Returns
/// * `Ok(())` on successful execution
/// * `Err(PolicyKitError::Cancelled)` if user dismissed dialog (exit code 126)
/// * `Err(PolicyKitError::Denied)` if authorization failed (exit code 127)
///
/// # Example
/// ```ignore
/// execute_privileged_linux("mkdir -p /usr/local/bin && cp /tmp/kodegend /usr/local/bin/").await?;
/// ```
pub async fn execute_privileged_linux(script: &str) -> Result<(), PolicyKitError> {
    // Check if pkexec is available
    let pkexec_check = Command::new("which")
        .arg("pkexec")
        .output()
        .await
        .map_err(PolicyKitError::IoError)?;

    if !pkexec_check.status.success() {
        return Err(PolicyKitError::NotAvailable);
    }

    // Execute script with pkexec - ONE auth prompt for ALL commands
    // Uses `sh -c` to run the entire script in a single invocation
    let output = Command::new("pkexec")
        .args(["sh", "-c", script])
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(PolicyKitError::IoError)?;

    match output.status.code() {
        Some(0) => Ok(()),
        Some(126) => Err(PolicyKitError::Cancelled),
        Some(127) => Err(PolicyKitError::Denied),
        Some(code) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(PolicyKitError::Failed {
                code,
                stderr: stderr.to_string(),
            })
        }
        None => Err(PolicyKitError::Signal),
    }
}

/// Errors that can occur during PolicyKit authorization
#[derive(Debug)]
pub enum PolicyKitError {
    /// pkexec is not installed on this system
    NotAvailable,
    /// User dismissed the authentication dialog (exit code 126)
    Cancelled,
    /// Authorization denied or authentication failed (exit code 127)
    Denied,
    /// Command failed with other exit code
    Failed { code: i32, stderr: String },
    /// Command terminated by signal
    Signal,
    /// I/O error spawning process
    IoError(std::io::Error),
}

impl std::fmt::Display for PolicyKitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable => write!(
                f,
                "PolicyKit (pkexec) not available. Install polkit or run from terminal."
            ),
            Self::Cancelled => write!(f, "Authentication cancelled by user"),
            Self::Denied => write!(f, "Authorization denied"),
            Self::Failed { code, stderr } => {
                write!(f, "Command failed (exit {}): {}", code, stderr)
            }
            Self::Signal => write!(f, "Command terminated by signal"),
            Self::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for PolicyKitError {}
