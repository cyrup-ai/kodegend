//! Linux privilege escalation using PolicyKit (pkexec).
//!
//! This module uses `pkexec` to show native desktop authentication dialogs
//! on GNOME, KDE, XFCE, and other desktop environments.
//!
//! # Authorization Reuse
//!
//! This module provides two patterns:
//! 1. `execute_privileged_linux()` - Creates a new pkexec process for each call (legacy)
//! 2. `ElevatedShell` - Spawns a persistent elevated shell, commands sent via stdin
//!
//! The second pattern is preferred for multi-operation installations to avoid multiple auth dialogs.
//!
//! # References
//! - https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html
//! - https://wiki.archlinux.org/title/Polkit
//!
//! # Exit Codes
//! - 0: Success
//! - 126: User dismissed the authentication dialog
//! - 127: Authorization denied or authentication failed

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

// ============================================================================
// ELEVATED SHELL - Persistent pkexec shell for multiple commands
// ============================================================================

/// Command completion marker used to detect when a command finishes
const CMD_DONE_MARKER: &str = "___KODEGEN_CMD_DONE___";

/// A persistent elevated shell process started via pkexec.
///
/// Commands are sent via stdin, eliminating repeated auth dialogs.
/// This is the preferred method for multi-operation installations.
///
/// # Example
/// ```ignore
/// let mut shell = ElevatedShell::spawn()?;  // ONE auth dialog
/// shell.exec("mkdir -p /usr/local/bin")?;   // No new dialog
/// shell.exec("cp /tmp/kodegend /usr/local/bin/")?;  // No new dialog
/// // Shell is closed automatically when dropped
/// ```
pub struct ElevatedShell {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl ElevatedShell {
    /// Spawn a persistent elevated shell via pkexec (ONE auth dialog).
    ///
    /// The shell runs a loop that reads commands from stdin and executes them,
    /// printing a marker after each command to signal completion.
    ///
    /// # Returns
    /// * `Ok(ElevatedShell)` - Ready to accept commands via `exec()`
    /// * `Err(PolicyKitError::NotAvailable)` - pkexec not installed
    /// * `Err(PolicyKitError::Cancelled)` - User dismissed auth dialog
    pub fn spawn() -> Result<Self, PolicyKitError> {
        // Check if pkexec is available
        let pkexec_check = std::process::Command::new("which")
            .arg("pkexec")
            .output()
            .map_err(PolicyKitError::IoError)?;

        if !pkexec_check.status.success() {
            return Err(PolicyKitError::NotAvailable);
        }

        log::info!("Spawning persistent elevated shell via pkexec...");

        // Spawn persistent elevated shell
        // The shell reads commands from stdin, executes them, and prints a marker
        // Using a read loop that handles one command at a time
        let shell_script = format!(
            r#"while IFS= read -r cmd; do
                eval "$cmd" 2>&1
                echo '{}'
            done"#,
            CMD_DONE_MARKER
        );

        let mut child = std::process::Command::new("pkexec")
            .args(["sh", "-c", &shell_script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(PolicyKitError::IoError)?;

        let stdin = child.stdin.take()
            .ok_or_else(|| PolicyKitError::IoError(std::io::Error::other(
                "Failed to get stdin from elevated shell")))?;
        let stdout = child.stdout.take()
            .ok_or_else(|| PolicyKitError::IoError(std::io::Error::other(
                "Failed to get stdout from elevated shell")))?;

        log::info!("Elevated shell spawned successfully");

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    /// Execute a command in the elevated shell (NO new auth dialog).
    ///
    /// # Arguments
    /// * `script` - Shell command to execute with root privileges
    ///
    /// # Returns
    /// * `Ok(String)` - Command output (stdout)
    /// * `Err(PolicyKitError::IoError)` - Communication with shell failed
    pub fn exec(&mut self, script: &str) -> Result<String, PolicyKitError> {
        log::debug!("Elevated shell executing: {}", script);

        // Send command to shell (single line, no trailing newline in command itself)
        writeln!(self.stdin, "{}", script)
            .map_err(PolicyKitError::IoError)?;
        self.stdin.flush()
            .map_err(PolicyKitError::IoError)?;

        // Read output until we see the completion marker
        let mut output = String::new();
        loop {
            let mut line = String::new();
            match self.stdout.read_line(&mut line) {
                Ok(0) => {
                    // EOF - shell exited unexpectedly
                    log::warn!("Elevated shell exited unexpectedly");
                    break;
                }
                Ok(_) => {
                    if line.trim() == CMD_DONE_MARKER {
                        // Command completed
                        break;
                    }
                    output.push_str(&line);
                }
                Err(e) => return Err(PolicyKitError::IoError(e)),
            }
        }

        log::debug!("Elevated shell command completed, output length: {}", output.len());
        Ok(output)
    }
}

impl Drop for ElevatedShell {
    fn drop(&mut self) {
        log::debug!("Dropping ElevatedShell, terminating child process");

        // Send exit command (best effort)
        let _ = writeln!(self.stdin, "exit 0");
        let _ = self.stdin.flush();

        // Give the shell a moment to exit gracefully, then kill if needed
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Kill the process if still running
        let _ = self.child.kill();
        let _ = self.child.wait();

        log::debug!("ElevatedShell terminated");
    }
}
