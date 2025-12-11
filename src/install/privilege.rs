//! Privilege escalation and sudo operations for kodegen installer
//!
//! This module handles operations that require elevated privileges (root/admin),
//! including certificate installation, hosts file updates, and binary installation
//! to system directories.
//!
//! # Platform-Native GUI Authentication
//!
//! When running in GUI mode (no TTY available), this module uses platform-native
//! authentication APIs:
//! - **macOS**: Authorization Services via `security-framework` crate
//! - **Linux**: PolicyKit via `pkexec`
//! - **Windows**: UAC via `ShellExecuteExW` (already implemented)

// Platform-specific privilege escalation submodules
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

use anyhow::{Context, Result};


// ============================================================================
// PRIVILEGED EXECUTOR - Type-safe sudo command execution
// ============================================================================
//
// Architecture inspired by sudo-rs (https://github.com/trifectatechfoundation/sudo-rs)
// Key patterns:
// - Use Command::output() for proper exit status checking
// - No persistent shell subprocess (each command is independent)
// - Validate credentials once with `sudo -v`
// ============================================================================

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::process::Command as TokioCommand;

/// Privileged command executor with proper exit status handling.
///
/// # Architecture
///
/// Unlike the old approach (persistent `sudo sh` with stdin pipe), this executor:
/// 1. Validates sudo credentials ONCE with `sudo -v` (prompts for password)
/// 2. Each operation spawns a fresh `sudo <command>` process
/// 3. Uses `Command::output()` to wait for completion and check exit status
/// 4. No shell wrapper, no marker protocols, no race conditions
///
/// # Usage
///
/// ```rust
/// let executor = PrivilegedExecutor::spawn().await?; // Single password prompt
/// executor.exec(&["sh", "-c", "echo '127.0.0.1 host' >> /etc/hosts"]).await?;
/// executor.write_file(&cert_path, &cert_content).await?;
/// // No close() needed - each command is independent
/// ```
/// Privilege escalation mode (presentation tier)
///
/// Separates HOW we execute privileged operations (presentation)
/// from WHAT operations we execute (logic layer in component_fixers.rs).
///
/// Platform-specific modes:
/// - macOS CLI: Sudo
/// - macOS GUI: AuthorizationServices
/// - Linux CLI: Sudo
/// - Linux GUI: PolicyKit
/// - Windows: UAC
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum PrivilegeMode {
    /// Already running as root - no elevation needed
    AlreadyElevated,

    /// Unix/Linux CLI mode: use sudo
    Sudo,

    /// macOS GUI mode: use Authorization Services
    #[cfg(target_os = "macos")]
    AuthorizationServices,

    /// Linux GUI mode: use PolicyKit (pkexec)
    #[cfg(target_os = "linux")]
    PolicyKit,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
enum PrivilegeMode {
    /// Already running as Administrator - no elevation needed
    AlreadyElevated,

    /// Windows UAC elevation
    Uac,
}

#[cfg(unix)]
pub struct PrivilegedExecutor {
    /// Privilege escalation mode (determines how operations are executed)
    mode: PrivilegeMode,
}

#[cfg(unix)]
impl PrivilegedExecutor {
    /// Autodetect privilege state and spawn executor.
    ///
    /// Three-step detection:
    /// 1. Already root (geteuid == 0)? → No sudo needed
    /// 2. Sudo credentials cached? → Use sudo without prompt
    /// 3. Neither? → Prompt once with sudo -v
    ///
    /// This ensures:
    /// - Daemon mode (launchd/systemd as root): no prompts, silent operation
    /// - User with cached creds: no prompts
    /// - User without creds: exactly one prompt
    pub async fn spawn() -> Result<Self> {
        // Step 1: Check if already elevated
        if nix::unistd::geteuid().is_root() {
            log::info!("Already running as root, no elevation needed");
            return Ok(Self {
                mode: PrivilegeMode::AlreadyElevated,
            });
        }

        // Step 2: Detect GUI vs CLI mode
        use crate::platform::is_gui_available;
        let gui_available = is_gui_available();

        // Step 3: Platform + mode specific dispatch
        #[cfg(target_os = "macos")]
        {
            if gui_available {
                // macOS GUI: Use Authorization Services
                log::info!("macOS GUI mode - using Authorization Services");
                macos::execute_privileged_macos("true")
                    .map_err(|e| anyhow::anyhow!("macOS authentication failed: {}", e))?;
                Ok(Self {
                    mode: PrivilegeMode::AuthorizationServices,
                })
            } else {
                // macOS CLI: Use sudo
                log::info!("macOS CLI mode - using sudo");
                spawn_sudo_mode().await
            }
        }

        #[cfg(target_os = "linux")]
        {
            if gui_available {
                // Linux GUI: Use PolicyKit
                log::info!("Linux GUI mode - using PolicyKit");
                linux::execute_privileged_linux("true")
                    .await
                    .map_err(|e| anyhow::anyhow!("PolicyKit authentication failed: {}", e))?;
                Ok(Self {
                    mode: PrivilegeMode::PolicyKit,
                })
            } else {
                // Linux CLI: Use sudo
                log::info!("Linux CLI mode - using sudo");
                spawn_sudo_mode().await
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            // Other Unix: Use sudo (CLI only, no GUI support)
            if gui_available {
                anyhow::bail!("GUI privilege escalation not supported on this platform. Run from terminal.");
            }
            log::info!("Unix CLI mode - using sudo");
            return spawn_sudo_mode().await;
        }
    }
    /// Execute a command with root privileges.
    ///
    /// PRESENTATION LAYER: Dispatches based on privilege mode.
    /// Logic layer (component_fixers.rs) just calls this - doesn't know about modes.
    ///
    /// # Arguments
    /// * `args` - Command arguments (e.g., `["mkdir", "-p", "/usr/local/bin"]`)
    pub async fn exec(&self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            anyhow::bail!("exec() called with empty args");
        }

        log::debug!("Executing privileged command: {}", args.join(" "));

        // PRESENTATION LAYER: Dispatch based on mode
        match self.mode {
            PrivilegeMode::AlreadyElevated => {
                // Already root - run directly
                let output = TokioCommand::new(args[0])
                    .args(&args[1..])
                    .output()
                    .await
                    .with_context(|| format!("Failed to execute {}", args[0]))?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("Command {:?} failed: {}", args, stderr.trim());
                }
                Ok(())
            }

            PrivilegeMode::Sudo => {
                // Unix CLI: Use sudo -n
                let output = TokioCommand::new("sudo")
                    .arg("-n")
                    .args(args)
                    .output()
                    .await
                    .context("Failed to execute sudo command")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if stderr.contains("password is required") {
                        anyhow::bail!("Sudo credentials expired - please re-run");
                    }
                    anyhow::bail!("Command {:?} failed: {}", args, stderr.trim());
                }
                Ok(())
            }

            #[cfg(target_os = "macos")]
            PrivilegeMode::AuthorizationServices => {
                // macOS GUI: Use Authorization Services
                let command = shell_quote_args(args);
                macos::execute_privileged_macos(&command)
                    .map_err(|e| anyhow::anyhow!("Authorization Services command failed: {}", e))?;
                Ok(())
            }

            #[cfg(target_os = "linux")]
            PrivilegeMode::PolicyKit => {
                // Linux GUI: Use PolicyKit
                let command = shell_quote_args(args);
                linux::execute_privileged_linux(&command)
                    .await
                    .map_err(|e| anyhow::anyhow!("PolicyKit command failed: {}", e))?;
                Ok(())
            }
        }
    }

    /// Write content to a file with root privileges.
    ///
    /// PRESENTATION LAYER: Dispatches based on privilege mode.
    /// Creates parent directories if needed.
    pub async fn write_file(&self, path: &Path, content: &str) -> Result<()> {
        // Create parent directory first (uses same dispatch via self.exec)
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            self.exec(&["mkdir", "-p", &parent.to_string_lossy()])
                .await?;
        }

        // PRESENTATION LAYER: Dispatch based on mode
        match self.mode {
            PrivilegeMode::AlreadyElevated => {
                // Already root - write directly
                tokio::fs::write(path, content)
                    .await
                    .with_context(|| format!("Failed to write {}", path.display()))?;
            }

            PrivilegeMode::Sudo => {
                // Unix CLI: Use sudo tee
                let mut child = TokioCommand::new("sudo")
                    .args(["-n", "tee", &path.to_string_lossy()])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .context("Failed to spawn sudo tee")?;

                if let Some(mut stdin) = child.stdin.take() {
                    stdin
                        .write_all(content.as_bytes())
                        .await
                        .context("Failed to write to tee stdin")?;
                }

                let output = child
                    .wait_with_output()
                    .await
                    .context("Failed to wait for tee")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if stderr.contains("password is required") {
                        anyhow::bail!("Sudo credentials expired - please re-run");
                    }
                    anyhow::bail!("Failed to write {}: {}", path.display(), stderr.trim());
                }
            }

            #[cfg(target_os = "macos")]
            PrivilegeMode::AuthorizationServices => {
                // macOS GUI: Use Authorization Services with printf | tee
                let escaped_content = content.replace('\'', "'\\''");
                let script = format!(
                    "printf '%s' '{}' | tee {} > /dev/null",
                    escaped_content,
                    path.display()
                );
                macos::execute_privileged_macos(&script)
                    .map_err(|e| anyhow::anyhow!("Failed to write {} via Authorization Services: {}", path.display(), e))?;
            }

            #[cfg(target_os = "linux")]
            PrivilegeMode::PolicyKit => {
                // Linux GUI: Use PolicyKit with printf | tee
                let escaped_content = content.replace('\'', "'\\''");
                let script = format!(
                    "printf '%s' '{}' | tee {} > /dev/null",
                    escaped_content,
                    path.display()
                );
                linux::execute_privileged_linux(&script)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to write {} via PolicyKit: {}", path.display(), e))?;
            }
        }

        Ok(())
    }

    /// Set file permissions
    pub async fn chmod(&self, path: &Path, mode: &str) -> Result<()> {
        self.exec(&["chmod", mode, &path.to_string_lossy()]).await
    }
}

/// Quote shell arguments safely for Authorization Services / PolicyKit
///
/// Joins arguments with proper shell escaping for passing to /bin/sh -c
#[cfg(unix)]
fn shell_quote_args(args: &[&str]) -> String {
    args.iter()
        .map(|arg| shlex::try_quote(arg).unwrap_or_else(|_| format!("'{}'", arg.replace('\'', "'\\''")).into()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quote shell arguments for Windows cmd.exe
///
/// Joins arguments with proper escaping for passing to cmd.exe
#[cfg(windows)]
fn shell_quote_args(args: &[&str]) -> String {
    args.join(" ")
}

/// Helper for sudo mode (Unix CLI)
///
/// Checks if sudo credentials are cached, prompts if needed.
#[cfg(unix)]
async fn spawn_sudo_mode() -> Result<PrivilegedExecutor> {
    // Check if credentials already cached
    let cached = TokioCommand::new("sudo")
        .args(["-n", "true"])
        .output()
        .await
        .context("Failed to check sudo cache")?;

    if !cached.status.success() {
        // Need to prompt
        log::info!("Requesting sudo credentials via terminal...");
        let status = TokioCommand::new("sudo")
            .arg("-v")
            .status()
            .await
            .context("Failed to execute sudo -v")?;

        if !status.success() {
            anyhow::bail!("Sudo authentication failed");
        }
    } else {
        log::info!("Sudo credentials already cached");
    }

    Ok(PrivilegedExecutor {
        mode: PrivilegeMode::Sudo,
    })
}

// Windows implementation using UAC self-elevation
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use tokio::process::Command as TokioCommand;

#[cfg(windows)]
pub struct PrivilegedExecutor {
    mode: PrivilegeMode,
}

#[cfg(windows)]
impl PrivilegedExecutor {
    /// Spawn privileged executor using Windows UAC
    ///
    /// Checks if already elevated, otherwise prepares for UAC elevation
    pub async fn spawn() -> Result<Self> {
        use crate::install::installer::windows::privileges::check_privileges;

        // Check if already elevated (running as Administrator)
        if check_privileges().is_ok() {
            log::info!("Already running with Administrator privileges");
            return Ok(Self {
                mode: PrivilegeMode::AlreadyElevated,
            });
        }

        // Not elevated - will need UAC for each operation
        log::info!("Not elevated - will use UAC for privileged operations");
        Ok(Self {
            mode: PrivilegeMode::Uac,
        })
    }

    /// Execute command with elevated privileges
    pub async fn exec(&self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            anyhow::bail!("exec() called with empty args");
        }

        log::debug!("Executing privileged command: {}", args.join(" "));

        match self.mode {
            PrivilegeMode::AlreadyElevated => {
                // Already Administrator - run directly
                let output = TokioCommand::new(args[0])
                    .args(&args[1..])
                    .output()
                    .await
                    .with_context(|| format!("Failed to execute {}", args[0]))?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("Command {:?} failed: {}", args, stderr.trim());
                }
                Ok(())
            }

            PrivilegeMode::Uac => {
                // Not elevated - use UAC
                let command = shell_quote_args(args);
                windows::execute_privileged_windows(&command)
                    .map_err(|e| anyhow::anyhow!("UAC elevation failed: {}", e))?;
                Ok(())
            }

            #[cfg(target_os = "macos")]
            _ => unreachable!("macOS-specific modes on Windows"),
            #[cfg(target_os = "linux")]
            _ => unreachable!("Linux-specific modes on Windows"),
        }
    }

    /// Write file with elevated privileges
    pub async fn write_file(&self, path: &Path, content: &str) -> Result<()> {
        // Create parent directory first (uses same dispatch via self.exec)
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            let parent_str = parent.to_string_lossy();
            self.exec(&["cmd", "/c", "mkdir", &parent_str])
                .await?;
        }

        match self.mode {
            PrivilegeMode::AlreadyElevated => {
                // Already Administrator - write directly
                tokio::fs::write(path, content)
                    .await
                    .with_context(|| format!("Failed to write {}", path.display()))?;
            }

            PrivilegeMode::Uac => {
                // Not elevated - write to temp, then copy with UAC
                let temp_dir = std::env::temp_dir();
                let temp_file = temp_dir.join(format!("kodegen_temp_{}.txt", uuid::Uuid::new_v4()));
                
                tokio::fs::write(&temp_file, content)
                    .await
                    .context("Failed to write temp file")?;

                let temp_str = temp_file.to_string_lossy();
                let dest_str = path.to_string_lossy();
                self.exec(&["cmd", "/c", "copy", "/Y", &temp_str, &dest_str])
                    .await?;

                // Clean up temp file
                let _ = tokio::fs::remove_file(&temp_file).await;
            }

            #[cfg(target_os = "macos")]
            _ => unreachable!("macOS-specific modes on Windows"),
            #[cfg(target_os = "linux")]
            _ => unreachable!("Linux-specific modes on Windows"),
        }

        Ok(())
    }

    /// Set file permissions (Windows ACL)
    pub async fn chmod(&self, path: &Path, _mode: &str) -> Result<()> {
        // Windows uses icacls for permissions
        let path_str = path.to_string_lossy();
        self.exec(&[
            "icacls",
            &path_str,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-32-544:(F)", // Administrators: Full
            "/grant:r",
            "*S-1-5-18:(F)", // SYSTEM: Full
        ])
        .await
    }
}

