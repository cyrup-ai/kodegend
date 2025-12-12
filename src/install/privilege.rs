//! Privilege escalation using worker thread + IPC channel architecture.
//!
//! This module handles operations that require elevated privileges (root/admin),
//! including certificate installation, hosts file updates, and binary installation
//! to system directories.
//!
//! # Architecture
//!
//! Uses a dedicated worker thread that owns all platform-specific authorization handles.
//! The main async runtime communicates with the worker via `mpsc` channels.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Main Async Runtime                          │
//! │  PrivilegedExecutor                                             │
//! │  - command_tx: Sender<WorkerCommand>                            │
//! │  - result_rx: Receiver<WorkerResult>                            │
//! │                                                                 │
//! │  exec() / write_file() / chmod()  ──────────► Channel           │
//! └─────────────────────────────────────────────────────────────────┘
//!                               │
//!                               ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                 Dedicated Worker Thread                          │
//! │  PlatformPrivilegeHandle (NOT Send!)                            │
//! │  - macOS GUI: Authorization Services                            │
//! │  - macOS CLI: sudo credentials                                  │
//! │  - Linux GUI: ElevatedShell (pkexec)                            │
//! │  - Linux CLI: sudo credentials                                  │
//! │  - Windows: ElevatedHelper (UAC)                                │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Safety
//!
//! `PrivilegedExecutor` is `Send + Sync` because it only holds channel endpoints.
//! All non-Send platform handles live in the worker thread.

// Platform-specific privilege escalation submodules
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

use anyhow::{Context, Result};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

// ============================================================================
// PUBLIC API - PrivilegedExecutor (Send + Sync)
// ============================================================================

/// Privileged command executor using worker thread + channel IPC.
///
/// This executor spawns a dedicated worker thread that handles ALL privileged
/// operations. The worker obtains authorization ONCE during construction and
/// reuses it for all subsequent commands.
///
/// # Thread Safety
///
/// The executor is `Send + Sync` because it only holds channel endpoints.
/// All non-Send platform handles (macOS Authorization, etc.) live in the worker thread.
///
/// # Usage
///
/// ```rust,ignore
/// let mut executor = PrivilegedExecutor::spawn().await?;  // ONE auth prompt
/// executor.exec(&["mkdir", "-p", "/usr/local/bin"]).await?;  // No new prompt
/// executor.exec(&["cp", "binary", "/usr/local/bin/"]).await?;  // No new prompt
/// // Worker is shutdown automatically on drop
/// ```
pub struct PrivilegedExecutor {
    /// Channel to send commands to the worker
    command_tx: Sender<WorkerCommand>,
    /// Channel to receive results from the worker
    result_rx: Receiver<WorkerResult>,
    /// Worker thread handle (joined on drop)
    worker_handle: Option<JoinHandle<()>>,
}

/// Commands sent from executor to worker
enum WorkerCommand {
    /// Execute a shell command with elevated privileges
    Exec { command: String },
    /// Write content to a file with elevated privileges
    WriteFile { path: String, content: String },
    /// Shutdown the worker thread
    Shutdown,
}

/// Results sent from worker back to executor
pub(crate) enum WorkerResult {
    /// Command completed successfully
    Success,
    /// Command completed with output
    #[allow(dead_code)]
    Output(String),
    /// Command failed with error message
    Error(String),
}

impl PrivilegedExecutor {
    /// Spawn the privileged executor with a dedicated worker thread.
    ///
    /// This triggers the authorization prompt (if needed) ONCE.
    /// The worker thread handles all subsequent privileged operations.
    pub async fn spawn() -> Result<Self> {
        // Create bidirectional channels
        let (command_tx, command_rx) = mpsc::channel::<WorkerCommand>();
        let (result_tx, result_rx) = mpsc::channel::<WorkerResult>();

        // Spawn worker thread - blocks until authorization is obtained
        let worker_handle = thread::Builder::new()
            .name("privilege-worker".to_string())
            .spawn(move || {
                worker_thread_main(command_rx, result_tx);
            })
            .context("Failed to spawn privilege worker thread")?;

        // Wait for worker to signal ready (authorization obtained)
        match result_rx.recv() {
            Ok(WorkerResult::Success) => {
                log::info!("Privilege worker ready - authorization obtained");
            }
            Ok(WorkerResult::Error(e)) => {
                // Join worker thread before returning error
                let _ = worker_handle.join();
                anyhow::bail!("Privilege worker failed to initialize: {}", e);
            }
            Err(e) => {
                let _ = worker_handle.join();
                anyhow::bail!("Privilege worker channel closed unexpectedly: {}", e);
            }
            Ok(WorkerResult::Output(_)) => {
                // Unexpected but not fatal - treat as success
                log::warn!("Privilege worker sent unexpected Output during init");
            }
        }

        Ok(Self {
            command_tx,
            result_rx,
            worker_handle: Some(worker_handle),
        })
    }

    /// Execute a command with elevated privileges.
    ///
    /// Sends command to worker thread and waits for result.
    /// NO new authorization prompt - reuses the one from spawn().
    ///
    /// # Arguments
    /// * `args` - Command arguments (e.g., `["mkdir", "-p", "/usr/local/bin"]`)
    pub async fn exec(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            anyhow::bail!("exec() called with empty args");
        }

        let command = shell_quote_args(args);
        log::debug!("Executing privileged command: {}", command);

        self.command_tx
            .send(WorkerCommand::Exec { command: command.clone() })
            .context("Failed to send command to privilege worker")?;

        match self.result_rx.recv() {
            Ok(WorkerResult::Success) => Ok(()),
            Ok(WorkerResult::Output(_)) => Ok(()),
            Ok(WorkerResult::Error(e)) => {
                anyhow::bail!("Privileged command failed: {}", e)
            }
            Err(e) => anyhow::bail!("Privilege worker channel closed: {}", e),
        }
    }

    /// Write content to a file with elevated privileges.
    ///
    /// Creates parent directories if needed.
    pub async fn write_file(&mut self, path: &Path, content: &str) -> Result<()> {
        // Create parent directory first
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            #[cfg(unix)]
            self.exec(&["mkdir", "-p", &parent.to_string_lossy()]).await?;
            #[cfg(windows)]
            {
                let parent_str = parent.to_string_lossy();
                self.exec(&["cmd", "/c", "mkdir", &parent_str]).await.ok(); // mkdir may fail if exists
            }
        }

        let path_str = path.to_string_lossy().to_string();
        log::debug!("Writing privileged file: {}", path_str);

        self.command_tx
            .send(WorkerCommand::WriteFile {
                path: path_str.clone(),
                content: content.to_string(),
            })
            .context("Failed to send write command to privilege worker")?;

        match self.result_rx.recv() {
            Ok(WorkerResult::Success) => Ok(()),
            Ok(WorkerResult::Output(_)) => Ok(()),
            Ok(WorkerResult::Error(e)) => {
                anyhow::bail!("Failed to write {}: {}", path_str, e)
            }
            Err(e) => anyhow::bail!("Privilege worker channel closed: {}", e),
        }
    }

    /// Set file permissions.
    #[cfg(unix)]
    pub async fn chmod(&mut self, path: &Path, mode: &str) -> Result<()> {
        self.exec(&["chmod", mode, &path.to_string_lossy()]).await
    }

    /// Set file permissions (Windows ACL).
    #[cfg(windows)]
    pub async fn chmod(&mut self, path: &Path, _mode: &str) -> Result<()> {
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

impl Drop for PrivilegedExecutor {
    fn drop(&mut self) {
        log::debug!("PrivilegedExecutor dropping, signaling worker shutdown");

        // Signal worker to shutdown
        let _ = self.command_tx.send(WorkerCommand::Shutdown);

        // Join worker thread (wait for clean shutdown)
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }

        log::debug!("PrivilegedExecutor dropped, worker shutdown complete");
    }
}

// ============================================================================
// WORKER THREAD IMPLEMENTATION
// ============================================================================

/// Main function for the privilege worker thread.
///
/// This function:
/// 1. Detects platform and mode (GUI vs CLI)
/// 2. Obtains authorization ONCE (triggers auth prompt)
/// 3. Signals ready to main thread
/// 4. Enters command loop, executing commands until shutdown
fn worker_thread_main(
    command_rx: Receiver<WorkerCommand>,
    result_tx: Sender<WorkerResult>,
) {
    log::debug!("Privilege worker thread started");

    // Initialize platform-specific privilege handle
    let mut handle = match PlatformPrivilegeHandle::new() {
        Ok(h) => h,
        Err(e) => {
            log::error!("Privilege worker failed to initialize: {}", e);
            let _ = result_tx.send(WorkerResult::Error(e));
            return;
        }
    };

    // Signal ready - authorization obtained successfully
    if result_tx.send(WorkerResult::Success).is_err() {
        log::debug!("Privilege worker: main thread gone during init");
        return; // Main thread gone
    }

    log::debug!("Privilege worker entering command loop");

    // Command loop
    loop {
        match command_rx.recv() {
            Ok(WorkerCommand::Exec { command }) => {
                log::debug!("Privilege worker executing: {}", command);
                let result = handle.exec(&command);
                let _ = result_tx.send(result);
            }
            Ok(WorkerCommand::WriteFile { path, content }) => {
                log::debug!("Privilege worker writing file: {}", path);
                let result = handle.write_file(&path, &content);
                let _ = result_tx.send(result);
            }
            Ok(WorkerCommand::Shutdown) => {
                log::debug!("Privilege worker received shutdown signal");
                break;
            }
            Err(_) => {
                // Channel closed - main thread dropped executor
                log::debug!("Privilege worker channel closed, shutting down");
                break;
            }
        }
    }

    log::debug!("Privilege worker thread exiting");
    // Cleanup handled by PlatformPrivilegeHandle::drop()
}

// ============================================================================
// SHELL QUOTING
// ============================================================================

/// Quote shell arguments safely for Unix shells
#[cfg(unix)]
fn shell_quote_args(args: &[&str]) -> String {
    args.iter()
        .map(|arg| {
            shlex::try_quote(arg)
                .unwrap_or_else(|_| format!("'{}'", arg.replace('\'', "'\\''")).into())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quote shell arguments for Windows cmd.exe
#[cfg(windows)]
fn shell_quote_args(args: &[&str]) -> String {
    args.join(" ")
}

// ============================================================================
// UNIX PLATFORM HANDLE
// ============================================================================

#[cfg(unix)]
enum PlatformPrivilegeHandle {
    /// Already running as root
    AlreadyElevated,
    /// CLI mode using sudo (credentials cached via sudo -v)
    Sudo,
    /// macOS GUI mode using Authorization Services
    #[cfg(target_os = "macos")]
    MacosAuthorization(macos::MacosAuthHandle),
    /// Linux GUI mode using PolicyKit elevated shell
    #[cfg(target_os = "linux")]
    LinuxPolicyKit(linux::ElevatedShell),
}

#[cfg(unix)]
impl PlatformPrivilegeHandle {
    fn new() -> Result<Self, String> {
        // Check if already root
        if nix::unistd::geteuid().is_root() {
            log::info!("Already running as root, no elevation needed");
            return Ok(Self::AlreadyElevated);
        }

        // Detect GUI vs CLI mode
        let gui_available = crate::platform::is_gui_available();

        #[cfg(target_os = "macos")]
        {
            if gui_available {
                // macOS GUI: Use Authorization Services
                log::info!("macOS GUI mode - creating Authorization");
                let auth = macos::MacosAuthHandle::new()
                    .map_err(|e| format!("macOS authorization failed: {}", e))?;
                return Ok(Self::MacosAuthorization(auth));
            }
        }

        #[cfg(target_os = "linux")]
        {
            if gui_available {
                // Linux GUI: Use PolicyKit with persistent shell
                log::info!("Linux GUI mode - spawning elevated shell via PolicyKit");
                let shell = linux::ElevatedShell::spawn()
                    .map_err(|e| format!("PolicyKit failed: {}", e))?;
                return Ok(Self::LinuxPolicyKit(shell));
            }
        }

        // CLI mode: Use sudo
        log::info!("CLI mode - using sudo");
        Self::init_sudo()?;
        Ok(Self::Sudo)
    }

    fn init_sudo() -> Result<(), String> {
        use std::process::Command;

        // Check if credentials already cached
        let cached = Command::new("sudo")
            .args(["-n", "true"])
            .output()
            .map_err(|e| format!("Failed to check sudo: {}", e))?;

        if !cached.status.success() {
            // Prompt for credentials ONCE
            log::info!("Requesting sudo credentials...");
            let status = Command::new("sudo")
                .arg("-v")
                .status()
                .map_err(|e| format!("sudo -v failed: {}", e))?;

            if !status.success() {
                return Err("Sudo authentication failed".to_string());
            }
        } else {
            log::info!("Sudo credentials already cached");
        }

        Ok(())
    }

    fn exec(&mut self, command: &str) -> WorkerResult {
        match self {
            Self::AlreadyElevated => Self::exec_direct(command),
            Self::Sudo => Self::exec_sudo(command),
            #[cfg(target_os = "macos")]
            Self::MacosAuthorization(auth) => auth.exec(command),
            #[cfg(target_os = "linux")]
            Self::LinuxPolicyKit(shell) => match shell.exec(command) {
                Ok(output) => WorkerResult::Output(output),
                Err(e) => WorkerResult::Error(e.to_string()),
            },
        }
    }

    fn write_file(&mut self, path: &str, content: &str) -> WorkerResult {
        // Escape content and use printf > file pattern
        let escaped = content.replace('\'', "'\\''");
        let command = format!("printf '%s' '{}' > '{}'", escaped, path);
        self.exec(&command)
    }

    fn exec_direct(command: &str) -> WorkerResult {
        use std::process::Command;
        match Command::new("sh").args(["-c", command]).output() {
            Ok(output) if output.status.success() => WorkerResult::Success,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                WorkerResult::Error(stderr.to_string())
            }
            Err(e) => WorkerResult::Error(e.to_string()),
        }
    }

    fn exec_sudo(command: &str) -> WorkerResult {
        use std::process::Command;
        match Command::new("sudo")
            .args(["-n", "sh", "-c", command])
            .output()
        {
            Ok(output) if output.status.success() => WorkerResult::Success,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("password is required") {
                    WorkerResult::Error("Sudo credentials expired".to_string())
                } else {
                    WorkerResult::Error(stderr.to_string())
                }
            }
            Err(e) => WorkerResult::Error(e.to_string()),
        }
    }
}

// ============================================================================
// WINDOWS PLATFORM HANDLE
// ============================================================================

#[cfg(windows)]
enum PlatformPrivilegeHandle {
    /// Already running as Administrator
    AlreadyElevated,
    /// UAC elevated helper process
    UacHelper(windows::ElevatedHelper),
}

#[cfg(windows)]
impl PlatformPrivilegeHandle {
    fn new() -> Result<Self, String> {
        use crate::install::installer::windows::privileges::check_privileges;

        // Check if already elevated
        if check_privileges().is_ok() {
            log::info!("Already running with Administrator privileges");
            return Ok(Self::AlreadyElevated);
        }

        // Spawn elevated helper (ONE UAC prompt)
        log::info!("Not elevated - spawning elevated helper via UAC");
        let helper = windows::ElevatedHelper::spawn()
            .map_err(|e| format!("UAC elevation failed: {}", e))?;
        log::info!("Elevated helper spawned - will be reused for all operations");

        Ok(Self::UacHelper(helper))
    }

    fn exec(&mut self, command: &str) -> WorkerResult {
        match self {
            Self::AlreadyElevated => {
                use std::process::Command;
                match Command::new("cmd").args(["/c", command]).output() {
                    Ok(output) if output.status.success() => WorkerResult::Success,
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        WorkerResult::Error(stderr.to_string())
                    }
                    Err(e) => WorkerResult::Error(e.to_string()),
                }
            }
            Self::UacHelper(helper) => match helper.exec(command) {
                Ok(output) => WorkerResult::Output(output),
                Err(e) => WorkerResult::Error(e.to_string()),
            },
        }
    }

    fn write_file(&mut self, path: &str, content: &str) -> WorkerResult {
        match self {
            Self::AlreadyElevated => match std::fs::write(path, content) {
                Ok(()) => WorkerResult::Success,
                Err(e) => WorkerResult::Error(e.to_string()),
            },
            Self::UacHelper(helper) => {
                // Write to temp, copy with elevated helper
                let temp_path = std::env::temp_dir()
                    .join(format!("kodegen_temp_{}.txt", uuid::Uuid::new_v4()));

                if let Err(e) = std::fs::write(&temp_path, content) {
                    return WorkerResult::Error(format!("Failed to write temp: {}", e));
                }

                let cmd = format!("copy /Y \"{}\" \"{}\"", temp_path.display(), path);
                let result = match helper.exec(&cmd) {
                    Ok(_) => WorkerResult::Success,
                    Err(e) => WorkerResult::Error(e.to_string()),
                };

                let _ = std::fs::remove_file(&temp_path);
                result
            }
        }
    }
}
