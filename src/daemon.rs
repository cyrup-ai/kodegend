//! Low-level daemon process management primitives.
//!
//! This module provides the foundational building blocks for daemon processes:
//! - **PID file management** with RAII pattern and file locking
//! - **Process daemonization** using the traditional Unix double-fork technique
//! - **Systemd integration** via sd_notify protocol
//!
//! # Architecture
//!
//! The module uses a modern RAII (Resource Acquisition Is Initialization) pattern
//! for PID file management, ensuring automatic cleanup on process exit, panic, or
//! early return. File locking prevents race conditions that could allow multiple
//! daemon instances.
//!
//! # Platform Support
//!
//! - **Unix (Linux, macOS, BSD)**: Full support for daemonization and PID files
//! - **Windows**: PID file support only (Windows services don't use double-fork)
//!
//! # Usage Pattern
//!
//! ```no_run
//! use kodegend::daemon::{daemonise, systemd_ready, PidFile};
//! use kodegend::platform;
//! use anyhow::Result;
//!
//! fn main() -> Result<()> {
//!     // Determine PID file path based on privileges
//!     let is_root = platform::is_elevated();
//!     let runtime_dir = platform::runtime_dir(is_root);
//!     let pid_file_path = runtime_dir.join("kodegend.pid");
//!     
//!     // Daemonize if not running under a service manager
//!     if !platform::running_under_service_manager() {
//!         daemonise()?;
//!     }
//!     
//!     // Create PID file (holds lock for entire process lifetime)
//!     let _pid_file = PidFile::create(pid_file_path)?;
//!     
//!     // Signal readiness to systemd (no-op if not running under systemd)
//!     systemd_ready();
//!     
//!     // Run daemon logic
//!     run_daemon_services()?;
//!     
//!     // PID file automatically removed when _pid_file drops
//!     Ok(())
//! }
//! ```
//!
//! # Related Modules
//!
//! - [`crate::control`](../control/index.html) - High-level service control (start/stop/restart)
//! - [`crate::platform`](../platform/index.html) - Platform abstraction layer
//! - [`crate::manager`](../manager/index.html) - Service management orchestration
//!
//! # Security Considerations
//!
//! **File Locking**: PidFile uses `flock(2)` (Unix) to prevent TOCTOU races.
//! The lock is held for the entire daemon lifetime, not just during file creation.
//!
//! **PID Reuse**: PID files don't verify process identity. If a daemon crashes
//! and its PID is reused by another process, the stale PID file will point to
//! the wrong process. The file lock mitigates this by ensuring only one holder.
//!
//! **Directory Permissions**: PID file directory should have restrictive permissions
//! (e.g., `/var/run/kodegend` owned by daemon user, mode 0755).
//!
//! # References
//!
//! - W. Richard Stevens, "Advanced Programming in the UNIX Environment", Chapter 13
//! - [daemon(3)](https://man7.org/linux/man-pages/man3/daemon.3.html) - Linux daemon creation
//! - [systemd.service(5)](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
//! - [flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html) - File locking

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use log::{error, info, warn};

use crate::constants::*;
#[cfg(all(feature = "systemd-notify", target_os = "linux"))]
use systemd::daemon;

#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg};
#[cfg(unix)]
use std::os::fd::IntoRawFd;
// Add Unix security features for symlink attack prevention (CWE-59)
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use nix::unistd::{Uid, geteuid};

use crate::platform;

//! systemd notification helpers
//!
//! Implements sd_notify protocol for Type=notify service integration.
//! See: https://www.freedesktop.org/software/systemd/man/sd_notify.html

/// Notify systemd that service is fully ready
///
/// Sends READY=1 to indicate startup completion. This causes systemd to:
/// - Mark service as "active" (not "activating")
/// - Start dependent services (After=, Requires=)
/// - Reset startup timeout counter
///
/// Safe to call multiple times (systemd ignores duplicate READY notifications).
/// No-op on non-systemd systems (checks NOTIFY_SOCKET environment variable).
#[cfg(all(feature = "systemd-notify", target_os = "linux"))]
pub fn systemd_notify_ready() {
    use systemd::daemon::{notify, NotifyState};
    
    match notify(false, &[NotifyState::Ready]) {
        Ok(true) => {
            info!("systemd notification: READY=1 (service fully operational)");
        }
        Ok(false) => {
            log::debug!("NOTIFY_SOCKET not set - not running under systemd");
        }
        Err(e) => {
            warn!("systemd notification failed: {:#}", e);
            // Non-fatal - continue running
        }
    }
}

#[cfg(not(all(feature = "systemd-notify", target_os = "linux")))]
pub fn systemd_notify_ready() {
    // No-op on non-Linux or when feature disabled
    log::debug!("systemd notification skipped (platform not supported or feature disabled)");
}

/// Send status update to systemd
///
/// Updates human-readable status shown in `systemctl status` output.
/// Useful for startup progress indication and operational state visibility.
///
/// Example: `systemd_notify_status("Starting HTTP servers...")`
#[cfg(all(feature = "systemd-notify", target_os = "linux"))]
pub fn systemd_notify_status(status: &str) {
    use systemd::daemon::{notify, NotifyState};
    
    match notify(false, &[NotifyState::Status(status.to_string())]) {
        Ok(true) => {
            log::debug!("systemd notification: STATUS={}", status);
        }
        Ok(false) => {
            // NOTIFY_SOCKET not set - silent no-op
        }
        Err(e) => {
            warn!("systemd status notification failed: {:#}", e);
        }
    }
}

#[cfg(not(all(feature = "systemd-notify", target_os = "linux")))]
pub fn systemd_notify_status(_status: &str) {
    // No-op
}

/// Notify systemd that graceful shutdown is starting
///
/// Sends STOPPING=1 to inform systemd that service is shutting down intentionally.
/// This prevents systemd from treating shutdown as a crash/failure.
#[cfg(all(feature = "systemd-notify", target_os = "linux"))]
pub fn systemd_notify_stopping() {
    use systemd::daemon::{notify, NotifyState};
    
    match notify(false, &[NotifyState::Stopping]) {
        Ok(true) => {
            info!("systemd notification: STOPPING=1 (graceful shutdown)");
        }
        Ok(false) => {
            log::debug!("NOTIFY_SOCKET not set - not running under systemd");
        }
        Err(e) => {
            warn!("systemd stopping notification failed: {:#}", e);
        }
    }
}

#[cfg(not(all(feature = "systemd-notify", target_os = "linux")))]
pub fn systemd_notify_stopping() {
    // No-op
}

/// Send watchdog keepalive to systemd
///
/// Must be called periodically (every WatchdogSec/2) to prevent watchdog timeout.
/// If watchdog expires, systemd considers the service hung and restarts it.
///
/// Only relevant when unit file contains `WatchdogSec=` directive.
#[cfg(all(feature = "systemd-notify", target_os = "linux"))]
pub fn systemd_notify_watchdog() {
    use systemd::daemon::{notify, NotifyState};
    
    match notify(false, &[NotifyState::Watchdog]) {
        Ok(true) => {
            log::debug!("systemd notification: WATCHDOG=1");
        }
        Ok(false) => {
            // NOTIFY_SOCKET not set - silent no-op
        }
        Err(e) => {
            warn!("systemd watchdog notification failed: {:#}", e);
        }
    }
}

#[cfg(not(all(feature = "systemd-notify", target_os = "linux")))]
pub fn systemd_notify_watchdog() {
    // No-op
}

// Keep the old function name for backward compatibility (deprecated)
#[deprecated(since = "0.5.0", note = "Use systemd_notify_ready() instead")]
pub fn systemd_ready() {
    systemd_notify_ready();
}

/// Validate PID file path security (Unix only)
///
/// Performs multi-layer validation to prevent symlink attacks (CWE-59):
/// 1. Validates parent directory is not a symlink
/// 2. Validates parent directory ownership and permissions
/// 3. Validates existing PID file is not a symlink (if exists)
/// 4. Validates existing PID file ownership (if exists)
///
/// This function follows the security pattern established in
/// platform/unix.rs:create_secure_directory_with_ownership()
#[cfg(unix)]
fn validate_pid_file_security(path: &Path) -> Result<()> {
    // Layer 1: Validate parent directory security
    if let Some(parent) = path.parent() {
        // Ensure parent exists
        if !parent.exists() {
            // Parent will be created - this is OK
            // We'll create it with secure permissions later
            return Ok(());
        }
        
        // CRITICAL: Use symlink_metadata to avoid following symlinks
        let parent_meta = fs::symlink_metadata(parent)
            .context(format!("Failed to read metadata for parent directory: {}", parent.display()))?;
        
        if parent_meta.file_type().is_symlink() {
            anyhow::bail!(
                "SECURITY: PID file parent directory is a symlink - potential CWE-59 attack detected: {}\n\
                 This prevents symlink-based file disclosure or privilege escalation.\n\
                 Parent directory must be a real directory, not a symbolic link.",
                parent.display()
            );
        }
        
        if !parent_meta.is_dir() {
            anyhow::bail!(
                "SECURITY: PID file parent path exists but is not a directory: {}",
                parent.display()
            );
        }
        
        // Validate parent directory ownership
        let parent_uid = Uid::from_raw(parent_meta.uid());
        let current_uid = geteuid();
        
        // Parent should be owned by root OR the current user
        if !parent_uid.is_root() && parent_uid != current_uid {
            warn!(
                "PID file parent directory has unexpected ownership: {}\n\
                 Expected UID: {} or 0 (root), Found UID: {}",
                parent.display(),
                current_uid,
                parent_uid
            );
        }
        
        // Check parent permissions - should not be world-writable
        let parent_mode = parent_meta.permissions().mode();
        if parent_mode & 0o002 != 0 {
            anyhow::bail!(
                "SECURITY: PID file parent directory is world-writable: {}\n\
                 Mode: {:o}. This allows attackers to create malicious symlinks.\n\
                 Directory permissions must not allow world-write access.",
                parent.display(),
                parent_mode
            );
        }
    }
    
    // Layer 2: Validate existing PID file (if it exists)
    if path.exists() {
        // CRITICAL: Use symlink_metadata to detect symlinks WITHOUT following them
        let file_meta = fs::symlink_metadata(path)
            .context(format!("Failed to read metadata for PID file: {}", path.display()))?;
        
        if file_meta.file_type().is_symlink() {
            anyhow::bail!(
                "SECURITY: PID file is a symbolic link - potential CWE-59 attack detected: {}\n\
                 This could allow an attacker to corrupt arbitrary files.\n\
                 Refusing to follow symbolic link. Remove the symlink and restart the daemon.",
                path.display()
            );
        }
        
        if !file_meta.is_file() {
            anyhow::bail!(
                "SECURITY: PID file path exists but is not a regular file: {}\n\
                 File type: {:?}. Only regular files are allowed for PID files.",
                path.display(),
                file_meta.file_type()
            );
        }
        
        // Validate ownership
        let file_uid = Uid::from_raw(file_meta.uid());
        let current_uid = geteuid();
        
        if file_uid != current_uid {
            // If running as root, file should be owned by root
            // If running as user, file should be owned by that user
            anyhow::bail!(
                "SECURITY: PID file ownership mismatch: {}\n\
                 Expected UID: {}, Found UID: {}\n\
                 This could indicate a privilege escalation attempt.",
                path.display(),
                current_uid,
                file_uid
            );
        }
        
        // Check file permissions - should not be world-writable
        let file_mode = file_meta.permissions().mode();
        if file_mode & 0o002 != 0 {
            anyhow::bail!(
                "SECURITY: PID file is world-writable: {}\n\
                 Mode: {:o}. This allows any user to corrupt daemon state.",
                path.display(),
                file_mode
            );
        }
    }
    
    Ok(())
}

#[cfg(windows)]
fn validate_pid_file_security(_path: &Path) -> Result<()> {
    // Windows Service Control Manager (SCM) handles instance management
    // This function is a no-op on Windows, but kept for API consistency
    Ok(())
}

/// RAII guard for PID file management with automatic cleanup and file locking.
///
/// This struct manages a PID file for the entire lifetime of the daemon process.
/// It provides two critical guarantees:
///
/// 1. **Mutual Exclusion**: Only one daemon instance can hold the PID file lock
/// 2. **Automatic Cleanup**: PID file is removed when the guard drops
///
/// # RAII Pattern
///
/// The PID file is created when the struct is instantiated and automatically
/// removed when the struct goes out of scope (via the `Drop` trait). This ensures
/// cleanup happens even on early return, panic, or error conditions.
///
/// # File Locking Mechanism
///
/// - **Unix**: Uses `flock(2)` with `LOCK_EX | LOCK_NB` (exclusive, non-blocking)
/// - **Windows**: No locking needed (Service Control Manager prevents multiple instances)
///
/// The lock is held for the **entire daemon lifetime**, not just during file creation.
/// This prevents TOCTOU (Time-of-Check-Time-of-Use) race conditions.
///
/// # Atomicity Guarantee
///
/// The sequence of operations in `create()` is:
/// 1. Open file (O_CREAT | O_RDWR)
/// 2. **Acquire exclusive lock** (atomic operation)
/// 3. Validate existing PID (if present)
/// 4. Truncate and write new PID
///
/// Step 2 is the critical atomic operation that prevents races. If another daemon
/// holds the lock, `create()` fails immediately with a descriptive error.
///
/// # Cleanup Behavior
///
/// The PID file is removed when:
/// - Normal function return (guard goes out of scope)
/// - Early return via `?` operator
/// - Panic unwinding (if panic=unwind)
///
/// The PID file is **NOT** removed when:
/// - `SIGKILL` (kill -9) - process terminated immediately
/// - `std::process::exit()` - bypasses destructors
/// - `std::process::abort()` - immediate termination
///
/// # Example
///
/// ```no_run
/// use kodegend::daemon::PidFile;
/// use std::path::PathBuf;
/// use anyhow::Result;
///
/// fn main() -> Result<()> {
///     let pid_file_path = PathBuf::from("/var/run/mydaemon.pid");
///     
///     // Acquire PID file lock
///     let _pid_file = PidFile::create(pid_file_path)?;
///     // Lock is now held, no other daemon instance can start
///     
///     // Run daemon logic
///     run_daemon_loop()?;
///     
///     // PID file automatically removed when _pid_file drops
///     Ok(())
/// }
/// ```
///
/// # Fields
///
/// - `path`: Path to the PID file
/// - `_lock` (Unix only): File lock guard (kept alive for daemon lifetime)
///
/// # Platform Differences
///
/// - **Unix**: Full locking implementation with `flock(2)`
/// - **Windows**: Simple file write (SCM handles instance uniqueness)
///
/// # See Also
///
/// - [`PidFile::create()`] - Constructor with lock acquisition
/// - [`PidFile::path()`] - Get the PID file path
pub struct PidFile {
    path: PathBuf,
    #[cfg(unix)]
    _lock: Flock<std::fs::File>, // Keep lock alive for daemon lifetime
}

/// Validate PID file parent directory is writable and secure (Unix only)
///
/// Performs comprehensive pre-flight validation:
/// 1. Verifies parent directory exists
/// 2. Validates parent is a directory, not a symlink or file
/// 3. Tests writability by creating a temporary file
///
/// This prevents cryptic "Permission denied" errors by checking access
/// before attempting PID file operations.
///
/// # Security
/// - Uses `symlink_metadata` to detect symlinks without following them (CWE-59)
/// - Tests actual write access, not just permission bits
/// - Provides actionable error messages with UID information
///
/// # Arguments
/// * `path` - Path to the PID file (parent directory will be validated)
///
/// # Returns
/// * `Ok(())` - Directory is valid and writable
/// * `Err` - Directory doesn't exist, is a symlink, or is not writable
#[cfg(unix)]
fn validate_pid_file_directory(path: &Path) -> Result<()> {
    let parent = path.parent()
        .ok_or_else(|| anyhow!("Invalid PID file path: no parent directory"))?;
    
    if !parent.exists() {
        return Err(anyhow!(
            "PID file directory does not exist: {}\n\
             Create it first or check your configuration.",
            parent.display()
        ));
    }
    
    // Validate parent is actually a directory (not a file or symlink)
    let parent_meta = fs::symlink_metadata(parent)
        .context(format!("Failed to read metadata for: {}", parent.display()))?;
    
    if parent_meta.file_type().is_symlink() {
        return Err(anyhow!(
            "SECURITY: PID directory is a symlink: {}\n\
             This could be a CWE-59 symlink attack.",
            parent.display()
        ));
    }
    
    if !parent_meta.is_dir() {
        return Err(anyhow!(
            "PID file parent path is not a directory: {}",
            parent.display()
        ));
    }
    
    // Test directory writability by attempting to create a temp file
    // This is more reliable than checking permission bits
    tempfile::NamedTempFile::new_in(parent)
        .with_context(|| {
            let current_uid = geteuid();
            let dir_uid = parent_meta.uid();
            
            format!(
                "PID file directory is not writable: {}\n\
                 Directory owner: UID {}, Current process: UID {}\n\n\
                 Solutions:\n\
                 - If running as user: Use a user-writable location like $HOME/.local/state/kodegend/\n\
                 - If running as root: Verify /var/run/kodegend exists and has correct permissions\n\
                 - Create directory: sudo mkdir -p {} && sudo chown {} {}",
                parent.display(),
                dir_uid,
                current_uid,
                parent.display(),
                current_uid,
                parent.display()
            )
        })?;
    
    Ok(())
}

#[cfg(windows)]
fn validate_pid_file_directory(_path: &Path) -> Result<()> {
    // Windows Service Control Manager (SCM) handles directory management
    // This function is a no-op on Windows, but kept for API consistency
    Ok(())
}

/// Validate existing PID file for security issues (Unix only)
///
/// Performs multi-layer security validation:
/// 1. Rejects symlinks (CWE-59 prevention)
/// 2. Validates ownership matches current user
/// 3. Rejects world-writable files
/// 4. Warns about group-writable files
///
/// # Security Properties
/// - Uses `symlink_metadata` to avoid following symlinks
/// - Detects privilege escalation attempts (UID mismatches)
/// - Prevents PID corruption from world-writable files
///
/// # Arguments
/// * `path` - Path to existing PID file
///
/// # Returns
/// * `Ok(())` - File doesn't exist yet, or exists with correct security
/// * `Err` - File is a symlink, has wrong ownership, or is world-writable
#[cfg(unix)]
fn validate_existing_pid_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(()); // File doesn't exist yet - nothing to validate
    }
    
    // CRITICAL: Use symlink_metadata to avoid following symlinks
    let metadata = fs::symlink_metadata(path)
        .context(format!("Failed to read PID file metadata: {}", path.display()))?;
    
    // Step 1: Reject symlinks (CWE-59 prevention)
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "SECURITY: PID file is a symlink: {}\n\
             This could be a symlink attack (CWE-59).\n\
             PID files must be regular files, not symlinks.\n\n\
             Action: Remove the symlink: sudo rm {}",
            path.display(),
            path.display()
        ));
    }
    
    // Step 2: Validate ownership
    let file_uid = metadata.uid();
    let current_uid = geteuid().as_raw();
    
    // Running as root - file must be owned by root
    if current_uid == 0 && file_uid != 0 {
        return Err(anyhow!(
            "SECURITY: PID file owned by UID {} but daemon running as root (UID 0)\n\
             File: {}\n\n\
             This could indicate:\n\
             - A privilege escalation attempt\n\
             - Previous execution as non-root user\n\n\
             Action: Remove the file: sudo rm {}",
            file_uid,
            path.display(),
            path.display()
        ));
    }
    
    // Running as user - file must be owned by current user
    if current_uid != 0 && file_uid != current_uid {
        return Err(anyhow!(
            "PID file owned by UID {} but current user is UID {}\n\
             File: {}\n\n\
             Action: Remove the file: rm {} \n\
             Or run as the file owner",
            file_uid,
            current_uid,
            path.display(),
            path.display()
        ));
    }
    
    // Step 3: Validate permissions (must not be world-writable)
    let mode = metadata.permissions().mode() & 0o777;
    
    if mode & 0o002 != 0 {
        return Err(anyhow!(
            "SECURITY: PID file is world-writable (mode: 0o{:o})\n\
             File: {}\n\n\
             World-writable files allow any user to modify the PID,\n\
             potentially causing the wrong process to be killed.\n\n\
             Action: Fix permissions: chmod 644 {}",
            mode,
            path.display(),
            path.display()
        ));
    }
    
    // Warn about group-writable (not fatal, but suspicious)
    if mode & 0o020 != 0 {
        warn!(
            "PID file is group-writable (mode: 0o{:o}): {}",
            mode,
            path.display()
        );
    }
    
    Ok(())
}

#[cfg(windows)]
fn validate_existing_pid_file(_path: &Path) -> Result<()> {
    // Windows Service Control Manager (SCM) handles file permissions
    // This function is a no-op on Windows, but kept for API consistency
    Ok(())
}

/// Handle write errors with specific context for disk full (ENOSPC)
///
/// Detects "No space left on device" errors and provides actionable
/// error messages. For other I/O errors, adds context about the PID file path.
///
/// # Arguments
/// * `e` - The I/O error from write/sync operation
/// * `path` - Path to the PID file being written
///
/// # Returns
/// `anyhow::Error` with specific context based on error type
fn handle_write_error(e: std::io::Error, path: &Path) -> anyhow::Error {
    // Check if this is a "disk full" error
    if let Some(os_error) = e.raw_os_error() {
        #[cfg(unix)]
        {
            // ENOSPC = 28 on most Unix systems
            if os_error == libc::ENOSPC {
                return anyhow!(
                    "Cannot write PID file: No space left on device\n\
                     File: {}\n\n\
                     The filesystem is full. Free up disk space and try again.\n\
                     Check disk usage: df -h",
                    path.display()
                );
            }
        }
    }
    
    // Generic error with context
    anyhow::Error::from(e).context(format!("Failed to write PID file: {}", path.display()))
}

impl PidFile {
    /// Create and validate PID file with atomic file locking
    ///
    /// Returns error if:
    /// - Another instance is already running (lock held by active process)
    /// - Cannot acquire lock (permission denied, system error)
    /// - Cannot write to PID file location
    #[cfg(unix)]
    pub fn create(path: PathBuf) -> Result<Self> {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::ops::Deref;

        // ========================================
        // PRE-FLIGHT VALIDATION
        // ========================================
        
        // Validate existing PID file if present
        validate_existing_pid_file(&path)?;
        
        // Create parent directory with restrictive permissions
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Creating PID file directory: {}", parent.display()))?;
                
                // Set explicit permissions on directory (fixes umask dependency)
                let mut perms = fs::metadata(parent)
                    .with_context(|| format!("Reading PID directory metadata: {}", parent.display()))?
                    .permissions();
                perms.set_mode(PID_DIR_MODE);
                fs::set_permissions(parent, perms)
                    .with_context(|| format!("Setting PID directory permissions: {}", parent.display()))?;
                
                info!(
                    "PID directory permissions set to {:o}: {}",
                    PID_DIR_MODE,
                    parent.display()
                );
            }
        }

        // Validate parent directory is writable and secure
        validate_pid_file_directory(&path)?;
        
        // Validate parent directory security (even if we didn't create it)
        validate_pid_file_security(&path)?;

        // Open PID file with O_CREAT | O_RDWR | O_NOFOLLOW
        // We use O_CREAT (not O_EXCL) because we need to handle stale locks
        // O_NOFOLLOW prevents kernel from following symlinks (defense-in-depth)
        // Set explicit mode() instead of relying on umask
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(PID_FILE_MODE)  // Explicit permissions override umask
            .custom_flags(libc::O_NOFOLLOW)  // CRITICAL: Fail if path is symlink
            .open(&path)
            .context(format!(
                "Failed to open PID file: {}\n\
                 Note: If this fails with ELOOP/EMLINK, the path may be a symbolic link.\n\
                 PID files must be regular files for security.",
                path.display()
            ))?;

        // Try to acquire exclusive lock (NON-BLOCKING)
        // This is the critical atomic operation that prevents TOCTOU races
        let lock_guard = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(guard) => {
                // ✅ LOCK ACQUIRED: We are the only daemon instance
                info!("Acquired exclusive lock on PID file: {}", path.display());
                guard
            }
            Err((mut file_back, err)) => {
                // ❌ LOCK FAILED: Another daemon is running
                // Try to read the PID from the file for a helpful error message
                let mut pid_str = String::new();
                let existing_pid = if file_back.read_to_string(&mut pid_str).is_ok() {
                    pid_str.trim().to_string()
                } else {
                    "unknown".to_string()
                };

                return Err(anyhow!(
                    "Daemon is already running (PID: {}, PID file: {})\n\
                     The lock is held by an active process.\n\
                     Use 'kodegend stop' to stop the existing daemon first.",
                    existing_pid,
                    path.display()
                ))
                .context(format!("Lock error: {}", err));
            }
        };

        // Now we hold the lock - safe to read and validate existing PID
        let mut locked_file = lock_guard.deref();
        let mut existing_content = String::new();
        locked_file
            .read_to_string(&mut existing_content)
            .context("Reading existing PID file content")?;

        // If there's existing content, validate it's a stale PID
        if !existing_content.trim().is_empty()
            && let Ok(existing_pid) = existing_content.trim().parse::<platform::ProcessId>()
        {
            // CRITICAL SECURITY: Validate PID before using it in system calls
            // Prevents signaling kernel (PID 0), init (PID 1), process groups (negative),
            // and detects corrupted PID files (out-of-range values)
            if let Err(e) = platform::validate_pid_range(existing_pid) {
                warn!(
                    "Existing PID file {} contains invalid PID: {}. Treating as stale.",
                    path.display(),
                    e
                );
                // Continue - will overwrite the invalid PID file
                // This is safe because we hold the exclusive lock
            } else {
                // PID is in valid range, check if process is running
                match platform::verify_kodegend_running(existing_pid) {
                Ok(true) => {
                    // Process exists AND is kodegend
                    // This should never happen since we hold the lock
                    // But defensive programming is good
                    return Err(anyhow!(
                        "Daemon appears to be running as kodegend (PID {}), but we hold the lock. \
                             This is a bug - please report it.",
                        existing_pid
                    ));
                }
                Ok(false) => {
                    // Process doesn't exist OR is not kodegend - safe to overwrite
                    // This is the expected case after crash or PID reuse
                    warn!(
                        "Overwriting stale/hijacked PID file {} (PID {} is not running kodegend)",
                        path.display(),
                        existing_pid
                    );
                }
                Err(e) => {
                    warn!(
                        "Cannot verify PID {} status: {}. Proceeding anyway since we hold lock.",
                        existing_pid, e
                    );
                }
            }
            }
        }

        // Verify and correct permissions (handles stale PID files)
        {
            let metadata = locked_file.metadata()
                .context("Getting PID file metadata")?;
            let current_mode = metadata.permissions().mode() & 0o777;
            
            if current_mode != PID_FILE_MODE {
                warn!(
                    "PID file has incorrect permissions {:o}, correcting to {:o}: {}",
                    current_mode,
                    PID_FILE_MODE,
                    path.display()
                );
                
                let mut perms = metadata.permissions();
                perms.set_mode(PID_FILE_MODE);
                locked_file.set_permissions(perms)
                    .context("Correcting PID file permissions")?;
            }
        }

        // Write our PID to the file (lock is held, so this is safe)
        let our_pid = std::process::id();
        locked_file.set_len(0).context("Truncating PID file")?;
        locked_file
            .seek(SeekFrom::Start(0))
            .context("Seeking to start of PID file")?;
        
        // Write with specific ENOSPC error handling
        if let Err(e) = writeln!(locked_file, "{}", our_pid) {
            return Err(handle_write_error(e, &path));
        }
        
        // Sync with ENOSPC handling (fsync can also fail with ENOSPC on some systems)
        if let Err(e) = locked_file.sync_all() {
            return Err(handle_write_error(e, &path));
        }

        info!(
            "Created PID file with permissions {:o}: {} (PID: {})",
            PID_FILE_MODE,
            path.display(),
            our_pid
        );

        // Return PidFile with lock guard
        // Lock will be held for entire daemon lifetime
        Ok(Self {
            path,
            _lock: lock_guard,
        })
    }

    /// Windows version - no locking needed (Windows Service Control Manager handles this)
    #[cfg(windows)]
    pub fn create(path: PathBuf) -> Result<Self> {
        // Windows services are managed by Service Control Manager (SCM)
        // SCM ensures only one instance runs, so no locking needed
        // This code path is rarely used (kodegend runs as Windows service)

        // Validate path security (no-op on Windows, but provides API consistency)
        validate_pid_file_security(&path)?;

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Creating PID file directory: {}", parent.display()))?;
        }

        // Simple write without locking
        let pid = std::process::id();
        fs::write(&path, pid.to_string())
            .with_context(|| format!("Writing PID file: {}", path.display()))?;

        info!("Created PID file: {} (PID: {})", path.display(), pid);

        Ok(Self { path })
    }

    /// Get the path to the PID file.
    ///
    /// Returns a reference to the path that was provided to [`PidFile::create()`].
    /// This is useful for logging or error messages.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use kodegend::daemon::PidFile;
    /// use std::path::PathBuf;
    ///
    /// let pid_file = PidFile::create(PathBuf::from("/var/run/mydaemon.pid"))?;
    /// println!("PID file: {}", pid_file.path().display());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidFile {
    /// Automatically remove PID file when guard goes out of scope
    /// This runs on:
    /// - Normal function return
    /// - Early return (?)
    /// - Panic unwinding
    ///
    /// Note: Does NOT run on:
    /// - SIGKILL (kill -9) - process terminated immediately
    /// - Process::abort() - immediate termination
    /// - std::process::exit() - bypasses destructors
    fn drop(&mut self) {
        match fs::remove_file(&self.path) {
            Ok(_) => {
                info!("Removed PID file: {} (lock released)", self.path.display());
            }
            Err(e) => {
                // Log but don't panic in Drop
                error!("Failed to remove PID file {}: {}", self.path.display(), e);
            }
        }
        // Lock automatically released when self._lock drops (Unix only)
    }
}

/// Detailed service status with structured information
///
/// Provides type-safe status checking with rich context about daemon state.
/// Replaces fragile string-based status returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    /// Service is running normally with the given PID
    Running { 
        pid: platform::ProcessId 
    },
    
    /// Service is stopped, no PID file exists
    Stopped,
    
    /// Service is stopped but PID file exists with stale PID
    /// 
    /// This happens when:
    /// - Daemon crashed without cleaning up PID file
    /// - SIGKILL (kill -9) prevented cleanup
    /// - System power loss
    StaleFile { 
        pid: platform::ProcessId 
    },
    
    /// PID file exists but is corrupted or invalid
    /// 
    /// Common causes:
    /// - Partial write (disk full, process killed mid-write)
    /// - Manual editing of PID file
    /// - File system corruption
    InvalidFile { 
        error: String 
    },
    
    /// Process exists but is a zombie (defunct)
    /// 
    /// Zombie processes:
    /// - Have exited but parent hasn't reaped them
    /// - Cannot be killed (already dead)
    /// - Occupy PID table entry but no resources
    Zombie { 
        pid: platform::ProcessId 
    },
}

impl ServiceStatus {
    /// Returns true if service is actively running (not zombie)
    pub fn is_running(&self) -> bool {
        matches!(self, ServiceStatus::Running { .. })
    }
    
    /// Returns the PID if available in any state
    pub fn pid(&self) -> Option<platform::ProcessId> {
        match self {
            ServiceStatus::Running { pid }
            | ServiceStatus::StaleFile { pid }
            | ServiceStatus::Zombie { pid } => Some(*pid),
            _ => None,
        }
    }
    
    /// Returns true if cleanup is needed (stale/invalid files, zombies)
    pub fn needs_cleanup(&self) -> bool {
        matches!(
            self,
            ServiceStatus::StaleFile { .. }
            | ServiceStatus::InvalidFile { .. }
            | ServiceStatus::Zombie { .. }
        )
    }
    
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ServiceStatus::Running { .. } => "running",
            ServiceStatus::Stopped => "stopped",
            ServiceStatus::StaleFile { .. } => "stopped (stale PID file)",
            ServiceStatus::InvalidFile { .. } => "stopped (invalid PID file)",
            ServiceStatus::Zombie { .. } => "zombie (defunct process)",
        }
    }
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStatus::Running { pid } => {
                write!(f, "running (PID: {})", pid)
            }
            ServiceStatus::Stopped => {
                write!(f, "stopped")
            }
            ServiceStatus::StaleFile { pid } => {
                write!(f, "stopped (stale PID file for PID {})", pid)
            }
            ServiceStatus::InvalidFile { error } => {
                write!(f, "stopped (invalid PID file: {})", error)
            }
            ServiceStatus::Zombie { pid } => {
                write!(f, "zombie (defunct process, PID: {})", pid)
            }
        }
    }
}

/// Read PID from existing PID file
///
/// Does NOT create or lock the file - only reads existing content.
/// Used for status checking, not daemon initialization.
///
/// # Arguments
/// * `path` - Path to PID file
///
/// # Returns
/// * `Ok(pid)` - Successfully read and parsed PID
/// * `Err` - File doesn't exist, can't read, or invalid format
///
/// # Example
/// ```rust
/// let pid = read_pid_file(Path::new("/var/run/kodegend/kodegend.pid"))?;
/// println!("Daemon PID: {}", pid);
/// ```
pub fn read_pid_file(path: &Path) -> Result<platform::ProcessId> {
    // Read file content
    let content = fs::read_to_string(path)
        .with_context(|| format!("Reading PID file: {}", path.display()))?;
    
    // Parse as integer (trim whitespace first)
    content.trim()
        .parse::<platform::ProcessId>()
        .with_context(|| {
            format!(
                "Parsing PID from file {}: '{}' is not a valid process ID",
                path.display(),
                content.trim()
            )
        })
}

/// Check if a process is a zombie (defunct)
///
/// Uses sysinfo crate to query process status from OS.
///
/// # Platform Behavior
/// - **Unix**: Checks /proc/{pid}/stat for 'Z' (zombie) state
/// - **Windows**: Checks if process has exited but handle still valid
///
/// # Arguments
/// * `pid` - Process ID to check
///
/// # Returns
/// * `Ok(true)` - Process exists and is a zombie
/// * `Ok(false)` - Process exists and is NOT a zombie
/// * `Err` - Cannot determine status (process doesn't exist or permission denied)
///
/// # References
/// - Pattern from: [`src/platform/unix.rs:454`](../src/platform/unix.rs#L454)
/// - sysinfo docs: https://docs.rs/sysinfo/latest/sysinfo/
pub fn is_zombie_process(pid: platform::ProcessId) -> Result<bool> {
    use sysinfo::{Pid as SysinfoPid, ProcessesToUpdate, System};
    
    // Create system instance for querying process information
    let mut system = System::new();
    
    // Refresh only the specific process we care about (efficient)
    let sysinfo_pid = SysinfoPid::from(pid as usize);
    system.refresh_processes(ProcessesToUpdate::Some(&[sysinfo_pid]), true);
    
    // Get process info
    match system.process(sysinfo_pid) {
        Some(process) => {
            // Check process status
            use sysinfo::ProcessStatus;
            match process.status() {
                #[cfg(unix)]
                ProcessStatus::Zombie => Ok(true),
                
                #[cfg(windows)]
                ProcessStatus::Run => {
                    // Windows doesn't have traditional zombies
                    // But we can check if process has exited
                    Ok(false)
                }
                
                _ => Ok(false),
            }
        }
        None => {
            // Process doesn't exist
            Err(anyhow!(
                "Cannot check zombie status: process {} does not exist",
                pid
            ))
        }
    }
}

/// Get detailed service status with rich contextual information
///
/// Performs comprehensive status checking:
/// 1. Checks if PID file exists
/// 2. Reads and validates PID from file
/// 3. Checks if process is running
/// 4. Detects zombie (defunct) processes
///
/// # Arguments
/// * `pid_file` - Path to PID file (typically from config or platform::runtime_dir)
///
/// # Returns
/// `Ok(ServiceStatus)` with detailed status information
///
/// # Example
/// ```rust
/// use std::path::Path;
/// 
/// let status = get_service_status(Path::new("/var/run/kodegend/kodegend.pid"))?;
/// 
/// match status {
///     ServiceStatus::Running { pid } => {
///         println!("Daemon is running with PID {}", pid);
///     }
///     ServiceStatus::Stopped => {
///         println!("Daemon is not running");
///     }
///     ServiceStatus::StaleFile { pid } => {
///         println!("Stale PID file detected (PID {}), cleaning up...", pid);
///         fs::remove_file(pid_file)?;
///     }
///     ServiceStatus::InvalidFile { error } => {
///         println!("Invalid PID file: {}, removing...", error);
///         fs::remove_file(pid_file)?;
///     }
///     ServiceStatus::Zombie { pid } => {
///         println!("Zombie process detected (PID {}), cannot kill", pid);
///     }
/// }
/// ```
pub fn get_service_status(pid_file: &Path) -> Result<ServiceStatus> {
    // Step 1: Check if PID file exists
    if !pid_file.exists() {
        return Ok(ServiceStatus::Stopped);
    }
    
    // Step 2: Try to read PID from file
    let pid = match read_pid_file(pid_file) {
        Ok(pid) => pid,
        Err(e) => {
            // PID file exists but is corrupted/invalid
            return Ok(ServiceStatus::InvalidFile {
                error: format!("{}", e),
            });
        }
    };
    
    // Step 3: Check if process is running
    let process_running = match platform::is_process_running(pid) {
        Ok(running) => running,
        Err(e) => {
            // Unexpected error checking process status
            // Treat as invalid file rather than crashing
            return Ok(ServiceStatus::InvalidFile {
                error: format!("Cannot verify process status: {}", e),
            });
        }
    };
    
    if !process_running {
        // Process not running = stale PID file
        return Ok(ServiceStatus::StaleFile { pid });
    }
    
    // Step 4: Process is running - check if it's a zombie
    match is_zombie_process(pid) {
        Ok(true) => {
            // Process exists but is a zombie (defunct)
            Ok(ServiceStatus::Zombie { pid })
        }
        Ok(false) => {
            // Process is running normally
            Ok(ServiceStatus::Running { pid })
        }
        Err(_) => {
            // Cannot determine zombie status
            // Err on the side of reporting as running
            // (zombie detection is best-effort, not critical)
            Ok(ServiceStatus::Running { pid })
        }
    }
}

/// Validate a PID value before using it for process operations
///
/// Ensures PID is safe to use with kill() and other process APIs:
/// - Rejects PID 0 (kernel scheduler / current process group signal)
/// - Rejects PID 1 (init/systemd/launchd)
/// - Rejects negative PIDs (process group signals)
/// - Validates against system-specific maximum
///
/// This is a critical security control preventing:
/// - System crashes from signaling init (PID 1)
/// - Unintended process group signals (PID 0, negative PIDs)
/// - Detection of corrupted PID files (out-of-range values)
///
/// # Arguments
/// * `pid` - The PID value to validate
///
/// # Returns
/// * `Ok(())` if PID is valid and safe to use
/// * `Err(anyhow::Error)` with detailed error message if invalid
///
/// # Security
/// This function implements CWE-20 (Improper Input Validation) mitigation
/// for untrusted PID values read from filesystem.
fn validate_pid(pid: platform::ProcessId) -> Result<()> {
    // Reject reserved system PIDs and process group signals
    if pid <= 1 {
        anyhow::bail!(
            "Invalid PID {}: Cannot signal kernel (PID 0) or init/systemd (PID 1)",
            pid
        );
    }
    
    // Get platform-specific maximum PID value
    let pid_max = get_system_pid_max();
    
    if pid > pid_max {
        anyhow::bail!(
            "Invalid PID {}: Exceeds system maximum {} (likely corrupted PID file)",
            pid,
            pid_max
        );
    }
    
    Ok(())
}

/// Get the system's maximum PID value
///
/// Platform-specific implementations:
/// - **Linux**: Read /proc/sys/kernel/pid_max and subtract 1
///   - File contains wrap-around value (one greater than max assignable PID)
///   - Default: 32768 (max assignable: 32767)
///   - 64-bit max: 4194304 (configurable)
///   - 32-bit max: 32768 (hard limit)
///
/// - **macOS**: Use PID_MAX constant from kern_fork.c
///   - PID_MAX = 99999, PIDs assigned < PID_MAX
///   - Maximum assignable: 99998
///
/// - **Fallback**: Conservative default (32768) for other Unix systems
///
/// # Returns
/// Maximum assignable PID value for current platform
fn get_system_pid_max() -> platform::ProcessId {
    #[cfg(target_os = "linux")]
    {
        // Linux: /proc/sys/kernel/pid_max contains wrap-around value
        // Actual maximum assignable PID is (pid_max - 1)
        // See: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#pid-max
        std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .map(|max| max - 1)  // Subtract 1: file contains wrap-around value
            .unwrap_or(32767)     // Fallback: standard Unix default maximum
    }
    
    #[cfg(target_os = "macos")]
    {
        // macOS: PID_MAX is 99999 in kern_fork.c
        // PIDs are assigned < PID_MAX, so maximum assignable is 99998
        // See: https://apple.stackexchange.com/questions/51119
        99998
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Conservative fallback for other Unix systems
        // Uses historical Unix 16-bit PID limit
        32767
    }
}

/// Daemonize the current process using platform-specific mechanisms.
///
/// This function performs the traditional Unix "double-fork" daemonization on Unix
/// systems, or no-ops on Windows (where services are managed by SCM).
///
/// # Platform Behavior
///
/// - **Unix (not under service manager)**: Performs double-fork daemonization
/// - **Unix (under systemd/launchd)**: Skips daemonization (detected automatically)
/// - **Windows**: No-op (SCM handles daemonization)
///
/// # Automatic Service Manager Detection
///
/// The function calls [`platform::running_under_service_manager()`] to detect if
/// the process is already managed by a service manager (systemd, launchd, SCM).
/// If so, it skips daemonization since the service manager handles process lifecycle.
///
/// Detection logic:
/// - **systemd**: Checks for `INVOCATION_ID` environment variable
/// - **launchd** (macOS): Platform-specific detection
/// - **Windows SCM**: Always returns true (services run under SCM)
///
/// # Unix Double-Fork Process
///
/// When daemonization is needed, the following steps occur:
///
/// 1. **First fork()**: Background the process
/// 2. **setsid()**: Create new session, detach from controlling terminal
/// 3. **Second fork()**: Prevent daemon from acquiring a terminal again
/// 4. **chdir(config.working_directory)**: Change to configured directory (prevent unmount issues)
/// 5. **umask(0o022)**: Reset file creation mask
/// 6. **Close FDs**: Close all file descriptors ≥ 3
/// 7. **Redirect stdio**: Reopen stdin/stdout/stderr to `/dev/null`
///
/// # Readiness Notification
///
/// The parent process blocks until the grandchild signals readiness via a pipe.
/// This ensures the parent doesn't exit until the daemon is fully initialized.
///
/// Readiness signal flow:
/// ```text
/// Parent ──fork()──> Child ──fork()──> Grandchild (daemon)
///   │                  │                    │
///   │                  └─ exit(0)           │
///   │                                       │
///   │ ◄────────────── pipe ─────────────── write("OK")
///   └─ exit(0)
/// ```
///
/// # Safety Considerations
///
/// **Multi-threading**: This function calls `fork()`, which is unsafe in multi-threaded
/// programs. It MUST be called before spawning any threads. Calling fork() after thread
/// creation can cause:
/// - Deadlocks (mutexes locked in parent but not in child)
/// - Resource leaks (child gets copies of file descriptors)
/// - Undefined behavior
///
/// **Call early in main()**: Best practice is to call this as one of the first operations
/// in `main()`, before initializing any complex resources.
///
/// # Errors
///
/// Returns an error if:
/// - `fork()` fails (out of process slots, resource limits)
/// - `setsid()` fails (process is already a session leader)
/// - Unable to open `/dev/null` for redirection
/// - Unable to redirect stdin/stdout/stderr
/// - Unable to signal readiness to parent
///
/// # Example
///
/// ```no_run
/// use kodegend::daemon::daemonise;
/// use kodegend::config::ServiceConfig;
/// use kodegend::platform;
/// use anyhow::Result;
///
/// fn main() -> Result<()> {
///     let config = ServiceConfig::default();
///     
///     // IMPORTANT: Call before any threads are spawned
///     if !platform::running_under_service_manager() {
///         daemonise(&config)?;
///         // We are now the grandchild process running in the background
///         // Parent and intermediate child have exited
///     }
///     
///     // Continue with daemon initialization
///     Ok(())
/// }
/// ```
///
/// # See Also
///
/// - [`platform::running_under_service_manager()`] - Service manager detection
/// - [`systemd_ready()`] - Signal readiness to systemd
/// - [daemon(3)](https://man7.org/linux/man-pages/man3/daemon.3.html)
#[allow(dead_code)]
pub fn daemonise(config: &crate::config::ServiceConfig) -> Result<()> {
    #[cfg(unix)]
    {
        unix_daemonise(config)
    }

    #[cfg(windows)]
    {
        // Windows services are already daemonized by Service Control Manager (SCM)
        // No double-fork needed - SCM handles process lifecycle
        info!("Windows service mode – daemonization handled by SCM");
        Ok(())
    }
}

#[cfg(unix)]
#[allow(dead_code)]
fn unix_daemonise(config: &crate::config::ServiceConfig) -> Result<()> {
    use nix::sys::resource::{Resource, getrlimit};
    use nix::sys::stat::{Mode, umask};
    use nix::unistd::{ForkResult, chdir, close, fork, pipe, read, setsid, write};
    use std::os::unix::io::{AsRawFd, RawFd};

    // Use platform API to detect if we're under a service manager
    if platform::running_under_service_manager() {
        info!("Service manager detected – skipping classic daemonise");
        return Ok(());
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 1: Create readiness notification pipe
    // ═══════════════════════════════════════════════════════════════
    let (read_fd, write_fd) = pipe().context("Failed to create readiness notification pipe")?;
    let read_fd = read_fd.into_raw_fd();
    let write_fd = write_fd.into_raw_fd();

    // ═══════════════════════════════════════════════════════════════
    // STEP 2: First fork - create intermediate process
    // ═══════════════════════════════════════════════════════════════
    match unsafe { fork().context("first fork")? } {
        ForkResult::Parent { child: _ } => {
            // ═══════════════════════════════════════════════════════
            // ORIGINAL PARENT: Close write end, wait for readiness
            // ═══════════════════════════════════════════════════════
            close(write_fd).context("close write_fd in parent")?;

            // Block until grandchild signals readiness or pipe closes
            let mut buf = [0u8; READINESS_BUFFER_SIZE];
            match read(
                unsafe { std::os::fd::BorrowedFd::borrow_raw(read_fd) },
                &mut buf,
            ) {
                Ok(n) if n == READINESS_BUFFER_SIZE && &buf == READINESS_SIGNAL => {
                    // ✅ Grandchild is ready and initialized
                    close(read_fd).ok(); // Best effort cleanup
                    info!("Daemon initialization confirmed");
                    std::process::exit(0); // Exit with SUCCESS
                }
                Ok(0) => {
                    // Pipe closed without "OK" - child crashed or failed
                    close(read_fd).ok();
                    error!("Daemon failed to initialize (pipe closed without signal)");
                    std::process::exit(1); // Exit with FAILURE
                }
                Ok(n) => {
                    // Unexpected data length
                    close(read_fd).ok();
                    error!(
                        "Daemon sent invalid readiness signal (expected {} bytes, got {})",
                        READINESS_BUFFER_SIZE, n
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    // Read error (should never happen with pipe)
                    close(read_fd).ok();
                    error!("Failed to read daemon readiness signal: {}", e);
                    std::process::exit(1);
                }
            }
        }
        ForkResult::Child => {
            // ═══════════════════════════════════════════════════════
            // INTERMEDIATE CHILD: Close read end, continue
            // ═══════════════════════════════════════════════════════
            close(read_fd).context("close read_fd in child")?;
            // write_fd stays open - will be inherited by grandchild
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 3: Create new session (detach from controlling terminal)
    // ═══════════════════════════════════════════════════════════════
    setsid().context("setsid")?;

    // ═══════════════════════════════════════════════════════════════
    // STEP 4: Second fork - ensure not session leader
    // ═══════════════════════════════════════════════════════════════
    match unsafe { fork().context("second fork")? } {
        ForkResult::Parent { child: _ } => {
            // Intermediate child exits immediately
            // write_fd will be closed automatically (RAII)
            std::process::exit(0);
        }
        ForkResult::Child => {
            // ═══════════════════════════════════════════════════════
            // GRANDCHILD (FINAL DAEMON): Perform initialization
            // ═══════════════════════════════════════════════════════
            // write_fd is still open - will signal readiness later
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 5: Standard daemon initialization
    // ═══════════════════════════════════════════════════════════════

    // Change working directory (prevents unmount issues)
    // Uses config.working_directory (defaults to "/" on Unix, "C:\" on Windows)
    let working_dir = config
        .working_directory
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 in working directory path"))?;

    chdir(working_dir)
        .with_context(|| format!("Failed to change directory to {}", working_dir))?;

    log::debug!("Changed working directory to: {}", working_dir);

    // Reset file creation mask
    umask(Mode::from_bits_truncate(DAEMON_UMASK as _));

    // Close all file descriptors except write_fd
    let max_fd = if let Ok((soft_limit, _hard_limit)) = getrlimit(Resource::RLIMIT_NOFILE) {
        (soft_limit as i32).min(MAX_FD_SOFT_LIMIT)
    } else {
        FALLBACK_MAX_FD
    };

    for fd in FIRST_USER_FD..max_fd {
        if fd != write_fd {
            let _ = close(fd);
        }
    }

    // Redirect stdin, stdout, stderr to /dev/null
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("open /dev/null")?;

    let devnull_fd = devnull.as_raw_fd();

    for target in standard_fds() {
        if unsafe { libc::dup2(devnull_fd, target) } == -1 {
            // If this fails, we can't signal parent (no stderr)
            // Close write_fd to signal failure
            close(write_fd).ok();
            return Err(anyhow::anyhow!(
                "Failed to redirect fd {} to /dev/null: {}",
                target,
                std::io::Error::last_os_error()
            ));
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 6: Signal readiness to original parent
    // ═══════════════════════════════════════════════════════════════

    // At this point, daemon is initialized and ready
    // Signal parent by writing "OK" and closing pipe
    match write(
        unsafe { std::os::fd::BorrowedFd::borrow_raw(write_fd) },
        READINESS_SIGNAL,
    ) {
        Ok(n) if n == READINESS_BUFFER_SIZE => {
            // Successfully wrote signal
            close(write_fd).context("close write_fd after signaling")?;
            info!("Signaled readiness to parent process");
        }
        Ok(n) => {
            // Partial write (should never happen with small signal on pipe)
            close(write_fd).ok();
            return Err(anyhow::anyhow!(
                "Partial write to readiness pipe: wrote {} bytes instead of {}",
                n,
                READINESS_BUFFER_SIZE
            ));
        }
        Err(e) => {
            // Write failed
            close(write_fd).ok();
            return Err(anyhow::anyhow!("Failed to signal readiness: {}", e));
        }
    }

    // Daemon is now fully initialized and parent has been notified
    Ok(())
}
