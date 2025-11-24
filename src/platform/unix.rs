//! Unix platform implementation (Linux, macOS, BSD)
//!
//! Preserves existing kodegend Unix behavior:
//! - Uses nix crate for system calls
//! - Fork-based daemonization (see daemon.rs)
//! - POSIX signals for process management
//! - XDG Base Directory Specification for paths

use std::path::{Path, PathBuf};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use nix::unistd::{Pid, getpid, geteuid, Uid};
use nix::sys::signal::kill;
use anyhow::{Context, Result, bail};

/// Securely ensure a directory exists with correct ownership and permissions
/// 
/// This function prevents symlink attacks by:
/// 1. Attempting atomic creation with restrictive permissions (0o700)
/// 2. If directory exists, validating it is NOT a symlink
/// 3. Verifying ownership matches expected UID
/// 4. Verifying permissions are 0o700 (owner-only access)
/// 
/// # Security Properties
/// - Fails-secure: Returns error rather than using unsafe directory
/// - TOCTOU-resistant: Validates after creation attempt, not before
/// - Defense-in-depth: Multiple validation layers
/// 
/// # Arguments
/// - `path`: Directory path to create/validate
/// - `expected_uid`: Expected owner UID (typically current user)
/// 
/// # Errors
/// Returns security error if:
/// - Path is a symlink (CWE-59 prevention)
/// - Ownership mismatch (privilege escalation prevention)
/// - Permissions too permissive (data exposure prevention)
fn ensure_secure_directory(path: &Path, expected_uid: Uid) -> Result<()> {
    // Step 1: Attempt atomic directory creation with restrictive permissions
    let mut builder = DirBuilder::new();
    builder.mode(0o700); // Owner-only: rwx------
    
    match builder.create(path) {
        Ok(_) => {
            // Successfully created - we own it with correct permissions
            log::debug!("Created secure directory: {}", path.display());
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Directory exists - must validate it's safe to use
            log::debug!("Directory exists, validating security: {}", path.display());
        }
        Err(e) => {
            // Other error (permission denied, disk full, etc.)
            return Err(e).context(format!("Failed to create directory: {}", path.display()));
        }
    }
    
    // Step 2: Validate existing directory is NOT a symlink (CRITICAL)
    // Use symlink_metadata to avoid following symlinks
    let metadata = fs::symlink_metadata(path)
        .context(format!("Failed to read metadata for: {}", path.display()))?;
    
    if metadata.file_type().is_symlink() {
        bail!(
            "SECURITY: Directory is a symlink - potential attack detected: {}\n\
             This could be a CWE-59 symlink attack. Directory will not be used.",
            path.display()
        );
    }
    
    if !metadata.is_dir() {
        bail!(
            "SECURITY: Path exists but is not a directory: {}",
            path.display()
        );
    }
    
    // Step 3: Verify ownership matches expected UID
    let file_uid = Uid::from_raw(metadata.uid());
    
    if file_uid != expected_uid {
        bail!(
            "SECURITY: Directory ownership mismatch: {}\n\
             Expected UID: {}, Found UID: {}\n\
             This could indicate a privilege escalation attack.",
            path.display(),
            expected_uid,
            file_uid
        );
    }
    
    // Step 4: Verify permissions are sufficiently restrictive (0o700)
    let perms = metadata.permissions();
    let mode = perms.mode() & 0o777; // Extract permission bits
    
    if mode != 0o700 {
        bail!(
            "SECURITY: Directory has unsafe permissions: {}\n\
             Expected: 0o700 (rwx------), Found: 0o{:o}\n\
             Permissions must be owner-only to prevent privilege escalation.",
            path.display(),
            mode
        );
    }
    
    log::debug!("Validated secure directory: {} (uid={}, mode=0o{:o})", 
                path.display(), expected_uid, mode);
    Ok(())
}

/// Check if running as root (uid == 0)
///
/// Uses nix::unistd::geteuid() - same as existing config.rs logic
pub fn platform_is_elevated() -> bool {
    geteuid().is_root()
}

/// Detect systemd or launchd service manager
///
/// Preserves existing logic from daemon.rs:15-33
#[allow(dead_code)]
pub fn platform_running_under_service_manager() -> bool {
    // systemd sets INVOCATION_ID (daemon.rs:16)
    if std::env::var_os("INVOCATION_ID").is_some() {
        return true;
    }

    // macOS launchd detection (daemon.rs:32)
    if cfg!(target_os = "macos")
        && (std::env::var_os("LAUNCHED_BY_LAUNCHD").is_some()
            || std::env::var_os("XPC_SERVICE_NAME").is_some()) {
            return true;
        }

    false
}

/// Get current process PID
///
/// Uses nix::unistd::getpid()
#[allow(dead_code)]
pub fn platform_current_process_id() -> i32 {
    getpid().as_raw()
}

/// Check if process is running using POSIX kill() with signal 0
///
/// Preserves exact logic from daemon.rs:83-108
///
/// Returns:
/// - Ok(true): Process exists (kill succeeded or EPERM)
/// - Ok(false): Process doesn't exist (ESRCH)
/// - Err: System error
pub fn platform_is_process_running(pid: i32) -> Result<bool, std::io::Error> {
    match kill(Pid::from_raw(pid), None) {
        Ok(_) => Ok(true),  // Process exists and we can signal it
        Err(nix::errno::Errno::ESRCH) => Ok(false),  // No such process
        Err(nix::errno::Errno::EPERM) => Ok(true),   // Process exists but permission denied
        Err(e) => Err(std::io::Error::from_raw_os_error(e as i32)),
    }
}

/// System configuration directory: /etc/kodegend
pub fn platform_system_config_dir() -> PathBuf {
    PathBuf::from("/etc/kodegend")
}

/// User configuration directory: ~/.config/kodegend
///
/// Follows XDG Base Directory Specification
pub fn platform_user_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("kodegend")
}

/// Runtime directory for PID files and sockets
///
/// Elevated: /var/run/kodegend
/// User: $XDG_RUNTIME_DIR/kodegend or /tmp/kodegend-{uid}/kodegend (securely created)
///
/// # Security
/// 
/// When falling back to /tmp, this function ensures both the base directory
/// and subdirectory are created securely to prevent CWE-59 symlink attacks.
pub fn platform_runtime_dir(is_elevated: bool) -> PathBuf {
    if is_elevated {
        PathBuf::from("/var/run/kodegend")
    } else {
        // Try XDG_RUNTIME_DIR first (preferred, systemd provides this securely)
        if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
            return PathBuf::from(xdg_runtime).join("kodegend");
        }
        
        // Try dirs::runtime_dir() (platform-specific secure runtime directory)
        if let Some(runtime) = dirs::runtime_dir() {
            return runtime.join("kodegend");
        }
        
        // Fallback: /tmp/kodegend-{uid}/kodegend with security validation
        let current_uid = geteuid();
        let base_dir = PathBuf::from(format!("/tmp/kodegend-{}", current_uid));
        let runtime_dir = base_dir.join("kodegend");
        
        // Securely create both base and subdirectory
        // This prevents symlink attacks at ANY level of the path
        if let Err(e) = ensure_secure_directory(&base_dir, current_uid) {
            log::error!(
                "Failed to create secure base runtime directory: {}\n\
                 Error: {}\n\
                 Daemon cannot start safely. Please check directory permissions.",
                base_dir.display(),
                e
            );
            panic!(
                "SECURITY: Cannot create secure runtime directory at {}: {}",
                base_dir.display(),
                e
            );
        }
        
        if let Err(e) = ensure_secure_directory(&runtime_dir, current_uid) {
            log::error!(
                "Failed to create secure runtime subdirectory: {}\n\
                 Error: {}\n\
                 Daemon cannot start safely.",
                runtime_dir.display(),
                e
            );
            panic!(
                "SECURITY: Cannot create secure runtime directory at {}: {}",
                runtime_dir.display(),
                e
            );
        }
        
        log::info!("Using secure fallback runtime directory: {}", runtime_dir.display());
        runtime_dir
    }
}

/// Log directory
///
/// Elevated: /var/log/kodegend
/// User: ~/.local/state/kodegend/logs
pub fn platform_log_dir(is_elevated: bool) -> PathBuf {
    if is_elevated {
        PathBuf::from("/var/log/kodegend")
    } else {
        dirs::state_dir()
            .unwrap_or_else(|| PathBuf::from("~/.local/state"))
            .join("kodegend/logs")
    }
}
