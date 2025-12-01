//! Unix platform implementation (Linux, macOS, BSD)
//!
//! Preserves existing kodegend Unix behavior:
//! - Uses nix crate for system calls
//! - Fork-based daemonization (see daemon.rs)
//! - POSIX signals for process management
//! - XDG Base Directory Specification for paths

use anyhow::{Context, Result, bail};
use kodegen_config::KodegenConfig;
use nix::sys::signal::kill;
use nix::unistd::{Pid, Uid, geteuid, getpid};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use sysinfo::{Pid as SysinfoPid, ProcessesToUpdate, System};

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

    log::debug!(
        "Validated secure directory: {} (uid={}, mode=0o{:o})",
        path.display(),
        expected_uid,
        mode
    );
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
            || std::env::var_os("XPC_SERVICE_NAME").is_some())
    {
        return true;
    }

    false
}

/// Cache for systemd availability detection (checked once, used forever)
#[allow(dead_code)] // FALSE POSITIVE: Used by is_systemd_available() via get_or_init()
static SYSTEMD_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Detect if systemd is the init system on this machine
///
/// Uses the official detection method from systemd documentation:
/// checks if /run/systemd/system directory exists.
///
/// This is cached globally because systemd availability never changes at runtime.
/// First call: ~0.01ms (filesystem stat)
/// Subsequent calls: ~0.000001ms (cached value)
///
/// # Returns
///
/// - `true` if systemd is the init system (PID 1)
/// - `false` on non-systemd systems (Alpine/OpenRC, Void/runit, Devuan/sysvinit, etc.)
///
/// # References
///
/// - [sd_booted(3) man page](https://www.freedesktop.org/software/systemd/man/sd_booted.html)
/// - Official systemd detection method since systemd v44 (2011)
///
/// # Examples
///
/// ```rust
/// use kodegend::platform;
///
/// if platform::is_systemd_available() {
///     // Use systemctl commands, create .service files
///     install_systemd_unit()?;
/// } else {
///     // Fallback to traditional daemon mode or show error
///     eprintln!("systemd not detected - manual daemon management required");
/// }
/// ```
#[allow(dead_code)] // FALSE POSITIVE: Exported and used via platform::is_systemd_available()
pub fn is_systemd_available() -> bool {
    *SYSTEMD_AVAILABLE.get_or_init(|| {
        std::path::Path::new("/run/systemd/system").exists()
    })
}

/// Get current process PID
///
/// Uses nix::unistd::getpid()
#[allow(dead_code)]
pub fn platform_current_process_id() -> i32 {
    getpid().as_raw()
}

/// Check if process exists and is NOT a zombie
///
/// Uses platform-specific methods to verify process is alive and operational:
/// - Linux: Reads /proc/PID/stat to check process state
/// - macOS: Uses `ps -p PID -o state=` to check state
/// - Other Unix: Fallback to `ps` command parsing
///
/// Returns:
/// - Ok(true): Process exists and is running (not zombie)
/// - Ok(false): Process doesn't exist or is zombie
/// - Err: System error (permission denied, etc.)
pub fn platform_is_process_running(pid: i32) -> Result<bool, std::io::Error> {
    // Quick existence check using kill(pid, 0)
    match kill(Pid::from_raw(pid), None) {
        Err(nix::errno::Errno::ESRCH) => {
            // Process definitely doesn't exist
            return Ok(false);
        }
        Err(e) => {
            // System error (permission denied, invalid argument, etc.)
            return Err(std::io::Error::from_raw_os_error(e as i32));
        }
        Ok(_) => {
            // Process exists - now check if it's a zombie
            // Fall through to platform-specific checks
        }
    }

    // Platform-specific zombie detection
    #[cfg(target_os = "linux")]
    {
        is_process_alive_linux(pid)
    }

    #[cfg(not(target_os = "linux"))]
    {
        is_process_alive_ps(pid)
    }
}

/// Linux-specific: Check /proc/PID/stat for zombie state
///
/// The /proc/PID/stat format (from proc(5) man page):
/// ```
/// pid (comm) state ppid pgrp session tty_nr tpgid flags ...
/// ```
/// The 3rd field is the process state:
/// - R: Running
/// - S: Sleeping
/// - D: Disk sleep (uninterruptible)
/// - Z: Zombie ❌
/// - T: Stopped
/// - t: Tracing stop
/// - X: Dead
///
/// See: https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
#[cfg(target_os = "linux")]
fn is_process_alive_linux(pid: i32) -> Result<bool, std::io::Error> {
    let stat_path = format!("/proc/{}/stat", pid);
    
    // Read /proc/PID/stat file
    let stat_content = match fs::read_to_string(&stat_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Process disappeared between kill(0) and stat read
            return Ok(false);
        }
        Err(e) => {
            // Permission denied or other I/O error
            return Err(e);
        }
    };
    
    // Parse the state field (third whitespace-separated field)
    // We need to handle process names with spaces, which are enclosed in parentheses
    // Example: "1234 (my process) S ..."
    
    // Find the last ')' which closes the process name
    let close_paren = stat_content.rfind(')').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid /proc/{}/stat format: no closing paren", pid)
        )
    })?;
    
    // State is the first character after ") "
    let state_char = stat_content[close_paren + 2..]
        .chars()
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid /proc/{}/stat format: no state field", pid)
            )
        })?;
    
    // Return false for zombie processes, true otherwise
    Ok(state_char != 'Z')
}

/// macOS/BSD/other Unix: Use `ps` command to check state
///
/// The `ps -p PID -o state=` command outputs the process state code.
/// On macOS/BSD, zombie processes show as 'Z' in the state field.
///
/// This is less efficient than Linux's /proc but works across all Unix variants.
/// The command runs in ~2-5ms which is acceptable for non-hot-path status checks.
///
/// See: BSD ps(1) man page
#[cfg(not(target_os = "linux"))]
fn is_process_alive_ps(pid: i32) -> Result<bool, std::io::Error> {
    // Run: ps -p PID -o state=
    // This outputs only the state code without headers
    let output = Command::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("state=")
        .output()?;
    
    if !output.status.success() {
        // ps command failed - process likely doesn't exist
        return Ok(false);
    }
    
    // Parse state output (should be a single character or short code)
    let state = String::from_utf8_lossy(&output.stdout);
    let state = state.trim();
    
    // Check if state contains 'Z' (zombie)
    // On some systems it's just "Z", on others "Z+", "Zs", etc.
    Ok(!state.contains('Z'))
}

/// System configuration directory: /etc/kodegend
pub fn platform_system_config_dir() -> PathBuf {
    PathBuf::from("/etc/kodegend")
}

/// User configuration directory: ~/.config/kodegen/kodegend
///
/// Follows XDG Base Directory Specification via kodegen-config
pub fn platform_user_config_dir() -> PathBuf {
    KodegenConfig::user_config_dir()
        .map(|dir| dir.join("kodegend"))
        .unwrap_or_else(|_| PathBuf::from(".config/kodegen/kodegend"))
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

        log::info!(
            "Using secure fallback runtime directory: {}",
            runtime_dir.display()
        );
        runtime_dir
    }
}

/// Log directory
///
/// Elevated: /var/log/kodegend
/// User: Uses kodegen-config's log_dir for consistency
pub fn platform_log_dir(is_elevated: bool) -> PathBuf {
    if is_elevated {
        PathBuf::from("/var/log/kodegend")
    } else {
        // Use kodegen-config's log_dir for consistency
        kodegen_config::KodegenConfig::log_dir()
            .unwrap_or_else(|_| PathBuf::from("/tmp/kodegend/logs"))
    }
}

/// Status socket path for daemon queries
///
/// Elevated: /var/run/kodegend/status.sock
/// User: $XDG_RUNTIME_DIR/kodegend/status.sock or /tmp/kodegend-{uid}/kodegend/status.sock
///
/// Uses same base directory as runtime_dir for consistency
pub fn platform_status_socket_path(is_elevated: bool) -> PathBuf {
    platform_runtime_dir(is_elevated).join("status.sock")
}

/// Get the system's maximum PID value for Unix platforms
///
/// Platform-specific implementations:
/// - **Linux**: Read /proc/sys/kernel/pid_max and subtract 1
///   - File contains wrap-around value (one greater than max assignable PID)
///   - Default: 32768 (max assignable: 32767)
///   - 64-bit max: 4194304 (configurable)
///   - Fallback: 4,194,303 (absolute max for 64-bit Linux)
///
/// - **macOS**: PID_MAX is 99999 in kern_fork.c
///   - PIDs are assigned < PID_MAX, so maximum assignable is 99998
///   - See: https://github.com/apple/darwin-xnu/blob/main/bsd/kern/kern_fork.c
///
/// - **FreeBSD**: Read kern.pid_max sysctl
///   - Fallback to 99,999 if sysctl unavailable
///
/// - **Other Unix**: Conservative default (32767)
///
/// # Returns
/// Maximum assignable PID value for current platform
pub(super) fn platform_get_system_pid_max() -> i32 {
    #[cfg(target_os = "linux")]
    {
        // Linux: /proc/sys/kernel/pid_max contains wrap-around value
        // Actual maximum assignable PID is (pid_max - 1)
        // See: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#pid-max
        std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .map(|max| max - 1)  // Subtract 1: file contains wrap-around value
            .unwrap_or(4_194_303)  // Fallback: absolute max for 64-bit Linux
    }
    
    #[cfg(target_os = "macos")]
    {
        // macOS: PID_MAX is 99999 in kern_fork.c
        // PIDs are assigned < PID_MAX, so maximum assignable is 99998
        // See: https://apple.stackexchange.com/questions/51119
        // XNU source: https://github.com/apple/darwin-xnu/blob/main/bsd/kern/kern_fork.c
        99998
    }
    
    #[cfg(target_os = "freebsd")]
    {
        // FreeBSD: Try to read kern.pid_max sysctl
        // Fallback to typical maximum if unavailable
        get_freebsd_pid_max().unwrap_or(99_999)
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        // Conservative fallback for other Unix systems
        // Uses historical Unix 16-bit PID limit
        32767
    }
}

/// Platform-specific PID validation for Unix systems
///
/// Validates that a PID is within the safe range for this platform.
/// This prevents dangerous operations like signaling init (PID 1), the kernel
/// (PID 0), or using process group semantics (negative PIDs).
///
/// # Validation Rules
/// 1. PID must be positive (> 0)
/// 2. PID must not be 1 (init/systemd/launchd - critical system process)
/// 3. PID must not exceed platform-specific maximum (prevents corrupted PID files)
///
/// # Returns
/// - Ok(()) if PID is valid and safe to use
/// - Err with detailed error message if invalid
pub(super) fn platform_validate_pid_range(pid: i32) -> Result<(), anyhow::Error> {
    // Check 1: PID must be positive (rejects PID 0 and negative values)
    if pid <= 0 {
        bail!(
            "Invalid PID: {} (PIDs must be positive integers)\n\
             \n\
             Special cases:\n\
             - PID 0: Reserved for kernel scheduler\n\
             - Negative PIDs: Used for process groups in kill()\n\
             \n\
             This likely indicates a corrupted or malicious PID file.",
            pid
        );
    }
    
    // Check 2: PID must not be 1 (init/systemd/launchd)
    if pid == 1 {
        bail!(
            "Invalid PID: 1 (init/systemd/launchd)\n\
             \n\
             PID 1 is the system init process and must never be signaled.\n\
             This indicates a corrupted PID file.",
        );
    }
    
    // Check 3: Platform-specific maximum (detects corrupted PID files)
    let max_pid = platform_get_system_pid_max();
    
    if pid > max_pid {
        bail!(
            "Invalid PID: {} exceeds system maximum {}\n\
             \n\
             Platform-specific PID limits:\n\
             - Linux: Configurable via /proc/sys/kernel/pid_max (typically 32767, max 4194303)\n\
             - macOS: Hard limit of 99998\n\
             - FreeBSD: Configurable via kern.pid_max sysctl (typically 99999)\n\
             - Other Unix: Conservative default of 32767\n\
             \n\
             This PID is outside the valid range for this system and likely indicates\n\
             a corrupted PID file or malicious input.",
            pid,
            max_pid
        );
    }
    
    Ok(())
}

/// Read FreeBSD kern.pid_max sysctl value
///
/// Attempts to read the kern.pid_max sysctl using the sysctl command.
/// This is a fallback method that works without additional dependencies.
///
/// Returns Some(max_pid) if successful, None otherwise.
#[cfg(target_os = "freebsd")]
fn get_freebsd_pid_max() -> Option<i32> {
    let output = Command::new("sysctl")
        .arg("-n")
        .arg("kern.pid_max")
        .output()
        .ok()?;
    
    let pid_max_str = String::from_utf8(output.stdout).ok()?;
    pid_max_str.trim().parse().ok()
}

/// Verify PID belongs to kodegend using sysinfo
///
/// Uses sysinfo::System to get process info and check executable path.
/// This is the cross-platform approach that works on Linux, macOS, FreeBSD.
///
/// Pattern copied from service/port_cleanup.rs:128-138
///
/// # Implementation Details
/// 1. Quick check: Does PID exist at all? (via kill signal 0)
/// 2. Use sysinfo to get Process object
/// 3. Extract executable path via Process::exe()
/// 4. Verify filename is "kodegend" or starts with "kodegend"
///
/// # Race Conditions
/// A process could exit between the existence check and sysinfo lookup.
/// This is safe - we return false (process not kodegend), allowing daemon startup.
///
/// # Performance
/// - System::new(): ~0.5ms
/// - refresh_processes(): ~1-5ms depending on system load
/// - Total: ~1-5ms per call (acceptable for daemon control operations)
///
/// # Security
/// Prevents CVE-2023-30328 class attacks (CVSS 9.8 CRITICAL)
pub(super) fn platform_verify_kodegend_running(pid: i32) -> Result<bool, std::io::Error> {
    // First check if process exists at all (fast path)
    if !platform_is_process_running(pid)? {
        return Ok(false);
    }

    // Use sysinfo to get process details
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);

    let sysinfo_pid = SysinfoPid::from(pid as usize);
    let process = match system.process(sysinfo_pid) {
        Some(p) => p,
        None => {
            // Race condition: process exited between kill(0) check and sysinfo lookup
            // This is safe - process is gone, not kodegend
            log::debug!(
                "Process {} exited between existence check and verification",
                pid
            );
            return Ok(false);
        }
    };

    // Check executable path (most reliable method)
    match process.exe() {
        Some(exe_path) => {
            // Extract filename from path
            let exe_name = exe_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Verify it's kodegend
            // Accept both "kodegend" and "kodegend-debug" or similar variants
            let is_kodegend = exe_name == "kodegend" || exe_name.starts_with("kodegend");

            if is_kodegend {
                log::debug!(
                    "Verified PID {} is kodegend (exe: {})",
                    pid,
                    exe_path.display()
                );
            } else {
                log::debug!("PID {} is NOT kodegend (exe: {})", pid, exe_path.display());
            }

            Ok(is_kodegend)
        }
        None => {
            // Cannot read executable path (permission denied or process characteristics)
            // This could happen with kernel threads or special system processes
            // Fail-safe: assume it's NOT kodegend
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Cannot read executable path for PID {}", pid),
            ))
        }
    }
}
