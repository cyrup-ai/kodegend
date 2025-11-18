use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use log::{info, warn, error};
#[cfg(all(feature = "systemd-notify", target_os = "linux"))]
use systemd::daemon;

use crate::platform;

/// Tell systemd the daemon is ready (no‑op when feature is off).
///
/// On Unix: Uses sd_notify to signal readiness to systemd
/// On Windows: No-op (Windows Services use ServiceStatusHandle for status reporting)
#[cfg(unix)]
pub fn systemd_ready() {
    #[cfg(all(feature = "systemd-notify", target_os = "linux"))]
    {
        if let Err(e) = daemon::notify(false, &[daemon::NotifyState::Ready]) {
            warn!("sd_notify failed: {e}");
        }
    }
}

#[cfg(windows)]
pub fn systemd_ready() {
    // No-op on Windows - systemd doesn't exist
    // Windows Service status is reported via ServiceStatusHandle (see platform/windows_service.rs)
}

/// RAII guard for PID file management
/// 
/// Automatically removes PID file when dropped (on normal exit, panic, or scope exit).
/// Validates existing PID files to prevent multiple daemon instances.
pub struct PidFile {
    path: PathBuf,
}

impl PidFile {
    /// Create and validate PID file
    /// 
    /// Returns error if:
    /// - Another instance is already running (PID exists and process is alive)
    /// - Cannot write to PID file location (permission denied)
    /// - Cannot validate existing PID (may be running as different user)
    pub fn create(path: PathBuf) -> Result<Self> {
        // Check if PID file already exists
        if path.exists() {
            Self::handle_existing_pid_file(&path)?;
        }
        
        // Create parent directory if needed (e.g., user's first run)
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Creating PID file directory: {}", parent.display()))?;
        }
        
        // Write current process PID
        let pid = std::process::id();
        fs::write(&path, pid.to_string())
            .with_context(|| format!("Writing PID file: {}", path.display()))?;
        
        info!("Created PID file: {} (PID: {})", path.display(), pid);
        
        Ok(Self { path })
    }
    
    /// Handle existing PID file - validate if process is still running
    ///
    /// Uses platform-agnostic process checking:
    /// - Unix: kill(pid, 0) via platform::is_process_running()
    /// - Windows: OpenProcess() via platform::is_process_running()
    fn handle_existing_pid_file(path: &Path) -> Result<()> {
        // Read existing PID
        let pid_str = fs::read_to_string(path)
            .with_context(|| format!("Reading existing PID file: {}", path.display()))?;
        
        // Use platform::ProcessId for cross-platform compatibility
        let existing_pid = pid_str.trim().parse::<platform::ProcessId>()
            .with_context(|| format!("Parsing PID from file {}: '{}'", path.display(), pid_str))?;
        
        // Use platform-agnostic process checking
        match platform::is_process_running(existing_pid) {
            Ok(true) => {
                // Process exists - daemon already running
                Err(anyhow!(
                    "Daemon already running with PID {} (PID file: {})\n\
                     Use 'kodegend stop' to stop the existing daemon first.",
                    existing_pid,
                    path.display()
                ))
            }
            Ok(false) => {
                // Process doesn't exist - stale PID file, safe to remove
                warn!(
                    "Removing stale PID file {} (PID {} not running)",
                    path.display(),
                    existing_pid
                );
                fs::remove_file(path)
                    .with_context(|| format!("Removing stale PID file: {}", path.display()))?;
                Ok(())
            }
            Err(e) => {
                // Error checking process status (permission denied, system error, etc.)
                Err(anyhow!(
                    "Error checking if daemon is running (PID {}): {}\n\
                     PID file: {}",
                    existing_pid,
                    e,
                    path.display()
                ))
            }
        }
    }
    
    /// Get the path to the PID file
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
                info!("Removed PID file: {}", self.path.display());
            }
            Err(e) => {
                // Log but don't panic in Drop
                error!("Failed to remove PID file {}: {}", self.path.display(), e);
            }
        }
    }
}

/// Perform the traditional Unix "double‑fork" daemonisation
/// 
/// Steps:
/// 1. `fork`; parent exits.
/// 2. Child calls `setsid` to drop the controlling TTY.
/// 3. `fork` again so we are **not** a session leader (protects from reacquiring a TTY).
/// 4. `chdir /`, reset umask.
/// 5. Close every FD ≥ 3.
/// 6. Re‑open `/dev/null` on stdin/stdout/stderr.
/// 
/// NOTE: PID file creation now handled by caller using PidFile RAII guard
/// Platform-specific daemonization
///
/// On Unix: Performs double-fork daemonization for classic init systems
/// On Windows: No-op because SCM handles process management
pub fn daemonise() -> Result<()> {
    #[cfg(unix)]
    {
        unix_daemonise()
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
fn unix_daemonise() -> Result<()> {
    // Import Unix-specific types only within cfg(unix) block
    use std::os::unix::io::{AsRawFd, RawFd};
    use nix::sys::resource::{getrlimit, Resource};
    use nix::sys::stat::{Mode, umask};
    use nix::unistd::{ForkResult, chdir, close, fork, setsid};

    // Use platform API to detect if we're under a service manager
    if platform::running_under_service_manager() {
        info!("Service manager detected – skipping classic daemonise");
        return Ok(());
    }

    match unsafe { fork().context("first fork")? } {
        ForkResult::Parent { .. } => std::process::exit(0),
        ForkResult::Child => {}
    }

    setsid().context("setsid")?;

    match unsafe { fork().context("second fork")? } {
        ForkResult::Parent { .. } => std::process::exit(0),
        ForkResult::Child => {}
    }

    chdir("/").context("chdir")?;
    umask(Mode::from_bits_truncate(0o022));

    // Close everything except stdin/out/err.
    // Use getrlimit(RLIMIT_NOFILE) to determine the process's max open files limit.
    // This is the canonical approach from Stevens & Rago APUE, Chapter 13.
    let max_fd = if let Ok((soft_limit, _hard_limit)) = getrlimit(Resource::RLIMIT_NOFILE) {
        // Cap at 65536 to avoid excessive syscalls if limit is very high (e.g., RLIM_INFINITY).
        // This covers 99.99% of real-world cases while preventing multi-second delays.
        soft_limit.min(65536) as RawFd
    } else {
        // Fallback: reasonable default if getrlimit fails (should never happen on POSIX systems)
        1024
    };

    // Close all FDs from 3 to max_fd.
    // Closing unopened FDs returns EBADF, which we safely ignore - this is standard practice.
    // Cost: ~100ms for 65536 syscalls, but most FDs don't exist so they're fast-path errors.
    for fd in 3..max_fd {
        let _ = close(fd);
    }

    // stdin, stdout, stderr → /dev/null
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("open /dev/null")?;

    let devnull_fd = devnull.as_raw_fd();

    // Redirect stdin, stdout, stderr to /dev/null using raw FDs
    for target in 0..=2 {
        if unsafe { libc::dup2(devnull_fd, target) } == -1 {
            return Err(anyhow::anyhow!(
                "Failed to redirect fd {} to /dev/null: {}",
                target,
                std::io::Error::last_os_error()
            ));
        }
    }

    // devnull File will be closed automatically when it goes out of scope

    // PID file creation now happens in caller using PidFile::create()
    // This ensures RAII cleanup works properly
    
    Ok(())
}
