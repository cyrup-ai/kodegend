use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use log::{info, warn, error};
#[cfg(all(feature = "systemd-notify", target_os = "linux"))]
use systemd::daemon;

#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg};
#[cfg(unix)]
use std::os::fd::IntoRawFd;

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
    #[cfg(unix)]
    _lock: Flock<std::fs::File>,  // Keep lock alive for daemon lifetime
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
        
        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Creating PID file directory: {}", parent.display()))?;
        }
        
        // Open PID file with O_CREAT | O_RDWR
        // We use O_CREAT (not O_EXCL) because we need to handle stale locks
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .with_context(|| format!("Opening PID file: {}", path.display()))?;
        
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
                )).context(format!("Lock error: {}", err));
            }
        };
        
        // Now we hold the lock - safe to read and validate existing PID
        let mut locked_file = lock_guard.deref();
        let mut existing_content = String::new();
        locked_file.read_to_string(&mut existing_content)
            .context("Reading existing PID file content")?;
        
        // If there's existing content, validate it's a stale PID
        if !existing_content.trim().is_empty()
            && let Ok(existing_pid) = existing_content.trim().parse::<platform::ProcessId>() {
                match platform::is_process_running(existing_pid) {
                    Ok(true) => {
                        // This should never happen since we hold the lock
                        // But defensive programming is good
                        return Err(anyhow!(
                            "Daemon appears to be running (PID {}), but we hold the lock. \
                             This is a bug - please report it.",
                            existing_pid
                        ));
                    }
                    Ok(false) => {
                        // Stale PID - safe to overwrite
                        warn!(
                            "Overwriting stale PID file {} (PID {} not running)",
                            path.display(),
                            existing_pid
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Cannot verify PID {} status: {}. Proceeding anyway since we hold lock.",
                            existing_pid,
                            e
                        );
                    }
                }
            }
        
        // Write our PID to the file (lock is held, so this is safe)
        let our_pid = std::process::id();
        locked_file.set_len(0)
            .context("Truncating PID file")?;
        locked_file.seek(SeekFrom::Start(0))
            .context("Seeking to start of PID file")?;
        writeln!(locked_file, "{}", our_pid)
            .with_context(|| format!("Writing PID {} to file", our_pid))?;
        locked_file.sync_all()
            .context("Syncing PID file to disk")?;
        
        info!("Created PID file: {} (PID: {})", path.display(), our_pid);
        
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
#[allow(dead_code)]
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
#[allow(dead_code)]
fn unix_daemonise() -> Result<()> {
    use std::os::unix::io::{AsRawFd, RawFd};
    use nix::sys::resource::{getrlimit, Resource};
    use nix::sys::stat::{Mode, umask};
    use nix::unistd::{ForkResult, chdir, close, fork, setsid, pipe, read, write};

    // Use platform API to detect if we're under a service manager
    if platform::running_under_service_manager() {
        info!("Service manager detected – skipping classic daemonise");
        return Ok(());
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 1: Create readiness notification pipe
    // ═══════════════════════════════════════════════════════════════
    let (read_fd, write_fd) = pipe()
        .context("Failed to create readiness notification pipe")?;
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
            let mut buf = [0u8; 2];
            match read(unsafe { std::os::fd::BorrowedFd::borrow_raw(read_fd) }, &mut buf) {
                Ok(2) if &buf == b"OK" => {
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
                    error!("Daemon sent invalid readiness signal (expected 2 bytes, got {})", n);
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
    
    // Change to root directory (prevents unmount issues)
    chdir("/").context("chdir")?;
    
    // Reset file creation mask
    umask(Mode::from_bits_truncate(0o022));

    // Close all file descriptors except write_fd
    let max_fd = if let Ok((soft_limit, _hard_limit)) = getrlimit(Resource::RLIMIT_NOFILE) {
        soft_limit.min(65536) as RawFd
    } else {
        1024
    };

    for fd in 3..max_fd {
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

    for target in 0..=2 {
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
    match write(unsafe { std::os::fd::BorrowedFd::borrow_raw(write_fd) }, b"OK") {
        Ok(2) => {
            // Successfully wrote 2 bytes
            close(write_fd).context("close write_fd after signaling")?;
            info!("Signaled readiness to parent process");
        }
        Ok(n) => {
            // Partial write (should never happen with 2 bytes on pipe)
            close(write_fd).ok();
            return Err(anyhow::anyhow!(
                "Partial write to readiness pipe: wrote {} bytes instead of 2",
                n
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
