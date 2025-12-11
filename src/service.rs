mod autoconfig;
pub mod port_cleanup;
pub mod embedded_servers;
pub mod path_validation;

pub use path_validation::validate_and_normalize_working_dir;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use wait_timeout::ChildExt;

use anyhow::{Context, Result};
use chrono::Utc;
use crossbeam_channel::{Receiver, Sender, bounded, select, tick};
use log::{error, info, warn};
use thiserror::Error;

use crate::config::ServiceDefinition;
use crate::ipc::{Cmd, Evt, ServiceState};

#[cfg(windows)]
use crate::platform::windows::JobObject;

/// Maximum iterations when cleaning up old numbered log files.
/// This prevents unbounded loops while being generous enough for any realistic scenario.
/// Industry standard tools like logrotate typically keep 4-7 rotated files.
const MAX_LOG_CLEANUP_ITERATIONS: u32 = 100;

/// Service worker errors
#[derive(Error, Debug)]
pub enum ServiceError {
    /// Thread spawn failed due to OS resource limits
    #[error("Failed to spawn thread for service '{service}': {source}")]
    SpawnFailed {
        service: String,
        #[source]
        source: std::io::Error,
    },

    /// Channel communication error
    #[error("Channel send failed: {0}")]
    ChannelSend(#[from] crossbeam_channel::SendError<crate::ipc::Evt>),
}

pub struct ServiceWorker {
    name: Arc<str>,
    rx: Receiver<Cmd>,
    tx: Sender<Cmd>,
    bus: Sender<Evt>,
    def: ServiceDefinition,
    
    // Windows-specific: Job object for child process lifecycle management
    // When this handle is dropped, all assigned children are automatically terminated
    #[cfg(windows)]
    job: Option<JobObject>,
}

impl ServiceWorker {
    pub fn spawn(def: ServiceDefinition, bus: Sender<Evt>) -> Result<Sender<Cmd>, ServiceError> {
        let (tx, rx) = bounded::<Cmd>(16);
        
        // Convert to Arc<str> ONCE at service creation
        let name: Arc<str> = Arc::from(def.name.as_str());
        let name_for_thread = Arc::clone(&name);
        let tx_clone = tx.clone();

        // Windows-specific: Create job object for child process lifecycle
        // Uses KILL_ON_CLOSE flag - when handle drops, all children terminate
        #[cfg(windows)]
        let job = {
            // Create job with no resource limits (0, 0) - lifecycle only
            // Resource limits are handled by the separate job in main.rs
            match JobObject::new(0, 0) {
                Ok(j) => {
                    log::info!("{}: Created job object for child lifecycle management", name);
                    Some(j)
                }
                Err(e) => {
                    log::warn!("{}: Failed to create job object: {}. Child cleanup not guaranteed.", name, e);
                    None
                }
            }
        };

        thread::Builder::new()
            .name(format!("svc-{}", name_for_thread))
            .spawn(move || {
                let mut worker = ServiceWorker {
                    name: name_for_thread,
                    rx,
                    tx: tx_clone,
                    bus,
                    def,
                    #[cfg(windows)]
                    job,
                };
                if let Err(e) = worker.run() {
                    error!("Worker {} crashed: {:#}", worker.name, e);
                }
            })
            .map_err(|source| ServiceError::SpawnFailed {
                service: name.to_string(),
                source,
            })?;

        Ok(tx)
    }

    fn run(&mut self) -> Result<()> {
        let health_tick = tick(Duration::from_secs(60));
        let rotate_tick = tick(Duration::from_secs(3600));
        let mut child: Option<Child> = None;

        loop {
            select! {
                recv(self.rx) -> msg => match msg? {
                    Cmd::Start { correlation_id }    => self.start(&mut child, Some(correlation_id))?,
                    Cmd::Stop { correlation_id }     => self.stop(&mut child, Some(correlation_id))?,
                    Cmd::Restart { correlation_id }  => {
                        self.stop(&mut child, Some(correlation_id))?;
                        self.start(&mut child, Some(correlation_id))?;
                    },
                    Cmd::Pause { correlation_id } => {
                        // Report pausing state
                        self.bus.send(Evt::State {
                            service: Arc::clone(&self.name),
                            state: ServiceState::Pausing,
                            ts: Utc::now(),
                            pid: child.as_ref().map(|c| c.id()),
                            correlation_id: Some(correlation_id),
                        })?;
                        
                        // Stop child process (reuse existing stop logic)
                        self.stop(&mut child, Some(correlation_id))?;
                        
                        // Report paused state
                        self.bus.send(Evt::State {
                            service: Arc::clone(&self.name),
                            state: ServiceState::Paused,
                            ts: Utc::now(),
                            pid: None,  // No PID when paused
                            correlation_id: Some(correlation_id),
                        })?;
                    },
                    Cmd::Continue { correlation_id } => {
                        // Restart child process (reuse existing start logic)
                        self.start(&mut child, Some(correlation_id))?;
                        
                        // Note: start() already sends Running state via bus
                        // No additional state reporting needed
                    },
                    Cmd::Shutdown => {
                        self.stop(&mut child, None)?;
                        break;
                    },
                    Cmd::TickHealth { correlation_id }   => self.health_check(&mut child, correlation_id)?,
                    Cmd::TickLogRotate { correlation_id }=> self.rotate_logs(correlation_id)?,
                    // QueryVulnerabilities is a manager-level command, not sent to service workers
                    // It's handled by ServiceManager::run_vulnerability_scan() in manager.rs
                    Cmd::QueryVulnerabilities { .. } => {},
                },
                recv(health_tick) -> _ => {
                    // Spontaneous health check (not triggered by command)
                    let correlation_id = 0;
                    self.health_check(&mut child, correlation_id)?;
                },
                recv(rotate_tick) -> _ => {
                    // Spontaneous log rotation (not triggered by command)
                    let correlation_id = 0;
                    self.rotate_logs(correlation_id)?;
                },
            }
        }
        Ok(())
    }

    fn start(&self, child: &mut Option<Child>, correlation_id: Option<u64>) -> Result<()> {
        if child.is_some() {
            warn!("{} already running", self.name);
            return Ok(());
        }

        // Determine stdout target: log file or /dev/null
        let stdout_target = if let Some(path) = &self.def.log_stdout {
            // Convert &String to PathBuf for path operations
            let log_path = std::path::PathBuf::from(path);

            // Create parent directory if needed
            if let Some(parent) = log_path.parent() {
                std::fs::create_dir_all(parent).context("create log directory")?;
            }

            // Open log file in append mode
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .context("open stdout log")?;

            // Convert File to Stdio (transfers ownership to Command)
            Stdio::from(file)
        } else {
            Stdio::null() // Default to null device (cross-platform: /dev/null on Unix, NUL on Windows)
        };

        // Same pattern for stderr
        let stderr_target = if let Some(path) = &self.def.log_stderr {
            let log_path = std::path::PathBuf::from(path);

            if let Some(parent) = log_path.parent() {
                std::fs::create_dir_all(parent).context("create log directory")?;
            }

            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .context("open stderr log")?;

            Stdio::from(file)
        } else {
            Stdio::null() // Default to null device (cross-platform: /dev/null on Unix, NUL on Windows)
        };

        // Build command with redirected I/O
        #[cfg(unix)]
        let mut cmd = {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg(&self.def.command);
            cmd
        };

        #[cfg(windows)]
        let mut cmd = {
            let mut cmd = Command::new("cmd");
            cmd.args(["/C", &self.def.command]);
            cmd
        };

        cmd.stdout(stdout_target) // Attach log file or null device
            .stderr(stderr_target); // Attach log file or null device

        // Validate and apply working directory if configured
        if let Some(raw_dir) = &self.def.working_dir {
            // Validate and normalize the working directory
            // This expands ~, expands env vars, validates existence, and canonicalizes
            let validated_dir = validate_and_normalize_working_dir(
                raw_dir,
                &self.name
            ).context(format!(
                "Failed to validate working directory for service '{}'",
                self.name
            ))?;
            
            // Log the transformation for transparency
            if validated_dir.to_string_lossy() != *raw_dir {
                info!(
                    "{} working_dir: {} → {}",
                    self.name,
                    raw_dir,
                    validated_dir.display()
                );
            }
            
            cmd.current_dir(&validated_dir);
        }

        // Create new process group with child as leader (PGID = child PID)
        // This enables process group signaling for clean shutdown of entire subtree
        #[cfg(unix)]
        {
            cmd.process_group(0);
            
            log::debug!(
                "{}: Configuring new process group (PGID will equal PID after spawn)",
                self.name
            );
        }

        // Spawn the process (file handles are now owned by child)
        let mut spawned = cmd.spawn().context(format!(
            "Failed to spawn '{}' in directory '{:?}'", 
            self.def.command,
            self.def.working_dir.as_ref().unwrap_or(&".".to_string())
        ))?;
        let pid = spawned.id();

        // Windows-specific: Assign child to job object for automatic cleanup
        #[cfg(windows)]
        if let Some(ref job) = self.job {
            match job.assign_process(pid) {
                Ok(_) => {
                    log::debug!("{}: Assigned child (PID {}) to job object", self.name, pid);
                }
                Err(e) => {
                    // Log warning but continue - child will not be auto-terminated on exit
                    // Common causes: child already in another job (rare), permission issues
                    log::warn!(
                        "{}: Failed to assign child (PID {}) to job object: {}. \
                         Child may not be cleaned up when daemon exits.",
                        self.name, pid, e
                    );
                }
            }
        }

        // ADDED: Post-spawn verification - detect immediate failures
        // Wait 100ms to catch fast-fail scenarios (missing libs, permission errors, etc.)
        // This mirrors the pattern used in stop() method (line 241)
        thread::sleep(Duration::from_millis(100));

        // Check if process already exited (crash detection pattern from health_check line 333)
        match spawned.try_wait() {
            Ok(Some(status)) => {
                // Process exited immediately - startup failed
                let error_msg = format!(
                    "Process '{}' (pid {}) exited immediately with status: {:?}",
                    self.def.command, pid, status
                );
                
                error!("{}", error_msg);
                
                // Send crash event to trigger restart logic in manager
                self.bus.send(Evt::State {
                    service: Arc::clone(&self.name),
                    state: ServiceState::StoppedCrash,
                    ts: Utc::now(),
                    pid: Some(pid),
                    correlation_id,
                })?;
                
                // Return error to caller (propagates to manager.rs spawn call)
                return Err(anyhow::anyhow!(error_msg));
            }
            Ok(None) => {
                // Process still running after 100ms - likely successful start
                info!("{} verified running (pid {})", self.name, pid);
            }
            Err(e) => {
                // Error checking process status - fail closed
                let error_msg = format!(
                    "Failed to verify startup of '{}' (pid {}): {}",
                    self.def.command, pid, e
                );
                
                error!("{}", error_msg);
                
                // Send crash event
                self.bus.send(Evt::State {
                    service: Arc::clone(&self.name),
                    state: ServiceState::StoppedCrash,
                    ts: Utc::now(),
                    pid: Some(pid),
                    correlation_id,
                })?;
                
                return Err(anyhow::anyhow!(error_msg));
            }
        }

        // Process verified - safe to mark as Running and store child handle
        *child = Some(spawned);

        // Send state event
        self.bus.send(Evt::State {
            service: Arc::clone(&self.name),
            state: ServiceState::Running,
            ts: Utc::now(),
            pid: Some(pid),
            correlation_id,
        })?;

        info!("{} started and verified (pid {})", self.name, pid);
        Ok(())
    }

    fn stop(&self, child: &mut Option<Child>, correlation_id: Option<u64>) -> Result<()> {
        if let Some(mut ch) = child.take() {
            let pid = ch.id();

            // Unix-only: Try graceful shutdown with SIGTERM to process group first
            #[cfg(unix)]
            {
                use nix::sys::signal::{Signal, killpg};
                use nix::unistd::Pid;

                let pgid = Pid::from_raw(pid as i32);  // PGID == PID from process_group(0)
                
                info!("{} sending SIGTERM to process group (PGID: {})", self.name, pgid);

                // Send SIGTERM to entire process group for graceful shutdown
                match killpg(pgid, Signal::SIGTERM) {
                    Ok(_) => {
                        // Wait for graceful exit with configurable timeout
                        let grace_period = Duration::from_secs(
                            self.def.shutdown_timeout_secs.unwrap_or(10)
                        );

                        // Use wait_timeout - zero polling overhead
                        match ch.wait_timeout(grace_period)? {
                            Some(status) => {
                                // Process group exited gracefully within timeout
                                info!(
                                    "{} process group exited gracefully in <{:.1}s with status: {:?}",
                                    self.name,
                                    grace_period.as_secs_f64(),
                                    status
                                );
                                self.send_stopped_event(pid, correlation_id)?;
                                return Ok(());
                            }
                            None => {
                                // Timeout expired, process group still running
                                warn!(
                                    "{} process group did not exit within {:.1}s grace period, sending SIGKILL",
                                    self.name,
                                    grace_period.as_secs_f64()
                                );
                                
                                // Escalate to SIGKILL for entire process group
                                killpg(pgid, Signal::SIGKILL)
                                    .context("Failed to SIGKILL process group")?;
                                
                                ch.wait()?;
                                self.send_stopped_event(pid, correlation_id)?;
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        // Process group may have already exited (race condition)
                        // This is non-fatal - we'll wait on the child handle to confirm
                        warn!(
                            "{} killpg(SIGTERM) failed: {} (process group may have already exited)",
                            self.name, e
                        );
                        
                        // Still try to wait on child to reap zombie
                        let _ = ch.wait();
                        self.send_stopped_event(pid, correlation_id)?;
                        return Ok(());
                    }
                }
            }

            // Windows path: TerminateProcess (unchanged)
            #[cfg(windows)]
            {
                info!(
                    "{} terminating process (pid {}) via TerminateProcess",
                    self.name, pid
                );
                ch.kill().context("TerminateProcess failed")?;

                match ch.wait() {
                    Ok(status) => {
                        info!(
                            "{} terminated with TerminateProcess: {:?}",
                            self.name, status
                        );
                    }
                    Err(e) => {
                        warn!("{} wait() failed after TerminateProcess: {}", self.name, e);
                    }
                }

                self.send_stopped_event(pid, correlation_id)?;
            }
        }
        Ok(())
    }

    /// Helper to send stopped event on the bus
    fn send_stopped_event(&self, pid: u32, correlation_id: Option<u64>) -> Result<()> {
        self.bus.send(Evt::State {
            service: Arc::clone(&self.name),
            state: ServiceState::StoppedClean,
            ts: Utc::now(),
            pid: Some(pid),
            correlation_id,
        })?;
        Ok(())
    }

    fn health_check(&self, child: &mut Option<Child>, correlation_id: u64) -> Result<()> {
        // Track if this is a crash (unexpected exit) vs just not running
        let mut is_crash = false;

        // Explicitly handle all possible states instead of using .ok().flatten()
        let healthy = match child.as_mut() {
            Some(c) => {
                // We have a child process handle, check its status
                match c.try_wait() {
                    Ok(None) => {
                        // Process is still running - HEALTHY
                        // try_wait() returned Ok(None) means child hasn't exited
                        true
                    }
                    Ok(Some(status)) => {
                        // Process has exited unexpectedly - CRASH
                        // Log the exit status for debugging
                        warn!("{} process exited unexpectedly: {:?}", self.name, status);
                        is_crash = true;
                        false
                    }
                    Err(e) => {
                        // Error checking process status - FAIL CLOSED (treat as UNHEALTHY)
                        // This catches EPERM, ECHILD, EBADF, EINTR, etc.
                        // Previously these were silently treated as healthy via .ok()
                        error!(
                            "{} health check error: {} (treating as unhealthy)",
                            self.name, e
                        );
                        false
                    }
                }
            }
            None => {
                // No process running at all - UNHEALTHY (but not a crash, just not started)
                false
            }
        };

        // If process crashed, send crash event and clear child reference
        if is_crash {
            warn!("{} crashed, sending stopped-crash event", self.name);
            self.bus.send(Evt::State {
                service: Arc::clone(&self.name),
                state: ServiceState::StoppedCrash, // Unexpected exit = crash
                ts: Utc::now(),
                pid: None,
                correlation_id: None, // Crashes are spontaneous
            })?;
            
            // CRITICAL FIX: Properly cleanup Child to close file descriptors
            // take() removes Option<Child> and gives us ownership
            if let Some(mut crashed_child) = child.take() {
                // Even though try_wait() already reaped the zombie (returned Some(status)),
                // we must explicitly call wait() to ensure the Child's Drop implementation
                // properly closes all file descriptors in the parent process.
                //
                // From Rust docs: "dropping Child handles without waiting on them first 
                // is not recommended in long-running applications"
                //
                // wait() will return immediately since process already exited,
                // but ensures proper cleanup of stdio file handles.
                let _ = crashed_child.wait();
                
                // crashed_child is now dropped with full cleanup → FDs closed
            }
        }

        // Send health status to manager via crossbeam channel (zero-alloc)
        self.bus.send(Evt::Health {
            service: Arc::clone(&self.name),
            healthy,
            ts: Utc::now(),
            correlation_id,
        })?;

        // If unhealthy and auto_restart enabled, trigger restart via self-loop
        if !healthy && self.def.auto_restart {
            warn!("{} unhealthy → restart", self.name);
            
            // Use send_timeout to prevent indefinite blocking and detect channel issues
            // 2-second timeout is generous (command processing is typically <50ms)
            match self.tx.send_timeout(Cmd::Restart { correlation_id: 0 }, Duration::from_secs(2)) {
                Ok(_) => {
                    // Successfully queued restart command
                }
                Err(e) => {
                    // CRITICAL: Auto-restart failed - service will stay down
                    error!("{} CRITICAL: Auto-restart command failed: {}", self.name, e);
                    
                    // Notify monitoring systems via fatal event
                    self.bus.send(Evt::Fatal {
                        service: Arc::clone(&self.name),
                        msg: format!("Auto-restart channel send failed: {}", e).into(),
                        ts: Utc::now(),
                    })?;
                }
            }
        }

        Ok(())
    }

    fn rotate_logs(&self, correlation_id: u64) -> Result<()> {
        // Only rotate if log_rotation config exists
        let Some(ref rotation_config) = self.def.log_rotation else {
            // No rotation configured - just send event and return
            self.bus.send(Evt::LogRotate {
                service: Arc::clone(&self.name),
                ts: Utc::now(),
                correlation_id,
            })?;
            return Ok(());
        };

        // Rotate stdout log if configured
        if let Some(ref log_path) = self.def.log_stdout {
            rotate_single_log(
                log_path,
                rotation_config.max_size_mb,
                rotation_config.max_files,
                rotation_config.compress,
                rotation_config.timestamp,
            )?;
        }

        // Rotate stderr log if configured
        if let Some(ref log_path) = self.def.log_stderr {
            rotate_single_log(
                log_path,
                rotation_config.max_size_mb,
                rotation_config.max_files,
                rotation_config.compress,
                rotation_config.timestamp,
            )?;
        }

        // Send rotation event
        self.bus.send(Evt::LogRotate {
            service: Arc::clone(&self.name),
            ts: Utc::now(),
            correlation_id,
        })?;

        // Restart service to close old file descriptors and open new ones
        // This ensures the rotated file stops growing and a fresh log file is created
        // Uses correlation_id: 0 because this is a self-triggered restart (not from manager)
        if self.def.log_stdout.is_some() || self.def.log_stderr.is_some() {
            warn!(
                "{} rotating logs, restarting service to reopen file descriptors",
                self.name
            );
            self.tx.send(Cmd::Restart { correlation_id: 0 }).ok();
        }

        Ok(())
    }
}

/// Clean up orphaned temporary compressed files from previous crashes
///
/// Scans the log file's parent directory for .gz.tmp files (incomplete compression attempts)
/// and removes them. This is called at the start of each rotation to ensure a clean state.
///
/// This is a best-effort operation - failures are logged but do not prevent rotation.
fn cleanup_orphaned_temp_files(log_path: &str) -> Result<()> {
    use std::path::Path;
    
    // Get parent directory of log file
    let log_path = Path::new(log_path);
    let parent = match log_path.parent() {
        Some(p) => p,
        None => return Ok(()), // No parent directory
    };
    
    // Scan directory for .gz.tmp files
    let entries = match std::fs::read_dir(parent) {
        Ok(e) => e,
        Err(_) => return Ok(()), // Directory not accessible, skip cleanup
    };
    
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Remove any .gz.tmp files (orphaned from previous crashes)
            if name.ends_with(".gz.tmp") {
                log::warn!("Cleaning up orphaned temporary compressed file: {:?}", path);
                let _ = std::fs::remove_file(&path); // Best-effort, ignore errors
            }
        }
    }
    
    Ok(())
}

/// Helper function to rotate a single log file
///
/// Implements standard Unix log rotation:
/// - Checks file size against max_size_mb
/// - Renames current log to rotated name
/// - Creates new empty log file automatically on next write
/// - Optionally compresses rotated logs with gzip
/// - Deletes old rotated logs beyond max_files limit
fn rotate_single_log(
    log_path: &str,
    max_size_mb: u64,
    max_files: u32,
    compress: bool,
    timestamp: bool,
) -> Result<()> {
    use std::fs;
    use std::path::Path;

    // Clean up orphaned temp files from previous crashes
    cleanup_orphaned_temp_files(log_path)?;

    // ============================================================================
    // DEFENSIVE VALIDATION (Defense in Depth)
    // 
    // These checks should never trigger if config validation is working correctly.
    // They protect against:
    // - Bugs in config loading
    // - Programmatic construction of ServiceDefinition without validation
    // - Future refactoring mistakes
    // 
    // Pattern: Log warning and fail gracefully rather than panicking
    // ============================================================================
    
    // Check max_size_mb
    if max_size_mb == 0 {
        log::warn!(
            "rotate_single_log called with max_size_mb=0 for '{}'. \
             This should have been caught by config validation. \
             Skipping rotation to prevent constant rotation cycles.",
            log_path
        );
        return Ok(());
    }
    
    // Check max_files
    if max_files == 0 {
        log::warn!(
            "rotate_single_log called with max_files=0 for '{}'. \
             This should have been caught by config validation. \
             Skipping rotation to prevent immediate deletion of rotated logs.",
            log_path
        );
        return Ok(());
    }
    
    // Check log_path
    if log_path.is_empty() {
        return Err(anyhow::anyhow!(
            "rotate_single_log called with empty log_path. \
             This indicates a critical bug in config validation."
        ));
    }
    
    // ============================================================================
    // END DEFENSIVE VALIDATION
    // ============================================================================

    let path = Path::new(log_path);

    // Check if file exists and needs rotation
    if !path.exists() {
        return Ok(()); // Nothing to rotate
    }

    let metadata = fs::metadata(path)?;
    let size_mb = metadata.len() / (1024 * 1024);

    if size_mb < max_size_mb {
        return Ok(()); // Not large enough to rotate yet
    }

    // Generate rotated filename based on strategy
    let rotated_name = if timestamp {
        // Timestamped strategy: service.log.20250117_143022
        let now = chrono::Utc::now();
        format!("{}.{}", log_path, now.format("%Y%m%d_%H%M%S"))
    } else {
        // Numbered strategy: shift .1 → .2, .2 → .3, etc.
        // This loop shifts existing rotated files up by one
        for i in (1..max_files).rev() {
            let old = format!("{}.{}", log_path, i);
            let new = format!("{}.{}", log_path, i + 1);

            // Check both uncompressed and compressed versions
            if Path::new(&old).exists() {
                fs::rename(&old, &new)
                    .with_context(|| format!("Failed to shift rotated log {} → {}", old, new))?;
            }
            let old_gz = format!("{}.gz", old);
            let new_gz = format!("{}.gz", new);
            if Path::new(&old_gz).exists() {
                fs::rename(&old_gz, &new_gz)
                    .with_context(|| format!("Failed to shift compressed log {} → {}", old_gz, new_gz))?;
            }
        }

        format!("{}.1", log_path)
    };

    // Rename current log to rotated name
    // The service will be restarted to close old file descriptors and create new ones
    fs::rename(path, &rotated_name)?;

    // Compress if requested
    if compress {
        use std::io::{BufReader, BufWriter, copy};
        use flate2::Compression;
        use flate2::write::GzEncoder;
        
        // Compress to temporary file first (atomic rename pattern)
        let temp_compressed = format!("{}.gz.tmp", rotated_name);
        
        // Stream compress (memory efficient, handles large files)
        {
            let input_file = fs::File::open(&rotated_name)
                .context("open rotated log for compression")?;
            let mut input = BufReader::new(input_file);
            
            let output_file = fs::File::create(&temp_compressed)
                .context("create temporary compressed file")?;
            let output = BufWriter::new(output_file);
            let mut encoder = GzEncoder::new(output, Compression::default());
            
            copy(&mut input, &mut encoder)
                .context("compress log file")?;
            
            // Critical: finalize gzip stream (writes CRC32 trailer)
            encoder.finish()
                .context("finalize gzip stream")?;
        }  // Files closed and flushed here
        
        // Atomic rename: only now does compressed file become visible
        let final_compressed = format!("{}.gz", rotated_name);
        fs::rename(&temp_compressed, &final_compressed)
            .context("finalize compressed log")?;
        
        // Now safe to delete original (compressed version guaranteed complete)
        fs::remove_file(&rotated_name)
            .context("remove uncompressed rotated log")?;
    }

    // Clean up old rotated files beyond max_files limit
    if !timestamp {
        // For numbered rotation, delete files beyond max_files
        for i in (max_files + 1)..(max_files + 1 + MAX_LOG_CLEANUP_ITERATIONS) {
            let old_file = format!("{}.{}", log_path, i);
            let old_gz = format!("{}.gz", old_file);

            // Stop when no more files exist
            if !Path::new(&old_file).exists() && !Path::new(&old_gz).exists() {
                break;
            }

            // Remove both compressed and uncompressed versions
            // Cleanup failures are non-fatal (old files remain, no data loss)
            // But we warn so administrators can detect disk space issues
            // Ignore NotFound (race condition: file deleted by external process)
            if let Err(e) = fs::remove_file(&old_file)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                warn!("Failed to delete old log file {} (beyond max_files={}): {}", 
                      old_file, max_files, e);
            }
            if let Err(e) = fs::remove_file(&old_gz)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                warn!("Failed to delete compressed log {} (beyond max_files={}): {}", 
                      old_gz, max_files, e);
            }
        }
    } else {
        // For timestamped rotation, count existing archives and delete oldest
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let Some(file_name_os) = path.file_name() else {
            return Ok(()); // No filename to match, skip cleanup
        };
        let filename = file_name_os.to_string_lossy();

        // Find all rotated versions (both .gz and non-.gz)
        let mut archives: Vec<_> = fs::read_dir(parent)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                
                // Early return if doesn't match (avoids .to_string() allocation)
                // Uses Cow::to_string_lossy() which doesn't allocate for valid UTF-8
                if !name_str.starts_with(filename.as_ref()) || name_str == filename.as_ref() {
                    return None;
                }
                
                // Only matching entries reach here - no wasted allocations
                Some(entry)
            })
            .collect();

        // Sort by modification time using sort_by_cached_key
        // This calls metadata() ONCE per element, not once per comparison
        // Reduces metadata syscalls from O(n log n) to O(n)
        archives.sort_by_cached_key(|e| {
            e.metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });

        // Delete oldest archives beyond max_files
        let to_delete = archives.len().saturating_sub(max_files as usize);
        for entry in archives.iter().take(to_delete) {
            if let Err(e) = fs::remove_file(entry.path()) {
                // Timestamped cleanup failures should be visible but non-fatal
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Failed to delete old timestamped log {:?} (beyond max_files={}): {}", 
                          entry.path(), max_files, e);
                }
            }
        }
    }

    Ok(())
}

/// Public function to spawn a service worker
pub fn spawn(def: ServiceDefinition, bus: Sender<Evt>) -> Result<Sender<Cmd>, ServiceError> {
    // Check if this is the special autoconfig service
    if def.name == "kodegen-autoconfig" || def.service_type == Some("autoconfig".to_string()) {
        return autoconfig::spawn_autoconfig(def, bus);
    }

    // Otherwise spawn normal service
    ServiceWorker::spawn(def, bus)
}
