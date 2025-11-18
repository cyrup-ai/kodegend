mod autoconfig;
mod port_cleanup;

pub mod embedded_servers;

use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use crossbeam_channel::{Receiver, Sender, bounded, select, tick};
use log::{error, info, warn};
use thiserror::Error;

use crate::config::ServiceDefinition;
use crate::ipc::{Cmd, Evt};

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
    name: String,
    rx: Receiver<Cmd>,
    tx: Sender<Cmd>,
    bus: Sender<Evt>,
    def: ServiceDefinition,
}

impl ServiceWorker {
    pub fn spawn(def: ServiceDefinition, bus: Sender<Evt>) -> Result<Sender<Cmd>, ServiceError> {
        let (tx, rx) = bounded::<Cmd>(16);
        let name = def.name.clone();
        let name_for_thread = name.clone();
        let tx_clone = tx.clone();

        thread::Builder::new()
            .name(format!("svc-{}", name_for_thread))
            .spawn(move || {
                let mut worker = ServiceWorker {
                    name: name_for_thread,
                    rx,
                    tx: tx_clone,
                    bus,
                    def,
                };
                if let Err(e) = worker.run() {
                    error!("Worker {} crashed: {:#}", worker.name, e);
                }
            })
            .map_err(|source| ServiceError::SpawnFailed {
                service: name,
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
                    Cmd::Start    => self.start(&mut child)?,
                    Cmd::Stop     => self.stop(&mut child)?,
                    Cmd::Restart  => { self.stop(&mut child)?; self.start(&mut child)?; },
                    Cmd::Shutdown => { self.stop(&mut child)?; break; },
                    Cmd::TickHealth   => self.health_check(&mut child)?,
                    Cmd::TickLogRotate=> self.rotate_logs()?,
                },
                recv(health_tick) -> _ => self.health_check(&mut child)?,
                recv(rotate_tick) -> _ => self.rotate_logs()?,
            }
        }
        Ok(())
    }

    fn start(&self, child: &mut Option<Child>) -> Result<()> {
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
                std::fs::create_dir_all(parent)
                    .context("create log directory")?;
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
            Stdio::null()  // Default to null device (cross-platform: /dev/null on Unix, NUL on Windows)
        };
        
        // Same pattern for stderr
        let stderr_target = if let Some(path) = &self.def.log_stderr {
            let log_path = std::path::PathBuf::from(path);
            
            if let Some(parent) = log_path.parent() {
                std::fs::create_dir_all(parent)
                    .context("create log directory")?;
            }
            
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .context("open stderr log")?;
            
            Stdio::from(file)
        } else {
            Stdio::null()  // Default to null device (cross-platform: /dev/null on Unix, NUL on Windows)
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
        
        cmd.stdout(stdout_target)  // Attach log file or null device
            .stderr(stderr_target);  // Attach log file or null device
            
        // Apply working directory if configured
        if let Some(dir) = &self.def.working_dir {
            cmd.current_dir(dir);
        }
        
        // Spawn the process (file handles are now owned by child)
        let spawned = cmd.spawn().context("spawn")?;
        let pid = spawned.id();
        *child = Some(spawned);
        
        // Send state event
        self.bus.send(Evt::State {
            service: self.name.to_string(),
            kind: "running".into(),
            ts: Utc::now(),
            pid: Some(pid),
        })?;
        
        info!("{} started (pid {})", self.name, pid);
        Ok(())
    }

    fn stop(&self, child: &mut Option<Child>) -> Result<()> {
        if let Some(mut ch) = child.take() {
            let pid = ch.id();
            
            // Unix-only: Try graceful shutdown with SIGTERM first
            #[cfg(unix)]
            {
                use nix::sys::signal::{Signal, kill};
                use nix::unistd::Pid;
                
                info!("{} sending SIGTERM to pid {}", self.name, pid);
                
                // Send SIGTERM for graceful shutdown
                match kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
                    Ok(_) => {
                        // Wait for graceful exit with configurable timeout
                        let grace_period = Duration::from_secs(
                            self.def.shutdown_timeout_secs.unwrap_or(10)
                        );
                        let start = Instant::now();
                        
                        // Poll for process exit
                        while start.elapsed() < grace_period {
                            match ch.try_wait() {
                                Ok(Some(status)) => {
                                    // Process exited gracefully
                                    info!(
                                        "{} exited gracefully in {:.1}s with status: {:?}",
                                        self.name,
                                        start.elapsed().as_secs_f64(),
                                        status
                                    );
                                    self.send_stopped_event(pid)?;
                                    return Ok(());
                                }
                                Ok(None) => {
                                    // Still running, wait a bit
                                    thread::sleep(Duration::from_millis(100));
                                }
                                Err(e) => {
                                    // Error checking status, log and proceed to SIGKILL
                                    warn!(
                                        "{} error checking process status: {}, forcing SIGKILL",
                                        self.name, e
                                    );
                                    break;
                                }
                            }
                        }
                        
                        // Timeout reached without exit
                        warn!(
                            "{} did not exit within {}s, sending SIGKILL",
                            self.name,
                            grace_period.as_secs()
                        );
                    }
                    Err(e) => {
                        warn!(
                            "{} failed to send SIGTERM: {}, using SIGKILL",
                            self.name, e
                        );
                    }
                }
            }
            
            // Force kill (after timeout, SIGTERM failure, or on non-Unix)
            ch.kill().context("SIGKILL failed")?;
            
            // Wait for process to fully terminate
            match ch.wait() {
                Ok(status) => {
                    info!("{} terminated with SIGKILL: {:?}", self.name, status);
                }
                Err(e) => {
                    warn!("{} wait() failed after SIGKILL: {}", self.name, e);
                }
            }
            
            self.send_stopped_event(pid)?;
        }
        Ok(())
    }

    /// Helper to send stopped event on the bus
    fn send_stopped_event(&self, pid: u32) -> Result<()> {
        self.bus.send(Evt::State {
            service: self.name.to_string(),
            kind: "stopped-clean".into(),
            ts: Utc::now(),
            pid: Some(pid),
        })?;
        Ok(())
    }

    fn health_check(&self, child: &mut Option<Child>) -> Result<()> {
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
                        error!("{} health check error: {} (treating as unhealthy)", self.name, e);
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
                service: self.name.to_string(),
                kind: "stopped-crash".into(),  // Unexpected exit = crash
                ts: Utc::now(),
                pid: None,
            })?;
            *child = None;  // Clear the child reference
        }
        
        // Send health status to manager via crossbeam channel (zero-alloc)
        self.bus.send(Evt::Health {
            service: self.name.to_string(),
            healthy,
            ts: Utc::now(),
        })?;
        
        // If unhealthy and auto_restart enabled, trigger restart via self-loop
        if !healthy && self.def.auto_restart {
            warn!("{} unhealthy → restart", self.name);
            self.tx.send(Cmd::Restart).ok();  // Send to self via crossbeam channel
        }
        
        Ok(())
    }

    fn rotate_logs(&self) -> Result<()> {
        // Only rotate if log_rotation config exists
        let Some(ref rotation_config) = self.def.log_rotation else {
            // No rotation configured - just send event and return
            self.bus.send(Evt::LogRotate {
                service: self.name.to_string(),
                ts: Utc::now(),
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
            service: self.name.to_string(),
            ts: Utc::now(),
        })?;
        
        Ok(())
    }
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
    
    let path = Path::new(log_path);
    
    // Check if file exists and needs rotation
    if !path.exists() {
        return Ok(());  // Nothing to rotate
    }
    
    let metadata = fs::metadata(path)?;
    let size_mb = metadata.len() / (1024 * 1024);
    
    if size_mb < max_size_mb {
        return Ok(());  // Not large enough to rotate yet
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
                fs::rename(&old, &new).ok();
            }
            let old_gz = format!("{}.gz", old);
            let new_gz = format!("{}.gz", new);
            if Path::new(&old_gz).exists() {
                fs::rename(&old_gz, &new_gz).ok();
            }
        }
        
        format!("{}.1", log_path)
    };
    
    // Rename current log to rotated name
    // The service will automatically create a new file on next write
    fs::rename(path, &rotated_name)?;
    
    // Compress if requested
    if compress {
        // Use flate2 for gzip compression (already in Cargo.toml)
        use std::io::Write;
        use flate2::Compression;
        use flate2::write::GzEncoder;
        
        // Read the rotated file
        let input = fs::read(&rotated_name)?;
        
        // Write compressed version
        let output_path = format!("{}.gz", rotated_name);
        let output_file = fs::File::create(&output_path)?;
        let mut encoder = GzEncoder::new(output_file, Compression::default());
        encoder.write_all(&input)?;
        encoder.finish()?;  // Flush and finalize gzip stream
        
        // Remove uncompressed file (only keep .gz)
        fs::remove_file(&rotated_name)?;
    }
    
    // Clean up old rotated files beyond max_files limit
    if !timestamp {
        // For numbered rotation, delete files beyond max_files
        for i in (max_files + 1).. {
            let old_file = format!("{}.{}", log_path, i);
            let old_gz = format!("{}.gz", old_file);
            
            // Stop when no more files exist
            if !Path::new(&old_file).exists() && !Path::new(&old_gz).exists() {
                break;
            }
            
            // Remove both compressed and uncompressed versions
            fs::remove_file(&old_file).ok();
            fs::remove_file(&old_gz).ok();
        }
    } else {
        // For timestamped rotation, count existing archives and delete oldest
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let Some(file_name_os) = path.file_name() else {
            return Ok(());  // No filename to match, skip cleanup
        };
        let filename = file_name_os.to_string_lossy();
        
        // Find all rotated versions (both .gz and non-.gz)
        let mut archives: Vec<_> = fs::read_dir(parent)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with(filename.as_ref()) && name != filename
            })
            .collect();
        
        // Sort by modification time (oldest first)
        archives.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
        
        // Delete oldest archives beyond max_files
        let to_delete = archives.len().saturating_sub(max_files as usize);
        for entry in archives.iter().take(to_delete) {
            fs::remove_file(entry.path()).ok();
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
