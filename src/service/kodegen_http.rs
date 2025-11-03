// packages/daemon/src/service/kodegen_http.rs
use crate::config::CategoryServerConfig;
use crate::lifecycle::Lifecycle;
use crate::state_machine::State;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::process::Child;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

pub struct KodegenHttpService {
    servers: Vec<CategoryServer>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
}

struct CategoryServer {
    name: String,
    binary: String,
    port: u16,
    enabled: bool,
    process: Option<Arc<Mutex<Option<Child>>>>,  // Shared ownership with monitor via Arc
    stdout_task: Option<JoinHandle<()>>,
    stderr_task: Option<JoinHandle<()>>,
    
    // Crash monitoring fields
    #[allow(dead_code)] // Reserved for future state machine integration
    lifecycle: Lifecycle,
    state_tx: watch::Sender<State>,
    state_rx: watch::Receiver<State>,
    monitor_handle: Option<JoinHandle<()>>,
}

impl KodegenHttpService {
    #[must_use]
    pub fn new(configs: Vec<CategoryServerConfig>) -> Self {
        // Discover TLS certs once for all servers
        let (tls_cert, tls_key) = crate::config::discover_certificate_paths();
        
        let servers = configs
            .into_iter()
            .map(|cfg| {
                let (state_tx, state_rx) = watch::channel(State::Stopped);
                CategoryServer {
                    name: cfg.name,
                    binary: cfg.binary,
                    port: cfg.port,
                    enabled: cfg.enabled,
                    process: None,
                    stdout_task: None,
                    stderr_task: None,
                    lifecycle: Lifecycle::default(),
                    state_tx,
                    state_rx,
                    monitor_handle: None,
                }
            })
            .collect();

        Self {
            servers,
            tls_cert,
            tls_key,
        }
    }

    /// Rollback spawned servers in LIFO order
    async fn rollback_spawned(&mut self, spawned_indices: &[usize]) {
        log::warn!("Rolling back {} previously spawned servers", spawned_indices.len());
        
        for &idx in spawned_indices.iter().rev() {
            let server_name = self.servers[idx].name.clone();
            
            // Shutdown process BEFORE aborting monitor (same pattern as stop())
            if let Some(process_arc) = self.servers[idx].process.take() {
                let mut child_option = process_arc.lock().await;
                if let Some(mut child) = child_option.take() {
                    match Self::shutdown_server_graceful(&server_name, &mut child).await {
                        Ok(()) => {
                            log::info!("{} rolled back gracefully", server_name);
                        }
                        Err(e) => {
                            log::error!("Failed to rollback {}: {}", server_name, e);
                            // Continue rolling back other servers
                        }
                    }
                }
            }
            
            // NOW abort monitor (after process is terminated)
            if let Some(handle) = self.servers[idx].monitor_handle.take() {
                log::info!("Aborting {} monitor (rollback)", server_name);
                handle.abort();
            }
            
            // Abort log forwarding tasks
            if let Some(task) = self.servers[idx].stdout_task.take() {
                task.abort();
            }
            if let Some(task) = self.servers[idx].stderr_task.take() {
                task.abort();
            }
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        // Pre-flight port availability checks
        for server in &self.servers {
            if !server.enabled {
                continue;
            }
            
            if let Err(e) = Self::check_port_available(server.port).await {
                log::error!("Cannot start {} server: {}", server.name, e);
                return Err(e);
            }
        }
        
        log::info!("All ports verified available, proceeding with spawn");
        
        let mut spawned_indices = Vec::new();
        
        for idx in 0..self.servers.len() {
            if !self.servers[idx].enabled {
                log::debug!("Skipping disabled server: {}", self.servers[idx].name);
                continue;
            }

            let server_name = self.servers[idx].name.clone();
            let server_port = self.servers[idx].port;
            let server_binary = self.servers[idx].binary.clone();
            
            let addr = format!("127.0.0.1:{}", server_port);
            log::info!("Starting {} server on {addr}", server_name);

            // Resolve binary path using which crate
            let binary_path = which::which(&server_binary).unwrap_or_else(|_| {
                log::warn!("{} binary not found in PATH, using relative path", server_binary);
                PathBuf::from(&server_binary)
            });

            log::debug!("{} binary path: {binary_path:?}", server_name);

            // Build command to spawn category server with HTTP mode
            let mut cmd = tokio::process::Command::new(&binary_path);
            cmd.arg("--http")
                .arg(&addr)
                .stdout(std::process::Stdio::piped()) // Capture stdout for forwarding
                .stderr(std::process::Stdio::piped()); // Capture stderr for forwarding

            // Add TLS configuration if certificates are available
            if let (Some(cert_path), Some(key_path)) = (&self.tls_cert, &self.tls_key) {
                log::info!(
                    "Configuring {} with HTTPS (cert={}, key={})",
                    server_name,
                    cert_path.display(),
                    key_path.display()
                );
                cmd.arg("--tls-cert").arg(cert_path);
                cmd.arg("--tls-key").arg(key_path);
            } else {
                log::info!("No TLS certificates configured, {} starting in HTTP mode", server_name);
            }

            // Spawn subprocess with error context
            let mut child = cmd.spawn().map_err(|e| {
                anyhow::anyhow!(
                    "Failed to spawn {} server (binary: {binary_path:?}, addr: {addr}): {e}",
                    server_name
                )
            })?;

            let pid = child.id();
            let pid_str = pid.map_or("unavailable".to_string(), |p| p.to_string());
            log::info!("{} server spawned (PID: {})", server_name, pid_str);

            // CRITICAL: Extract stdout/stderr BEFORE spawning monitor (ownership!)
            if let Some(stdout) = child.stdout.take() {
                let name_clone = server_name.clone();
                let stdout_task = tokio::spawn(async move {
                    let reader = tokio::io::BufReader::new(stdout);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        log::info!("[{}] {}", name_clone, line);
                    }
                });
                self.servers[idx].stdout_task = Some(stdout_task);
            }

            if let Some(stderr) = child.stderr.take() {
                let name_clone = server_name.clone();
                let stderr_task = tokio::spawn(async move {
                    let reader = tokio::io::BufReader::new(stderr);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        log::error!("[{}] {}", name_clone, line);
                    }
                });
                self.servers[idx].stderr_task = Some(stderr_task);
            }

            // Set state to Starting before spawning monitor
            let _ = self.servers[idx].state_tx.send(State::Starting);
            
            // Wrap Child in Arc<Mutex<Option<>>> for shared ownership
            let child_arc = Arc::new(Mutex::new(Some(child)));
            self.servers[idx].process = Some(child_arc.clone());
            
            // Create weak reference for monitor
            let child_weak = Arc::downgrade(&child_arc);
            
            // Spawn background monitoring task with weak reference
            let monitor_handle = tokio::spawn(monitor_server_process(
                server_name.clone(),
                child_weak,
                self.servers[idx].state_tx.clone(),
            ));
            self.servers[idx].monitor_handle = Some(monitor_handle);

            log::info!("{} monitor task spawned, waiting for Running state", server_name);

            // Wait for server to transition to Running or Failed (timeout: 5s)
            let mut rx = self.servers[idx].state_rx.clone();
            match tokio::time::timeout(
                Duration::from_secs(5),
                async {
                    // Wait until state changes from Starting
                    while *rx.borrow_and_update() == State::Starting {
                        rx.changed().await.ok()?;
                    }
                    Some(*rx.borrow())
                }
            ).await {
                Ok(Some(State::Running)) => {
                    log::info!("{} verified healthy (PID: {})", server_name, pid_str);
                }
                Ok(Some(State::Failed)) => {
                    log::error!("{} crashed during startup", server_name);
                    self.rollback_spawned(&spawned_indices).await;
                    return Err(anyhow::anyhow!("{} crashed during startup", server_name));
                }
                _ => {
                    log::error!("{} failed to become healthy within 5s", server_name);
                    self.rollback_spawned(&spawned_indices).await;
                    return Err(anyhow::anyhow!(
                        "{} failed to become healthy within 5s",
                        server_name
                    ));
                }
            }

            // OPTIONAL: Keep HTTP health check as Layer 2 validation
            let use_tls = self.tls_cert.is_some() && self.tls_key.is_some();
            if let Err(e) = Self::verify_server_health(
                server_port,
                use_tls,
                Duration::from_secs(5)
            ).await {
                log::error!("{} failed HTTP health check: {}", server_name, e);
                
                // Abort monitor and rollback
                if let Some(handle) = self.servers[idx].monitor_handle.take() {
                    handle.abort();
                }
                self.rollback_spawned(&spawned_indices).await;
                
                return Err(anyhow::anyhow!("{} failed HTTP health check: {}", server_name, e));
            }

            spawned_indices.push(idx);
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        let total_servers = self.servers.iter()
            .filter(|s| s.process.is_some())
            .count();
        
        log::info!("Stopping {} servers concurrently", total_servers);
        
        // ═══════════════════════════════════════════════════════════════
        // Phase 1: Extract Children and spawn concurrent shutdown tasks
        // ═══════════════════════════════════════════════════════════════
        let mut shutdown_tasks = Vec::new();
        
        for server in &mut self.servers {
            // Take ownership of process Arc to shutdown gracefully
            if let Some(process_arc) = server.process.take() {
                let server_name = server.name.clone();
                
                // Extract Child from Arc for graceful shutdown
                let mut child_option = process_arc.lock().await;
                if let Some(mut child) = child_option.take() {
                    // Spawn concurrent shutdown task
                    let task = tokio::spawn(async move {
                        Self::shutdown_server_graceful(&server_name, &mut child).await
                    });
                    
                    shutdown_tasks.push((server.name.clone(), task));
                }
            }
        }
        
        // ═══════════════════════════════════════════════════════════════
        // Phase 2: Wait for all shutdowns concurrently (max 35 seconds)
        // ═══════════════════════════════════════════════════════════════
        let mut errors = Vec::new();
        
        for (name, task) in shutdown_tasks {
            match task.await {
                Ok(Ok(())) => {
                    log::info!("{} shutdown completed successfully", name);
                }
                Ok(Err(e)) => {
                    let msg = format!("{} shutdown failed: {}", name, e);
                    log::error!("{}", msg);
                    errors.push(msg);
                }
                Err(e) => {
                    let msg = format!("{} shutdown task panicked: {}", name, e);
                    log::error!("{}", msg);
                    errors.push(msg);
                }
            }
        }
        
        // ═══════════════════════════════════════════════════════════════
        // Phase 3: Clean up monitor and log tasks (processes are dead)
        // ═══════════════════════════════════════════════════════════════
        for server in &mut self.servers {
            if let Some(handle) = server.monitor_handle.take() {
                handle.abort();
            }
            if let Some(task) = server.stdout_task.take() {
                task.abort();
            }
            if let Some(task) = server.stderr_task.take() {
                task.abort();
            }
        }
        
        // ═══════════════════════════════════════════════════════════════
        // Phase 4: Return aggregated errors or success
        // ═══════════════════════════════════════════════════════════════
        if !errors.is_empty() {
            return Err(anyhow::anyhow!(
                "Shutdown completed with {} errors: {}",
                errors.len(),
                errors.join("; ")
            ));
        }
        
        log::info!("All {} servers stopped successfully", total_servers);
        Ok(())
    }

    /// Check if a port is available by attempting to bind then immediately releasing
    async fn check_port_available(port: u16) -> Result<()> {
        let addr = format!("127.0.0.1:{}", port);
        
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                drop(listener);
                log::debug!("Port {} is available", port);
                Ok(())
            }
            Err(e) => {
                Err(anyhow::anyhow!(
                    "Port {} is already in use or unavailable: {}",
                    port,
                    e
                ))
            }
        }
    }

    /// Verify server health by polling the /health endpoint
    async fn verify_server_health(
        port: u16,
        use_tls: bool,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let scheme = if use_tls { "https" } else { "http" };
        let health_url = format!("{}://127.0.0.1:{}/health", scheme, port);
        
        log::debug!("Verifying server health at {}", health_url);
        
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_error = None;
        
        while tokio::time::Instant::now() < deadline {
            match reqwest::get(&health_url).await {
                Ok(response) => {
                    if response.status().is_success() {
                        log::debug!("Server confirmed healthy at {}", health_url);
                        return Ok(());
                    } else {
                        last_error = Some(format!(
                            "Health check returned status {}",
                            response.status()
                        ));
                    }
                }
                Err(e) => {
                    last_error = Some(format!("Health check failed: {}", e));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        
        Err(anyhow::anyhow!(
            "Server failed to become healthy within {:?}. Last error: {}",
            timeout,
            last_error.unwrap_or_else(|| "unknown".to_string())
        ))
    }

    /// Gracefully shutdown a server process using try_wait() poll pattern
    /// 
    /// This function:
    /// 1. Sends SIGTERM for graceful shutdown
    /// 2. Polls every 100ms with try_wait() to detect early exit
    /// 3. Escalates to SIGKILL after 30s timeout
    /// 4. Ensures zombie reaping within ~100ms of process exit
    async fn shutdown_server_graceful(
        name: &str,
        child: &mut Child,
    ) -> Result<()> {
        let pid = child.id();
        
        #[cfg(unix)]
        {
            use nix::sys::signal::{self, Signal};
            use nix::unistd::Pid;
            
            if let Some(pid_u32) = pid {
                let nix_pid = Pid::from_raw(pid_u32 as i32);
                
                // Phase 1: SIGTERM
                if let Err(e) = signal::kill(nix_pid, Signal::SIGTERM) {
                    log::warn!("Failed SIGTERM to {}: {}", name, e);
                } else {
                    log::info!("Sent SIGTERM to {} (PID: {})", name, pid_u32);
                }
                
                // Phase 2: Poll-wait for graceful exit (30s timeout)
                let start = tokio::time::Instant::now();
                let graceful_deadline = start + Duration::from_secs(30);
                let poll_interval = Duration::from_millis(100);
                
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            let elapsed = start.elapsed();
                            log::info!(
                                "{} exited gracefully in {:.2}s: {}",
                                name,
                                elapsed.as_secs_f64(),
                                status
                            );
                            return Ok(()); // Process reaped!
                        }
                        Ok(None) => {
                            // Still running - check timeout
                            if tokio::time::Instant::now() >= graceful_deadline {
                                log::warn!(
                                    "{} graceful shutdown timeout (30s), escalating to SIGKILL",
                                    name
                                );
                                break; // Exit poll loop, proceed to SIGKILL
                            }
                            tokio::time::sleep(poll_interval).await;
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "Error checking {} status: {}",
                                name, e
                            ));
                        }
                    }
                }
                
                // Phase 3: SIGKILL
                child.start_kill()?;
                log::warn!("Sent SIGKILL to {} (PID: {})", name, pid_u32);
                
                // Phase 4: Poll-wait for SIGKILL (5s timeout)
                let kill_start = tokio::time::Instant::now();
                let kill_deadline = kill_start + Duration::from_secs(5);
                
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            log::info!("{} terminated by SIGKILL: {}", name, status);
                            return Ok(());
                        }
                        Ok(None) => {
                            if tokio::time::Instant::now() >= kill_deadline {
                                return Err(anyhow::anyhow!(
                                    "{} did not respond to SIGKILL after 5s (PID: {})",
                                    name, pid_u32
                                ));
                            }
                            tokio::time::sleep(poll_interval).await;
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "SIGKILL wait failed for {}: {}",
                                name, e
                            ));
                        }
                    }
                }
            } else {
                Ok(())
            }
        }
        
        #[cfg(windows)]
        {
            use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_C_EVENT};
            
            if let Some(pid_u32) = pid {
                // Phase 1: CTRL_C_EVENT
                let graceful_attempt = unsafe {
                    GenerateConsoleCtrlEvent(CTRL_C_EVENT, pid_u32)
                };
                
                if let Ok(()) = graceful_attempt {
                    log::info!("Sent CTRL_C_EVENT to {} (PID: {})", name, pid_u32);
                    
                    // Phase 2: Poll-wait for graceful exit (30s)
                    let start = tokio::time::Instant::now();
                    let deadline = start + Duration::from_secs(30);
                    let poll_interval = Duration::from_millis(100);
                    
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                log::info!(
                                    "{} exited gracefully in {:.2}s",
                                    name,
                                    start.elapsed().as_secs_f64()
                                );
                                return Ok(());
                            }
                            Ok(None) => {
                                if tokio::time::Instant::now() >= deadline {
                                    break;
                                }
                                tokio::time::sleep(poll_interval).await;
                            }
                            Err(e) => {
                                return Err(anyhow::anyhow!("Status check error: {}", e));
                            }
                        }
                    }
                }
                
                // Phase 3: TerminateProcess
                child.start_kill()?;
                log::warn!("Sent TerminateProcess to {} (PID: {})", name, pid_u32);
                
                // Phase 4: Poll-wait for termination (5s)
                let kill_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            log::info!("{} terminated: {}", name, status);
                            return Ok(());
                        }
                        Ok(None) => {
                            if tokio::time::Instant::now() >= kill_deadline {
                                return Err(anyhow::anyhow!(
                                    "{} did not terminate after 5s",
                                    name
                                ));
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!("Termination error: {}", e));
                        }
                    }
                }
            } else {
                Ok(())
            }
        }
    }
}

/// Helper function to shutdown a single server process
#[allow(dead_code)] // Kept for potential future use or alternative shutdown strategies
async fn shutdown_single_server(name: &str, mut child: Child) -> Result<()> {
    let pid = child.id();
    
    #[cfg(unix)]
    {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;
        use std::time::Duration;

        if let Some(pid_u32) = pid {
            let nix_pid = Pid::from_raw(pid_u32 as i32);

            // Phase 1: SIGTERM
            if let Err(e) = signal::kill(nix_pid, Signal::SIGTERM) {
                log::warn!("Failed SIGTERM to {}: {}", name, e);
            } else {
                log::info!("Sent SIGTERM to {} (PID: {})", name, pid_u32);
            }

            // Phase 2: Wait 30s for graceful exit
            match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
                Ok(Ok(status)) => {
                    log::info!("{} exited gracefully: {}", name, status);
                    return Ok(());
                }
                Ok(Err(e)) => {
                    log::warn!("Graceful wait error for {}: {}", name, e);
                    // Don't return yet - try SIGKILL
                }
                Err(_) => {
                    log::warn!("{} graceful timeout, escalating", name);
                }
            }

            // Phase 3: SIGKILL
            child.start_kill()?;
            log::warn!("Sent SIGKILL to {} (PID: {})", name, pid_u32);

            // Phase 4: Wait 5s for SIGKILL
            match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                Ok(Ok(status)) => {
                    log::info!("{} terminated by SIGKILL: {}", name, status);
                    Ok(())
                }
                Ok(Err(e)) => {
                    Err(anyhow::anyhow!("SIGKILL wait failed for {}: {}", name, e))
                }
                Err(_) => {
                    Err(anyhow::anyhow!(
                        "{} did not respond to SIGKILL after 5s (PID: {})",
                        name, pid_u32
                    ))
                }
            }
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    {
        use std::time::Duration;
        use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_C_EVENT};

        log::info!("Terminating {} (Windows)", name);
        
        if let Some(pid_u32) = pid {
            // Phase 1: Attempt graceful shutdown via CTRL_C_EVENT
            // SAFETY: Windows API - sending console control event to child process
            let graceful_attempt = unsafe {
                GenerateConsoleCtrlEvent(CTRL_C_EVENT, pid_u32)
            };

            match graceful_attempt {
                Ok(()) => {
                    log::info!("Sent CTRL_C_EVENT to {} (PID: {})", name, pid_u32);

                    // Phase 2: Wait up to 30 seconds for graceful exit
                    match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
                        Ok(Ok(status)) => {
                            log::info!("{} exited gracefully: {}", name, status);
                            return Ok(());
                        }
                        Ok(Err(e)) => {
                            log::warn!("Graceful wait error for {}: {}", name, e);
                            // Don't return yet - try TerminateProcess
                        }
                        Err(_) => {
                            log::warn!("{} graceful timeout, escalating to TerminateProcess", name);
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Failed to send CTRL_C_EVENT to {} (PID: {}): {:?}. Proceeding to forceful termination.",
                        name, pid_u32, e
                    );
                }
            }
        }
        
        // Phase 3: TerminateProcess (SIGKILL equivalent)
        child.start_kill()?;
        log::warn!("Sent TerminateProcess to {} process", name);
        
        // Phase 4: Wait 5s for TerminateProcess
        match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(Ok(status)) => {
                log::info!("{} terminated: {}", name, status);
                Ok(())
            }
            Ok(Err(e)) => {
                Err(anyhow::anyhow!("Termination error for {}: {}", name, e))
            }
            Err(_) => {
                let pid_str = pid.map_or("unavailable".to_string(), |p| p.to_string());
                Err(anyhow::anyhow!(
                    "{} did not terminate after 5s (PID: {})",
                    name, pid_str
                ))
            }
        }
    }
}

/// Background task that monitors a category server process for crashes.
///
/// This function runs in a separate tokio task and:
/// 1. Performs an initial health check after 100ms
/// 2. Continuously polls the process every 5 seconds via weak reference
/// 3. Detects crashes via `child.try_wait()`
/// 4. Updates state via watch channel
/// 5. Exits gracefully when Arc is dropped (service stopping)
///
/// The task exits when:
/// - Process exits (crash or clean shutdown)
/// - Weak reference can't be upgraded (Arc dropped - service stopping)
/// - Process.try_wait() returns an error
async fn monitor_server_process(
    name: String,
    child_weak: Weak<Mutex<Option<Child>>>,
    state_tx: watch::Sender<State>,
) {
    log::debug!("Starting health monitor for {}", name);
    
    // ═══════════════════════════════════════════════════════════════════════
    // Initial health check: Wait 100ms then verify process didn't crash
    // ═══════════════════════════════════════════════════════════════════════
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    if let Some(child_arc) = child_weak.upgrade() {
        let mut child_guard = child_arc.lock().await;
        if let Some(ref mut child) = *child_guard {
            match child.try_wait() {
                Ok(Some(status)) => {
                    log::error!("{} crashed immediately: {}", name, status);
                    let _ = state_tx.send(State::Failed);
                    return;
                }
                Ok(None) => {
                    log::info!("{} passed initial health check", name);
                    let _ = state_tx.send(State::Running);
                }
                Err(e) => {
                    log::error!("{} health check error: {}", name, e);
                    let _ = state_tx.send(State::Failed);
                    return;
                }
            }
        }
    } else {
        // Arc already dropped - service stopping
        return;
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // Continuous monitoring: Poll every 5 seconds for process exit
    // ═══════════════════════════════════════════════════════════════════════
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        
        // Try to upgrade weak ref
        let Some(child_arc) = child_weak.upgrade() else {
            // Arc dropped - service stopping
            log::debug!("{} monitor exiting: service stopping", name);
            return;
        };
        
        let mut child_guard = child_arc.lock().await;
        if let Some(ref mut child) = *child_guard {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process exited (crashed or shutdown)
                    log::error!("{} exited unexpectedly: {}", name, status);
                    let exit_code = status.code().unwrap_or(-1);
                    
                    if status.success() {
                        log::info!("{} exited cleanly (code: {})", name, exit_code);
                        let _ = state_tx.send(State::Stopped);
                    } else {
                        log::error!("{} crashed (code: {})", name, exit_code);
                        let _ = state_tx.send(State::Failed);
                    }
                    
                    return; // Exit monitor task - process is dead
                }
                Ok(None) => {
                    // Still running - continue monitoring
                    log::trace!("{} health check: OK", name);
                }
                Err(e) => {
                    // System error checking process status
                    log::error!("{} status check error: {}", name, e);
                    let _ = state_tx.send(State::Failed);
                    return;
                }
            }
        } else {
            // Child was taken - service stopping
            log::debug!("{} monitor exiting: child taken", name);
            return;
        }
    }
}
