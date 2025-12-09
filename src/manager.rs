use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender, bounded, select, tick};
use log::{error, info};

use crate::config::ServiceConfig;
use crate::ipc::{Cmd, Evt, ServiceState};
use crate::lifecycle::Lifecycle;
use crate::platform::{SignalKind, watch_signals};
use crate::service::embedded_servers::{EmbeddedServer, shutdown_all_servers};
use crate::service::port_cleanup::cleanup_port_if_needed;
use crate::state_machine::{Action, Event};

/// Global event bus size – small fixed size → zero heap growth.
const BUS_BOUND: usize = 128;

/// Restart state for a service
///
/// Tracks restart attempts and timing for exponential backoff enforcement.
/// Models circuit breaker pattern from kodegen-tools-citescrape.
#[derive(Debug)]
struct RestartState {
    stop_time: Instant,
    attempts: u32,
    /// When service last started successfully (for success window calculation)
    ///
    /// If service runs for >success_window_secs after this timestamp,
    /// the attempts counter is reset to 1 on next failure.
    ///
    /// Set when restart is executed (process_pending_restarts line 316)
    /// Checked when scheduling next restart (schedule_restart line 454)
    last_successful_start: Option<Instant>,
}

/// Last known state for a service (used for status queries)
#[derive(Debug, Clone)]
struct LastServiceState {
    state: ServiceState,
    pid: Option<u32>,
    timestamp: Instant,
    failure_reason: Option<String>,
}

/// Top‑level in‑process manager supervising *all* workers.
pub struct ServiceManager {
    bus_tx: Sender<Evt>,
    bus_rx: Receiver<Evt>,
    workers: HashMap<String, Sender<Cmd>>,
    pending_restarts: HashMap<String, RestartState>,

    /// Vulnerability scanner for periodic security audits
    /// Enabled via config.security.enable_vulnerability_scanning
    vulnerability_scanner: Option<Arc<crate::security::audit::VulnerabilityScanner>>,

    /// Restart policies per service (loaded from config)
    /// Allows per-service policy customization
    restart_policies: HashMap<String, crate::config::RestartPolicy>,

    /// Last known state for each service (for status queries)
    last_state: HashMap<String, LastServiceState>,

    lifecycle: Lifecycle,
    embedded_servers: Option<Vec<EmbeddedServer>>,

    /// Configuration for runtime reload
    config: std::sync::Arc<parking_lot::RwLock<ServiceConfig>>,

    /// Correlation ID generator for IPC request tracking
    /// Uses Relaxed ordering since correlation IDs don't require synchronization
    next_correlation_id: AtomicU64,

    /// External shutdown trigger channel
    /// 
    /// This allows Windows service or other external callers to trigger shutdown
    /// without relying on OS signals. The run() loop monitors this receiver
    /// and breaks when signaled.
    /// 
    /// Uses crossbeam channel (bounded, size 1) for compatibility with existing
    /// select! macro infrastructure. Sender is exposed via shutdown() method.
    shutdown_rx: Receiver<()>,
    /// Sender half of shutdown channel - used by shutdown() method on Windows
    /// 
    /// On Unix platforms, shutdown is triggered via OS signals (SIGTERM/SIGINT)
    /// which are handled directly in the run() loop. The shutdown_tx is only
    /// used on Windows where the Service Control Manager needs a programmatic
    /// way to trigger graceful shutdown.
    #[cfg_attr(not(windows), allow(dead_code))]
    shutdown_tx: Sender<()>,
}

impl ServiceManager {
    /// Load config, spawn workers, and return the fully‑primed manager.
    pub fn new(cfg: ServiceConfig) -> Result<Self> {
        let (bus_tx, bus_rx) = bounded::<Evt>(BUS_BOUND);
        let mut workers = HashMap::new();
        let mut restart_policies = HashMap::new();

        let config = std::sync::Arc::new(parking_lot::RwLock::new(cfg));
        let cfg_read = config.read();

        // Load services from config file
        for def in cfg_read.services.clone() {
            match crate::service::spawn(def.clone(), bus_tx.clone()) {
                Ok(tx) => {
                    workers.insert(def.name.clone(), tx);
                    // Store restart policy for this service
                    restart_policies.insert(def.name.clone(), def.restart_policy.clone());
                }
                Err(e) => {
                    error!("Failed to spawn service '{}': {}", def.name, e);
                    // Continue with other services - graceful degradation
                }
            }
        }

        // Load services from services directory
        if let Some(services_dir) = &cfg_read.services_dir
            && let Ok(entries) = std::fs::read_dir(services_dir)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            match toml::from_str::<crate::config::ServiceDefinition>(&content) {
                                Ok(def) => {
                                    match crate::service::spawn(def.clone(), bus_tx.clone()) {
                                        Ok(tx) => {
                                            info!(
                                                "Loaded service '{}' from {}",
                                                def.name,
                                                path.display()
                                            );
                                            workers.insert(def.name.clone(), tx);
                                            // Store restart policy for dynamically loaded service
                                            restart_policies.insert(
                                                def.name.clone(),
                                                def.restart_policy.clone(),
                                            );
                                        }
                                        Err(e) => {
                                            error!(
                                                "Failed to spawn service '{}' from {}: {}",
                                                def.name,
                                                path.display(),
                                                e
                                            );
                                            // Continue loading other services
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse service file {}: {}", path.display(), e)
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to read service file {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        // Initialize vulnerability scanner if enabled in config
        let vulnerability_scanner = if cfg_read.security.enable_vulnerability_scanning.unwrap_or(false) {
            let thresholds = crate::security::audit::AuditThresholds::new(
                cfg_read.security.vulnerability_thresholds.critical_max.unwrap_or(0),
                cfg_read.security.vulnerability_thresholds.high_max.unwrap_or(2),
                cfg_read.security.vulnerability_thresholds.medium_max.unwrap_or(10),
                cfg_read.security.vulnerability_thresholds.low_max.unwrap_or(50),
            );
            info!("Vulnerability scanning enabled with thresholds: critical={}, high={}, medium={}, low={}",
                cfg_read.security.vulnerability_thresholds.critical_max.unwrap_or(0),
                cfg_read.security.vulnerability_thresholds.high_max.unwrap_or(2),
                cfg_read.security.vulnerability_thresholds.medium_max.unwrap_or(10),
                cfg_read.security.vulnerability_thresholds.low_max.unwrap_or(50),
            );
            Some(Arc::new(crate::security::audit::VulnerabilityScanner::new(thresholds)))
        } else {
            info!("Vulnerability scanning disabled (enable via config.security.enable_vulnerability_scanning)");
            None
        };

        drop(cfg_read); // Release read lock

        // Initialize shutdown coordination channel
        // Bounded channel (size 1) for external shutdown trigger (Windows service, API, etc.)
        let (shutdown_tx, shutdown_rx) = bounded::<()>(1);

        Ok(Self {
            bus_tx,
            bus_rx,
            workers,
            pending_restarts: HashMap::new(),
            vulnerability_scanner,
            restart_policies,
            last_state: HashMap::new(),
            lifecycle: Lifecycle::default(),
            embedded_servers: None,
            config,
            next_correlation_id: AtomicU64::new(1),
            shutdown_rx,
            shutdown_tx,
        })
    }

    /// Generate next correlation ID using relaxed ordering
    /// Relaxed is safe here because correlation IDs are opaque identifiers
    /// and don't require happens-before relationships
    fn next_correlation_id(&self) -> u64 {
        self.next_correlation_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Start HTTP servers with graceful degradation
    ///
    /// Individual server failures are logged but don't prevent daemon startup.
    /// Each server runs as a background tokio task (via embedded_servers.rs).
    async fn start_servers_gracefully(&mut self) {
        use crate::service::embedded_servers::{EmbeddedServer, start_server};
        use std::net::SocketAddr;

        let configs = self.config.read().category_servers.clone();
        let (tls_cert, tls_key) = crate::config::discover_certificate_paths();

        let mut servers = Vec::new();
        let mut failed_count = 0;

        for config in &configs {
            if !config.enabled {
                continue;
            }

            let addr: SocketAddr = match format!("127.0.0.1:{}", config.port).parse() {
                Ok(addr) => addr,
                Err(e) => {
                    log::error!("Invalid port {} for {}: {}", config.port, config.name, e);
                    failed_count += 1;
                    continue;
                }
            };

            // CRITICAL: Clear port before starting server to prevent "address in use" errors
            // This is essential for service manager integration - daemon MUST NOT exit on port conflicts
            log::info!("Clearing port {} for {} server", config.port, config.name);
            match cleanup_port_if_needed(config.port).await {
                Ok(()) => {
                    log::debug!("Port {} is available for {}", config.port, config.name);
                }
                Err(e) => {
                    log::error!(
                        "✗ Port cleanup failed for {} (port {}): {:#}",
                        config.name,
                        config.port,
                        e
                    );
                    log::error!("  This indicates port is held by a process that cannot be killed");
                    log::error!(
                        "  Daemon continues with {} unavailable (graceful degradation)",
                        config.name
                    );
                    failed_count += 1;
                    continue; // Skip this server, try next one
                }
            }

            // Port is now guaranteed available - start server
            log::debug!(
                "Starting {} server on port {} (post-cleanup)",
                config.name,
                config.port
            );
            match start_server(&config.name, addr, tls_cert.clone(), tls_key.clone()).await {
                Ok(handle) => {
                    log::info!("✓ Started {} server on port {}", config.name, config.port);
                    servers.push(EmbeddedServer {
                        name: config.name.clone(),
                        port: config.port,
                        server_handle: handle,
                    });
                }
                Err(e) => {
                    log::error!("✗ Failed to start {} server: {:#}", config.name, e);
                    log::error!(
                        "  Port {} was cleared but server startup failed - check server implementation",
                        config.port
                    );
                    log::error!(
                        "  Daemon continues with {} unavailable (graceful degradation)",
                        config.name
                    );
                    failed_count += 1;
                }
            }
        }

        let total = configs.iter().filter(|c| c.enabled).count();
        let succeeded = servers.len();

        if succeeded == 0 {
            log::error!(
                "No HTTP servers started successfully ({} failed)",
                failed_count
            );
            log::error!("Daemon running but no services available");
        } else if failed_count > 0 {
            log::warn!(
                "Started {}/{} servers ({} failed)",
                succeeded,
                total,
                failed_count
            );
        } else {
            log::info!("Started all {} servers successfully", succeeded);
        }

        self.embedded_servers = Some(servers);
    }

    /// Reload configuration from disk and apply changes
    ///
    /// Compares old and new service definitions:
    /// - Starts new services
    /// - Stops removed services  
    /// - Restarts modified services
    fn reload_config(&mut self) -> Result<()> {
        info!("Reloading configuration from disk");

        // Read current config to find file path
        let config_path = {
            let cfg = self.config.read();
            match &cfg.config_file_path {
                Some(path) => path.clone(),
                None => {
                    return Err(anyhow::anyhow!(
                        "No config file path stored - cannot reload"
                    ));
                }
            }
        };

        // Load new config from disk
        let new_cfg = ServiceConfig::load_from_file(&config_path).with_context(|| {
            format!(
                "Failed to load updated configuration from {:?}",
                config_path
            )
        })?;

        // Get old service names
        let old_services: HashMap<String, _> = {
            let cfg = self.config.read();
            cfg.services
                .iter()
                .map(|def| (def.name.clone(), def.clone()))
                .collect()
        };

        // Get new service names
        let new_services: HashMap<String, _> = new_cfg
            .services
            .iter()
            .map(|def| (def.name.clone(), def.clone()))
            .collect();

        // Find services to stop (in old but not in new)
        for name in old_services.keys() {
            if !new_services.contains_key(name) {
                info!("Stopping removed service: {}", name);
                if let Some(tx) = self.workers.get(name)
                    && let Err(e) = tx.send(Cmd::Shutdown)
                {
                    error!("Failed to send shutdown to service {}: {}", name, e);
                }
                self.workers.remove(name);
                self.restart_policies.remove(name);
            }
        }

        // Find services to start (in new but not in old)
        for (name, def) in &new_services {
            if !old_services.contains_key(name.as_str()) {
                info!("Starting new service: {}", name);
                match crate::service::spawn(def.clone(), self.bus_tx.clone()) {
                    Ok(tx) => {
                        self.workers.insert(name.clone(), tx);
                        self.restart_policies
                            .insert(name.clone(), def.restart_policy.clone());
                    }
                    Err(e) => {
                        error!("Failed to spawn new service '{}': {}", name, e);
                    }
                }
            }
        }

        // Find services to restart (in both but definition changed)
        for (name, new_def) in &new_services {
            if let Some(old_def) = old_services.get(name.as_str()) {
                // Compare definitions (simplified - check if debug representation differs)
                if format!("{:?}", old_def) != format!("{:?}", new_def) {
                    info!("Restarting modified service: {}", name);

                    // Stop old version
                    if let Some(tx) = self.workers.get(name)
                        && let Err(e) = tx.send(Cmd::Shutdown)
                    {
                        error!("Failed to send shutdown to service {}: {}", name, e);
                    }

                    // Start new version
                    match crate::service::spawn(new_def.clone(), self.bus_tx.clone()) {
                        Ok(tx) => {
                            self.workers.insert(name.clone(), tx);
                            self.restart_policies
                                .insert(name.clone(), new_def.restart_policy.clone());
                        }
                        Err(e) => {
                            error!("Failed to restart service '{}': {}", name, e);
                        }
                    }
                }
            }
        }

        // Update stored config
        *self.config.write() = new_cfg;

        info!("Configuration reload complete");
        Ok(())
    }

    /// Log detailed diagnostics for signal channel disconnection
    /// 
    /// Called when recv() returns RecvError, indicating all signal senders
    /// were dropped (typically due to signal watcher thread panic/exit).
    fn log_signal_channel_disconnection(&self) {
        error!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        error!("CRITICAL: Signal channel disconnected (RecvError)");
        error!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        error!("");
        error!("Root cause: All signal senders were dropped");
        error!("Most likely: Signal watcher thread has exited or panicked");
        error!("");
        error!("DEBUGGING STEPS:");
        error!("  1. Search logs for 'Signal watcher thread panicked'");
        error!("  2. Search logs for 'Signal watcher failed 3 times, giving up'");
        error!("  3. Check for tokio runtime creation failures");
        error!("  4. Review packages/kodegend/src/platform/signal.rs for bugs");
        error!("");
        error!("CONSEQUENCES:");
        error!("  • Daemon will NO LONGER respond to SIGTERM or SIGINT");
        error!("  • Must use SIGKILL (kill -9) to stop daemon");
        error!("  • Graceful shutdown is no longer possible");
        error!("");
        error!("TECHNICAL DETAILS:");
        error!("  Channel: crossbeam_channel::bounded<SignalKind>(16)");
        error!("  Sender: platform/signal.rs:116 (signal watcher thread)");
        error!("  Receiver: manager.rs:385 (ServiceManager event loop)");
        error!("  Error: crossbeam_channel::RecvError (all senders dropped)");
        error!("  Docs: https://docs.rs/crossbeam-channel/latest/crossbeam_channel/struct.RecvError.html");
        error!("");
        log::warn!("Proceeding with emergency shutdown of service manager...");
    }

    /// Central event‑loop.  Runs until SIGINT / SIGTERM.
    pub async fn run(mut self) -> Result<()> {
        // Process lifecycle start event
        let action = self.lifecycle.step(Event::CmdStart);
        if action == Action::SpawnProcess {
            // Announce startup phase
            crate::daemon::systemd_notify_status("Initializing service manager");
            
            // Announce manager start
            self.bus_tx.send(Evt::State {
                service: Arc::from("manager"),
                state: ServiceState::Starting,
                ts: chrono::Utc::now(),
                pid: Some(std::process::id()),
                correlation_id: None,
            })?;

            // Start worker services
            crate::daemon::systemd_notify_status(
                &format!("Starting {} worker services", self.workers.len())
            );
            
            // Initial start‑up pass.
            for (name, tx) in &self.workers {
                let correlation_id = self.next_correlation_id();
                tx.send(Cmd::Start { correlation_id })?;
                info!("Started service: {name} (correlation_id={correlation_id})");
            }

            // Transition lifecycle state to Running now that workers are started
            let _action = self.lifecycle.step(Event::StartedOk);
            // Note: action will be Action::NotifyHealthy per state_machine.rs:83
            // Full action handling is out of scope (see lifecycle_actions_ignored.md)

            // Start HTTP servers
            let server_count = self.config.read()
                .category_servers
                .iter()
                .filter(|s| s.enabled)
                .count();
            
            crate::daemon::systemd_notify_status(
                &format!("Starting {} HTTP servers", server_count)
            );
            
            // Start HTTP servers with graceful degradation
            // NOTE: Servers run as background tokio tasks - this is correct
            self.start_servers_gracefully().await;

            // Manager is now running
            self.bus_tx.send(Evt::State {
                service: Arc::from("manager"),
                state: ServiceState::Running,
                ts: chrono::Utc::now(),
                pid: Some(std::process::id()),
                correlation_id: None,
            })?;
            
            // Notify full readiness with final status
            crate::daemon::systemd_notify_status("All services operational");
            crate::daemon::systemd_notify_ready();
            
            info!("ServiceManager fully operational - systemd notified");
        }
        // Handle any other action types (though CmdStart always returns SpawnProcess)
        self.handle_lifecycle_action(action).await;

        // Setup cross-platform signal watcher
        let signal_watcher = watch_signals()?;

        // Setup status query socket
        #[cfg(unix)]
        let socket_rx = {
            use std::os::unix::net::UnixListener;

            let is_elevated = crate::platform::is_elevated();
            let socket_path = crate::platform::status_socket_path(is_elevated);
            
            // Ensure parent directory exists
            if let Some(parent) = socket_path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create status socket directory: {}", parent.display())
                })?;
            }
            
            // Remove stale socket file if it exists
            let _ = std::fs::remove_file(&socket_path);
            
            match UnixListener::bind(&socket_path) {
                Ok(listener) => {
                    listener.set_nonblocking(true)
                        .context("Failed to set socket as non-blocking")?;
                    
                    // Spawn thread to accept connections
                    let (socket_tx, socket_rx) = bounded(8);
                    std::thread::spawn(move || {
                        for stream in listener.incoming() {
                            match stream {
                                Ok(stream) => {
                                    if socket_tx.send(stream).is_err() {
                                        break; // Receiver dropped, exit thread
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    std::thread::sleep(Duration::from_millis(100));
                                }
                                Err(e) => {
                                    log::error!("Error accepting status socket connection: {}", e);
                                }
                            }
                        }
                    });
                    
                    info!("Status query socket listening at: {}", socket_path.display());
                    Some(socket_rx)
                }
                Err(e) => {
                    error!("Failed to bind status socket at {}: {}", socket_path.display(), e);
                    error!("Status queries will not be available");
                    None
                }
            }
        };

        #[cfg(windows)]
        let socket_rx = {
            use crate::platform::windows::named_pipe::{NamedPipeStream, create_named_pipe_server};

            let is_elevated = crate::platform::is_elevated();
            let socket_path = crate::platform::status_socket_path(is_elevated);
            let path_str = socket_path.to_str().expect("Invalid pipe path");

            match create_named_pipe_server(path_str, 254) {
                Ok(initial_listener) => {
                    // Spawn thread to accept connections (Windows Named Pipe model)
                    let (socket_tx, socket_rx) = bounded(8);
                    let path_string = path_str.to_string();

                    std::thread::spawn(move || {
                        use windows::Win32::System::Pipes::ConnectNamedPipe;

                        let mut listener = initial_listener;
                        loop {
                            // Wait for client connection
                            let connect_result = unsafe {
                                ConnectNamedPipe(listener.as_raw_handle(), None)
                            };

                            match connect_result {
                                Ok(_) => {
                                    // Successfully connected - send stream through channel
                                    if socket_tx.send(listener).is_err() {
                                        break; // Receiver dropped, exit thread
                                    }

                                    // Create new named pipe instance for next connection
                                    match create_named_pipe_server(&path_string, 254) {
                                        Ok(new_listener) => listener = new_listener,
                                        Err(e) => {
                                            log::error!("Failed to recreate named pipe: {}", e);
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!("Error accepting named pipe connection: {}", e);
                                    std::thread::sleep(Duration::from_millis(100));
                                }
                            }
                        }
                    });

                    info!("Status query named pipe listening at: {}", socket_path.display());
                    Some(socket_rx)
                }
                Err(e) => {
                    error!("Failed to create named pipe at {}: {}", socket_path.display(), e);
                    error!("Status queries will not be available");
                    None
                }
            }
        };

        #[cfg(not(any(unix, windows)))]
        let socket_rx: Option<Receiver<()>> = None;

        let health_tick = tick(Duration::from_secs(30));
        let watchdog_tick = tick(Duration::from_secs(15)); // WatchdogSec/2
        let log_rotate_tick = tick(Duration::from_secs(3600));
        let restart_tick = tick(Duration::from_millis(100));
        
        // Vulnerability scan ticker - default 1 hour, configurable via security.vulnerability_scan_interval_secs
        let vuln_scan_interval = self.config.read().security.vulnerability_scan_interval_secs.unwrap_or(3600);
        let vuln_scan_tick = tick(Duration::from_secs(vuln_scan_interval));

        loop {
            select! {
                recv(self.bus_rx) -> evt => self.handle_event(evt?)?,
                
                // External shutdown trigger (Windows service or API)
                // This arm has priority over signal_watcher to ensure Windows service
                // stop requests are handled before Unix signals
                recv(self.shutdown_rx) -> _ => {
                    info!("External shutdown signal received (Windows service or API)");
                    
                    // Announce manager stopping
                    self.bus_tx.send(Evt::State {
                        service: Arc::from("manager"),
                        state: ServiceState::Stopping,
                        ts: chrono::Utc::now(),
                        pid: Some(std::process::id()),
                        correlation_id: None,
                    }).ok();

                    // Transition lifecycle to stopping state
                    // This triggers KillProcess action which shuts down workers
                    let action = self.lifecycle.step(Event::CmdStop);
                    self.handle_lifecycle_action(action).await;
                    
                    break;  // Exit event loop
                }
                
                recv(signal_watcher.receiver()) -> sig => {
                    match sig {
                        Ok(SignalKind::Terminate) | Ok(SignalKind::Interrupt) => {
                            info!("Received shutdown signal: {:?}", sig);
                            
                            // Notify systemd of graceful shutdown
                            crate::daemon::systemd_notify_stopping();
                            
                            self.bus_tx.send(Evt::State {
                                service: Arc::from("manager"),
                                state: ServiceState::Stopping,
                                ts: chrono::Utc::now(),
                                pid: Some(std::process::id()),
                                correlation_id: None,
                            }).ok();

                            // Transition lifecycle to stopping state
                            let action = self.lifecycle.step(Event::CmdStop);
                            self.handle_lifecycle_action(action).await;

                            break;
                        }
                        Ok(SignalKind::Hangup) => {
                            info!("Received SIGHUP/CTRL+BREAK - reloading configuration");
                            if let Err(e) = self.reload_config() {
                                error!("Config reload failed: {}", e);
                                // Continue running with old config
                            }
                        }
                        Ok(SignalKind::Shutdown) => {
                            info!("Received system shutdown signal - graceful shutdown");

                            // Transition lifecycle to stopping state
                            let action = self.lifecycle.step(Event::CmdStop);
                            self.handle_lifecycle_action(action).await;

                            break;
                        }
                        Err(_) => {
                            self.log_signal_channel_disconnection();
                            break;
                        }
                    }
                }
                recv(health_tick) -> _ => {
                    // Only trigger health checks if lifecycle is running
                    if self.lifecycle.is_running() {
                        // Trigger health checks on all services
                        for tx in self.workers.values() {
                            let correlation_id = self.next_correlation_id();
                            tx.send(Cmd::TickHealth { correlation_id }).ok();
                        }
                    }
                }
                recv(watchdog_tick) -> _ => {
                    // Send watchdog keepalive to systemd
                    // Only has effect if unit file contains WatchdogSec=
                    if self.lifecycle.is_running() {
                        crate::daemon::systemd_notify_watchdog();
                    }
                }
                recv(log_rotate_tick) -> _ => {
                    // Trigger log rotation on all services
                    for tx in self.workers.values() {
                        let correlation_id = self.next_correlation_id();
                        tx.send(Cmd::TickLogRotate { correlation_id }).ok();
                    }
                    // Announce log rotation
                    self.bus_tx.send(Evt::LogRotate {
                        service: Arc::from("manager"),
                        ts: chrono::Utc::now(),
                        correlation_id: 0,
                    }).ok();
                }
                recv(restart_tick) -> _ => {
                    // Process pending restarts
                    self.process_pending_restarts();
                }
                recv(vuln_scan_tick) -> _ => {
                    // Run vulnerability scan if scanner is enabled
                    if let Some(scanner) = &self.vulnerability_scanner {
                        self.run_vulnerability_scan(scanner.clone()).await;
                    }
                }
            }

            // Handle status queries (cross-platform: Unix socket or Windows Named Pipe)
            #[cfg(any(unix, windows))]
            if let Some(ref rx) = socket_rx {
                select! {
                    recv(rx) -> stream => {
                        if let Ok(stream) = stream
                            && let Err(e) = self.handle_status_query(stream)
                        {
                            error!("Error handling status query: {}", e);
                        }
                    }
                }
            }
        }

        // Announce manager stopped
        self.bus_tx
            .send(Evt::State {
                service: Arc::from("manager"),
                state: ServiceState::Stopped,
                ts: chrono::Utc::now(),
                pid: Some(std::process::id()),
                correlation_id: None,
            })
            .ok();

        Ok(())
    }

    fn handle_event(&mut self, evt: Evt) -> Result<()> {
        match &evt {
            Evt::State {
                service,
                state,
                ts,
                pid,
                correlation_id,
            } => {
                if let Some(id) = correlation_id {
                    info!("{service} → {state} (pid: {pid:?}, ts: {ts}, correlation_id={id})");
                } else {
                    info!("{service} → {state} (pid: {pid:?}, ts: {ts}, spontaneous)");
                }

                // Store last known state for status queries
                self.last_state.insert(service.to_string(), LastServiceState {
                    state: *state,
                    pid: *pid,
                    timestamp: Instant::now(),
                    failure_reason: None,
                });

                // Only restart on crash, not clean stop
                // Use enum variants for type-safe matching
                if *state == ServiceState::StoppedCrash && service.as_ref() != "manager" {
                    if !self.schedule_restart(service.as_ref(), 0) {
                        // Max attempts exceeded, log permanent failure
                        error!("{} permanently failed, will not restart", service);
                    }
                } else if *state == ServiceState::StoppedClean {
                    info!("{} stopped cleanly, not restarting", service);
                    // Clean stop - remove from pending restarts to prevent stale state
                    self.pending_restarts.remove(service.as_ref());
                }
            }
            Evt::Health {
                service,
                healthy,
                ts,
                correlation_id,
            } => {
                if *healthy {
                    info!("{service} health check OK at {ts} (correlation_id={correlation_id})");
                } else {
                    error!(
                        "{service} health check FAILED at {ts} (correlation_id={correlation_id})"
                    );
                    // Schedule restart with 100ms delay, respect max attempts
                    if !self.schedule_restart(service.as_ref(), 100) {
                        error!(
                            "{} exceeded max restart attempts after health failure",
                            service
                        );
                    }
                }
            }
            Evt::LogRotate {
                service,
                ts,
                correlation_id,
            } => {
                info!("{service} rotated logs at {ts} (correlation_id={correlation_id})");
            }
            Evt::Fatal { service, msg, ts } => {
                error!("{service} FATAL at {ts}: {msg}");
                
                // Store failure reason in last_state
                if let Some(state) = self.last_state.get_mut(service.as_ref()) {
                    state.failure_reason = Some(msg.to_string());
                }
                
                // Schedule restart with longer delay (1000ms), respect max attempts
                if !self.schedule_restart(service.as_ref(), 1000) {
                    error!(
                        "{} exceeded max restart attempts after fatal error",
                        service
                    );
                }
            }
            Evt::VulnerabilitiesReport {
                vulnerabilities,
                metrics,
                ts,
                correlation_id,
            } => {
                info!(
                    "Vulnerability report received at {ts} (correlation_id={correlation_id}): {} vulnerabilities, {} critical",
                    vulnerabilities.len(),
                    metrics.critical_count
                );
            }
        }
        Ok(())
    }

    /// Handle status query from Unix socket
    #[cfg(unix)]
    fn handle_status_query(&mut self, mut stream: std::os::unix::net::UnixStream) -> Result<()> {
        use crate::status::{StatusQuery, recv_message, send_message};

        // Set read timeout to prevent hanging on malicious clients
        stream.set_read_timeout(Some(Duration::from_secs(5)))
            .context("Failed to set socket read timeout")?;

        // Receive query from CLI
        let query: StatusQuery = recv_message(&mut stream)
            .context("Failed to receive status query")?;

        // Handle query
        match query {
            StatusQuery::All => {
                let response = self.build_full_status()?;
                send_message(&mut stream, &response)
                    .context("Failed to send status response")?;
            }
            StatusQuery::Service(name) => {
                let response = self.build_service_status(&name)?;
                send_message(&mut stream, &response)
                    .context("Failed to send status response")?;
            }
            StatusQuery::UsageStats(connection_id) => {
                // Block on async aggregation (we're in sync context)
                let rt = tokio::runtime::Handle::current();
                let response = rt.block_on(self.aggregate_usage_stats(&connection_id))?;
                send_message(&mut stream, &response)
                    .context("Failed to send usage stats response")?;
            }
            StatusQuery::ToolHistory(connection_id) => {
                // Block on async aggregation (we're in sync context)
                let rt = tokio::runtime::Handle::current();
                let response = rt.block_on(self.aggregate_tool_history(&connection_id))?;
                send_message(&mut stream, &response)
                    .context("Failed to send tool history response")?;
            }
        }

        Ok(())
    }

    /// Handle status query from Windows Named Pipe
    #[cfg(windows)]
    fn handle_status_query(&mut self, mut stream: crate::platform::windows::named_pipe::NamedPipeStream) -> Result<()> {
        use crate::status::{StatusQuery, recv_message, send_message};

        // Note: Windows Named Pipes don't have set_read_timeout in our wrapper
        // The timeout is handled at the pipe creation level

        // Receive query from CLI
        let query: StatusQuery = recv_message(&mut stream)
            .context("Failed to receive status query")?;

        // Handle query (same logic as Unix)
        match query {
            StatusQuery::All => {
                let response = self.build_full_status()?;
                send_message(&mut stream, &response)
                    .context("Failed to send status response")?;
            }
            StatusQuery::Service(name) => {
                let response = self.build_service_status(&name)?;
                send_message(&mut stream, &response)
                    .context("Failed to send status response")?;
            }
            StatusQuery::UsageStats(connection_id) => {
                // Block on async aggregation (we're in sync context)
                let rt = tokio::runtime::Handle::current();
                let response = rt.block_on(self.aggregate_usage_stats(&connection_id))?;
                send_message(&mut stream, &response)
                    .context("Failed to send usage stats response")?;
            }
            StatusQuery::ToolHistory(connection_id) => {
                // Block on async aggregation (we're in sync context)
                let rt = tokio::runtime::Handle::current();
                let response = rt.block_on(self.aggregate_tool_history(&connection_id))?;
                send_message(&mut stream, &response)
                    .context("Failed to send tool history response")?;
            }
        }

        Ok(())
    }

    /// Build full status response for all services
    fn build_full_status(&self) -> Result<crate::status::StatusResponse> {
        use crate::status::{ServiceStatus, ServiceStateKind, StatusResponse};
        
        let daemon_uptime = self.lifecycle.start_time().elapsed();
        
        let mut services = Vec::new();
        
        // Collect status for all registered services
        for service_name in self.workers.keys() {
            let restart_state = self.pending_restarts.get(service_name);
            let policy = self.restart_policies.get(service_name);
            let last_state = self.last_state.get(service_name);
            
            // Convert ServiceState to ServiceStateKind
            let state_kind = if let Some(last) = last_state {
                match last.state {
                    ServiceState::Starting => ServiceStateKind::Starting,
                    ServiceState::Running => ServiceStateKind::Running,
                    ServiceState::Stopping => ServiceStateKind::Stopped,
                    ServiceState::Stopped => ServiceStateKind::Stopped,
                    ServiceState::StoppedClean => ServiceStateKind::Stopped,
                    ServiceState::StoppedCrash => ServiceStateKind::Failed,
                    ServiceState::RestartedService => ServiceStateKind::Restarting,
                }
            } else {
                ServiceStateKind::Stopped
            };
            
            // Calculate uptime if running
            let uptime = if let Some(last) = last_state {
                if matches!(last.state, ServiceState::Running) {
                    Some(last.timestamp.elapsed())
                } else {
                    None
                }
            } else {
                None
            };
            
            // Get restart count and max
            let restart_count = restart_state.map(|s| s.attempts).unwrap_or(0);
            let max_restarts = policy.and_then(|p| p.max_attempts);
            
            // Calculate next restart delay if restarting
            let next_restart_delay = restart_state.and_then(|s| {
                let now = Instant::now();
                if s.stop_time > now {
                    Some(s.stop_time - now)
                } else {
                    None
                }
            });
            
            // Calculate success window remaining
            let success_window_remaining = if let (Some(rs), Some(pol)) = (restart_state, policy) {
                rs.last_successful_start.map(|start| {
                    let window = Duration::from_secs(pol.success_window_secs);
                    let elapsed = start.elapsed();
                    window.saturating_sub(elapsed)
                })
            } else {
                None
            };
            
            let status = ServiceStatus {
                name: service_name.clone(),
                state: state_kind,
                pid: last_state.and_then(|s| s.pid),
                uptime,
                restart_count,
                max_restarts,
                next_restart_delay,
                success_window_remaining,
                failure_reason: last_state.and_then(|s| s.failure_reason.clone()),
            };
            
            services.push(status);
        }
        
        Ok(StatusResponse {
            daemon_running: true,
            daemon_pid: std::process::id(),
            daemon_uptime,
            services,
        })
    }

    /// Build status response for a specific service
    fn build_service_status(&self, service_name: &str) -> Result<crate::status::StatusResponse> {
        // For now, just build full status and filter
        // In the future, could optimize to only query specific service
        let mut response = self.build_full_status()?;
        response.services.retain(|s| s.name == service_name);
        Ok(response)
    }

    /// Execute the side-effect requested by a lifecycle state transition.
    ///
    /// This method maps the pure Action enum returned by the state machine
    /// to concrete side-effects: spawning processes, killing processes, and
    /// sending health notifications.
    async fn handle_lifecycle_action(&mut self, action: Action) {
        match action {
            Action::SpawnProcess => {
                // Currently handled inline at line 256-291
                // Future: could refactor worker spawn logic here for consistency
                log::debug!("Lifecycle action: SpawnProcess (handled by caller)");
            }

            Action::KillProcess => {
                log::info!("Lifecycle action: KillProcess - shutting down workers");

                // Phase 1: Shutdown embedded HTTP servers (has timeout: 30s per server)
                if let Some(servers) = self.embedded_servers.take() {
                    log::info!("Shutting down {} embedded HTTP servers", servers.len());
                    if let Err(e) = shutdown_all_servers(servers).await {
                        log::error!("Error shutting down embedded servers: {}", e);
                        // Continue anyway - don't let server shutdown failure block worker shutdown
                    }
                }

                // Phase 2: Send shutdown commands to all workers
                log::info!("Sending shutdown command to {} workers", self.workers.len());
                for (name, tx) in &self.workers {
                    if let Err(e) = tx.send(Cmd::Shutdown) {
                        log::error!("Failed to send shutdown to {}: {}", name, e);
                    }
                }

                // Phase 3: Wait for workers to complete shutdown
                let timeout = Duration::from_secs(self.config.read().daemon_shutdown_timeout_secs);
                log::info!("Waiting for workers to complete shutdown (timeout: {:?})", timeout);
                
                match self.wait_for_workers_shutdown(timeout) {
                    Ok(()) => {
                        log::info!("All workers shutdown successfully");
                    }
                    Err(e) => {
                        log::error!("Worker shutdown timeout: {}", e);
                        log::warn!("Continuing with daemon shutdown despite worker timeout");
                        log::warn!("Hung workers may be forcefully terminated by OS");
                        // Don't return error - allow PID cleanup to proceed
                    }
                }
            }

            Action::NotifyHealthy => {
                log::info!("Lifecycle action: NotifyHealthy - manager is healthy");
                self.bus_tx
                    .send(Evt::Health {
                        service: Arc::from("manager"),
                        healthy: true,
                        ts: chrono::Utc::now(),
                        correlation_id: 0,
                    })
                    .ok();
            }

            Action::NotifyUnhealthy => {
                log::error!("Lifecycle action: NotifyUnhealthy - manager in failed state");
                self.bus_tx
                    .send(Evt::Health {
                        service: Arc::from("manager"),
                        healthy: false,
                        ts: chrono::Utc::now(),
                        correlation_id: 0,
                    })
                    .ok();
            }

            Action::Noop => {
                // Explicitly do nothing - transition completed with no side-effect
                log::trace!("Lifecycle action: Noop");
            }
        }
    }

    /// Wait for all worker threads to complete shutdown
    /// 
    /// Workers send ServiceState::StoppedClean or ServiceState::StoppedCrash
    /// when they finish their shutdown procedures. This method waits for
    /// all workers to send one of these events.
    /// 
    /// # Timeout Behavior
    /// 
    /// On timeout, logs which workers are still running and returns an error.
    /// The caller should continue cleanup (PID file removal) despite timeout.
    /// 
    /// # Architecture Note
    /// 
    /// This bridges async manager (tokio) with sync workers (OS threads):
    /// - Workers run in OS threads spawned by thread::spawn()
    /// - Workers communicate via crossbeam channels (blocking)
    /// - Manager runs in tokio runtime (async)
    /// - Uses crossbeam select! for consistent architecture
    fn wait_for_workers_shutdown(&mut self, timeout: Duration) -> Result<()> {
        let worker_names: HashSet<_> = self.workers.keys().cloned().collect();
        if worker_names.is_empty() {
            log::info!("No workers to wait for");
            return Ok(());
        }
        
        log::info!(
            "Waiting for {} workers to shutdown (timeout: {:?})",
            worker_names.len(),
            timeout
        );
        
        let mut stopped_workers = HashSet::new();
        let start = Instant::now();
        let timeout_tick = tick(timeout);
        
        loop {
            select! {
                recv(self.bus_rx) -> evt => {
                    match evt {
                        Ok(Evt::State { service, state, .. }) 
                            if worker_names.contains(service.as_ref()) 
                            && matches!(state, ServiceState::StoppedClean | ServiceState::StoppedCrash) => {
                            
                            let elapsed = start.elapsed();
                            log::info!(
                                "Worker '{}' stopped {} in {:.2}s",
                                service,
                                if state == ServiceState::StoppedClean { "cleanly" } else { "with crash" },
                                elapsed.as_secs_f64()
                            );
                            
                            stopped_workers.insert(service.as_ref().to_string());
                            
                            // Warn about slow shutdowns (>5s)
                            if elapsed > Duration::from_secs(5) {
                                log::warn!(
                                    "Worker '{}' took {:.2}s to shutdown (slow)",
                                    service,
                                    elapsed.as_secs_f64()
                                );
                            }
                            
                            if stopped_workers.len() == worker_names.len() {
                                log::info!(
                                    "All {} workers stopped successfully in {:.2}s",
                                    worker_names.len(),
                                    start.elapsed().as_secs_f64()
                                );
                                return Ok(());
                            }
                        }
                        Ok(_) => {
                            // Event from non-worker or non-state event, ignore
                            continue;
                        }
                        Err(_) => {
                            // Channel disconnected
                            log::warn!("Event bus disconnected during shutdown wait");
                            break;
                        }
                    }
                }
                recv(timeout_tick) -> _ => {
                    // Timeout reached
                    let still_running: Vec<_> = worker_names
                        .difference(&stopped_workers)
                        .collect();
                    
                    log::error!(
                        "Worker shutdown timeout after {:?}. {} workers still running:",
                        start.elapsed(),
                        still_running.len()
                    );
                    
                    for worker in &still_running {
                        log::error!("  - {} (hung or slow shutdown)", worker);
                    }
                    
                    return Err(anyhow::anyhow!(
                        "Shutdown timeout: {} workers did not stop within {:?}",
                        still_running.len(),
                        timeout
                    ));
                }
            }
        }
        
        Ok(())
    }

    /// Schedule a service for restart after a delay with exponential backoff
    ///
    /// Implements exponential backoff using the proven formula from
    /// kodegen-bundler-release/retry.rs (line 103):
    ///   delay = initial_delay * multiplier^(attempts-1)
    ///
    /// Returns true if restart was scheduled, false if max attempts exceeded.
    ///
    /// # Arguments
    /// * `service` - Service name to restart
    /// * `base_delay_ms` - Minimum delay from failure type (0=crash, 100=health, 1000=fatal)
    fn schedule_restart(&mut self, service: &str, base_delay_ms: u64) -> bool {
        // Get restart policy for this service (or use default)
        let policy = self
            .restart_policies
            .get(service)
            .cloned()
            .unwrap_or_default();

        // Handle max_attempts = Some(0) → never restart
        if policy.max_attempts == Some(0) {
            info!("{} has auto-restart disabled (max_attempts=0)", service);
            return false;
        }

        if let Some(tx) = self.workers.get(service) {
            // Send stop command immediately
            let correlation_id = self.next_correlation_id();
            tx.send(Cmd::Stop { correlation_id }).ok();

            // Calculate attempts counter with success window reset
            let state = self.pending_restarts.get(service);

            // Check if service ran successfully long enough to reset counter
            // This implements the "success window" pattern from circuit_breaker.rs
            let should_reset = state
                .and_then(|s| s.last_successful_start)
                .map(|start_time| {
                    start_time.elapsed() >= Duration::from_secs(policy.success_window_secs)
                })
                .unwrap_or(false);

            let attempts = if should_reset {
                info!(
                    "{} ran successfully for ≥{}s, resetting restart counter",
                    service, policy.success_window_secs
                );
                1
            } else {
                state.map_or(1, |s| s.attempts + 1)
            };

            // Check maximum attempts limit
            if let Some(max) = policy.max_attempts
                && attempts > max
            {
                error!(
                    "{} has failed {} times (max: {}), giving up permanently",
                    service, attempts, max
                );

                // Send fatal event to log the permanent failure
                self.bus_tx
                    .send(Evt::Fatal {
                        service: Arc::from(service),
                        msg: std::borrow::Cow::Owned(format!(
                            "Service exceeded max restart attempts ({})",
                            max
                        )),
                        ts: chrono::Utc::now(),
                    })
                    .ok();

                // Remove from pending restarts - permanently failed
                self.pending_restarts.remove(service);
                return false; // Do not restart
            }

            // Calculate exponential backoff delay
            // Uses proven formula from kodegen-bundler-release/retry.rs:103
            // Formula: initial_delay * multiplier^(attempts-1), capped at max_delay
            // Example with defaults: 100ms, 200ms, 400ms, 800ms, 1600ms, ... up to 60s
            let exponential_delay = (policy.initial_delay_ms as f64
                * policy.backoff_multiplier.powi((attempts - 1) as i32))
            .min(policy.max_delay_ms as f64) as u64;

            // Use greater of base_delay_ms (from failure type) or exponential backoff
            // This ensures fatal errors still get their 1000ms minimum delay
            let delay_ms = exponential_delay.max(base_delay_ms);

            let restart_time = Instant::now() + Duration::from_millis(delay_ms);

            self.pending_restarts.insert(
                service.to_string(),
                RestartState {
                    stop_time: restart_time,
                    attempts,
                    last_successful_start: None, // Will be set on successful start
                },
            );

            info!(
                "Scheduled restart for {} in {}ms (attempt #{}/{})",
                service,
                delay_ms,
                attempts,
                policy
                    .max_attempts
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "∞".to_string())
            );

            true
        } else {
            error!("Cannot restart {}: service not found in workers", service);
            false
        }
    }

    /// Run vulnerability scan and log results
    ///
    /// Executes a cargo-audit based vulnerability scan and logs metrics.
    /// If thresholds are exceeded, logs an error with details.
    /// Uses VulnerabilityMetrics helper methods for health monitoring and alerting.
    async fn run_vulnerability_scan(&self, scanner: Arc<crate::security::audit::VulnerabilityScanner>) {
        use crate::security::audit::ci_cd;
        
        info!("Starting periodic vulnerability scan");
        
        match scanner.scan_dependencies().await {
            Ok(result) => {
                let metrics = scanner.get_metrics();
                
                // Log scan summary using total_vulnerabilities() helper
                info!(
                    "Vulnerability scan completed: {} total vulnerabilities (critical={}, high={}, medium={}, low={})",
                    metrics.total_vulnerabilities(),
                    metrics.critical_count,
                    metrics.high_count,
                    metrics.medium_count,
                    metrics.low_count
                );
                
                // Check for critical vulnerabilities using has_critical() helper
                // This provides immediate alerting for the most severe security issues
                if metrics.has_critical() {
                    error!(
                        "CRITICAL VULNERABILITIES DETECTED: {} critical vulnerabilities require immediate attention!",
                        metrics.critical_count
                    );
                    // Log detailed scan results for investigation
                    info!("{}", ci_cd::format_scan_results(&result));
                }
                
                // Check if thresholds are exceeded (includes all severity levels)
                if ci_cd::should_fail_build(&scanner, &result) {
                    error!(
                        "SECURITY ALERT: {}",
                        ci_cd::generate_failure_message(&result, &scanner.thresholds)
                    );
                    // Only log detailed results if not already logged for critical
                    if !metrics.has_critical() {
                        info!("{}", ci_cd::format_scan_results(&result));
                    }
                }
                
                // Health monitoring using success_rate() helper
                // Warn if scan success rate drops below 80%
                let rate = metrics.success_rate();
                if rate < 80.0 && metrics.total_scans > 0 {
                    log::warn!(
                        "Vulnerability scanner health degraded: success rate {:.1}% (below 80% threshold)",
                        rate
                    );
                }
                
                // Log success rate for monitoring
                info!(
                    "Vulnerability scanner stats: {}/{} scans successful ({:.1}%), cache size: {}",
                    metrics.successful_scans,
                    metrics.total_scans,
                    rate,
                    metrics.cache_size
                );
            }
            Err(e) => {
                error!("Vulnerability scan failed: {}", e);
            }
        }
    }

    /// Aggregate usage statistics from all embedded HTTP servers
    ///
    /// Queries all backend servers in parallel via GET /mcp/stats, aggregates results,
    /// and returns AggregatedUsageStats for Unix socket serialization.
    ///
    /// # Returns
    /// - Returns AggregatedUsageStats even if some servers fail (partial failure tolerance)
    /// - Failed servers are marked with available=false and error message
    /// - Global aggregates only include stats from available servers
    ///
    /// # Performance
    /// - Parallel HTTP queries (all servers queried simultaneously)
    /// - 2-second timeout per server (prevents hanging on crashed servers)
    /// - Total aggregation time: ~2 seconds for all servers
    async fn aggregate_usage_stats(&self, connection_id: &str) -> anyhow::Result<crate::status::AggregatedUsageStats> {
        use tokio::time::{timeout, Duration};
        use anyhow::Context;
        use crate::status::{AggregatedUsageStats, ServerStats, UsageStatsSnapshot, GlobalAggregates};

        let aggregated_at = chrono::Utc::now().timestamp();

        // Get embedded servers or return empty response if None
        let embedded_servers = match &self.embedded_servers {
            Some(servers) => servers,
            None => {
                return Ok(AggregatedUsageStats {
                    aggregated_at,
                    servers_queried: 0,
                    servers_failed: 0,
                    servers: Vec::new(),
                    global: GlobalAggregates {
                        total_tool_calls: 0,
                        successful_calls: 0,
                        failed_calls: 0,
                        success_rate: 0.0,
                        total_sessions: 0,
                        categories_active: 0,
                    },
                });
            }
        };

        // Create HTTP client (reuse TLS config, connection pooling)
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))  // Per-request timeout
            .build()
            .context("Failed to create HTTP client for stats aggregation")?;

        // Query all servers in parallel
        let futures: Vec<_> = embedded_servers
            .iter()
            .map(|server| {
                let client = client.clone();
                let category = server.name.clone();
                let port = server.port;
                let conn_id = connection_id.to_string();

                async move {
                    // Query with timeout (include connection_id parameter for per-connection isolation)
                    let url = format!("http://127.0.0.1:{}/mcp/stats?connection_id={}", port, conn_id);

                    match timeout(
                        Duration::from_secs(2),
                        client.get(&url).send()
                    ).await {
                        Ok(Ok(response)) => {
                            // Successfully received response - parse UsageStats JSON
                            match response.json::<serde_json::Value>().await {
                                Ok(json) => {
                                    // Parse UsageStats fields into UsageStatsSnapshot
                                    let snapshot = UsageStatsSnapshot {
                                        total_tool_calls: json["stats"]["total_tool_calls"].as_u64().unwrap_or(0),
                                        successful_calls: json["stats"]["successful_calls"].as_u64().unwrap_or(0),
                                        failed_calls: json["stats"]["failed_calls"].as_u64().unwrap_or(0),
                                        tool_counts: json["stats"]["tool_counts"]
                                            .as_object()
                                            .map(|obj| {
                                                obj.iter()
                                                    .filter_map(|(k, v)| {
                                                        v.as_u64().map(|count| (k.clone(), count))
                                                    })
                                                    .collect()
                                            })
                                            .unwrap_or_default(),
                                        first_used: json["stats"]["first_used"].as_i64().unwrap_or(0),
                                        last_used: json["stats"]["last_used"].as_i64().unwrap_or(0),
                                        total_sessions: json["stats"]["total_sessions"].as_u64().unwrap_or(0),
                                    };

                                    ServerStats {
                                        category,
                                        port,
                                        available: true,
                                        error: None,
                                        stats: snapshot,
                                    }
                                }
                                Err(e) => {
                                    // JSON parse error
                                    ServerStats {
                                        category,
                                        port,
                                        available: false,
                                        error: Some(format!("JSON parse error: {}", e)),
                                        stats: UsageStatsSnapshot {
                                            total_tool_calls: 0,
                                            successful_calls: 0,
                                            failed_calls: 0,
                                            tool_counts: std::collections::HashMap::new(),
                                            first_used: 0,
                                            last_used: 0,
                                            total_sessions: 0,
                                        },
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            // HTTP request error
                            ServerStats {
                                category,
                                port,
                                available: false,
                                error: Some(format!("HTTP error: {}", e)),
                                stats: UsageStatsSnapshot {
                                    total_tool_calls: 0,
                                    successful_calls: 0,
                                    failed_calls: 0,
                                    tool_counts: std::collections::HashMap::new(),
                                    first_used: 0,
                                    last_used: 0,
                                    total_sessions: 0,
                                },
                            }
                        }
                        Err(_) => {
                            // Timeout
                            ServerStats {
                                category,
                                port,
                                available: false,
                                error: Some("Timeout (2s)".to_string()),
                                stats: UsageStatsSnapshot {
                                    total_tool_calls: 0,
                                    successful_calls: 0,
                                    failed_calls: 0,
                                    tool_counts: std::collections::HashMap::new(),
                                    first_used: 0,
                                    last_used: 0,
                                    total_sessions: 0,
                                },
                            }
                        }
                    }
                }
            })
            .collect();

        // Wait for all queries to complete (no early exit on failure)
        let server_results = futures::future::join_all(futures).await;

        // Compute global aggregates and count failures
        let mut global_total_calls = 0u64;
        let mut global_successful = 0u64;
        let mut global_failed = 0u64;
        let mut global_sessions = 0u64;
        let mut servers_failed = 0usize;
        let mut categories_active = 0usize;

        for server_stats in &server_results {
            if !server_stats.available {
                servers_failed += 1;
            } else {
                // Only aggregate from available servers
                global_total_calls += server_stats.stats.total_tool_calls;
                global_successful += server_stats.stats.successful_calls;
                global_failed += server_stats.stats.failed_calls;
                global_sessions += server_stats.stats.total_sessions;

                if server_stats.stats.total_tool_calls > 0 {
                    categories_active += 1;
                }
            }
        }

        let success_rate = if global_total_calls > 0 {
            (global_successful as f64) / (global_total_calls as f64)
        } else {
            0.0
        };

        Ok(AggregatedUsageStats {
            aggregated_at,
            servers_queried: embedded_servers.len(),
            servers_failed,
            servers: server_results,
            global: GlobalAggregates {
                total_tool_calls: global_total_calls,
                successful_calls: global_successful,
                failed_calls: global_failed,
                success_rate,
                total_sessions: global_sessions,
                categories_active,
            },
        })
    }

    /// Aggregate tool history from all embedded HTTP servers for a specific connection
    ///
    /// Similar to aggregate_usage_stats but queries /mcp/history endpoint instead.
    /// Returns tool call records across all servers for the given connection_id.
    ///
    /// # Returns
    /// - Returns AggregatedToolHistory even if some servers fail (partial failure tolerance)
    /// - Failed servers are marked with available=false and error message
    ///
    /// # Performance
    /// - Parallel HTTP queries (all servers queried simultaneously)
    /// - 2-second timeout per server (prevents hanging on crashed servers)
    async fn aggregate_tool_history(&self, connection_id: &str) -> anyhow::Result<crate::status::AggregatedToolHistory> {
        use tokio::time::{timeout, Duration};
        use anyhow::Context;
        use crate::status::{AggregatedToolHistory, ServerToolHistory, ToolCallRecord};

        let aggregated_at = chrono::Utc::now().timestamp();

        // Get embedded servers or return empty response
        let embedded_servers = match &self.embedded_servers {
            Some(servers) => servers,
            None => {
                return Ok(AggregatedToolHistory {
                    aggregated_at,
                    connection_id: connection_id.to_string(),
                    servers_queried: 0,
                    servers_failed: 0,
                    servers: Vec::new(),
                    total_calls: 0,
                });
            }
        };

        // Create HTTP client (reuse TLS config, connection pooling)
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))  // Per-request timeout
            .build()
            .context("Failed to create HTTP client for tool history aggregation")?;

        // Query all servers in parallel
        let futures: Vec<_> = embedded_servers
            .iter()
            .map(|server| {
                let client = client.clone();
                let category = server.name.clone();
                let port = server.port;
                let conn_id = connection_id.to_string();

                async move {
                    // Query with timeout (include connection_id parameter for per-connection isolation)
                    let url = format!("http://127.0.0.1:{}/mcp/history?connection_id={}", port, conn_id);

                    match timeout(
                        Duration::from_secs(2),
                        client.get(&url).send()
                    ).await {
                        Ok(Ok(response)) => {
                            // Successfully received response - parse history JSON
                            match response.json::<serde_json::Value>().await {
                                Ok(json) => {
                                    // Parse tool call records from response
                                    let calls: Vec<ToolCallRecord> = json["calls"]
                                        .as_array()
                                        .map(|arr| {
                                            arr.iter()
                                                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                                                .collect()
                                        })
                                        .unwrap_or_default();

                                    ServerToolHistory {
                                        category,
                                        port,
                                        available: true,
                                        error: None,
                                        calls,
                                    }
                                }
                                Err(e) => {
                                    ServerToolHistory {
                                        category,
                                        port,
                                        available: false,
                                        error: Some(format!("JSON parse error: {}", e)),
                                        calls: Vec::new(),
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            ServerToolHistory {
                                category,
                                port,
                                available: false,
                                error: Some(format!("HTTP error: {}", e)),
                                calls: Vec::new(),
                            }
                        }
                        Err(_) => {
                            ServerToolHistory {
                                category,
                                port,
                                available: false,
                                error: Some("Timeout (2s)".to_string()),
                                calls: Vec::new(),
                            }
                        }
                    }
                }
            })
            .collect();

        let server_results = futures::future::join_all(futures).await;

        // Count failures and total calls across all servers
        let mut servers_failed = 0usize;
        let mut total_calls = 0usize;

        for server in &server_results {
            if !server.available {
                servers_failed += 1;
            } else {
                total_calls += server.calls.len();
            }
        }

        Ok(AggregatedToolHistory {
            aggregated_at,
            connection_id: connection_id.to_string(),
            servers_queried: embedded_servers.len(),
            servers_failed,
            servers: server_results,
            total_calls,
        })
    }

    /// Process pending restarts that are ready
    ///
    /// Executes restarts for services whose backoff delay has elapsed.
    /// Records successful start time to enable success window tracking.
    fn process_pending_restarts(&mut self) {
        let now = Instant::now();
        let mut to_restart = Vec::new();

        // Find services ready to restart
        for (service, state) in &self.pending_restarts {
            if now >= state.stop_time {
                to_restart.push(service.clone());
            }
        }

        // Restart ready services
        for service in to_restart {
            if let Some(mut state) = self.pending_restarts.remove(&service)
                && let Some(tx) = self.workers.get(&service)
            {
                info!("Restarting {} (attempt #{})", service, state.attempts);

                // Record successful start time for success window tracking
                // This timestamp will be checked in schedule_restart() to determine
                // if service ran long enough to reset the attempts counter
                state.last_successful_start = Some(Instant::now());

                // Re-insert state with updated start time
                // Keep state in map so next failure can check elapsed time
                self.pending_restarts.insert(service.clone(), state);

                // Send start command to service worker
                let correlation_id = self.next_correlation_id();
                tx.send(Cmd::Start { correlation_id }).ok();

                // Announce restart completion to event bus
                self.bus_tx
                    .send(Evt::State {
                        service: Arc::from("manager"),
                        state: ServiceState::RestartedService,
                        ts: chrono::Utc::now(),
                        pid: Some(std::process::id()),
                        correlation_id: None,
                    })
                    .ok();
            }
        }
    }

    /// Trigger graceful shutdown
    /// 
    /// This method enables external callers (like Windows services) to shut down
    /// the ServiceManager event loop gracefully. It sends a shutdown signal to
    /// the run() loop which will then break from its select! and perform cleanup.
    /// 
    /// # Shutdown Sequence
    /// 
    /// 1. Sends shutdown signal to run() loop (non-blocking)
    /// 2. run() loop breaks from select! and enters cleanup:
    ///    - Calls handle_lifecycle_action(Action::KillProcess)
    ///    - Shuts down embedded HTTP servers
    ///    - Sends Shutdown commands to all workers
    ///    - Waits for worker termination
    /// 3. Returns immediately after sending signal
    /// 
    /// # Note on Timeout
    /// 
    /// This method returns immediately after sending the shutdown signal.
    /// The caller (Windows service) is responsible for:
    /// - Waiting on the run() task to complete (via JoinHandle)
    /// - Enforcing timeout at the task level
    /// - Handling timeout by allowing SCM to force-kill if needed
    /// 
    /// This design keeps shutdown() simple and avoids complex async/sync bridging.
    /// 
    /// # Arguments
    /// 
    /// * `_timeout` - Ignored, provided for API compatibility
    /// 
    /// # Example
    /// 
    /// ```rust
    /// // Send shutdown signal
    /// service_manager.shutdown(Duration::from_secs(5))?;
    /// 
    /// // Wait for run() task with timeout
    /// match tokio::time::timeout(Duration::from_secs(5), run_handle).await {
    ///     Ok(_) => info!("Shutdown complete"),
    ///     Err(_) => error!("Shutdown timeout"),
    /// }
    /// ```
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn shutdown(&self, _timeout: Duration) -> Result<()> {
        info!("Sending shutdown signal to ServiceManager");

        // Send shutdown signal to run() loop
        // This will cause the select! to break and cleanup to begin
        self.shutdown_tx
            .send(())
            .context("Failed to send shutdown signal - channel disconnected")?;

        info!("Shutdown signal sent successfully");
        Ok(())
    }

    /// Get a clone of the shutdown sender for external signaling
    ///
    /// This allows external code (like Windows SCM handler) to send shutdown
    /// signals even after the ServiceManager is moved into a thread.
    #[cfg(windows)]
    pub fn get_shutdown_sender(&self) -> crossbeam_channel::Sender<()> {
        self.shutdown_tx.clone()
    }
}
