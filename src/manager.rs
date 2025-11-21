use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender, bounded, select, tick};
use log::{error, info};

use crate::config::ServiceConfig;
use crate::ipc::{Cmd, Evt, ServiceState};
use crate::lifecycle::Lifecycle;
use crate::platform::{SignalKind, watch_signals};
use crate::service::port_cleanup::cleanup_port_if_needed;
use crate::state_machine::{Action, Event};
use crate::service::embedded_servers::{EmbeddedServer, shutdown_all_servers};

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

/// Top‑level in‑process manager supervising *all* workers.
pub struct ServiceManager {
    bus_tx: Sender<Evt>,
    bus_rx: Receiver<Evt>,
    workers: HashMap<String, Sender<Cmd>>,
    pending_restarts: HashMap<String, RestartState>,
    
    /// Restart policies per service (loaded from config)
    /// Allows per-service policy customization
    restart_policies: HashMap<String, crate::config::RestartPolicy>,
    
    lifecycle: Lifecycle,
    embedded_servers: Option<Vec<EmbeddedServer>>,
    
    /// Configuration for runtime reload
    config: std::sync::Arc<parking_lot::RwLock<ServiceConfig>>,
    
    /// Correlation ID generator for IPC request tracking
    /// Uses Relaxed ordering since correlation IDs don't require synchronization
    next_correlation_id: AtomicU64,
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
                                            restart_policies.insert(def.name.clone(), def.restart_policy.clone());
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
        
        drop(cfg_read); // Release read lock

        Ok(Self {
            bus_tx,
            bus_rx,
            workers,
            pending_restarts: HashMap::new(),
            restart_policies,
            lifecycle: Lifecycle::default(),
            embedded_servers: None,
            config,
            next_correlation_id: AtomicU64::new(1),
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
        use std::net::SocketAddr;
        use crate::service::embedded_servers::{start_server, EmbeddedServer};

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
                    log::error!("✗ Port cleanup failed for {} (port {}): {:#}", config.name, config.port, e);
                    log::error!("  This indicates port is held by a process that cannot be killed");
                    log::error!("  Daemon continues with {} unavailable (graceful degradation)", config.name);
                    failed_count += 1;
                    continue;  // Skip this server, try next one
                }
            }

            // Port is now guaranteed available - start server
            log::debug!("Starting {} server on port {} (post-cleanup)", config.name, config.port);
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
                    log::error!("  Port {} was cleared but server startup failed - check server implementation", config.port);
                    log::error!("  Daemon continues with {} unavailable (graceful degradation)", config.name);
                    failed_count += 1;
                }
            }
        }
        
        let total = configs.iter().filter(|c| c.enabled).count();
        let succeeded = servers.len();
        
        if succeeded == 0 {
            log::error!("No HTTP servers started successfully ({} failed)", failed_count);
            log::error!("Daemon running but no services available");
        } else if failed_count > 0 {
            log::warn!("Started {}/{} servers ({} failed)", succeeded, total, failed_count);
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
                    return Err(anyhow::anyhow!("No config file path stored - cannot reload"));
                }
            }
        };
        
        // Load new config from disk
        let new_cfg = ServiceConfig::load_from_file(&config_path)
            .with_context(|| format!("Failed to load updated configuration from {:?}", config_path))?;
        
        // Get old service names
        let old_services: HashMap<String, _> = {
            let cfg = self.config.read();
            cfg.services.iter()
                .map(|def| (def.name.clone(), def.clone()))
                .collect()
        };
        
        // Get new service names
        let new_services: HashMap<String, _> = new_cfg.services.iter()
            .map(|def| (def.name.clone(), def.clone()))
            .collect();
        
        // Find services to stop (in old but not in new)
        for name in old_services.keys() {
            if !new_services.contains_key(name) {
                info!("Stopping removed service: {}", name);
                if let Some(tx) = self.workers.get(name) {
                    if let Err(e) = tx.send(Cmd::Shutdown) {
                        error!("Failed to send shutdown to service {}: {}", name, e);
                    }
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
                        self.restart_policies.insert(name.clone(), def.restart_policy.clone());
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
                    if let Some(tx) = self.workers.get(name) {
                        if let Err(e) = tx.send(Cmd::Shutdown) {
                            error!("Failed to send shutdown to service {}: {}", name, e);
                        }
                    }
                    
                    // Start new version
                    match crate::service::spawn(new_def.clone(), self.bus_tx.clone()) {
                        Ok(tx) => {
                            self.workers.insert(name.clone(), tx);
                            self.restart_policies.insert(name.clone(), new_def.restart_policy.clone());
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

    /// Central event‑loop.  Runs until SIGINT / SIGTERM.
    pub async fn run(mut self) -> Result<()> {
        // Process lifecycle start event
        let action = self.lifecycle.step(Event::CmdStart);
        if action == Action::SpawnProcess {
            // Announce manager start
            self.bus_tx.send(Evt::State {
                service: "manager".to_string(),
                state: ServiceState::Starting,
                ts: chrono::Utc::now(),
                pid: Some(std::process::id()),
                correlation_id: None,
            })?;

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
            
            // Start HTTP servers with graceful degradation
            // NOTE: Servers run as background tokio tasks - this is correct
            self.start_servers_gracefully().await;

            // Manager is now running
            self.bus_tx.send(Evt::State {
                service: "manager".to_string(),
                state: ServiceState::Running,
                ts: chrono::Utc::now(),
                pid: Some(std::process::id()),
                correlation_id: None,
            })?;
        }
        // Handle any other action types (though CmdStart always returns SpawnProcess)
        self.handle_lifecycle_action(action).await;

        // Setup cross-platform signal watcher
        let signal_rx = watch_signals()?;
        
        let health_tick = tick(Duration::from_secs(30));
        let log_rotate_tick = tick(Duration::from_secs(3600));
        let restart_tick = tick(Duration::from_millis(100));

        loop {
            select! {
                recv(self.bus_rx) -> evt => self.handle_event(evt?)?,
                recv(signal_rx) -> sig => {
                    match sig {
                        Ok(SignalKind::Terminate) | Ok(SignalKind::Interrupt) => {
                            info!("Received shutdown signal: {:?}", sig);
                            self.bus_tx.send(Evt::State {
                                service: "manager".to_string(),
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
                            error!("Signal channel closed unexpectedly");
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
                recv(log_rotate_tick) -> _ => {
                    // Trigger log rotation on all services
                    for tx in self.workers.values() {
                        let correlation_id = self.next_correlation_id();
                        tx.send(Cmd::TickLogRotate { correlation_id }).ok();
                    }
                    // Announce log rotation
                    self.bus_tx.send(Evt::LogRotate {
                        service: "manager".to_string(),
                        ts: chrono::Utc::now(),
                        correlation_id: 0,
                    }).ok();
                }
                recv(restart_tick) -> _ => {
                    // Process pending restarts
                    self.process_pending_restarts();
                }
            }
        }

        // Announce manager stopped
        self.bus_tx
            .send(Evt::State {
                service: "manager".to_string(),
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
                
                // Only restart on crash, not clean stop
                // Use enum variants for type-safe matching
                if *state == ServiceState::StoppedCrash && service != "manager" {
                    if !self.schedule_restart(service, 0) {
                        // Max attempts exceeded, log permanent failure
                        error!("{} permanently failed, will not restart", service);
                    }
                } else if *state == ServiceState::StoppedClean {
                    info!("{} stopped cleanly, not restarting", service);
                    // Clean stop - remove from pending restarts to prevent stale state
                    self.pending_restarts.remove(service.as_str());
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
                    error!("{service} health check FAILED at {ts} (correlation_id={correlation_id})");
                    // Schedule restart with 100ms delay, respect max attempts
                    if !self.schedule_restart(service, 100) {
                        error!("{} exceeded max restart attempts after health failure", service);
                    }
                }
            }
            Evt::LogRotate { service, ts, correlation_id } => {
                info!("{service} rotated logs at {ts} (correlation_id={correlation_id})");
            }
            Evt::Fatal { service, msg, ts } => {
                error!("{service} FATAL at {ts}: {msg}");
                // Schedule restart with longer delay (1000ms), respect max attempts
                if !self.schedule_restart(service, 1000) {
                    error!("{} exceeded max restart attempts after fatal error", service);
                }
            }
        }
        Ok(())
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
                
                // Shutdown embedded HTTP servers if running
                if let Some(servers) = self.embedded_servers.take() {
                    if let Err(e) = shutdown_all_servers(servers).await {
                        log::error!("Error shutting down embedded servers: {}", e);
                    }
                }
                
                // Send shutdown command to all workers
                for (name, tx) in &self.workers {
                    if let Err(e) = tx.send(Cmd::Shutdown) {
                        log::error!("Failed to send shutdown to {}: {}", name, e);
                    }
                }
            }
            
            Action::NotifyHealthy => {
                log::info!("Lifecycle action: NotifyHealthy - manager is healthy");
                self.bus_tx.send(Evt::Health {
                    service: "manager".to_string(),
                    healthy: true,
                    ts: chrono::Utc::now(),
                    correlation_id: 0,
                }).ok();
            }
            
            Action::NotifyUnhealthy => {
                log::error!("Lifecycle action: NotifyUnhealthy - manager in failed state");
                self.bus_tx.send(Evt::Health {
                    service: "manager".to_string(),
                    healthy: false,
                    ts: chrono::Utc::now(),
                    correlation_id: 0,
                }).ok();
            }
            
            Action::Noop => {
                // Explicitly do nothing - transition completed with no side-effect
                log::trace!("Lifecycle action: Noop");
            }
        }
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
        let policy = self.restart_policies
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
                self.bus_tx.send(Evt::Fatal {
                    service: service.to_string(),
                    msg: std::borrow::Cow::Owned(
                        format!("Service exceeded max restart attempts ({})", max)
                    ),
                    ts: chrono::Utc::now(),
                }).ok();

                // Remove from pending restarts - permanently failed
                self.pending_restarts.remove(service);
                return false;  // Do not restart
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
                    last_successful_start: None,  // Will be set on successful start
                },
            );

            info!(
                "Scheduled restart for {} in {}ms (attempt #{}/{})",
                service,
                delay_ms,
                attempts,
                policy.max_attempts.map(|m| m.to_string()).unwrap_or_else(|| "∞".to_string())
            );
            
            true
        } else {
            error!("Cannot restart {}: service not found in workers", service);
            false
        }
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
                        service: "manager".to_string(),
                        state: ServiceState::RestartedService,
                        ts: chrono::Utc::now(),
                        pid: Some(std::process::id()),
                        correlation_id: None,
                    })
                    .ok();
            }
        }
    }
}


