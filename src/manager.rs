use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender, bounded, select, tick};
use log::{error, info};

use crate::config::ServiceConfig;
use crate::ipc::{Cmd, Evt};
use crate::lifecycle::Lifecycle;
use crate::state_machine::{Action, Event};
use crate::service::embedded_servers::{EmbeddedServer, start_all_servers, shutdown_all_servers};

/// Global event bus size – small fixed size → zero heap growth.
const BUS_BOUND: usize = 128;

/// Restart state for a service
#[derive(Debug)]
struct RestartState {
    stop_time: Instant,
    attempts: u32,
}

/// Top‑level in‑process manager supervising *all* workers.
pub struct ServiceManager {
    bus_tx: Sender<Evt>,
    bus_rx: Receiver<Evt>,
    workers: HashMap<String, Sender<Cmd>>,
    pending_restarts: HashMap<String, RestartState>,
    lifecycle: Lifecycle,
    embedded_servers: Option<Vec<EmbeddedServer>>,
}

impl ServiceManager {
    /// Load config, spawn workers, and return the fully‑primed manager.
    pub fn new(cfg: &ServiceConfig) -> Result<Self> {
        let (bus_tx, bus_rx) = bounded::<Evt>(BUS_BOUND);
        let mut workers = HashMap::new();

        // Load services from config file
        for def in cfg.services.clone() {
            match crate::service::spawn(def.clone(), bus_tx.clone()) {
                Ok(tx) => {
                    workers.insert(def.name.clone(), tx);
                }
                Err(e) => {
                    error!("Failed to spawn service '{}': {}", def.name, e);
                    // Continue with other services - graceful degradation
                }
            }
        }

        // Load services from services directory
        if let Some(services_dir) = &cfg.services_dir
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

        Ok(Self {
            bus_tx,
            bus_rx,
            workers,
            pending_restarts: HashMap::new(),
            lifecycle: Lifecycle::default(),
            embedded_servers: None,
        })
    }

    /// Start category HTTP servers as embedded in-process servers
    pub async fn start_http_servers(&mut self, cfg: &ServiceConfig) -> Result<()> {
        let configs = cfg.category_servers.clone();
        let (tls_cert, tls_key) = crate::config::discover_certificate_paths();

        log::info!("Starting {} embedded HTTP servers", configs.len());
        for config in &configs {
            if config.enabled {
                log::info!("  {} (port {})", config.name, config.port);
            }
        }

        // Start all servers (fail-fast on error with automatic rollback)
        let servers = start_all_servers(configs, tls_cert, tls_key).await?;

        log::info!("✓ All HTTP servers started successfully");
        self.embedded_servers = Some(servers);

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
                kind: "starting",
                ts: chrono::Utc::now(),
                pid: Some(std::process::id()),
            })?;

            // Initial start‑up pass.
            for (name, tx) in &self.workers {
                tx.send(Cmd::Start)?;
                info!("Started service: {name}");
            }

            // Manager is now running
            self.bus_tx.send(Evt::State {
                service: "manager".to_string(),
                kind: "running",
                ts: chrono::Utc::now(),
                pid: Some(std::process::id()),
            })?;
        }

        let sig_tick = tick(Duration::from_millis(200));
        let health_tick = tick(Duration::from_secs(30));
        let log_rotate_tick = tick(Duration::from_secs(3600));
        let restart_tick = tick(Duration::from_millis(100));

        loop {
            select! {
                recv(self.bus_rx) -> evt => self.handle_event(evt?)?,
                recv(sig_tick)    -> _   => {
                    if let Some(sig) = check_signals() { // coarse polling ≈200 ms
                        info!("signal {sig:?} – orderly shutdown");
                        self.bus_tx.send(Evt::State {
                            service: "manager".to_string(),
                            kind: "stopping",
                            ts: chrono::Utc::now(),
                            pid: Some(std::process::id()),
                        }).ok();

                        // Shutdown embedded HTTP servers if running
                        if let Some(servers) = self.embedded_servers.take() {
                            shutdown_all_servers(servers).await;
                        }

                        for tx in self.workers.values() { tx.send(Cmd::Shutdown).ok(); }
                        break;
                    }
                }
                recv(health_tick) -> _ => {
                    // Only trigger health checks if lifecycle is running
                    if self.lifecycle.is_running() {
                        // Trigger health checks on all services
                        for tx in self.workers.values() {
                            tx.send(Cmd::TickHealth).ok();
                        }
                    }
                }
                recv(log_rotate_tick) -> _ => {
                    // Trigger log rotation on all services
                    for tx in self.workers.values() {
                        tx.send(Cmd::TickLogRotate).ok();
                    }
                    // Announce log rotation
                    self.bus_tx.send(Evt::LogRotate {
                        service: "manager".to_string(),
                        ts: chrono::Utc::now(),
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
                kind: "stopped",
                ts: chrono::Utc::now(),
                pid: Some(std::process::id()),
            })
            .ok();

        Ok(())
    }

    fn handle_event(&mut self, evt: Evt) -> Result<()> {
        match &evt {
            Evt::State {
                service,
                kind,
                ts,
                pid,
            } => {
                info!("{service} → {kind} (pid: {pid:?}, ts: {ts})");
                // Check if any service has died unexpectedly
                if *kind == "stopped" && service != "manager" {
                    // Schedule restart
                    self.schedule_restart(service, 0);
                }
            }
            Evt::Health {
                service,
                healthy,
                ts,
            } => {
                if *healthy {
                    info!("{service} health check OK at {ts}");
                } else {
                    error!("{service} health check FAILED at {ts}");
                    // Schedule restart with delay
                    self.schedule_restart(service, 100);
                }
            }
            Evt::LogRotate { service, ts } => {
                info!("{service} rotated logs at {ts}");
            }
            Evt::Fatal { service, msg, ts } => {
                error!("{service} FATAL at {ts}: {msg}");
                // Notify about fatal error
                let error_msg = format!("Service {service} encountered fatal error: {msg}");
                self.bus_tx
                    .send(Evt::Fatal {
                        service: "manager".to_string(),
                        msg: Box::leak(error_msg.into_boxed_str()) as &'static str,
                        ts: chrono::Utc::now(),
                    })
                    .ok();
                // Schedule restart with longer delay
                self.schedule_restart(service, 1000);
            }
        }
        Ok(())
    }

    /// Schedule a service for restart after a delay
    fn schedule_restart(&mut self, service: &str, delay_ms: u64) {
        if let Some(tx) = self.workers.get(service) {
            // Send stop command immediately
            tx.send(Cmd::Stop).ok();

            // Schedule the restart
            let restart_time = Instant::now() + Duration::from_millis(delay_ms);
            let attempts = self
                .pending_restarts
                .get(service)
                .map_or(1, |s| s.attempts + 1);

            self.pending_restarts.insert(
                service.to_string(),
                RestartState {
                    stop_time: restart_time,
                    attempts,
                },
            );

            info!("Scheduled restart for {service} in {delay_ms}ms (attempt #{attempts})");
        }
    }

    /// Process pending restarts that are ready
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
            if let Some(state) = self.pending_restarts.remove(&service)
                && let Some(tx) = self.workers.get(&service)
            {
                info!("Restarting {} (attempt #{})", service, state.attempts);
                tx.send(Cmd::Start).ok();
                self.bus_tx
                    .send(Evt::State {
                        service: "manager".to_string(),
                        kind: "restarted-service",
                        ts: chrono::Utc::now(),
                        pid: Some(std::process::id()),
                    })
                    .ok();
            }
        }
    }
}

// Cheap, polling‑based Unix signal handling (lock‑free).
static RECEIVED_SIGNAL: std::sync::LazyLock<std::sync::atomic::AtomicUsize> =
    std::sync::LazyLock::new(|| std::sync::atomic::AtomicUsize::new(0));

pub fn install_signal_handlers() -> anyhow::Result<()> {
    use nix::sys::signal::{self, Signal};
    extern "C" fn handler(sig: i32) {
        RECEIVED_SIGNAL.store(sig as usize, std::sync::atomic::Ordering::SeqCst);
    }
    unsafe {
        signal::sigaction(
            Signal::SIGINT,
            &signal::SigAction::new(
                signal::SigHandler::Handler(handler),
                signal::SaFlags::empty(),
                signal::SigSet::empty(),
            ),
        )
        .map_err(|e| anyhow::anyhow!(
            "Failed to register SIGINT handler: {e}. Signal handling is required for daemon operation."
        ))?;
        signal::sigaction(
            Signal::SIGTERM,
            &signal::SigAction::new(
                signal::SigHandler::Handler(handler),
                signal::SaFlags::empty(),
                signal::SigSet::empty(),
            ),
        )
        .map_err(|e| anyhow::anyhow!(
            "Failed to register SIGTERM handler: {e}. Signal handling is required for daemon operation."
        ))?;
    }
    Ok(())
}

/// Non‑blocking check – returns Some(signal) once.
fn check_signals() -> Option<nix::sys::signal::Signal> {
    use std::sync::atomic::Ordering::AcqRel;

    use nix::sys::signal::Signal;
    let val = RECEIVED_SIGNAL.swap(0, AcqRel);
    if val == 0 {
        None
    } else {
        // Try to convert signal number - if it fails (which should never happen since we stored it),
        // log the error and return None to avoid crashing the daemon
        match Signal::try_from(val as i32) {
            Ok(sig) => Some(sig),
            Err(e) => {
                log::error!("BUG: Invalid signal number {val} from signal handler: {e}. This indicates a programming error.");
                None
            }
        }
    }
}
