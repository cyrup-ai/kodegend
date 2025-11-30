use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use kodegen_bundler_autoconfig::{clients::all_clients, watcher::AutoConfigWatcher};
use log::{error, info};
use scopeguard::defer;
use tokio_util::sync::CancellationToken;

use crate::config::ServiceDefinition;
use crate::ipc::{Cmd, Evt, ServiceState};

/// Auto-configuration service that watches for MCP client installations
pub struct AutoConfigService {
    name: Arc<str>,
    bus: Sender<Evt>,
}

impl AutoConfigService {
    pub fn new(def: ServiceDefinition, bus: Sender<Evt>) -> Self {
        Self {
            name: Arc::from(def.name.as_str()),
            bus,
        }
    }

    pub fn run(self, cmd_rx: Receiver<Cmd>) -> Result<()> {
        info!("🍯 Starting MCP client auto-configuration service");

        // Create tokio runtime for the watcher
        let rt = tokio::runtime::Runtime::new()?;

        // Create cancellation token for graceful shutdown
        let cancel_token = CancellationToken::new();

        // Create shutdown completion flag for lock-free coordination
        let shutdown_complete = Arc::new(AtomicBool::new(false));

        // Create the watcher with all client plugins
        let clients = all_clients();
        let watcher = AutoConfigWatcher::new(clients)?;

        // Spawn the watcher task with graceful cancellation
        let watcher_handle = rt.spawn({
            let bus = self.bus.clone();
            let service_name = Arc::clone(&self.name);
            let cancel_token = cancel_token.clone();
            let shutdown_complete = Arc::clone(&shutdown_complete);

            async move {
                // Notify daemon we're starting
                let _ = bus.send(Evt::State {
                    service: Arc::clone(&service_name),
                    state: ServiceState::Running,
                    ts: chrono::Utc::now(),
                    pid: Some(std::process::id()),
                    correlation_id: None,
                });

                // Run watcher with cancellation support
                tokio::select! {
                    result = watcher.run() => {
                        if let Err(e) = result {
                            error!("Auto-config watcher failed: {e}");
                            let _ = bus.send(Evt::Fatal {
                                service: Arc::clone(&service_name),
                                msg: format!("Auto-config watcher failed: {}", e).into(),
                                ts: chrono::Utc::now(),
                            });
                        }
                    }
                    () = cancel_token.cancelled() => {
                        info!("Auto-config watcher cancelled gracefully");
                        let _ = bus.send(Evt::State {
                            service: Arc::clone(&service_name),
                            state: ServiceState::StoppedClean,
                            ts: chrono::Utc::now(),
                            pid: Some(std::process::id()),
                            correlation_id: None,
                        });
                    }
                }
                
                // Signal shutdown completion
                shutdown_complete.store(true, Ordering::Release);
            }
        });

        // CLEANUP GUARD: Ensures cleanup happens on ALL exit paths
        // This defer block runs when run() exits, regardless of how:
        // - Normal shutdown (Cmd::Stop/Shutdown breaks loop)
        // - Channel error (cmd_rx.recv() returns Err)
        // - Panic in command loop
        defer! {
            // Only cleanup if task hasn't already shut down gracefully
            if !shutdown_complete.load(Ordering::Acquire) {
                // Attempt graceful cancellation first
                cancel_token.cancel();
                
                // Wait briefly for graceful shutdown with exponential backoff
                let timeout = std::time::Duration::from_secs(5);
                let start = std::time::Instant::now();
                let mut backoff_ms = 1;
                
                while !shutdown_complete.load(Ordering::Acquire) && start.elapsed() < timeout {
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    backoff_ms = (backoff_ms * 2).min(100);  // Cap at 100ms
                }
                
                // Force abort if still running after timeout
                if !shutdown_complete.load(Ordering::Acquire) {
                    info!("Cleanup guard: Graceful shutdown timeout, aborting task");
                    watcher_handle.abort();
                }
            }
            
            // CRITICAL: Always wait for task to fully complete
            // This ensures the tokio runtime can shut down cleanly
            let _ = rt.block_on(watcher_handle);
        }

        // Handle control commands with lock-free coordination
        loop {
            match cmd_rx.recv()? {
                Cmd::Start { correlation_id: _ } => {
                    info!("Auto-config service already started");
                }
                Cmd::Stop { correlation_id: _ } => {
                    info!("Stopping auto-config service");
                    // Trigger graceful shutdown via helper
                    // Final cleanup is guaranteed by defer! guard above
                    let _did_abort = perform_graceful_shutdown(&cancel_token, &watcher_handle, &shutdown_complete);
                    break;
                }
                Cmd::Shutdown => {
                    info!("Shutting down auto-config service");
                    // Trigger graceful shutdown via helper
                    // Final cleanup is guaranteed by defer! guard above
                    let _did_abort = perform_graceful_shutdown(&cancel_token, &watcher_handle, &shutdown_complete);
                    break;
                }
                _ => {}
            }
        }

        Ok(())
    }
}

/// Performs graceful shutdown with exponential backoff and timeout
///
/// Cancels the watcher task, then waits up to 5 seconds for clean shutdown.
/// Uses exponential backoff (1ms → 2ms → 4ms → ... → 100ms) to avoid busy-waiting.
/// If timeout expires, forcefully aborts the task.
///
/// Returns `true` if the task was aborted due to timeout, `false` otherwise.
fn perform_graceful_shutdown(
    cancel_token: &CancellationToken,
    watcher_handle: &tokio::task::JoinHandle<()>,
    shutdown_complete: &Arc<AtomicBool>,
) -> bool {
    // Trigger graceful cancellation
    cancel_token.cancel();

    // Wait for shutdown completion with timeout
    let shutdown_timeout = std::time::Duration::from_secs(5);
    let start_time = std::time::Instant::now();

    // Spin-wait with exponential backoff for shutdown completion
    let mut backoff_ms = 1;
    let mut did_abort = false;
    while !shutdown_complete.load(Ordering::Acquire) {
        if start_time.elapsed() > shutdown_timeout {
            info!("Graceful shutdown timeout, aborting task");
            watcher_handle.abort();
            did_abort = true;
            break;
        }

        // Lock-free backoff using thread sleep
        std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
        backoff_ms = (backoff_ms * 2).min(100); // Cap at 100ms
    }
    
    did_abort
}

/// Spawn the auto-configuration service thread
pub fn spawn_autoconfig(
    def: ServiceDefinition,
    bus: Sender<Evt>,
) -> Result<Sender<Cmd>, crate::service::ServiceError> {
    let (cmd_tx, cmd_rx) = crossbeam_channel::bounded(16);
    let service_name = def.name.clone();

    thread::Builder::new()
        .name(format!("svc-autoconfig-{service_name}"))
        .spawn(move || {
            let service = AutoConfigService::new(def, bus);
            if let Err(e) = service.run(cmd_rx) {
                error!("Auto-config service error: {e}");
            }
        })
        .map_err(|source| crate::service::ServiceError::SpawnFailed {
            service: service_name,
            source,
        })?;

    Ok(cmd_tx)
}
