//! macOS Internal Watchdog for Service Health Monitoring
//!
//! Since macOS launchd does not support native watchdog functionality like Linux systemd's
//! WatchdogSec, this module implements an internal self-monitoring watchdog thread.
//!
//! ## Architecture
//!
//! - Main thread updates a shared `Instant` timestamp on each event loop iteration
//! - Watchdog thread checks timestamp every 15 seconds (WatchdogSec/2)
//! - If timestamp is stale (>30s), watchdog calls `std::process::exit(1)`
//! - launchd automatically restarts the service via KeepAlive
//!
//! ## Limitations
//!
//! This approach cannot detect full process deadlock where both the main thread
//! and watchdog thread are hung. For maximum reliability, consider implementing
//! an external watchdog process (see task documentation).
//!
//! ## Graceful Shutdown
//!
//! The watchdog thread monitors an `AtomicBool` shutdown flag and terminates
//! cleanly when signaled, preventing false positives during service shutdown.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Watchdog configuration constants matching Linux systemd WatchdogSec=30s
const WATCHDOG_CHECK_INTERVAL: Duration = Duration::from_secs(15); // WatchdogSec/2
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(30); // Matches systemd WatchdogSec

/// Handle to the watchdog thread with graceful shutdown support
///
/// Manages the lifecycle of the watchdog monitoring thread, providing
/// methods to update heartbeat timestamps and trigger graceful shutdown.
///
/// # Example
///
/// ```no_run
/// use kodegend::platform::macos_watchdog::WatchdogHandle;
///
/// // Spawn watchdog thread
/// let watchdog = WatchdogHandle::spawn();
///
/// // In main event loop
/// loop {
///     // ... do work ...
///     watchdog.update_heartbeat();
/// }
///
/// // On shutdown
/// watchdog.shutdown();
/// ```
pub struct WatchdogHandle {
    /// Shared timestamp of last heartbeat update
    heartbeat: Arc<Mutex<Instant>>,
    
    /// Shutdown signal for graceful termination
    shutdown: Arc<AtomicBool>,
    
    /// Join handle for the watchdog thread
    thread_handle: Option<JoinHandle<()>>,
}

impl WatchdogHandle {
    /// Spawn a new watchdog monitoring thread
    ///
    /// The watchdog thread will check the heartbeat timestamp every 15 seconds
    /// and call `std::process::exit(1)` if no heartbeat has been received for 30 seconds.
    ///
    /// # Returns
    ///
    /// A `WatchdogHandle` that can be used to update the heartbeat and shutdown the watchdog.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let watchdog = WatchdogHandle::spawn();
    /// ```
    pub fn spawn() -> Self {
        let heartbeat = Arc::new(Mutex::new(Instant::now()));
        let shutdown = Arc::new(AtomicBool::new(false));
        
        let heartbeat_clone = Arc::clone(&heartbeat);
        let shutdown_clone = Arc::clone(&shutdown);
        
        let thread_handle = thread::spawn(move || {
            watchdog_thread_loop(heartbeat_clone, shutdown_clone);
        });
        
        log::info!(
            "macOS watchdog started: check_interval={}s, timeout={}s",
            WATCHDOG_CHECK_INTERVAL.as_secs(),
            WATCHDOG_TIMEOUT.as_secs()
        );
        
        Self {
            heartbeat,
            shutdown,
            thread_handle: Some(thread_handle),
        }
    }
    
    /// Update the heartbeat timestamp to indicate the service is healthy
    ///
    /// This should be called periodically (at least once every 30 seconds) from
    /// the main event loop to prevent watchdog timeout.
    ///
    /// # Error Handling
    ///
    /// If the mutex is poisoned (another thread panicked while holding it),
    /// this logs a warning but does not propagate the error. The watchdog
    /// thread will eventually timeout and restart the service.
    pub fn update_heartbeat(&self) {
        match self.heartbeat.lock() {
            Ok(mut guard) => {
                *guard = Instant::now();
                log::trace!("macOS watchdog: heartbeat updated");
            }
            Err(e) => {
                log::warn!(
                    "macOS watchdog: failed to update heartbeat (mutex poisoned): {}",
                    e
                );
                // Don't panic - let watchdog timeout handle this
            }
        }
    }
    
    /// Signal the watchdog thread to shutdown gracefully and wait for it to terminate
    ///
    /// This method should be called during service shutdown to prevent false
    /// positive watchdog timeouts while the service is stopping.
    ///
    /// # Blocking
    ///
    /// This method blocks until the watchdog thread has fully terminated
    /// (up to the next check interval, max 15 seconds).
    pub fn shutdown(mut self) {
        // Signal shutdown
        self.shutdown.store(true, Ordering::Relaxed);
        log::debug!("macOS watchdog: shutdown signal sent");
        
        // Wait for thread to terminate
        if let Some(handle) = self.thread_handle.take() {
            match handle.join() {
                Ok(()) => {
                    log::info!("macOS watchdog: thread terminated gracefully");
                }
                Err(e) => {
                    log::error!(
                        "macOS watchdog: thread panicked during shutdown: {:?}",
                        e
                    );
                }
            }
        }
    }
}

impl Drop for WatchdogHandle {
    fn drop(&mut self) {
        // Ensure shutdown is signaled if not already done
        self.shutdown.store(true, Ordering::Relaxed);
        
        // Don't block in Drop - just signal and let thread terminate naturally
        if self.thread_handle.is_some() {
            log::debug!("macOS watchdog: handle dropped, thread will terminate on next check");
        }
    }
}

/// Watchdog thread main loop
///
/// Monitors heartbeat timestamp and triggers service restart on timeout.
/// This function runs in a background thread and should never return normally.
///
/// # Arguments
///
/// * `heartbeat` - Shared timestamp of last heartbeat update
/// * `shutdown` - Atomic flag to signal graceful shutdown
fn watchdog_thread_loop(heartbeat: Arc<Mutex<Instant>>, shutdown: Arc<AtomicBool>) {
    log::debug!("macOS watchdog thread started");
    
    loop {
        // Sleep for check interval
        thread::sleep(WATCHDOG_CHECK_INTERVAL);
        
        // Check shutdown flag first
        if shutdown.load(Ordering::Relaxed) {
            log::debug!("macOS watchdog: shutdown flag detected, terminating");
            break;
        }
        
        // Check heartbeat timestamp
        match heartbeat.lock() {
            Ok(guard) => {
                let last_heartbeat = *guard;
                let elapsed = last_heartbeat.elapsed();
                
                if elapsed > WATCHDOG_TIMEOUT {
                    // Watchdog timeout - service is hung
                    log::error!(
                        "macOS watchdog TIMEOUT: no heartbeat for {:?} (threshold: {:?})",
                        elapsed,
                        WATCHDOG_TIMEOUT
                    );
                    log::error!("macOS watchdog: forcing service restart via exit(1)");
                    log::error!("macOS watchdog: launchd will automatically restart service");
                    
                    // Exit to trigger launchd restart
                    std::process::exit(1);
                } else {
                    log::trace!(
                        "macOS watchdog: heartbeat OK, last seen {:?} ago",
                        elapsed
                    );
                }
            }
            Err(e) => {
                // Mutex is poisoned - another thread panicked
                log::error!(
                    "macOS watchdog: heartbeat mutex poisoned: {}",
                    e
                );
                log::error!("macOS watchdog: cannot verify service health, forcing restart");
                
                // Treat poisoned mutex as a fatal error
                std::process::exit(1);
            }
        }
    }
    
    log::debug!("macOS watchdog thread terminated");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    
    #[test]
    fn test_watchdog_handle_creation() {
        let watchdog = WatchdogHandle::spawn();
        
        // Update heartbeat a few times
        for _ in 0..5 {
            watchdog.update_heartbeat();
            thread::sleep(Duration::from_millis(100));
        }
        
        // Graceful shutdown
        watchdog.shutdown();
    }
    
    #[test]
    fn test_watchdog_heartbeat_update() {
        let watchdog = WatchdogHandle::spawn();
        
        // Verify heartbeat can be updated without panic
        watchdog.update_heartbeat();
        thread::sleep(Duration::from_millis(50));
        watchdog.update_heartbeat();
        
        watchdog.shutdown();
    }
    
    // Note: Cannot test actual timeout behavior in unit tests
    // as it would call std::process::exit(1) and terminate the test process
}
