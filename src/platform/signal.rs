//! Cross-platform signal handling abstraction
//!
//! Unified API for OS signals on Unix (POSIX) and Windows (Console Control Handlers).

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender, unbounded};
use std::panic::{self, AssertUnwindSafe};
use std::thread;
use std::time::Duration;

/// Signal types recognized across platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    /// Termination request (SIGTERM on Unix, CTRL+CLOSE on Windows)
    Terminate,

    /// Interrupt signal (SIGINT/CTRL+C on both platforms)
    Interrupt,

    /// Hangup signal (SIGHUP on Unix, CTRL+BREAK on Windows)
    /// Used for configuration reload
    Hangup,

    /// Shutdown signal (Windows CTRL+SHUTDOWN only, never fires on Unix)
    #[allow(dead_code)]
    Shutdown,
}

/// Cross-platform signal watcher with automatic thread cleanup
///
/// Spawns a background thread to monitor OS signals and forwards them
/// to a crossbeam channel. The thread is automatically joined when
/// the watcher is dropped, providing proper RAII resource management.
///
/// # Example
/// ```
/// let watcher = watch_signals()?;
///
/// loop {
///     select! {
///         recv(watcher.receiver()) -> sig => {
///             match sig? {
///                 SignalKind::Terminate => break,
///                 // ... handle other signals
///             }
///         }
///     }
/// }
/// // watcher.drop() automatically joins thread here
/// ```
pub struct SignalWatcher {
    rx: Option<Receiver<SignalKind>>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl SignalWatcher {
    /// Get a reference to the signal receiver channel
    ///
    /// Use this with crossbeam's select! macro to receive signals
    /// in the daemon's main event loop.
    pub fn receiver(&self) -> &Receiver<SignalKind> {
        match self.rx.as_ref() {
            Some(rx) => rx,
            None => {
                // This should never happen - receiver is only None after Drop starts
                // If this panics, there's a logic error in the signal watcher usage
                panic!("SignalWatcher receiver accessed after Drop began");
            }
        }
    }
}

impl Drop for SignalWatcher {
    /// Automatically clean up signal watcher thread on drop
    ///
    /// This runs during:
    /// - Normal function return
    /// - Early return (?)  
    /// - Panic unwinding
    ///
    /// Does NOT run during:
    /// - SIGKILL (kill -9) - immediate termination
    /// - Process::abort() - immediate termination
    /// - std::process::exit() - bypasses destructors
    fn drop(&mut self) {
        // Step 1: Drop the receiver, which closes the channel
        // This signals the thread to exit (it checks tx.send().is_err())
        if let Some(rx) = self.rx.take() {
            drop(rx);
        }

        // Step 2: Join the thread and wait for it to finish
        if let Some(handle) = self.thread_handle.take() {
            match handle.join() {
                Ok(()) => {
                    log::info!("Signal watcher thread exited cleanly");
                }
                Err(e) => {
                    // Thread panicked - log but don't panic in Drop
                    // Following the pattern from daemon.rs PidFile (line 189)
                    log::error!("Signal watcher thread panicked: {:?}", e);
                }
            }
        }
    }
}

/// Start platform-specific signal watchers and return watcher with cleanup
///
/// Spawns background thread that listens for OS signals and forwards them
/// to the returned channel. The thread is automatically joined when the
/// SignalWatcher is dropped, providing proper RAII cleanup.
///
/// # Example
/// ```
/// let watcher = watch_signals()?;
///
/// loop {
///     select! {
///         recv(watcher.receiver()) -> sig => {
///             // Handle signals
///         }
///     }
/// }
/// ```
pub fn watch_signals() -> Result<SignalWatcher> {
    let (tx, rx) = unbounded::<SignalKind>();

    #[cfg(unix)]
    let handle = spawn_unix_watcher(tx)?;

    #[cfg(windows)]
    let handle = spawn_windows_watcher(tx)?;

    Ok(SignalWatcher {
        rx: Some(rx),
        thread_handle: Some(handle),
    })
}

// ============================================================================
// Unix Implementation
// ============================================================================

/// Internal: Run Unix signal handler loop (can panic - caller must handle)
#[cfg(unix)]
fn run_unix_signal_handler(tx: Sender<SignalKind>) {
    // Create tokio runtime for signal handling
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime for signal handling");

    rt.block_on(async {
        use tokio::signal::unix::{SignalKind as TokioSignalKind, signal};

        let mut sigterm =
            signal(TokioSignalKind::terminate()).expect("Failed to install SIGTERM handler");

        let mut sigint =
            signal(TokioSignalKind::interrupt()).expect("Failed to install SIGINT handler");

        let mut sighup =
            signal(TokioSignalKind::hangup()).expect("Failed to install SIGHUP handler");

        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    if tx.send(SignalKind::Terminate).is_err() {
                        break; // Channel closed
                    }
                }
                _ = sigint.recv() => {
                    if tx.send(SignalKind::Interrupt).is_err() {
                        break;
                    }
                }
                _ = sighup.recv() => {
                    if tx.send(SignalKind::Hangup).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(unix)]
fn spawn_unix_watcher(tx: Sender<SignalKind>) -> Result<std::thread::JoinHandle<()>> {
    let handle = thread::Builder::new()
        .name("signal-watcher-unix".to_string())
        .spawn(move || {
            const MAX_RESTARTS: u32 = 3;
            let mut restart_count = 0;
            
            loop {
                let tx_clone = tx.clone();
                
                // Wrap signal handler in panic catcher
                // AssertUnwindSafe is required because Sender is not UnwindSafe
                // This is safe because we're restarting the entire handler on panic
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    run_unix_signal_handler(tx_clone);
                }));
                
                match result {
                    Ok(()) => {
                        // Normal exit - signal handler loop terminated cleanly
                        log::info!("Signal watcher exiting normally");
                        break;
                    }
                    Err(panic_payload) => {
                        restart_count += 1;
                        
                        // Extract panic message using pattern from kodegen-mcp-tool/src/tool.rs:69-77
                        let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "Unknown panic (no message)".to_string()
                        };
                        
                        log::error!(
                            "CRITICAL: Signal watcher thread panicked (attempt {}/{}): {}",
                            restart_count,
                            MAX_RESTARTS,
                            panic_msg
                        );
                        
                        // Check if we've exhausted retries
                        if restart_count >= MAX_RESTARTS {
                            log::error!(
                                "Signal watcher failed {} times, giving up. \
                                 Daemon will not respond to SIGTERM/SIGINT and must be killed with SIGKILL.",
                                MAX_RESTARTS
                            );
                            break;
                        }
                        
                        // Exponential backoff: attempt 1 = 1s, attempt 2 = 2s, attempt 3 = 4s
                        // Pattern from kodegen-bundler-release and kodegend/src/service/port_cleanup.rs:298-301
                        let delay_secs = 1u64 << (restart_count - 1); // 2^(n-1) where n starts at 1
                        log::info!(
                            "Restarting signal watcher in {}s (attempt {}/{})",
                            delay_secs,
                            restart_count + 1,
                            MAX_RESTARTS
                        );
                        
                        thread::sleep(Duration::from_secs(delay_secs));
                    }
                }
            }
        })
        .context("Failed to spawn Unix signal watcher thread")?;

    Ok(handle)
}

// ============================================================================
// Windows Implementation
// ============================================================================

/// Internal: Run Windows signal handler loop (can panic - caller must handle)
#[cfg(windows)]
fn run_windows_signal_handler(tx: Sender<SignalKind>) {
    // Create tokio runtime for signal handling
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime for signal handling");

    rt.block_on(async {
        use tokio::signal::windows;

        let mut ctrl_c = windows::ctrl_c().expect("Failed to install CTRL+C handler");

        let mut ctrl_break = windows::ctrl_break().expect("Failed to install CTRL+BREAK handler");

        let mut ctrl_close = windows::ctrl_close().expect("Failed to install CTRL+CLOSE handler");

        let mut ctrl_shutdown =
            windows::ctrl_shutdown().expect("Failed to install CTRL+SHUTDOWN handler");

        loop {
            tokio::select! {
                _ = ctrl_c.recv() => {
                    if tx.send(SignalKind::Interrupt).is_err() {
                        break;
                    }
                }
                _ = ctrl_break.recv() => {
                    if tx.send(SignalKind::Hangup).is_err() {
                        break;
                    }
                }
                _ = ctrl_close.recv() => {
                    if tx.send(SignalKind::Terminate).is_err() {
                        break;
                    }
                }
                _ = ctrl_shutdown.recv() => {
                    if tx.send(SignalKind::Shutdown).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(windows)]
fn spawn_windows_watcher(tx: Sender<SignalKind>) -> Result<std::thread::JoinHandle<()>> {
    let handle = thread::Builder::new()
        .name("signal-watcher-windows".to_string())
        .spawn(move || {
            const MAX_RESTARTS: u32 = 3;
            let mut restart_count = 0;
            
            loop {
                let tx_clone = tx.clone();
                
                // Wrap signal handler in panic catcher
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    run_windows_signal_handler(tx_clone);
                }));
                
                match result {
                    Ok(()) => {
                        // Normal exit
                        log::info!("Signal watcher exiting normally");
                        break;
                    }
                    Err(panic_payload) => {
                        restart_count += 1;
                        
                        // Extract panic message
                        let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "Unknown panic (no message)".to_string()
                        };
                        
                        log::error!(
                            "CRITICAL: Signal watcher thread panicked (attempt {}/{}): {}",
                            restart_count,
                            MAX_RESTARTS,
                            panic_msg
                        );
                        
                        if restart_count >= MAX_RESTARTS {
                            log::error!(
                                "Signal watcher failed {} times, giving up. \
                                 Daemon will not respond to CTRL+C/CTRL+BREAK and must be terminated.",
                                MAX_RESTARTS
                            );
                            break;
                        }
                        
                        // Exponential backoff
                        let delay_secs = 1u64 << (restart_count - 1);
                        log::info!(
                            "Restarting signal watcher in {}s (attempt {}/{})",
                            delay_secs,
                            restart_count + 1,
                            MAX_RESTARTS
                        );
                        
                        thread::sleep(Duration::from_secs(delay_secs));
                    }
                }
            }
        })
        .context("Failed to spawn Windows signal watcher thread")?;

    Ok(handle)
}
