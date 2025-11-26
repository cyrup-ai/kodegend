//! Cross-platform signal handling abstraction
//!
//! Unified API for OS signals on Unix (POSIX) and Windows (Console Control Handlers).

use anyhow::{Result, Context};
use crossbeam_channel::{Sender, Receiver, bounded};
use std::thread;

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
        self.rx.as_ref().expect("SignalWatcher receiver already taken")
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
    let (tx, rx) = bounded::<SignalKind>(16);
    
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

#[cfg(unix)]
fn spawn_unix_watcher(tx: Sender<SignalKind>) -> Result<std::thread::JoinHandle<()>> {
    let handle = thread::Builder::new()
        .name("signal-watcher-unix".to_string())
        .spawn(move || {
            // Create tokio runtime for signal handling
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("Failed to create tokio runtime for signal handling: {}", e);
                    return;
                }
            };
            
            rt.block_on(async {
                use tokio::signal::unix::{signal, SignalKind as TokioSignalKind};
                
                let mut sigterm = match signal(TokioSignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to install SIGTERM handler: {}", e);
                        return;
                    }
                };
                
                let mut sigint = match signal(TokioSignalKind::interrupt()) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to install SIGINT handler: {}", e);
                        return;
                    }
                };
                
                let mut sighup = match signal(TokioSignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to install SIGHUP handler: {}", e);
                        return;
                    }
                };
                
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
        })
        .context("Failed to spawn Unix signal watcher thread")?;
    
    Ok(handle)
}

// ============================================================================
// Windows Implementation  
// ============================================================================

#[cfg(windows)]
fn spawn_windows_watcher(tx: Sender<SignalKind>) -> Result<std::thread::JoinHandle<()>> {
    let handle = thread::Builder::new()
        .name("signal-watcher-windows".to_string())
        .spawn(move || {
            // Create tokio runtime for signal handling
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("Failed to create tokio runtime for signal handling: {}", e);
                    return;
                }
            };
            
            rt.block_on(async {
                use tokio::signal::windows;
                
                let mut ctrl_c = match windows::ctrl_c() {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to install CTRL+C handler: {}", e);
                        return;
                    }
                };
                
                let mut ctrl_break = match windows::ctrl_break() {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to install CTRL+BREAK handler: {}", e);
                        return;
                    }
                };
                
                let mut ctrl_close = match windows::ctrl_close() {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to install CTRL+CLOSE handler: {}", e);
                        return;
                    }
                };
                
                let mut ctrl_shutdown = match windows::ctrl_shutdown() {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to install CTRL+SHUTDOWN handler: {}", e);
                        return;
                    }
                };
                
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
        })
        .context("Failed to spawn Windows signal watcher thread")?;
    
    Ok(handle)
}
