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

/// Start platform-specific signal watchers and return channel receiving signals
///
/// Spawns background thread that listens for OS signals and forwards them
/// to the returned channel. Non-blocking.
pub fn watch_signals() -> Result<Receiver<SignalKind>> {
    let (tx, rx) = bounded::<SignalKind>(16);
    
    #[cfg(unix)]
    spawn_unix_watcher(tx)?;
    
    #[cfg(windows)]
    spawn_windows_watcher(tx)?;
    
    Ok(rx)
}

// ============================================================================
// Unix Implementation
// ============================================================================

#[cfg(unix)]
fn spawn_unix_watcher(tx: Sender<SignalKind>) -> Result<()> {
    thread::Builder::new()
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
    
    Ok(())
}

// ============================================================================
// Windows Implementation  
// ============================================================================

#[cfg(windows)]
fn spawn_windows_watcher(tx: Sender<SignalKind>) -> Result<()> {
    thread::Builder::new()
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
    
    Ok(())
}
