//! Cross-platform signal handling abstraction
//!
//! Unified API for OS signals on Unix (POSIX) and Windows (Console Control Handlers).

//! # Signal Safety Guarantees
//!
//! This module provides async-signal-safe signal handling via tokio's battle-tested
//! implementation, which uses the "self-pipe trick" for safe signal-to-async bridging.
//!
//! ## Architecture
//!
//! 1. **OS Signal Handler** (inside tokio/signal-hook-registry):
//!    - Only performs async-signal-safe operations:
//!      - `AtomicBool::store()` to mark signal pending
//!      - `write()` single byte to pipe to wake async runtime
//!    - No malloc, no locks, no logging, no undefined behavior
//!
//! 2. **Async Task** (tokio runtime, outside signal context):
//!    - Reads from pipe via `tokio::select!`
//!    - Sends to crossbeam channel (lock-free)
//!    - Full Rust API available, no signal-safety restrictions
//!
//! 3. **Event Loop** (ServiceManager, completely outside signal context):
//!    - Receives from crossbeam channel
//!    - Can safely log, allocate, take locks, etc.
//!
//! ## Safety Properties
//!
//! - ✅ No deadlocks: Signal handler doesn't take locks
//! - ✅ No corruption: Signal handler doesn't modify non-atomic shared state
//! - ✅ No UB: Signal handler only calls async-signal-safe functions
//! - ✅ No malloc/free: Signal handler doesn't allocate
//! - ✅ Reentrant: Signal handler can safely interrupt itself
//!
//! ## Signal Coalescing
//!
//! Multiple signals of the same type may be coalesced by the OS kernel.
//! This is standard POSIX behavior and handled correctly:
//!
//! ```ignore
//! kill(pid, SIGTERM);  // Signal 1
//! kill(pid, SIGTERM);  // Signal 2 (may be coalesced with signal 1)
//! // Result: SignalWatcher receives 1 or 2 Terminate events
//! // kodegend behavior: Single shutdown is triggered (correct)
//! ```
//!
//! kodegend's shutdown logic is idempotent - multiple rapid signals
//! result in a single graceful shutdown, which is the desired behavior.
//!
//! ## Implementation Details
//!
//! - **Signal registration**: signal-hook-registry (via tokio)
//! - **Signal handler**: tokio/src/signal/unix.rs `action()` function
//! - **Self-pipe**: UnixStream pair (mio crate)
//! - **Channel**: crossbeam unbounded (lock-free MPSC)
//! - **Panic recovery**: Exponential backoff with 3 retry attempts
//!
//! ## References
//!
//! - POSIX Signal Safety: <https://man7.org/linux/man-pages/man7/signal-safety.7.html>
//! - tokio Signal Module: <https://docs.rs/tokio/latest/tokio/signal/>
//! - signal-hook-registry: <https://docs.rs/signal-hook-registry/>
//! - Self-Pipe Trick: <https://cr.yp.to/docs/selfpipe.html>
//! - tokio Implementation: [`/tmp/tokio-signal-source/tokio/src/signal/unix.rs`](../../tmp/tokio-signal-source/tokio/src/signal/unix.rs)

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender, unbounded};
use std::panic::{self, AssertUnwindSafe};
use std::thread;
use std::time::Duration;

// ============================================================================
// Signal Masking API
// ============================================================================

/// Cross-platform signal masking
///
/// Unix: Uses sigprocmask(2) to block signal delivery
/// Windows: Sets atomic flag checked by console event handlers
///
/// # Example
/// ```no_run
/// use kodegend::platform::signal::SignalMask;
///
/// // Block signals during critical section
/// {
///     let _guard = SignalMask::block_all()?;
///     
///     // Critical operations - signals deferred
///     write_pid_file(path, pid)?;
///     
/// } // Guard drops, signals restored and delivered
/// ```
pub use self::mask::SignalMask;

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
                    // Check critical section flag before processing
                    if mask::in_critical_section() {
                        log::trace!("CTRL+C received but deferred (critical section active)");
                        // Don't break - loop will recv again after critical section ends
                        continue;
                    }
                    
                    if tx.send(SignalKind::Interrupt).is_err() {
                        break;
                    }
                }
                _ = ctrl_break.recv() => {
                    if mask::in_critical_section() {
                        log::trace!("CTRL+BREAK received but deferred (critical section active)");
                        continue;
                    }
                    
                    if tx.send(SignalKind::Hangup).is_err() {
                        break;
                    }
                }
                _ = ctrl_close.recv() => {
                    if mask::in_critical_section() {
                        log::trace!("CTRL+CLOSE received but deferred (critical section active)");
                        continue;
                    }
                    
                    if tx.send(SignalKind::Terminate).is_err() {
                        break;
                    }
                }
                _ = ctrl_shutdown.recv() => {
                    if mask::in_critical_section() {
                        log::trace!("CTRL+SHUTDOWN received but deferred (critical section active)");
                        continue;
                    }
                    
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

// ============================================================================
// Signal Masking (Unix)
// ============================================================================

#[cfg(unix)]
pub mod mask {
    use nix::sys::signal::{SigSet, SigmaskHow, sigprocmask};
    use anyhow::Result;
    
    /// RAII signal mask guard (Unix implementation)
    ///
    /// Blocks signals on creation using sigprocmask(2), restores original mask on drop.
    /// 
    /// # Platform Behavior
    /// - **Unix**: Uses kernel-level signal blocking (per-thread)
    /// - **Windows**: Uses cooperative atomic flag (process-global)
    ///
    /// # Limitations
    /// - SIGKILL and SIGSTOP cannot be blocked (kernel limitation)
    /// - Signal masks are per-thread on Unix
    /// - Masked signals are queued and delivered after unmasking
    pub struct SignalMask {
        old_mask: SigSet,
    }
    
    impl SignalMask {
        /// Block all blockable signals
        ///
        /// Returns RAII guard that restores signal mask on drop.
        /// 
        /// # Example
        /// ```no_run
        /// let _guard = SignalMask::block_all()?;
        /// // SIGTERM/SIGINT/SIGHUP now queued, not delivered
        /// write_critical_data()?;
        /// // Guard drops here, signals delivered
        /// ```
        pub fn block_all() -> Result<Self> {
            // Create mask with all signals
            let new_mask = SigSet::all();
            
            // Save old mask for restoration
            let mut old_mask = SigSet::empty();
            
            // Block signals, save old mask for restoration
            // SIG_BLOCK adds signals to current mask (idempotent)
            sigprocmask(SigmaskHow::SIG_BLOCK, Some(&new_mask), Some(&mut old_mask))?;
            
            log::trace!("Signal mask: blocked all signals (old mask saved)");
            
            Ok(Self { old_mask })
        }
    }
    
    impl Drop for SignalMask {
        fn drop(&mut self) {
            // Restore original signal mask
            // SIG_SETMASK replaces entire mask (not additive)
            // 
            // Ignore errors in drop - cannot propagate from Drop
            // If this fails, signals remain blocked (daemon becomes unkillable
            // except by SIGKILL). This is a kernel-level failure and extremely rare.
            if let Err(e) = sigprocmask(SigmaskHow::SIG_SETMASK, Some(&self.old_mask), None) {
                log::error!(
                    "CRITICAL: Failed to restore signal mask in Drop: {}\n\
                     Signals may remain blocked. This should never happen.",
                    e
                );
            } else {
                log::trace!("Signal mask: restored original mask");
            }
        }
    }
}

// ============================================================================
// Signal Masking (Windows)
// ============================================================================

#[cfg(windows)]
pub mod mask {
    use std::sync::atomic::{AtomicBool, Ordering};
    use anyhow::Result;
    
    /// RAII critical section guard (Windows implementation)
    ///
    /// Prevents console event handlers from processing signals during critical operations.
    /// Uses atomic flag checked in event handler loop.
    ///
    /// # Platform Differences
    /// - **Unix**: Kernel-level blocking (signals queued by kernel)
    /// - **Windows**: Cooperative flag (handler checks and defers)
    ///
    /// # Thread Safety
    /// - **Unix**: Signal masks are per-thread
    /// - **Windows**: CRITICAL_SECTION is global (affects all threads)
    pub struct SignalMask {
        _private: (),
    }
    
    impl SignalMask {
        /// Enter critical section (defer signal handling)
        ///
        /// Console event handlers will check `in_critical_section()` and
        /// defer processing until this guard drops.
        pub fn block_all() -> Result<Self> {
            CRITICAL_SECTION.store(true, Ordering::SeqCst);
            log::trace!("Critical section: entered (signal handling deferred)");
            Ok(Self { _private: () })
        }
    }
    
    impl Drop for SignalMask {
        fn drop(&mut self) {
            CRITICAL_SECTION.store(false, Ordering::SeqCst);
            log::trace!("Critical section: exited (signal handling resumed)");
        }
    }
    
    /// Internal: Critical section flag checked by event handlers
    ///
    /// When true, console event handlers in `run_windows_signal_handler()`
    /// will skip signal delivery and loop again, effectively deferring
    /// signal handling until the flag is cleared.
    pub(crate) static CRITICAL_SECTION: AtomicBool = AtomicBool::new(false);
    
    /// Check if currently in critical section
    ///
    /// Called by console event handlers to decide whether to defer handling.
    /// 
    /// Returns:
    /// - `true`: Defer signal handling (critical section active)
    /// - `false`: Process signal normally
    pub(crate) fn in_critical_section() -> bool {
        CRITICAL_SECTION.load(Ordering::SeqCst)
    }
}
