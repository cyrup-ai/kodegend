//! macOS privilege escalation using native Authorization Services API.
//!
//! This module uses the `security-framework` crate to access macOS Authorization Services,
//! providing native authentication dialogs (password + Touch ID) without requiring osascript.
//!
//! # Threading Model
//!
//! Authorization Services requires execution context with window server access.
//! The main thread has this context; background threads do not.
//! We use GCD's `Queue::main().exec_sync()` to dispatch to the main thread.
//!
//! # Main Thread Storage Pattern
//!
//! Because `Authorization` contains raw pointers (not `Send`), we cannot return it
//! from `exec_sync` or store it in structures used across threads. Instead:
//! 1. Authorization is created on the main thread via GCD dispatch
//! 2. It's stored in a static that's ONLY accessed from the main thread
//! 3. `MacosAuthHandle` is a marker type - the worker thread uses it to coordinate
//!    but the actual Authorization lives on the main thread
//!
//! # Safety
//!
//! The static `MAIN_THREAD_AUTH` uses `UnsafeCell` because:
//! - It's only accessed from the main thread (via GCD dispatch)
//! - GCD serializes all operations on the main queue
//! - This is safe because we guarantee single-threaded access through GCD
//!
//! # References
//! - security-framework/src/authorization.rs:517-537 (execute_with_privileges)
//! - security-framework-sys/src/authorization.rs:7-22 (error codes)
//! - dispatch/src/queue.rs:82-88 (Queue::main)
//! - dispatch/src/queue.rs:135-153 (exec_sync)

use dispatch::Queue;
use security_framework::authorization::{Authorization, AuthorizationItemSetBuilder, Flags};
use std::cell::UnsafeCell;
use std::io::{BufRead, BufReader};
use std::ptr;

// ============================================================================
// Main Thread Authorization Storage
// ============================================================================

/// Global storage for Authorization - ONLY accessed from main thread via GCD.
///
/// # Safety
///
/// This is safe because:
/// 1. All access is via `Queue::main().exec_sync()` which serializes access
/// 2. The main thread is the only thread that ever reads/writes this
/// 3. We never access it from any other thread
static MAIN_THREAD_AUTH: MainThreadAuth = MainThreadAuth::new();

/// Wrapper for Authorization storage that's only accessed from main thread.
struct MainThreadAuth {
    /// Raw pointer to Authorization - null if not initialized
    auth: UnsafeCell<*mut Authorization>,
}

impl MainThreadAuth {
    const fn new() -> Self {
        Self {
            auth: UnsafeCell::new(ptr::null_mut()),
        }
    }

    /// Initialize the Authorization (called from main thread via GCD).
    ///
    /// # Safety
    /// Must only be called from main thread via GCD dispatch.
    unsafe fn initialize(&self) -> Result<(), AuthorizationError> {
        let ptr = self.auth.get();
        // Safety: ptr is valid because it comes from UnsafeCell::get() on a static
        if unsafe { !(*ptr).is_null() } {
            // Already initialized
            return Ok(());
        }

        let rights = AuthorizationItemSetBuilder::new()
            .add_right("system.privilege.admin")
            .map_err(|e| AuthorizationError::BuildRights(e.to_string()))?
            .build();

        log::info!("Creating Authorization with INTERACTION_ALLOWED | EXTEND_RIGHTS | PREAUTHORIZE");
        let auth = Authorization::new(
            Some(rights),
            None,
            Flags::INTERACTION_ALLOWED | Flags::EXTEND_RIGHTS | Flags::PREAUTHORIZE,
        )
        .map_err(|e| {
            let code = e.code();
            log::error!("Authorization::new failed with code {}: {}", code, e);
            match code {
                -60006 => AuthorizationError::Cancelled,
                -60005 => AuthorizationError::Denied,
                -60007 => AuthorizationError::NoInteraction,
                _ => AuthorizationError::Failed {
                    code,
                    message: e.to_string(),
                },
            }
        })?;

        // Store in static (Box::into_raw gives us ownership of the heap allocation)
        // Safety: ptr is valid and we're the only thread accessing this (via GCD main queue)
        unsafe { *ptr = Box::into_raw(Box::new(auth)) };
        Ok(())
    }

    /// Get a reference to the Authorization (called from main thread via GCD).
    ///
    /// # Safety
    /// Must only be called from main thread via GCD dispatch.
    /// Must only be called after `initialize()` succeeded.
    unsafe fn get(&self) -> &Authorization {
        // Safety: We're on the main thread (via GCD) and initialize() has been called
        let ptr = unsafe { *self.auth.get() };
        debug_assert!(!ptr.is_null(), "Authorization not initialized");
        // Safety: ptr is valid because initialize() stored it
        unsafe { &*ptr }
    }
}

// Safety: MainThreadAuth is Sync because all actual access is serialized via GCD main queue.
// The raw pointer is never accessed from multiple threads simultaneously.
unsafe impl Sync for MainThreadAuth {}

// ============================================================================
// MacosAuthHandle - Worker Thread Marker
// ============================================================================

/// macOS Authorization handle for the worker thread.
///
/// This is a marker type - the actual `Authorization` lives on the main thread
/// in `MAIN_THREAD_AUTH`. The worker thread uses this handle to coordinate
/// operations via GCD dispatch.
///
/// # Usage
///
/// ```rust,ignore
/// // In worker thread:
/// let auth = MacosAuthHandle::new()?;  // ONE auth dialog
/// auth.exec("mkdir -p /usr/local/bin")?;  // No new dialog
/// auth.exec("cp binary /usr/local/bin/")?;  // No new dialog
/// ```
pub struct MacosAuthHandle {
    // Marker field - prevents construction outside this module
    _private: (),
}

impl MacosAuthHandle {
    /// Create a new Authorization handle (triggers auth dialog ONCE).
    ///
    /// MUST be called from the worker thread, NOT the main thread.
    /// The actual Authorization creation is dispatched to the main queue
    /// via GCD for window server context.
    ///
    /// # Returns
    /// * `Ok(MacosAuthHandle)` - Ready to execute privileged commands
    /// * `Err(AuthorizationError)` - Authorization failed
    pub fn new() -> Result<Self, AuthorizationError> {
        // Safety: Calling from main thread would deadlock (exec_sync to same queue)
        debug_assert!(
            !is_main_thread(),
            "MacosAuthHandle::new called from main thread - would deadlock!"
        );

        log::info!("MacosAuthHandle: Creating Authorization via GCD dispatch to main queue");

        // Dispatch to main queue for window server context
        let result: Result<(), AuthorizationError> = Queue::main().exec_sync(|| {
            // Safety: We're on the main thread (via GCD dispatch)
            unsafe { MAIN_THREAD_AUTH.initialize() }
        });

        result?;

        log::info!("MacosAuthHandle: Authorization created successfully - will be reused for all operations");
        Ok(Self { _private: () })
    }

    /// Execute a command using the stored Authorization (NO new dialog).
    ///
    /// The execution is dispatched to the main queue via GCD for window server context.
    /// The Authorization obtained during `new()` is reused.
    ///
    /// # Arguments
    /// * `command` - Shell command to execute with root privileges
    ///
    /// # Returns
    /// * `WorkerResult::Success` or `WorkerResult::Output(output)` on success
    /// * `WorkerResult::Error(message)` on failure
    pub fn exec(&self, command: &str) -> super::WorkerResult {
        // Safety: Calling from main thread would deadlock
        debug_assert!(
            !is_main_thread(),
            "MacosAuthHandle::exec called from main thread - would deadlock!"
        );

        let command_owned = command.to_string();

        log::debug!("MacosAuthHandle: Executing via GCD dispatch: {}", command);

        // Dispatch to main queue for window server context
        let result: Result<String, String> = Queue::main().exec_sync(move || {
            // Safety: We're on the main thread (via GCD dispatch)
            let auth = unsafe { MAIN_THREAD_AUTH.get() };

            match auth.execute_with_privileges_piped(
                "/bin/sh",
                ["-c", &command_owned],
                Flags::DEFAULTS,
            ) {
                Ok(file) => {
                    // Drain output
                    let mut output = String::new();
                    for line in BufReader::new(file).lines().map_while(Result::ok) {
                        log::debug!("privileged: {}", line);
                        output.push_str(&line);
                        output.push('\n');
                    }
                    Ok(output)
                }
                Err(e) => Err(e.to_string()),
            }
        });

        match result {
            Ok(output) => {
                if output.is_empty() {
                    super::WorkerResult::Success
                } else {
                    super::WorkerResult::Output(output)
                }
            }
            Err(e) => super::WorkerResult::Error(e),
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Returns true if currently executing on the main thread.
fn is_main_thread() -> bool {
    // libc::pthread_main_np() returns non-zero on main thread
    unsafe { libc::pthread_main_np() != 0 }
}

// ============================================================================
// LEGACY API - Kept for backwards compatibility
// ============================================================================

/// Execute a shell script with root privileges using native macOS Authorization Services.
///
/// Shows the standard macOS authentication dialog (supports password + Touch ID).
/// Executes the entire script in a single authorization session.
///
/// **NOTE**: This creates a NEW Authorization for each call. For multiple operations,
/// use `MacosAuthHandle` instead to avoid multiple auth dialogs.
///
/// # Threading
///
/// This function dispatches to the main queue via GCD because Authorization Services
/// requires window server context. The caller MUST NOT be on the main thread (would deadlock).
///
/// # Arguments
/// * `script` - Shell script to execute with root privileges
///
/// # Returns
/// * `Ok(())` on successful execution
/// * `Err(AuthorizationError::Cancelled)` if user clicked Cancel (error code -60006)
/// * `Err(AuthorizationError::Denied)` if authentication failed (error code -60005)
#[allow(dead_code)]
pub fn execute_privileged_macos(script: &str) -> Result<(), AuthorizationError> {
    debug_assert!(
        !is_main_thread(),
        "execute_privileged_macos called from main thread - would deadlock!"
    );

    let script_owned = script.to_string();

    Queue::main().exec_sync(move || execute_on_main_thread(&script_owned))
}

/// Internal function that actually calls Authorization Services.
/// MUST be called on main thread (via Queue::main().exec_sync).
fn execute_on_main_thread(script: &str) -> Result<(), AuthorizationError> {
    log::info!("execute_on_main_thread called, script: {}", script);

    let rights = AuthorizationItemSetBuilder::new()
        .add_right("system.privilege.admin")
        .map_err(|e| AuthorizationError::BuildRights(e.to_string()))?
        .build();

    log::info!("Creating Authorization with INTERACTION_ALLOWED | EXTEND_RIGHTS | PREAUTHORIZE");
    let auth = Authorization::new(
        Some(rights),
        None,
        Flags::INTERACTION_ALLOWED | Flags::EXTEND_RIGHTS | Flags::PREAUTHORIZE,
    )
    .map_err(|e| {
        let code = e.code();
        log::error!("Authorization::new failed with code {}: {}", code, e);
        match code {
            -60006 => AuthorizationError::Cancelled,
            -60005 => AuthorizationError::Denied,
            -60007 => AuthorizationError::NoInteraction,
            _ => AuthorizationError::Failed {
                code,
                message: e.to_string(),
            },
        }
    })?;

    log::info!("Authorization created successfully, executing privileged command...");

    let file = auth
        .execute_with_privileges_piped("/bin/sh", ["-c", script], Flags::DEFAULTS)
        .map_err(|e| AuthorizationError::Execute(e.to_string()))?;

    for line in BufReader::new(file).lines().map_while(Result::ok) {
        log::debug!("privileged: {}", line);
    }

    Ok(())
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors that can occur during macOS authorization
#[derive(Debug)]
pub enum AuthorizationError {
    /// Failed to build authorization rights
    BuildRights(String),
    /// User clicked Cancel in the authentication dialog (error code -60006)
    Cancelled,
    /// Authorization denied - wrong password or access denied (error code -60005)
    Denied,
    /// Authorization requires interaction but none allowed (error code -60007)
    NoInteraction,
    /// Authorization failed with other error
    Failed { code: i32, message: String },
    /// Failed to execute privileged command
    Execute(String),
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BuildRights(e) => write!(f, "Failed to build authorization rights: {}", e),
            Self::Cancelled => write!(f, "Authentication cancelled by user"),
            Self::Denied => write!(f, "Authorization denied"),
            Self::NoInteraction => {
                write!(f, "Authorization requires interaction but none allowed")
            }
            Self::Failed { code, message } => {
                write!(f, "Authorization failed (code {}): {}", code, message)
            }
            Self::Execute(e) => write!(f, "Failed to execute privileged command: {}", e),
        }
    }
}

impl std::error::Error for AuthorizationError {}
