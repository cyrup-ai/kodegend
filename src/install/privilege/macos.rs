//! macOS privilege escalation using native Authorization Services API.
//!
//! This module uses the `security-framework` crate to access macOS Authorization Services,
//! providing native authentication dialogs (password + Touch ID) without requiring osascript.
//!
//! # Threading Model
//!
//! Authorization Services requires execution context with window server access.
//! The main thread (running egui) has this context; background threads do not.
//! We use GCD's `Queue::main().exec_sync()` to dispatch to the main thread.
//!
//! # References
//! - tmp/security-framework/security-framework/src/authorization.rs:517-537 (execute_with_privileges)
//! - tmp/security-framework/security-framework-sys/src/authorization.rs:7-22 (error codes)
//! - tmp/dispatch/src/queue.rs:82-88 (Queue::main)
//! - tmp/dispatch/src/queue.rs:135-153 (exec_sync)
//! - tmp/libc/src/unix/bsd/apple/mod.rs:4240 (pthread_main_np)
//! - tmp/winit/winit-appkit/src/observer.rs:99-100 (GCD + CFRunLoop integration)

use dispatch::Queue;
use security_framework::authorization::{Authorization, AuthorizationItemSetBuilder, Flags};
use std::io::{BufRead, BufReader};

/// Returns true if currently executing on the main thread.
/// Source: libc crate, tmp/libc/src/unix/bsd/apple/mod.rs:4240
fn is_main_thread() -> bool {
    // libc::pthread_main_np() returns non-zero on main thread
    unsafe { libc::pthread_main_np() != 0 }
}

/// Execute a shell script with root privileges using native macOS Authorization Services.
///
/// Shows the standard macOS authentication dialog (supports password + Touch ID).
/// Executes the entire script in a single authorization session.
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
///
/// # Panics
/// Debug builds panic if called from main thread (would deadlock).
///
/// # Example
/// ```ignore
/// execute_privileged_macos("mkdir -p /usr/local/bin && cp /tmp/kodegend /usr/local/bin/")?;
/// ```
pub fn execute_privileged_macos(script: &str) -> Result<(), AuthorizationError> {
    // Safety: Calling from main thread would deadlock (exec_sync to same queue)
    debug_assert!(
        !is_main_thread(),
        "execute_privileged_macos called from main thread - would deadlock!"
    );

    let script_owned = script.to_string();

    // Dispatch to main queue - REQUIRED for Authorization Services
    // Source: tmp/dispatch/src/queue.rs:135-153
    // exec_sync blocks until the closure completes on main thread
    Queue::main().exec_sync(move || execute_on_main_thread(&script_owned))
}

/// Internal function that actually calls Authorization Services.
/// MUST be called on main thread (via Queue::main().exec_sync).
fn execute_on_main_thread(script: &str) -> Result<(), AuthorizationError> {
    // Verify we're on main thread
    let on_main = unsafe { libc::pthread_main_np() != 0 };
    log::info!(
        "execute_on_main_thread called - on main thread: {}, script: {}",
        on_main,
        script
    );

    // Build rights request for admin privileges
    // Source: tmp/security-framework/security-framework/src/authorization.rs:787-789
    let rights = AuthorizationItemSetBuilder::new()
        .add_right("system.privilege.admin")
        .map_err(|e| AuthorizationError::BuildRights(e.to_string()))?
        .build();

    // Create authorization with interaction allowed
    // Source: tmp/security-framework/security-framework/src/authorization.rs:790-796
    log::info!("Creating Authorization with INTERACTION_ALLOWED | EXTEND_RIGHTS | PREAUTHORIZE");
    let auth = Authorization::new(
        Some(rights),
        None, // No environment
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

    // Execute script using AuthorizationExecuteWithPrivileges
    // This is deprecated since macOS 10.7 but still functional and the simplest path
    // Source: tmp/security-framework/security-framework/src/authorization.rs:541-560
    let file = auth
        .execute_with_privileges_piped("/bin/sh", ["-c", script], Flags::DEFAULTS)
        .map_err(|e| AuthorizationError::Execute(e.to_string()))?;

    // Read output (for logging/debugging)
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        log::debug!("privileged: {}", line);
    }

    Ok(())
}

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
