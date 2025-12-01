//! Common error types for daemon control operations across all platforms
//!
//! Provides a unified error type (DaemonControlError) that standardizes error
//! handling across Linux/systemd, macOS/launchd, and Windows/SCM implementations.

use std::time::Duration;
use thiserror::Error;

/// Errors that can occur during daemon control operations
///
/// This enum provides structured, machine-parseable errors with actionable
/// error messages that guide users to resolution. All variants include
/// helpful context about what went wrong and how to fix it.
#[derive(Error, Debug)]
pub enum DaemonControlError {
    /// Service/daemon is not installed on the system
    ///
    /// Occurs when attempting to control a service that doesn't exist in the
    /// service manager (systemd, launchd, or Windows SCM).
    #[error("Service '{service}' is not installed. Run 'kodegend install' to install the service first.")]
    ServiceNotFound { service: String },

    /// Insufficient permissions to perform the operation
    ///
    /// Occurs when the current user lacks privileges to control system services.
    /// Resolution requires running with elevated privileges.
    #[error("Permission denied for operation: {operation}. Try running with elevated privileges (sudo on Linux/macOS, Administrator on Windows).")]
    PermissionDenied { operation: String },

    /// Service is already running when attempting to start
    ///
    /// This is not necessarily an error condition - it indicates the service
    /// is already in the desired state. Calling code can ignore this.
    #[error("Service is already running")]
    ServiceAlreadyRunning,

    /// Service is not currently running when attempting to stop
    ///
    /// This is not necessarily an error condition - it indicates the service
    /// is already in the desired state. Calling code can ignore this.
    #[error("Service is not running")]
    ServiceNotRunning,

    /// Operation timed out waiting for service state change
    ///
    /// Occurs when the service doesn't transition to the expected state
    /// within the timeout period. Check service logs for startup/shutdown issues.
    #[error("Operation '{operation}' timed out after {duration:?}. Check service logs for details.")]
    Timeout {
        operation: String,
        duration: Duration,
    },

    /// Platform-specific system error with error code
    ///
    /// Contains the platform error code (Windows error code, Unix exit code)
    /// and a descriptive message. Use this for detailed debugging.
    #[error("{message} (error code: {code})")]
    SystemError { message: String, code: i32 },

    /// System error without an error code
    ///
    /// Fallback for errors where no numeric error code is available.
    #[error("{0}")]
    SystemErrorNoCode(String),

    /// Failed to execute platform command (systemctl, launchctl, etc.)
    ///
    /// This represents an I/O error when attempting to spawn or communicate
    /// with the platform's service control command.
    #[error("Failed to execute {command}: {source}")]
    CommandExecution {
        command: String,
        #[source]
        source: std::io::Error,
    },
}
