//! Environment detection for CLI vs Desktop
//!
//! Determines if running in a terminal (CLI) or desktop GUI environment.
//! Used by ensure_installed() to select appropriate installation UI.

/// Check if running in CLI environment
///
/// Returns `true` if any of:
/// - SSH connection detected (SSH_CONNECTION or SSH_CLIENT env vars)
/// - No GUI available (no DISPLAY on Linux/Unix)
/// - Running in TTY (stdout.is_terminal())
///
/// Conservative: defaults to `true` if uncertain (prefer CLI over GUI)
pub fn is_cli_environment() -> bool {
    // Check SSH connection
    if std::env::var("SSH_CONNECTION").is_ok() || std::env::var("SSH_CLIENT").is_ok() {
        return true;
    }
    
    // Check if no GUI on Linux/Unix
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    {
        if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
            return true;
        }
    }
    
    // Check if running in terminal
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        return true;
    }
    
    // Default to CLI if uncertain (conservative choice)
    true
}

/// Check if running in desktop GUI environment
///
/// Returns `true` if:
/// - Not in SSH connection
/// - GUI display available (DISPLAY or WAYLAND_DISPLAY on Linux)
/// - Not running in TTY
///
/// Inverse of is_cli_environment()
pub fn is_desktop_environment() -> bool {
    !is_cli_environment()
}
