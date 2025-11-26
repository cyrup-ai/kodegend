//! Environment detection for CLI vs Desktop
//!
//! Determines if running in a terminal (CLI) or desktop GUI environment.
//! Used by ensure_installed() to select appropriate installation UI.
//!
//! Detection strategy per platform:
//! - macOS: CoreGraphics display list (can we actually show windows?)
//! - Linux/BSD: X11 or Wayland display server available
//! - Windows: Session ID != 0 (Session 0 = service context, no GUI)

/// Check if a display is available for GUI rendering
///
/// Platform-specific detection:
/// - macOS: Uses CoreGraphics to check for active displays
/// - Linux/BSD: Checks DISPLAY or WAYLAND_DISPLAY environment variables
/// - Windows: Checks if running in Session 0 (services session = no GUI)
#[cfg(target_os = "macos")]
fn has_display() -> bool {
    use core_graphics2::display::get_active_display_list;

    // Get list of active displays - if any exist, we have GUI capability
    get_active_display_list(10)
        .map(|list| !list.is_empty())
        .unwrap_or(false)
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn has_display() -> bool {
    std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok()
}

#[cfg(target_os = "windows")]
fn has_display() -> bool {
    use windows::Win32::System::Threading::{GetCurrentProcessId, ProcessIdToSessionId};

    let mut session_id: u32 = 0;
    unsafe {
        if ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id).is_ok() {
            // Session 0 = service context = no display
            // Any other session = interactive user = has display
            session_id != 0
        } else {
            false
        }
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "windows"
)))]
fn has_display() -> bool {
    // Unknown platform - assume no display (conservative)
    false
}

/// Check if running in CLI environment (no GUI available)
///
/// Returns `true` if no display is available for GUI rendering.
pub fn is_cli_environment() -> bool {
    !has_display()
}

/// Check if running in desktop GUI environment
///
/// Returns `true` if a display is available for GUI rendering.
pub fn is_desktop_environment() -> bool {
    has_display()
}
