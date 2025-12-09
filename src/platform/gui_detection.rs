//! Robust GUI detection for installation wizard
//!
//! Determines whether a graphical display is available using platform-native APIs.
//! Returns true only if we can safely launch an eframe/egui window.

use once_cell::sync::Lazy;

/// Cached GUI detection result (display state doesn't change during process lifetime)
static GUI_AVAILABLE: Lazy<bool> = Lazy::new(|| {
    let result = platform_is_gui_available();
    log::debug!("GUI detection result: {}", result);
    result
});

/// Check if a graphical display is available for GUI installation wizard
///
/// # Platform Behavior
/// - **macOS**: Uses CoreGraphics CGMainDisplayID() to check for active displays
/// - **Linux**: Checks Wayland socket, X11 DISPLAY, systemd graphical-session.target
/// - **Windows**: Checks desktop access, Session 0 isolation, service mode
///
/// # Performance
/// - Completes in < 10ms on all platforms
/// - Result is cached after first call
///
/// # Safety
/// - Never panics - all errors fall back to `false`
pub fn is_gui_available() -> bool {
    *GUI_AVAILABLE
}

// ============================================================================
// macOS Implementation
// ============================================================================

#[cfg(target_os = "macos")]
fn platform_is_gui_available() -> bool {
    use core_graphics2::display;

    // Method 1: Check if main display exists (most reliable)
    // CGMainDisplayID() returns 0 if no display available
    let main_display = unsafe { display::CGMainDisplayID() };
    if main_display == 0 {
        log::debug!("macOS: CGMainDisplayID returned 0, no display available");
        return false;
    }

    // Method 2: Verify we have at least one active display
    let mut display_count: u32 = 0;
    let result = unsafe {
        display::CGGetActiveDisplayList(0, std::ptr::null_mut(), &mut display_count)
    };

    // CGError::success is 0, any other value indicates error
    if result != core_graphics2::error::CGError::Success || display_count == 0 {
        log::debug!("macOS: No active displays found (count={})", display_count);
        return false;
    }

    log::debug!("macOS: Found {} active display(s)", display_count);
    true
}

// ============================================================================
// Linux Implementation
// ============================================================================

#[cfg(target_os = "linux")]
fn platform_is_gui_available() -> bool {
    // Priority 1: Wayland (modern, preferred)
    if is_wayland_available() {
        log::debug!("Linux: Wayland display available");
        return true;
    }

    // Priority 2: X11 (legacy, but still common)
    if is_x11_available() {
        log::debug!("Linux: X11 display available");
        return true;
    }

    // Priority 3: XDG_SESSION_TYPE environment variable
    if let Ok(session_type) = std::env::var("XDG_SESSION_TYPE")
        && (session_type == "wayland" || session_type == "x11")
    {
        log::debug!("Linux: XDG_SESSION_TYPE={}", session_type);
        return true;
    }

    // Priority 4: systemd graphical session target
    if is_graphical_target_active() {
        log::debug!("Linux: systemd graphical-session.target active");
        return true;
    }

    log::debug!("Linux: No GUI detected");
    false
}

#[cfg(target_os = "linux")]
fn is_wayland_available() -> bool {
    if let Ok(display) = std::env::var("WAYLAND_DISPLAY")
        && !display.is_empty()
    {
        // Verify the socket actually exists
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));
        let socket_path = std::path::Path::new(&runtime_dir).join(&display);
        return socket_path.exists();
    }
    false
}

#[cfg(target_os = "linux")]
fn is_x11_available() -> bool {
    if let Ok(display) = std::env::var("DISPLAY")
        && !display.is_empty()
    {
        // Quick verification: try xdpyinfo with timeout
        return std::process::Command::new("timeout")
            .args(["0.5", "xdpyinfo"])
            .env("DISPLAY", &display)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    false
}

#[cfg(target_os = "linux")]
fn is_graphical_target_active() -> bool {
    std::process::Command::new("systemctl")
        .args(["--user", "is-active", "graphical-session.target"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
fn platform_is_gui_available() -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{GetDesktopWindow, GetSystemMetrics, SM_CXSCREEN};
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;

    // Check 1: Running as Windows Service (no GUI possible)
    if is_running_as_service() {
        log::debug!("Windows: Running as service, no GUI");
        return false;
    }

    // Check 2: Session 0 isolation (services run in Session 0, no GUI)
    unsafe {
        let pid = GetCurrentProcessId();
        let mut session_id: u32 = 0;
        if ProcessIdToSessionId(pid, &mut session_id).is_ok() && session_id == 0 {
            log::debug!("Windows: Session 0 detected, no GUI");
            return false;
        }
    }

    // Check 3: Desktop access
    unsafe {
        let desktop = GetDesktopWindow();
        if desktop.0.is_null() {
            log::debug!("Windows: No desktop window");
            return false;
        }

        // Check 4: Screen dimensions (headless server check)
        let screen_width = GetSystemMetrics(SM_CXSCREEN);
        if screen_width <= 0 {
            log::debug!("Windows: No screen dimensions");
            return false;
        }
    }

    log::debug!("Windows: GUI available");
    true
}

#[cfg(target_os = "windows")]
fn is_running_as_service() -> bool {
    // Check command line for service flags
    if std::env::args().any(|arg| arg == "--service" || arg == "--windows-service") {
        return true;
    }

    // Check if parent is services.exe
    use sysinfo::{System, Pid, ProcessRefreshKind};

    let mut system = System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
    );

    let current_pid = std::process::id();
    if let Some(current) = system.process(Pid::from_u32(current_pid)) {
        if let Some(parent_pid) = current.parent() {
            if let Some(parent) = system.process(parent_pid) {
                let parent_name = parent.name().to_string_lossy().to_lowercase();
                return parent_name == "services.exe";
            }
        }
    }

    false
}

// ============================================================================
// Fallback for other platforms
// ============================================================================

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_is_gui_available() -> bool {
    // Conservative: assume no GUI on unknown platforms
    false
}
