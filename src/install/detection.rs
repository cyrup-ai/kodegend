//! Installation state detection
//!
//! Determines if Kodegen is installed, partially installed, or not installed
//! by checking all required components:
//! - 1 binary in /usr/local/bin (kodegen MCP stdio server)
//! - System service file (launchd/systemd) - for kodegend
//! - TLS certificates in config directory
//! - Chromium browser in cache directory
//!
//! NOTE: We do NOT check for kodegend binary because kodegend is already
//! running when this code executes! It's kodegend calling ensure_installed().

use std::path::Path;

/// Installation state enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationState {
    /// No binaries or configuration found
    NotInstalled,
    /// Some components installed but incomplete (repair needed)
    PartiallyInstalled,
    /// All components installed and configured
    FullyInstalled,
}

/// Check current installation state by verifying all components
///
/// Returns:
/// - `FullyInstalled` if kodegen binary, service, certs, and chromium present
/// - `NotInstalled` if kodegen binary not found
/// - `PartiallyInstalled` otherwise (needs repair)
pub fn check_installation_state() -> InstallationState {
    let binaries_ok = check_binaries_installed();
    let service_ok = check_service_configured();
    let certs_ok = check_certificates_present();
    let chromium_ok = check_chromium_installed();
    
    match (binaries_ok, service_ok, certs_ok, chromium_ok) {
        (0, false, false, false) => InstallationState::NotInstalled,
        (1, true, true, true) => InstallationState::FullyInstalled,
        _ => InstallationState::PartiallyInstalled,
    }
}

/// Count how many of the 1 required binaries are installed in /usr/local/bin
///
/// Uses the canonical BINARIES array from src/binaries.rs:
/// ["kodegen"]
///
/// NOTE: We do NOT check for kodegend because it's already running!
fn check_binaries_installed() -> usize {
    use super::binaries::BINARIES;
    
    #[cfg(unix)]
    let bin_dir = Path::new("/usr/local/bin");
    
    #[cfg(windows)]
    let bin_dir = Path::new(r"C:\Program Files\Kodegen");
    
    BINARIES.iter()
        .filter(|name| bin_dir.join(name).exists())
        .count()
}

/// Check if system service is configured
///
/// Paths:
/// - macOS: /Library/LaunchDaemons/com.kodegen.daemon.plist
/// - Linux: /etc/systemd/system/kodegend.service
/// - Windows: Registry key (HKLM\SYSTEM\CurrentControlSet\Services\kodegend)
fn check_service_configured() -> bool {
    #[cfg(target_os = "macos")]
    {
        Path::new("/Library/LaunchDaemons/com.kodegen.daemon.plist").exists()
    }
    
    #[cfg(target_os = "linux")]
    {
        Path::new("/etc/systemd/system/kodegend.service").exists()
    }
    
    #[cfg(target_os = "windows")]
    {
        // Check if kodegend service exists in Windows Service Manager
        // Uses minimal permissions for read-only detection
        use windows::Win32::System::Services::{
            OpenSCManagerW, OpenServiceW, CloseServiceHandle,
            SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
        };
        use windows::core::PCWSTR;
        
        // Service name to check
        let service_name = "kodegend";
        
        // Convert to UTF-16 (Windows native string format)
        let wide_name: Vec<u16> = service_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        
        unsafe {
            // Open Service Control Manager with minimal permissions
            let scm = OpenSCManagerW(
                PCWSTR::null(),           // Local machine
                PCWSTR::null(),           // Default database
                SC_MANAGER_CONNECT,       // Minimal read-only access
            );
            
            if scm.is_invalid() {
                return false;  // SCM not available or no permissions
            }
            
            // Try to open the kodegend service
            let service = OpenServiceW(
                scm,
                PCWSTR::from_raw(wide_name.as_ptr()),
                SERVICE_QUERY_STATUS,     // Minimal read-only access
            );
            
            let exists = !service.is_invalid();
            
            // Clean up handles (RAII pattern)
            if !service.is_invalid() {
                let _ = CloseServiceHandle(service);
            }
            let _ = CloseServiceHandle(scm);
            
            exists  // Return true if service was opened successfully
        }
    }
    
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Check if certificates directory exists and has files
///
/// Path: dirs::config_dir()/kodegen/certs/
/// Expected files: *.crt, *.key, *.pem
fn check_certificates_present() -> bool {
    if let Some(config_dir) = dirs::config_dir() {
        let cert_dir = config_dir.join("kodegen").join("certs");
        cert_dir.exists() && cert_dir.read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    } else {
        false
    }
}

/// Check if Chromium is installed in cache directory
///
/// Chromium is downloaded by kodegen_tools_citescrape::download_managed_browser()
///
/// Paths:
/// - macOS: ~/Library/Caches/kodegen/chromium/
/// - Linux: ~/.cache/kodegen/chromium/
/// - Windows: %LOCALAPPDATA%\kodegen\chromium\
fn check_chromium_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            let chromium_path = home.join("Library/Caches/kodegen/chromium");
            chromium_path.exists()
        } else {
            false
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        if let Some(cache) = dirs::cache_dir() {
            let chromium_path = cache.join("kodegen/chromium");
            chromium_path.exists()
        } else {
            false
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        if let Some(local_data) = dirs::data_local_dir() {
            let chromium_path = local_data.join("kodegen\\chromium");
            chromium_path.exists()
        } else {
            false
        }
    }
    
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}
